package clavis

import (
	"errors"
	"net/http"
	"uuid"

	"clavisid.org/clavis/internal/app"
	"clavisid.org/clavis/internal/authn/password"
	"clavisid.org/clavis/internal/i18n"
	"clavisid.org/clavis/internal/ui"
)

// handleResetPage asks for the email address of the account whose password
// the user resets, for the authorization request in the query (ADR 0027),
// or for the account pages without one (ADR 0028).
func (s *Server) handleResetPage(w http.ResponseWriter, r *http.Request, t tenant) {
	if !t.reset {
		s.flowUnavailable(w, r, t, resetFlow)
		return
	}
	query := r.URL.Query()
	if query.Get("request") == "" {
		// A reset for the account pages.
		s.resetPage(w, r, t, nil, s.locale(w, r, query.Get(ui.LocaleParam), ""), "", "")
		return
	}
	p, err := app.FindAuthorizationRequest(r.Context(), s.deps, t.ID, query.Get("request"), bindingHash(r))
	if err != nil {
		s.authorizationRequestError(w, r, t, err)
		return
	}
	if p.Request.SessionID != uuid.Nil() {
		// A user signed in for the request already; it waits for consent.
		seeOther(w, pageURL(t, consentPath, p.Request.ID))
		return
	}
	s.resetPage(w, r, t, &p, s.locale(w, r, query.Get(ui.LocaleParam), p.Request.UILocales),
		p.Request.LoginHint, "")
}

// handleReset starts the password reset of the posted address and sends the
// browser to the page that asks for the code. The response is the same
// whether or not the address has an account (ADR 0027).
func (s *Server) handleReset(w http.ResponseWriter, r *http.Request, t tenant) {
	form, ok := s.flowForm(w, r, t, resetFlow)
	if !ok {
		return
	}
	var p *app.PendingAuthorization
	var uiLocales string
	if form.Get("request") != "" {
		pending, err := app.FindAuthorizationRequest(r.Context(), s.deps, t.ID, form.Get("request"), bindingHash(r))
		if err != nil {
			s.authorizationRequestError(w, r, t, err)
			return
		}
		p, uiLocales = &pending, pending.Request.UILocales
	}
	l := s.locale(w, r, "", uiLocales)
	// The account pages have no binding cookie of their own; a reset binds
	// to the browser like an authorization request does.
	id, err := app.StartPasswordReset(r.Context(), s.deps, t.authorizationTenant(), p, form.Get("email"),
		s.bindBrowser(w, r), s.catalogs.Printer(l), t.issuer+resetVerifyPath)
	switch {
	case errors.Is(err, app.ErrInvalidEmail):
		s.resetPage(w, r, t, p, l, form.Get("email"), i18n.SignupInvalidEmail)
		return
	case errors.Is(err, app.ErrResetUnavailable):
		s.flowUnavailable(w, r, t, resetFlow)
		return
	case errors.Is(err, app.ErrTooManyMessages):
		s.tooManyMessages(w, r, t, l)
		return
	case err != nil:
		s.authorizationRequestError(w, r, t, err)
		return
	}
	seeOther(w, verificationURL(t, resetVerifyPath, id))
}

// handleResetPassword sets the posted password and sends the user back to
// the sign-in form of the authorization request, filled with the address,
// or says that the password has changed when the request is gone. The user
// signs in with the new password: a reset never replaces a sign-in.
func (s *Server) handleResetPassword(w http.ResponseWriter, r *http.Request, t tenant) {
	form, ok := s.flowForm(w, r, t, resetFlow)
	if !ok {
		return
	}
	v, p, ok := s.findVerification(w, r, t, resetFlow, form.Get("verification"))
	if !ok {
		return
	}
	if v.VerifiedAt.IsZero() {
		seeOther(w, verificationURL(t, resetVerifyPath, v.ID))
		return
	}
	u, err := app.CompletePasswordReset(r.Context(), s.deps, s.passwords, v, form.Get("password"))
	switch {
	case errors.Is(err, password.ErrPolicy):
		s.passwordPage(w, r, t, resetFlow, v, p, s.flowLocale(w, r, p, ""), i18n.PasswordPolicy)
		return
	case err != nil:
		s.verificationError(w, r, t, resetFlow, err)
		return
	}
	// The reset ended the browser's session along with every other.
	s.clearSessionCookie(w, r, t)
	l := s.flowLocale(w, r, p, "")
	if v.AuthorizationRequestID == "" {
		s.accountLoginPage(w, r, t, l, u.Email, "", i18n.LoginPasswordChanged)
		return
	}
	if p != nil && p.Request.SessionID == uuid.Nil() {
		s.loginPage(w, r, t, *p, l, u.Email, "", i18n.LoginPasswordChanged)
		return
	}
	layout := s.layout(r, t, l)
	ui.SetPageHeaders(w.Header(), layout.ContentSecurityPolicy(false))
	s.render(w, r, http.StatusOK, ui.PasswordChanged(ui.PasswordChangedPage{Layout: layout}))
}

// resetPage renders the form that asks for the email address of the account
// in locale l, filled with email, with the message of problem unless it is
// empty.
func (s *Server) resetPage(w http.ResponseWriter, r *http.Request, t tenant, p *app.PendingAuthorization,
	l i18n.Locale, email string, problem i18n.Key,
) {
	layout := s.layout(r, t, l)
	selector := &ui.LanguageSelector{Method: http.MethodGet, Action: t.path + resetPath}
	requestID, loginURL := "", t.issuer+accountLoginPath
	if p != nil {
		requestID, loginURL = p.Request.ID, pageURL(t, loginPath, p.Request.ID)
		selector.Fields = []ui.Field{{Name: "request", Value: requestID}}
	}
	layout.Languages = selector
	var message string
	if problem != "" {
		message = layout.T(problem)
	}
	ui.SetPageHeaders(w.Header(), layout.ContentSecurityPolicy(true))
	s.render(w, r, http.StatusOK, ui.Reset(ui.ResetPage{
		Layout:    layout,
		Action:    t.path + resetPath,
		RequestID: requestID,
		Email:     email,
		Error:     message,
		LoginURL:  loginURL,
	}))
}
