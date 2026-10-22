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

// handleSignupPage asks for the email address of a new account, for the
// authorization request in the query (ADR 0026).
func (s *Server) handleSignupPage(w http.ResponseWriter, r *http.Request, t tenant) {
	if !t.signup {
		s.flowUnavailable(w, r, t, signupFlow)
		return
	}
	p, err := app.FindAuthorizationRequest(r.Context(), s.deps, t.ID, r.URL.Query().Get("request"), bindingHash(r))
	if err != nil {
		s.authorizationRequestError(w, r, t, err)
		return
	}
	if p.Request.SessionID != uuid.Nil() {
		// A user signed in for the request already; it waits for consent.
		seeOther(w, pageURL(t, consentPath, p.Request.ID))
		return
	}
	s.signupPage(w, r, t, p, s.locale(w, r, r.URL.Query().Get(ui.LocaleParam), p.Request.UILocales),
		p.Request.LoginHint, "")
}

// handleSignup starts the signup of the posted address and sends the
// browser to the page that asks for the code. The response is the same
// whether or not the address has an account (ADR 0026).
func (s *Server) handleSignup(w http.ResponseWriter, r *http.Request, t tenant) {
	form, ok := s.flowForm(w, r, t, signupFlow)
	if !ok {
		return
	}
	p, err := app.FindAuthorizationRequest(r.Context(), s.deps, t.ID, form.Get("request"), bindingHash(r))
	if err != nil {
		s.authorizationRequestError(w, r, t, err)
		return
	}
	l := s.locale(w, r, "", p.Request.UILocales)
	id, err := app.StartSignup(r.Context(), s.deps, t.authorizationTenant(), p, form.Get("email"), bindingHash(r),
		s.catalogs.Printer(l), t.issuer+signupVerifyPath)
	switch {
	case errors.Is(err, app.ErrInvalidEmail):
		s.signupPage(w, r, t, p, l, form.Get("email"), i18n.SignupInvalidEmail)
		return
	case errors.Is(err, app.ErrSignupUnavailable):
		s.flowUnavailable(w, r, t, signupFlow)
		return
	case err != nil:
		s.authorizationRequestError(w, r, t, err)
		return
	}
	seeOther(w, verificationURL(t, signupVerifyPath, id))
}

// handleSignupPassword creates the account with the posted password, signs
// the user in, and goes on with the authorization request as a sign-in
// does, or says that the account is ready when the request is gone.
func (s *Server) handleSignupPassword(w http.ResponseWriter, r *http.Request, t tenant) {
	form, ok := s.flowForm(w, r, t, signupFlow)
	if !ok {
		return
	}
	v, p, ok := s.findVerification(w, r, t, signupFlow, form.Get("verification"))
	if !ok {
		return
	}
	if v.VerifiedAt.IsZero() {
		seeOther(w, verificationURL(t, signupVerifyPath, v.ID))
		return
	}
	signup, err := app.CompleteSignup(r.Context(), s.deps, s.passwords, t.authorizationTenant(), v,
		form.Get("password"), p, sessionHash(r, t.ID))
	switch {
	case errors.Is(err, password.ErrPolicy):
		s.passwordPage(w, r, t, signupFlow, v, p, s.flowLocale(w, r, p, ""), i18n.PasswordPolicy)
		return
	case errors.Is(err, app.ErrUserExists):
		// The user proved the address, so its account need not stay secret.
		s.errorPage(w, r, t, s.flowLocale(w, r, p, ""), http.StatusConflict, i18n.ErrorAccountExistsTitle,
			i18n.ErrorAccountExists)
		return
	case err != nil:
		s.verificationError(w, r, t, signupFlow, err)
		return
	}
	s.setSessionCookie(w, t, signup.Login)
	switch {
	case !signup.Request:
		layout := s.layout(r, t, s.flowLocale(w, r, p, ""))
		ui.SetPageHeaders(w.Header(), layout.ContentSecurityPolicy(false))
		s.render(w, r, http.StatusOK, ui.SignedUp(ui.SignedUpPage{Layout: layout}))
	case signup.Consent:
		seeOther(w, pageURL(t, consentPath, p.Request.ID))
	default:
		s.respond(w, r, t, p.Request.UILocales, signup.Response)
	}
}

// signupPage renders the form that asks for the email address in locale l,
// filled with email, with the message of problem unless it is empty.
func (s *Server) signupPage(w http.ResponseWriter, r *http.Request, t tenant, p app.PendingAuthorization,
	l i18n.Locale, email string, problem i18n.Key,
) {
	layout := s.layout(r, t, l)
	layout.Languages = &ui.LanguageSelector{Method: http.MethodGet, Action: t.path + signupPath,
		Fields: []ui.Field{{Name: "request", Value: p.Request.ID}}}
	var message string
	if problem != "" {
		message = layout.T(problem)
	}
	ui.SetPageHeaders(w.Header(), layout.ContentSecurityPolicy(true))
	s.render(w, r, http.StatusOK, ui.Signup(ui.SignupPage{
		Layout:     layout,
		ClientName: p.Client.Name,
		Action:     t.path + signupPath,
		RequestID:  p.Request.ID,
		Email:      email,
		Error:      message,
		LoginURL:   pageURL(t, loginPath, p.Request.ID),
	}))
}
