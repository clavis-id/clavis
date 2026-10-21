package clavis

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"uuid"

	"clavisid.org/clavis/internal/app"
	"clavisid.org/clavis/internal/authn/password"
	"clavisid.org/clavis/internal/i18n"
	"clavisid.org/clavis/internal/ui"
	"clavisid.org/clavis/store"
)

// Paths of the signup pages, relative to a tenant's issuer (ADR 0026).
const (
	signupPath         = "/signup"
	signupVerifyPath   = "/signup/verify"
	signupPasswordPath = "/signup/password"
)

// handleSignupPage asks for the email address of a new account, for the
// authorization request in the query.
func (s *Server) handleSignupPage(w http.ResponseWriter, r *http.Request, t tenant) {
	if !t.signup {
		s.signupUnavailable(w, r, t)
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
	form, ok := s.signupForm(w, r, t)
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
		s.signupUnavailable(w, r, t)
		return
	case err != nil:
		s.authorizationRequestError(w, r, t, err)
		return
	}
	seeOther(w, verificationURL(t, signupVerifyPath, id))
}

// handleVerifyPage asks for the code of an email verification or, when the
// query holds the token of its link, asks the user to confirm the link.
func (s *Server) handleVerifyPage(w http.ResponseWriter, r *http.Request, t tenant) {
	query := r.URL.Query()
	v, p, ok := s.findSignup(w, r, t, query.Get("verification"))
	if !ok {
		return
	}
	if !v.VerifiedAt.IsZero() {
		seeOther(w, verificationURL(t, signupPasswordPath, v.ID))
		return
	}
	token := query.Get("token")
	if token != "" && !validToken(token) {
		s.verificationError(w, r, t, app.ErrVerificationNotFound)
		return
	}
	s.verifyPage(w, r, t, v, s.signupLocale(w, r, p, query.Get(ui.LocaleParam)), token, "")
}

// handleVerify checks the posted code, or the token of a link, and sends the
// browser on to the page that asks for the password.
func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request, t tenant) {
	form, ok := s.signupForm(w, r, t)
	if !ok {
		return
	}
	v, p, ok := s.findSignup(w, r, t, form.Get("verification"))
	if !ok {
		return
	}
	var err error
	if token := form.Get("token"); token != "" {
		err = app.VerifyLink(r.Context(), s.deps, v, token)
	} else {
		err = app.VerifyCode(r.Context(), s.deps, v, form.Get("code"))
	}
	switch {
	case errors.Is(err, app.ErrWrongCode):
		s.verifyPage(w, r, t, v, s.signupLocale(w, r, p, ""), "", i18n.VerifyWrongCode)
		return
	case err != nil:
		s.verificationError(w, r, t, err)
		return
	}
	seeOther(w, verificationURL(t, signupPasswordPath, v.ID))
}

// handlePasswordPage asks for the password of the new account, once its
// address is verified.
func (s *Server) handlePasswordPage(w http.ResponseWriter, r *http.Request, t tenant) {
	query := r.URL.Query()
	v, p, ok := s.findSignup(w, r, t, query.Get("verification"))
	if !ok {
		return
	}
	if v.VerifiedAt.IsZero() {
		seeOther(w, verificationURL(t, signupVerifyPath, v.ID))
		return
	}
	s.passwordPage(w, r, t, v, p, s.signupLocale(w, r, p, query.Get(ui.LocaleParam)), "")
}

// handleSignupPassword creates the account with the posted password, signs
// the user in, and goes on with the authorization request as a sign-in
// does, or says that the account is ready when the request is gone.
func (s *Server) handleSignupPassword(w http.ResponseWriter, r *http.Request, t tenant) {
	form, ok := s.signupForm(w, r, t)
	if !ok {
		return
	}
	v, p, ok := s.findSignup(w, r, t, form.Get("verification"))
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
		s.passwordPage(w, r, t, v, p, s.signupLocale(w, r, p, ""), i18n.PasswordPolicy)
		return
	case errors.Is(err, app.ErrUserExists):
		// The user proved the address, so its account need not stay secret.
		s.errorPage(w, r, t, s.signupLocale(w, r, p, ""), http.StatusConflict, i18n.ErrorAccountExistsTitle,
			i18n.ErrorAccountExists)
		return
	case err != nil:
		s.verificationError(w, r, t, err)
		return
	}
	s.setSessionCookie(w, t, signup.Login)
	switch {
	case !signup.Request:
		layout := s.layout(r, t, s.signupLocale(w, r, p, ""))
		ui.SetPageHeaders(w.Header(), layout.ContentSecurityPolicy(false))
		s.render(w, r, http.StatusOK, ui.SignedUp(ui.SignedUpPage{Layout: layout}))
	case signup.Consent:
		seeOther(w, pageURL(t, consentPath, p.Request.ID))
	default:
		s.respond(w, r, t, p.Request.UILocales, signup.Response)
	}
}

// signupForm checks that a signup form comes from Clavis's own pages, that
// the tenant offers signup, and parses the form. On failure it answers the
// request and returns false.
func (s *Server) signupForm(w http.ResponseWriter, r *http.Request, t tenant) (url.Values, bool) {
	if err := s.crossOrigin.Check(r); err != nil {
		s.errorPage(w, r, t, s.locale(w, r, "", ""), http.StatusForbidden, i18n.ErrorBlockedTitle,
			i18n.ErrorCrossSiteSignupForm)
		return nil, false
	}
	if !t.signup {
		s.signupUnavailable(w, r, t)
		return nil, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		s.errorPage(w, r, t, s.locale(w, r, "", ""), http.StatusBadRequest, i18n.ErrorInvalidSignupTitle,
			i18n.ErrorMalformedSignupForm)
		return nil, false
	}
	return r.PostForm, true
}

// findSignup returns the signup verification with the given ID, which must
// belong to this browser, and its authorization request, or nil when the
// request is gone. On failure it answers the request and returns false.
func (s *Server) findSignup(w http.ResponseWriter, r *http.Request, t tenant, id string,
) (store.EmailVerification, *app.PendingAuthorization, bool) {
	if !t.signup {
		s.signupUnavailable(w, r, t)
		return store.EmailVerification{}, nil, false
	}
	v, err := app.FindEmailVerification(r.Context(), s.deps, t.ID, id, bindingHash(r), store.VerifySignup)
	if err != nil {
		s.verificationError(w, r, t, err)
		return store.EmailVerification{}, nil, false
	}
	p, err := app.FindAuthorizationRequest(r.Context(), s.deps, t.ID, v.AuthorizationRequestID, bindingHash(r))
	switch {
	case errors.Is(err, app.ErrAuthorizationRequestNotFound):
		return v, nil, true
	case err != nil:
		s.internalError(w, r, "finding the authorization request of a signup", err)
		return store.EmailVerification{}, nil, false
	}
	return v, &p, true
}

// signupLocale returns the language of a signup page: as for any page, with
// the ui_locales of the authorization request p, when it is still pending.
func (s *Server) signupLocale(w http.ResponseWriter, r *http.Request, p *app.PendingAuthorization,
	chosen string,
) i18n.Locale {
	var uiLocales string
	if p != nil {
		uiLocales = p.Request.UILocales
	}
	return s.locale(w, r, chosen, uiLocales)
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

// verifyPage renders the form for the code of v in locale l, or the
// confirmation of its link when token is set, with the message of problem
// unless it is empty.
func (s *Server) verifyPage(w http.ResponseWriter, r *http.Request, t tenant, v store.EmailVerification,
	l i18n.Locale, token string, problem i18n.Key,
) {
	layout := s.layout(r, t, l)
	fields := []ui.Field{{Name: "verification", Value: v.ID}}
	if token != "" {
		fields = append(fields, ui.Field{Name: "token", Value: token})
	}
	layout.Languages = &ui.LanguageSelector{Method: http.MethodGet, Action: t.path + signupVerifyPath, Fields: fields}
	var message string
	if problem != "" {
		message = layout.T(problem)
	}
	ui.SetPageHeaders(w.Header(), layout.ContentSecurityPolicy(true))
	s.render(w, r, http.StatusOK, ui.Verify(ui.VerifyPage{
		Layout:         layout,
		Email:          v.Email,
		Action:         t.path + signupVerifyPath,
		VerificationID: v.ID,
		Token:          token,
		Error:          message,
		RestartURL:     pageURL(t, signupPath, v.AuthorizationRequestID),
	}))
}

// passwordPage renders the form for the password of the account of v in
// locale l, with the message of problem unless it is empty. Its policy lets
// the form submission redirect to the client of p, as on the login page.
func (s *Server) passwordPage(w http.ResponseWriter, r *http.Request, t tenant, v store.EmailVerification,
	p *app.PendingAuthorization, l i18n.Locale, problem i18n.Key,
) {
	layout := s.layout(r, t, l)
	layout.Languages = &ui.LanguageSelector{Method: http.MethodGet, Action: t.path + signupPasswordPath,
		Fields: []ui.Field{{Name: "verification", Value: v.ID}}}
	var targets []string
	if p != nil {
		if target := ui.FormTarget(p.Request.RedirectURI); target != "" {
			targets = append(targets, target)
		}
	}
	minLength, maxLength := s.passwords.MinLength(), password.MaxLength
	var message string
	if problem != "" {
		message = layout.T(problem, "min", strconv.Itoa(minLength), "max", strconv.Itoa(maxLength))
	}
	ui.SetPageHeaders(w.Header(), layout.ContentSecurityPolicy(true, targets...))
	s.render(w, r, http.StatusOK, ui.Password(ui.PasswordPage{
		Layout:         layout,
		Email:          v.Email,
		Action:         t.path + signupPasswordPath,
		VerificationID: v.ID,
		MinLength:      minLength,
		MaxLength:      maxLength,
		Error:          message,
	}))
}

// signupUnavailable answers a signup request to a tenant that offers no
// signup, or to a server without email.
func (s *Server) signupUnavailable(w http.ResponseWriter, r *http.Request, t tenant) {
	s.errorPage(w, r, t, s.locale(w, r, "", ""), http.StatusNotFound, i18n.ErrorSignupUnavailableTitle,
		i18n.ErrorSignupUnavailable)
}

// verificationError answers a request whose email verification cannot be
// used.
func (s *Server) verificationError(w http.ResponseWriter, r *http.Request, t tenant, err error) {
	switch {
	case errors.Is(err, app.ErrTooManyAttempts):
		s.errorPage(w, r, t, s.locale(w, r, "", ""), http.StatusBadRequest, i18n.ErrorTooManyCodesTitle,
			i18n.ErrorTooManyCodes)
	case errors.Is(err, app.ErrVerificationNotFound):
		s.errorPage(w, r, t, s.locale(w, r, "", ""), http.StatusBadRequest, i18n.ErrorExpiredSignupTitle,
			i18n.ErrorExpiredSignup)
	default:
		s.internalError(w, r, "signing up", err)
	}
}

// verificationURL returns the URL of a signup page of tenant t for the email
// verification with the given ID.
func verificationURL(t tenant, path, id string) string {
	return t.issuer + path + "?" + url.Values{"verification": {id}}.Encode()
}

// validToken reports whether token has the form of a value from
// oauth.NewToken, so other values never reach a page.
func validToken(token string) bool {
	return len(token) == tokenLength && strings.Trim(token, base64URLAlphabet) == ""
}
