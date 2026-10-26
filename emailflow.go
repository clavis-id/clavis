package clavis

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"clavisid.org/clavis/internal/app"
	"clavisid.org/clavis/internal/authn/password"
	"clavisid.org/clavis/internal/i18n"
	"clavisid.org/clavis/internal/ui"
	"clavisid.org/clavis/store"
)

// emailFlow is a series of hosted pages that proves an email address with a
// code or a link and then lets the user choose a password: signup (ADR
// 0026) or password reset (ADR 0027). Each flow has its own paths and the
// messages of its error pages.
type emailFlow struct {
	purpose      store.EmailVerificationPurpose
	startPath    string
	verifyPath   string
	passwordPath string

	invalidTitle     i18n.Key
	malformedForm    i18n.Key
	crossSiteForm    i18n.Key
	unavailableTitle i18n.Key
	unavailable      i18n.Key
	expiredTitle     i18n.Key
	expired          i18n.Key
}

// Paths of the signup and password reset pages, relative to a tenant's
// issuer.
const (
	signupPath         = "/signup"
	signupVerifyPath   = "/signup/verify"
	signupPasswordPath = "/signup/password"
	resetPath          = "/reset"
	resetVerifyPath    = "/reset/verify"
	resetPasswordPath  = "/reset/password"
)

var (
	signupFlow = emailFlow{
		purpose:          store.VerifySignup,
		startPath:        signupPath,
		verifyPath:       signupVerifyPath,
		passwordPath:     signupPasswordPath,
		invalidTitle:     i18n.ErrorInvalidSignupTitle,
		malformedForm:    i18n.ErrorMalformedSignupForm,
		crossSiteForm:    i18n.ErrorCrossSiteSignupForm,
		unavailableTitle: i18n.ErrorSignupUnavailableTitle,
		unavailable:      i18n.ErrorSignupUnavailable,
		expiredTitle:     i18n.ErrorExpiredSignupTitle,
		expired:          i18n.ErrorExpiredSignup,
	}
	resetFlow = emailFlow{
		purpose:          store.VerifyPasswordReset,
		startPath:        resetPath,
		verifyPath:       resetVerifyPath,
		passwordPath:     resetPasswordPath,
		invalidTitle:     i18n.ErrorInvalidResetTitle,
		malformedForm:    i18n.ErrorMalformedResetForm,
		crossSiteForm:    i18n.ErrorCrossSiteResetForm,
		unavailableTitle: i18n.ErrorResetUnavailableTitle,
		unavailable:      i18n.ErrorResetUnavailable,
		expiredTitle:     i18n.ErrorExpiredResetTitle,
		expired:          i18n.ErrorExpiredReset,
	}
)

// reset reports whether f is the password reset flow.
func (f emailFlow) reset() bool { return f.purpose == store.VerifyPasswordReset }

// available reports whether tenant t offers the flow.
func (f emailFlow) available(t tenant) bool {
	if f.reset() {
		return t.reset
	}
	return t.signup
}

// handleVerifyPage asks for the code of an email verification of flow f or,
// when the query holds the token of its link, asks the user to confirm the
// link.
func (s *Server) handleVerifyPage(f emailFlow) tenantHandler {
	return func(w http.ResponseWriter, r *http.Request, t tenant) {
		query := r.URL.Query()
		v, p, ok := s.findVerification(w, r, t, f, query.Get("verification"))
		if !ok {
			return
		}
		if !v.VerifiedAt.IsZero() {
			seeOther(w, verificationURL(t, f.passwordPath, v.ID))
			return
		}
		token := query.Get("token")
		if token != "" && !validToken(token) {
			s.verificationError(w, r, t, f, app.ErrVerificationNotFound)
			return
		}
		s.verifyPage(w, r, t, f, v, s.flowLocale(w, r, p, query.Get(ui.LocaleParam)), token, "")
	}
}

// handleVerify checks the posted code, or the token of a link, and sends the
// browser on to the page that asks for the password.
func (s *Server) handleVerify(f emailFlow) tenantHandler {
	return func(w http.ResponseWriter, r *http.Request, t tenant) {
		form, ok := s.flowForm(w, r, t, f)
		if !ok {
			return
		}
		v, p, ok := s.findVerification(w, r, t, f, form.Get("verification"))
		if !ok {
			return
		}
		var err error
		// Links cannot be guessed, so only codes are limited.
		if token := form.Get("token"); token != "" {
			err = app.VerifyLink(r.Context(), s.deps, v, token)
		} else {
			res, ok := s.reservePage(w, r, t, s.limits.codes)
			if !ok {
				return
			}
			err = app.VerifyCode(r.Context(), s.deps, v, form.Get("code"))
			s.settle(res, errors.Is(err, app.ErrWrongCode) || errors.Is(err, app.ErrTooManyAttempts))
		}
		switch {
		case errors.Is(err, app.ErrWrongCode):
			s.verifyPage(w, r, t, f, v, s.flowLocale(w, r, p, ""), "", i18n.VerifyWrongCode)
			return
		case err != nil:
			s.verificationError(w, r, t, f, err)
			return
		}
		seeOther(w, verificationURL(t, f.passwordPath, v.ID))
	}
}

// handlePasswordPage asks for the password once the address of the
// verification is proved.
func (s *Server) handlePasswordPage(f emailFlow) tenantHandler {
	return func(w http.ResponseWriter, r *http.Request, t tenant) {
		query := r.URL.Query()
		v, p, ok := s.findVerification(w, r, t, f, query.Get("verification"))
		if !ok {
			return
		}
		if v.VerifiedAt.IsZero() {
			seeOther(w, verificationURL(t, f.verifyPath, v.ID))
			return
		}
		s.passwordPage(w, r, t, f, v, p, s.flowLocale(w, r, p, query.Get(ui.LocaleParam)), "")
	}
}

// flowForm checks that a form of flow f comes from Clavis's own pages and
// that the tenant offers the flow, and parses the form. On failure it
// answers the request and returns false.
func (s *Server) flowForm(w http.ResponseWriter, r *http.Request, t tenant, f emailFlow) (url.Values, bool) {
	if err := s.crossOrigin.Check(r); err != nil {
		s.errorPage(w, r, t, s.locale(w, r, "", ""), http.StatusForbidden, i18n.ErrorBlockedTitle, f.crossSiteForm)
		return nil, false
	}
	if !f.available(t) {
		s.flowUnavailable(w, r, t, f)
		return nil, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		s.errorPage(w, r, t, s.locale(w, r, "", ""), http.StatusBadRequest, f.invalidTitle, f.malformedForm)
		return nil, false
	}
	return r.PostForm, true
}

// findVerification returns the email verification of flow f with the given
// ID, which must belong to this browser, and its authorization request, or
// nil when the request is gone. On failure it answers the request and
// returns false.
func (s *Server) findVerification(w http.ResponseWriter, r *http.Request, t tenant, f emailFlow, id string,
) (store.EmailVerification, *app.PendingAuthorization, bool) {
	if !f.available(t) {
		s.flowUnavailable(w, r, t, f)
		return store.EmailVerification{}, nil, false
	}
	v, err := app.FindEmailVerification(r.Context(), s.deps, t.ID, id, bindingHash(r), f.purpose)
	if err != nil {
		s.verificationError(w, r, t, f, err)
		return store.EmailVerification{}, nil, false
	}
	p, err := app.FindAuthorizationRequest(r.Context(), s.deps, t.ID, v.AuthorizationRequestID, bindingHash(r))
	switch {
	case errors.Is(err, app.ErrAuthorizationRequestNotFound):
		return v, nil, true
	case err != nil:
		s.internalError(w, r, "finding the authorization request of an email verification", err)
		return store.EmailVerification{}, nil, false
	}
	return v, &p, true
}

// flowLocale returns the language of a page of a flow: as for any page,
// with the ui_locales of the authorization request p, when it is still
// pending.
func (s *Server) flowLocale(w http.ResponseWriter, r *http.Request, p *app.PendingAuthorization,
	chosen string,
) i18n.Locale {
	var uiLocales string
	if p != nil {
		uiLocales = p.Request.UILocales
	}
	return s.locale(w, r, chosen, uiLocales)
}

// verifyPage renders the form for the code of v in locale l, or the
// confirmation of its link when token is set, with the message of problem
// unless it is empty.
func (s *Server) verifyPage(w http.ResponseWriter, r *http.Request, t tenant, f emailFlow,
	v store.EmailVerification, l i18n.Locale, token string, problem i18n.Key,
) {
	layout := s.layout(r, t, l)
	fields := []ui.Field{{Name: "verification", Value: v.ID}}
	if token != "" {
		fields = append(fields, ui.Field{Name: "token", Value: token})
	}
	layout.Languages = &ui.LanguageSelector{Method: http.MethodGet, Action: t.path + f.verifyPath, Fields: fields}
	var message string
	if problem != "" {
		message = layout.T(problem)
	}
	ui.SetPageHeaders(w.Header(), layout.ContentSecurityPolicy(true))
	s.render(w, r, http.StatusOK, ui.Verify(ui.VerifyPage{
		Layout:         layout,
		Reset:          f.reset(),
		Email:          v.Email,
		Action:         t.path + f.verifyPath,
		VerificationID: v.ID,
		Token:          token,
		Error:          message,
		RestartURL:     pageURL(t, f.startPath, v.AuthorizationRequestID),
	}))
}

// passwordPage renders the form for the password of the account of v in
// locale l, with the message of problem unless it is empty. Its policy lets
// the form submission redirect to the client of p, as on the login page.
func (s *Server) passwordPage(w http.ResponseWriter, r *http.Request, t tenant, f emailFlow,
	v store.EmailVerification, p *app.PendingAuthorization, l i18n.Locale, problem i18n.Key,
) {
	layout := s.layout(r, t, l)
	layout.Languages = &ui.LanguageSelector{Method: http.MethodGet, Action: t.path + f.passwordPath,
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
		Reset:          f.reset(),
		Email:          v.Email,
		Action:         t.path + f.passwordPath,
		VerificationID: v.ID,
		MinLength:      minLength,
		MaxLength:      maxLength,
		Error:          message,
	}))
}

// flowUnavailable answers a request of flow f to a tenant that does not
// offer it.
func (s *Server) flowUnavailable(w http.ResponseWriter, r *http.Request, t tenant, f emailFlow) {
	s.errorPage(w, r, t, s.locale(w, r, "", ""), http.StatusNotFound, f.unavailableTitle, f.unavailable)
}

// verificationError answers a request whose email verification cannot be
// used.
func (s *Server) verificationError(w http.ResponseWriter, r *http.Request, t tenant, f emailFlow, err error) {
	switch {
	case errors.Is(err, app.ErrTooManyAttempts):
		s.errorPage(w, r, t, s.locale(w, r, "", ""), http.StatusBadRequest, i18n.ErrorTooManyCodesTitle,
			i18n.ErrorTooManyCodes)
	case errors.Is(err, app.ErrCodesLocked):
		// The address is locked, not the verification: its link still works.
		s.errorPage(w, r, t, s.locale(w, r, "", ""), http.StatusTooManyRequests, i18n.ErrorTooManyCodesTitle,
			i18n.ErrorCodesLocked)
	case errors.Is(err, app.ErrVerificationNotFound):
		s.errorPage(w, r, t, s.locale(w, r, "", ""), http.StatusBadRequest, f.expiredTitle, f.expired)
	default:
		s.internalError(w, r, "verifying an email address", err)
	}
}

// tooManyMessages answers a request to start a flow for an address that
// received too many messages (ADR 0030). The page is the same whether or
// not the address has an account.
func (s *Server) tooManyMessages(w http.ResponseWriter, r *http.Request, t tenant, l i18n.Locale) {
	s.errorPage(w, r, t, l, http.StatusTooManyRequests, i18n.ErrorTooManyMessagesTitle, i18n.ErrorTooManyMessages)
}

// verificationURL returns the URL of a page of tenant t for the email
// verification with the given ID.
func verificationURL(t tenant, path, id string) string {
	return t.issuer + path + "?" + url.Values{"verification": {id}}.Encode()
}

// validToken reports whether token has the form of a value from
// oauth.NewToken, so other values never reach a page.
func validToken(token string) bool {
	return len(token) == tokenLength && strings.Trim(token, base64URLAlphabet) == ""
}
