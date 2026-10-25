package clavis

import (
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"uuid"

	"clavisid.org/clavis/internal/app"
	"clavisid.org/clavis/internal/i18n"
	"clavisid.org/clavis/internal/oauth"
	"clavisid.org/clavis/internal/ui"
)

// Paths of the hosted pages, relative to a tenant's issuer, and of the
// static assets, relative to the issuer of the default tenant.
const (
	loginPath   = "/login"
	consentPath = "/consent"
	assetsPath  = "/assets/"
)

// maxFormBytes bounds the body of the forms Clavis accepts.
const maxFormBytes = 64 << 10

// bindingCookie carries the random value that binds stored authorization
// requests to the browser that started them (ADR 0013). The __Host- prefix
// keeps other hosts, such as sibling subdomains, from setting it.
const bindingCookie = "__Host-clavis-binding"

// sessionCookiePrefix starts the name of the session cookie of a tenant.
// Each tenant has its own cookie, so tenants on one host never share a
// session (ADR 0013).
const sessionCookiePrefix = "__Host-clavis-session-"

// tokenLength is the length of a value from oauth.NewToken.
const tokenLength = 43

// handleAuthorize serves the authorization endpoint (RFC 6749, section
// 3.1; OpenID Connect Core 1.0, section 3.1.2.1). When the browser's session
// answers a valid request, the browser goes back to the client with a code;
// otherwise the request is stored and the browser goes on to the login page,
// or to the consent page when the session's user must allow the client.
// An invalid request either goes back to the client with an error or, when
// the client or redirect URI cannot be trusted, ends on an error page.
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request, t tenant) {
	// The mux sends HEAD to GET routes, but a HEAD request has no use for a
	// stored authorization request.
	if r.Method == http.MethodHead {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	params, err := authorizationParams(w, r)
	if err != nil {
		s.errorPage(w, r, t, s.locale(w, r, "", ""), http.StatusBadRequest, i18n.ErrorInvalidSignInTitle,
			i18n.ErrorMalformedSignIn)
		return
	}
	uiLocales := oauth.UILocales(params)
	a, err := app.StartAuthorization(r.Context(), s.deps, s.signer, t.authorizationTenant(), params,
		s.bindBrowser(w, r), sessionHash(r, t.ID))
	var redirect *app.RedirectError
	switch {
	case errors.As(err, &redirect):
		s.respond(w, r, t, uiLocales, redirect.Response)
	case errors.Is(err, oauth.ErrInvalidAuthorizationTarget):
		// The problem holds only fixed English text, never request input:
		// it names a parameter for the application's developers.
		s.errorPage(w, r, t, s.locale(w, r, "", uiLocales), http.StatusBadRequest, i18n.ErrorInvalidSignInTitle,
			i18n.ErrorRejectedSignIn, "problem", err.Error())
	case err != nil:
		s.internalError(w, r, "starting the authorization", err)
	case a.Response.RedirectURI != "":
		s.respond(w, r, t, uiLocales, a.Response)
	case a.Consent:
		seeOther(w, pageURL(t, consentPath, a.RequestID))
	case a.Signup:
		seeOther(w, pageURL(t, signupPath, a.RequestID))
	default:
		seeOther(w, pageURL(t, loginPath, a.RequestID))
	}
}

// pageURL returns the URL of a hosted page of a stored authorization
// request.
func pageURL(t tenant, path, requestID string) string {
	return t.issuer + path + "?" + url.Values{"request": {requestID}}.Encode()
}

// authorizationParams returns the parameters of an authorization request:
// the query of a GET request, or the form body of a POST request (OpenID
// Connect Core 1.0, section 3.1.2.1).
func authorizationParams(w http.ResponseWriter, r *http.Request) (url.Values, error) {
	if r.Method != http.MethodPost {
		params, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			return nil, fmt.Errorf("parsing the query: %w", err)
		}
		return params, nil
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		return nil, fmt.Errorf("parsing the form: %w", err)
	}
	return r.PostForm, nil
}

// handleLoginPage shows the sign-in form of a stored authorization request.
func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request, t tenant) {
	p, err := app.FindAuthorizationRequest(r.Context(), s.deps, t.ID, r.URL.Query().Get("request"), bindingHash(r))
	if err != nil {
		s.authorizationRequestError(w, r, t, err)
		return
	}
	if p.Request.SessionID != uuid.Nil() {
		// The user signed in already, for example before going back a page.
		seeOther(w, pageURL(t, consentPath, p.Request.ID))
		return
	}
	s.loginPage(w, r, t, p, s.locale(w, r, r.URL.Query().Get(ui.LocaleParam), p.Request.UILocales),
		p.Request.LoginHint, "", "")
}

// handleLogin checks the credentials posted from the sign-in form. On
// success it starts a session and sends the browser back to the client with
// an authorization code.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request, t tenant) {
	if err := s.crossOrigin.Check(r); err != nil {
		s.errorPage(w, r, t, s.locale(w, r, "", ""), http.StatusForbidden, i18n.ErrorBlockedTitle,
			i18n.ErrorCrossSiteSignInForm)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		s.errorPage(w, r, t, s.locale(w, r, "", ""), http.StatusBadRequest, i18n.ErrorInvalidSignInTitle,
			i18n.ErrorMalformedSignInForm)
		return
	}
	form := r.PostForm
	if s.pageLimited(w, r, t, s.limits.passwords) {
		return
	}
	p, err := app.FindAuthorizationRequest(r.Context(), s.deps, t.ID, form.Get("request"), bindingHash(r))
	if err != nil {
		s.authorizationRequestError(w, r, t, err)
		return
	}
	email := form.Get("email")
	login, err := app.CompletePasswordLogin(r.Context(), s.deps, s.passwords, t.authorizationTenant(), p, email,
		form.Get("password"), sessionHash(r, t.ID))
	switch {
	case errors.Is(err, app.ErrInvalidCredentials):
		s.countClient(s.limits.passwords, r)
		s.loginPage(w, r, t, p, s.locale(w, r, "", p.Request.UILocales), email, i18n.LoginInvalidCredentials, "")
		return
	case errors.Is(err, app.ErrUserDisabled):
		s.loginPage(w, r, t, p, s.locale(w, r, "", p.Request.UILocales), email, i18n.LoginDisabled, "")
		return
	case err != nil:
		s.authorizationRequestError(w, r, t, err)
		return
	}
	s.setSessionCookie(w, t, login)
	if login.Consent {
		seeOther(w, pageURL(t, consentPath, p.Request.ID))
		return
	}
	s.respond(w, r, t, p.Request.UILocales, login.Response)
}

// handleConsentPage asks the signed-in user to allow or deny the client of
// a stored authorization request (ADR 0020).
func (s *Server) handleConsentPage(w http.ResponseWriter, r *http.Request, t tenant) {
	c, err := app.FindConsent(r.Context(), s.deps, t.ID, r.URL.Query().Get("request"), bindingHash(r),
		sessionHash(r, t.ID))
	if err != nil {
		s.authorizationRequestError(w, r, t, err)
		return
	}
	layout := s.layout(r, t, s.locale(w, r, r.URL.Query().Get(ui.LocaleParam), c.Request.UILocales))
	layout.Languages = &ui.LanguageSelector{Method: http.MethodGet, Action: t.path + consentPath,
		Fields: []ui.Field{{Name: "request", Value: c.Request.ID}}}
	scopes := make([]string, len(c.Scopes))
	for i, scope := range c.Scopes {
		scopes[i] = ui.ScopeDescription(layout.Text, scope.Scope, scope.Resource)
	}
	// The decision redirects to the client, which form-action must allow.
	var targets []string
	if target := ui.FormTarget(c.Request.RedirectURI); target != "" {
		targets = append(targets, target)
	}
	ui.SetPageHeaders(w.Header(), layout.ContentSecurityPolicy(true, targets...))
	s.render(w, r, http.StatusOK, ui.Consent(ui.ConsentPage{
		Layout:     layout,
		ClientName: c.Client.Name,
		Account:    c.User.Email,
		Scopes:     scopes,
		Action:     t.path + consentPath,
		RequestID:  c.Request.ID,
	}))
}

// handleConsent records the decision posted from the consent page and sends
// the browser back to the client.
func (s *Server) handleConsent(w http.ResponseWriter, r *http.Request, t tenant) {
	if err := s.crossOrigin.Check(r); err != nil {
		s.errorPage(w, r, t, s.locale(w, r, "", ""), http.StatusForbidden, i18n.ErrorBlockedTitle,
			i18n.ErrorCrossSiteConsentForm)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	err := r.ParseForm()
	decision := r.PostForm.Get("decision")
	if err != nil || decision != "allow" && decision != "deny" {
		s.errorPage(w, r, t, s.locale(w, r, "", ""), http.StatusBadRequest, i18n.ErrorInvalidConsentTitle,
			i18n.ErrorMalformedConsentForm)
		return
	}
	c, err := app.FindConsent(r.Context(), s.deps, t.ID, r.PostForm.Get("request"), bindingHash(r), sessionHash(r, t.ID))
	if err != nil {
		s.authorizationRequestError(w, r, t, err)
		return
	}
	resp, err := app.CompleteConsent(r.Context(), s.deps, t.authorizationTenant(), c, decision == "allow")
	if err != nil {
		s.authorizationRequestError(w, r, t, err)
		return
	}
	s.respond(w, r, t, c.Request.UILocales, resp)
}

// respond sends the browser back to the client with an authorization
// response: a redirect in the query response mode, or a page that posts the
// response in the form_post response mode (OAuth 2.0 Form Post Response
// Mode, section 2). uiLocales is the ui_locales parameter of the request.
func (s *Server) respond(w http.ResponseWriter, r *http.Request, t tenant, uiLocales string,
	resp app.AuthorizationResponse,
) {
	if !resp.FormPost {
		seeOther(w, resp.URI())
		return
	}
	fields := make([]ui.Field, 0, len(resp.Params))
	for _, name := range slices.Sorted(maps.Keys(resp.Params)) {
		for _, value := range resp.Params[name] {
			fields = append(fields, ui.Field{Name: name, Value: value})
		}
	}
	layout := s.layout(r, t, s.locale(w, r, "", uiLocales))
	ui.SetPageHeaders(w.Header(), layout.FormPostContentSecurityPolicy(ui.FormTarget(resp.RedirectURI)))
	s.render(w, r, http.StatusOK, ui.FormPost(ui.FormPostPage{
		Layout: layout,
		Action: resp.RedirectURI,
		Fields: fields,
	}))
}

// loginPage renders the sign-in form in locale l, with the email address
// to fill in, the message of problem and the message of notice, unless they
// are empty. Its policy lets the form submission redirect to the client,
// which browsers check against form-action.
func (s *Server) loginPage(w http.ResponseWriter, r *http.Request, t tenant, p app.PendingAuthorization,
	l i18n.Locale, email string, problem, notice i18n.Key,
) {
	layout := s.layout(r, t, l)
	layout.Languages = &ui.LanguageSelector{Method: http.MethodGet, Action: t.path + loginPath,
		Fields: []ui.Field{{Name: "request", Value: p.Request.ID}}}
	var targets []string
	if target := ui.FormTarget(p.Request.RedirectURI); target != "" {
		targets = append(targets, target)
	}
	var message, info, signupURL, resetURL string
	if problem != "" {
		message = layout.T(problem)
	}
	if notice != "" {
		info = layout.T(notice)
	}
	if t.signup {
		signupURL = pageURL(t, signupPath, p.Request.ID)
	}
	if t.reset {
		resetURL = pageURL(t, resetPath, p.Request.ID)
	}
	ui.SetPageHeaders(w.Header(), layout.ContentSecurityPolicy(true, targets...))
	s.render(w, r, http.StatusOK, ui.Login(ui.LoginPage{
		Layout:     layout,
		ClientName: p.Client.Name,
		Action:     t.path + loginPath,
		RequestID:  p.Request.ID,
		Email:      email,
		Error:      message,
		Notice:     info,
		SignupURL:  signupURL,
		ResetURL:   resetURL,
	}))
}

// authorizationRequestError answers a request whose stored authorization
// request cannot be used.
func (s *Server) authorizationRequestError(w http.ResponseWriter, r *http.Request, t tenant, err error) {
	if !errors.Is(err, app.ErrAuthorizationRequestNotFound) {
		s.internalError(w, r, "signing in", err)
		return
	}
	s.errorPage(w, r, t, s.locale(w, r, "", ""), http.StatusBadRequest, i18n.ErrorExpiredSignInTitle,
		i18n.ErrorExpiredSignIn)
}

// handleAsset serves the static files of the hosted pages.
func (s *Server) handleAsset(w http.ResponseWriter, r *http.Request) {
	s.assets.ServeAsset(w, r, r.PathValue("name"))
}

// setSessionCookie sets the cookie of the session that login started (ADR
// 0013).
func (s *Server) setSessionCookie(w http.ResponseWriter, t tenant, login app.Login) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName(t.ID),
		Value:    login.SessionToken,
		Path:     "/",
		MaxAge:   int(login.SessionExpiresAt.Sub(s.deps.Now()).Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// clearSessionCookie removes the browser's session cookie for tenant t, if
// it has one.
func (s *Server) clearSessionCookie(w http.ResponseWriter, r *http.Request, t tenant) {
	if _, err := r.Cookie(sessionCookieName(t.ID)); err != nil {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName(t.ID),
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// bindBrowser returns the hash of the browser's binding cookie, setting the
// cookie first when the browser has none.
//
// The cookie is SameSite=Lax like the session cookie, so a cross-site POST
// to the authorization endpoint does not carry it; the browser then gets a
// new value, and requests it started earlier in other tabs no longer match.
func (s *Server) bindBrowser(w http.ResponseWriter, r *http.Request) []byte {
	if h := bindingHash(r); h != nil {
		return h
	}
	value := oauth.NewToken()
	http.SetCookie(w, &http.Cookie{
		Name:     bindingCookie,
		Value:    value,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	return oauth.HashToken(value)
}

// bindingHash returns the hash of the browser's binding cookie, or nil.
func bindingHash(r *http.Request) []byte {
	return cookieHash(r, bindingCookie)
}

// sessionHash returns the hash of the browser's session cookie for a
// tenant, or nil.
func sessionHash(r *http.Request, tenantID uuid.UUID) []byte {
	return cookieHash(r, sessionCookieName(tenantID))
}

// cookieHash returns the hash of a cookie that holds a token, or nil when
// the request has no such cookie with a well-formed value.
func cookieHash(r *http.Request, name string) []byte {
	c, err := r.Cookie(name)
	if err != nil || len(c.Value) != tokenLength || strings.Trim(c.Value, base64URLAlphabet) != "" {
		return nil
	}
	return oauth.HashToken(c.Value)
}

// base64URLAlphabet is the alphabet of base64url (RFC 4648, section 5).
const base64URLAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

func sessionCookieName(tenantID uuid.UUID) string {
	return sessionCookiePrefix + tenantID.String()
}

// seeOther redirects the browser with 303, which turns a form submission
// into a GET (RFC 9700, section 4.12). Responses that carry codes are never
// cached, and the next page learns nothing from the referrer.
func seeOther(w http.ResponseWriter, location string) {
	h := w.Header()
	h.Set("Location", location)
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(http.StatusSeeOther)
}
