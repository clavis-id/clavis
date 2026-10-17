package clavis

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"uuid"

	"github.com/a-h/templ"

	"clavisid.org/clavis/internal/app"
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
		s.errorPage(w, r, http.StatusBadRequest, "Invalid sign-in request",
			"The sign-in request is malformed. Return to the application and try again.")
		return
	}
	a, err := app.StartAuthorization(r.Context(), s.deps, s.signer, t.authorizationTenant(), params,
		s.bindBrowser(w, r), sessionHash(r, t.ID))
	var redirect *app.RedirectError
	switch {
	case errors.As(err, &redirect):
		seeOther(w, redirect.URI)
	case errors.Is(err, oauth.ErrInvalidAuthorizationTarget):
		// The message holds only fixed text, never request input.
		s.errorPage(w, r, http.StatusBadRequest, "Invalid sign-in request",
			"The application sent a sign-in request that cannot be accepted ("+err.Error()+
				"). Return to the application and try again.")
	case err != nil:
		s.internalError(w, r, "starting the authorization", err)
	case a.RedirectURI != "":
		seeOther(w, a.RedirectURI)
	case a.Consent:
		seeOther(w, pageURL(t, consentPath, a.RequestID))
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
		s.authorizationRequestError(w, r, err)
		return
	}
	if p.Request.SessionID != uuid.Nil() {
		// The user signed in already, for example before going back a page.
		seeOther(w, pageURL(t, consentPath, p.Request.ID))
		return
	}
	s.loginPage(w, r, t, p, p.Request.LoginHint, "")
}

// handleLogin checks the credentials posted from the sign-in form. On
// success it starts a session and sends the browser back to the client with
// an authorization code.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request, t tenant) {
	if err := s.crossOrigin.Check(r); err != nil {
		s.errorPage(w, r, http.StatusForbidden, "Request blocked",
			"The sign-in form was submitted from another site.")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		s.errorPage(w, r, http.StatusBadRequest, "Invalid sign-in request",
			"The sign-in form is malformed. Return to the application and try again.")
		return
	}
	form := r.PostForm
	p, err := app.FindAuthorizationRequest(r.Context(), s.deps, t.ID, form.Get("request"), bindingHash(r))
	if err != nil {
		s.authorizationRequestError(w, r, err)
		return
	}
	email := form.Get("email")
	login, err := app.CompletePasswordLogin(r.Context(), s.deps, s.passwords, t.authorizationTenant(), p, email,
		form.Get("password"), sessionHash(r, t.ID))
	switch {
	case errors.Is(err, app.ErrInvalidCredentials):
		s.loginPage(w, r, t, p, email, "The email or password is incorrect.")
		return
	case errors.Is(err, app.ErrUserDisabled):
		s.loginPage(w, r, t, p, email, "This account is disabled.")
		return
	case err != nil:
		s.authorizationRequestError(w, r, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName(t.ID),
		Value:    login.SessionToken,
		Path:     "/",
		MaxAge:   int(login.SessionExpiresAt.Sub(s.deps.Now()).Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	if login.Consent {
		seeOther(w, pageURL(t, consentPath, p.Request.ID))
		return
	}
	seeOther(w, login.RedirectURI)
}

// handleConsentPage asks the signed-in user to allow or deny the client of
// a stored authorization request (ADR 0020).
func (s *Server) handleConsentPage(w http.ResponseWriter, r *http.Request, t tenant) {
	c, err := app.FindConsent(r.Context(), s.deps, t.ID, r.URL.Query().Get("request"), bindingHash(r),
		sessionHash(r, t.ID))
	if err != nil {
		s.authorizationRequestError(w, r, err)
		return
	}
	scopes := make([]string, len(c.Scopes))
	for i, scope := range c.Scopes {
		scopes[i] = ui.ScopeDescription(scope.Scope, scope.Resource)
	}
	// The decision redirects to the client, which form-action must allow.
	var targets []string
	if target := ui.FormTarget(c.Request.RedirectURI); target != "" {
		targets = append(targets, target)
	}
	ui.SetPageHeaders(w.Header(), ui.ContentSecurityPolicy(true, targets...))
	s.render(w, r, http.StatusOK, ui.Consent(ui.ConsentPage{
		Layout:     s.layout(),
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
		s.errorPage(w, r, http.StatusForbidden, "Request blocked",
			"The consent form was submitted from another site.")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	err := r.ParseForm()
	decision := r.PostForm.Get("decision")
	if err != nil || decision != "allow" && decision != "deny" {
		s.errorPage(w, r, http.StatusBadRequest, "Invalid consent request",
			"The consent form is malformed. Return to the application and try again.")
		return
	}
	c, err := app.FindConsent(r.Context(), s.deps, t.ID, r.PostForm.Get("request"), bindingHash(r), sessionHash(r, t.ID))
	if err != nil {
		s.authorizationRequestError(w, r, err)
		return
	}
	uri, err := app.CompleteConsent(r.Context(), s.deps, t.authorizationTenant(), c, decision == "allow")
	if err != nil {
		s.authorizationRequestError(w, r, err)
		return
	}
	seeOther(w, uri)
}

// loginPage renders the sign-in form. Its policy lets the form submission
// redirect to the client, which browsers check against form-action.
func (s *Server) loginPage(w http.ResponseWriter, r *http.Request, t tenant, p app.PendingAuthorization,
	email, message string,
) {
	var targets []string
	if target := ui.FormTarget(p.Request.RedirectURI); target != "" {
		targets = append(targets, target)
	}
	ui.SetPageHeaders(w.Header(), ui.ContentSecurityPolicy(true, targets...))
	s.render(w, r, http.StatusOK, ui.Login(ui.LoginPage{
		Layout:     s.layout(),
		ClientName: p.Client.Name,
		Action:     t.path + loginPath,
		RequestID:  p.Request.ID,
		Email:      email,
		Error:      message,
	}))
}

// authorizationRequestError answers a request whose stored authorization
// request cannot be used.
func (s *Server) authorizationRequestError(w http.ResponseWriter, r *http.Request, err error) {
	if !errors.Is(err, app.ErrAuthorizationRequestNotFound) {
		s.internalError(w, r, "signing in", err)
		return
	}
	s.errorPage(w, r, http.StatusBadRequest, "Sign-in request no longer valid",
		"This sign-in request has expired, was already completed, or was started in another browser. "+
			"Return to the application and sign in again.")
}

// handleAsset serves the static files of the hosted pages.
func (s *Server) handleAsset(w http.ResponseWriter, r *http.Request) {
	s.assets.ServeAsset(w, r, r.PathValue("name"))
}

// errorPage renders a page that explains why a request cannot continue.
func (s *Server) errorPage(w http.ResponseWriter, r *http.Request, status int, title, message string) {
	ui.SetPageHeaders(w.Header(), ui.ContentSecurityPolicy(false))
	s.render(w, r, status, ui.Error(ui.ErrorPage{Layout: s.layout(), Title: title, Message: message}))
}

// render writes a page with the given status. Headers must be set already.
func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, page templ.Component) {
	w.WriteHeader(status)
	if err := page.Render(r.Context(), w); err != nil {
		s.logger.LogAttrs(r.Context(), slog.LevelWarn, "rendering a page failed",
			slog.String("route", r.Pattern), slog.String("error", err.Error()))
	}
}

// layout returns what every hosted page needs.
func (s *Server) layout() ui.Layout {
	return ui.Layout{Stylesheet: s.issuer.Path + assetsPath + s.assets.Stylesheet()}
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
