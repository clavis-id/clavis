package clavis

import (
	"net/http"
	"net/url"

	"clavisid.org/clavis/internal/app"
	"clavisid.org/clavis/internal/i18n"
	"clavisid.org/clavis/internal/oauth"
	"clavisid.org/clavis/internal/oidc"
	"clavisid.org/clavis/internal/ui"
)

// logoutPath is where the confirmation page posts, relative to a tenant's
// issuer.
const logoutPath = "/logout"

// logoutParams names the parameters of a logout request that the
// confirmation page carries to logoutPath, and that its language selector
// sends again to the end session endpoint.
var logoutParams = []string{"id_token_hint", "client_id", "post_logout_redirect_uri", "state", "ui_locales"}

// handleEndSession serves the end session endpoint (OpenID Connect
// RP-Initiated Logout 1.0, section 2), with GET or POST. A browser with an
// active session gets a page where the user confirms signing out (ADR
// 0023), and so does a POST without the session cookie; any other browser
// is signed out at once.
func (s *Server) handleEndSession(w http.ResponseWriter, r *http.Request, t tenant) {
	if r.Method == http.MethodHead {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	params, err := authorizationParams(w, r)
	if err != nil {
		s.errorPage(w, r, t, s.locale(w, r, "", ""), http.StatusBadRequest, i18n.ErrorInvalidSignOutTitle,
			i18n.ErrorMalformedSignOut)
		return
	}
	l, err := app.StartLogout(r.Context(), s.deps, s.signer, t.authorizationTenant(), params, sessionHash(r, t.ID))
	if err != nil {
		s.internalError(w, r, "starting a logout", err)
		return
	}
	// A browser does not send SameSite=Lax cookies with a cross-site POST, so
	// a POST without the session cookie may come from a signed-in browser.
	// The confirmation, which Clavis itself submits, carries the cookie.
	if !l.Confirm && (r.Method != http.MethodPost || sessionHash(r, t.ID) != nil) {
		s.logout(w, r, t, params)
		return
	}
	// A request with a problem is confirmed without its parameters, so the
	// user stays at Clavis; the language goes on in any case.
	var request, fields []ui.Field
	for _, name := range logoutParams {
		if value := params.Get(name); value != "" {
			request = append(request, ui.Field{Name: name, Value: value})
			if l.Problem == "" || name == "ui_locales" {
				fields = append(fields, ui.Field{Name: name, Value: value})
			}
		}
	}
	layout := s.layout(r, t, s.locale(w, r, params.Get(ui.LocaleParam), oauth.UILocales(params)))
	layout.Languages = &ui.LanguageSelector{Method: http.MethodPost, Action: t.path + oidc.EndSessionPath,
		Fields: request}
	// Browsers apply form-action to the redirect that follows the form.
	var targets []string
	if target := ui.FormTarget(l.RedirectURI); target != "" {
		targets = append(targets, target)
	}
	ui.SetPageHeaders(w.Header(), layout.ContentSecurityPolicy(true, targets...))
	s.render(w, r, http.StatusOK, ui.Logout(ui.LogoutPage{
		Layout:     layout,
		Account:    l.Account,
		ClientName: l.Client.Name,
		Problem:    l.Problem,
		Action:     t.path + logoutPath,
		Fields:     fields,
	}))
}

// handleLogout signs the user out after the confirmation page.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, t tenant) {
	if err := s.crossOrigin.Check(r); err != nil {
		s.errorPage(w, r, t, s.locale(w, r, "", ""), http.StatusForbidden, i18n.ErrorBlockedTitle,
			i18n.ErrorCrossSiteSignOutForm)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		s.errorPage(w, r, t, s.locale(w, r, "", ""), http.StatusBadRequest, i18n.ErrorInvalidSignOutTitle,
			i18n.ErrorMalformedSignOutForm)
		return
	}
	s.logout(w, r, t, r.PostForm)
}

// logout ends the browser's session, removes its cookie, and sends the
// browser to the post-logout redirect URI or to a page that says the user
// is signed out.
func (s *Server) logout(w http.ResponseWriter, r *http.Request, t tenant, params url.Values) {
	l, err := app.CompleteLogout(r.Context(), s.deps, s.signer, t.authorizationTenant(), params, sessionHash(r, t.ID))
	if err != nil {
		s.internalError(w, r, "signing out", err)
		return
	}
	if _, err := r.Cookie(sessionCookieName(t.ID)); err == nil {
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
	if uri := l.ResponseURI(); uri != "" {
		seeOther(w, uri)
		return
	}
	layout := s.layout(r, t, s.locale(w, r, "", oauth.UILocales(params)))
	ui.SetPageHeaders(w.Header(), layout.ContentSecurityPolicy(false))
	s.render(w, r, http.StatusOK, ui.SignedOut(ui.SignedOutPage{Layout: layout, Problem: l.Problem}))
}
