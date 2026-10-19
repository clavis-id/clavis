package clavis

import (
	"net/http"
	"net/url"

	"clavisid.org/clavis/internal/app"
	"clavisid.org/clavis/internal/ui"
)

// logoutPath is where the confirmation page posts, relative to a tenant's
// issuer.
const logoutPath = "/logout"

// logoutParams names the parameters of a logout request that the
// confirmation page carries to logoutPath.
var logoutParams = []string{"id_token_hint", "client_id", "post_logout_redirect_uri", "state"}

// handleEndSession serves the end session endpoint (OpenID Connect
// RP-Initiated Logout 1.0, section 2), with GET or POST. A browser with an
// active session gets a page where the user confirms signing out (ADR
// 0023); any other browser is signed out at once.
func (s *Server) handleEndSession(w http.ResponseWriter, r *http.Request, t tenant) {
	if r.Method == http.MethodHead {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	params, err := authorizationParams(w, r)
	if err != nil {
		s.errorPage(w, r, http.StatusBadRequest, "Invalid sign-out request",
			"The sign-out request is malformed. Return to the application and try again.")
		return
	}
	l, err := app.StartLogout(r.Context(), s.deps, s.signer, t.authorizationTenant(), params, sessionHash(r, t.ID))
	if err != nil {
		s.internalError(w, r, "starting a logout", err)
		return
	}
	if !l.Confirm {
		s.logout(w, r, t, params)
		return
	}
	var fields []ui.Field
	if l.Problem == "" {
		for _, name := range logoutParams {
			if value := params.Get(name); value != "" {
				fields = append(fields, ui.Field{Name: name, Value: value})
			}
		}
	}
	// Browsers apply form-action to the redirect that follows the form.
	var targets []string
	if target := ui.FormTarget(l.RedirectURI); target != "" {
		targets = append(targets, target)
	}
	ui.SetPageHeaders(w.Header(), ui.ContentSecurityPolicy(true, targets...))
	s.render(w, r, http.StatusOK, ui.Logout(ui.LogoutPage{
		Layout:     s.layout(),
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
		s.errorPage(w, r, http.StatusForbidden, "Request blocked",
			"The sign-out form was submitted from another site.")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		s.errorPage(w, r, http.StatusBadRequest, "Invalid sign-out request",
			"The sign-out form is malformed. Return to the application and try again.")
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
	ui.SetPageHeaders(w.Header(), ui.ContentSecurityPolicy(false))
	s.render(w, r, http.StatusOK, ui.SignedOut(ui.SignedOutPage{Layout: s.layout(), Problem: l.Problem}))
}
