package clavis

import (
	"encoding/json/v2"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"clavisid.org/clavis/internal/oidc"
	"clavisid.org/clavis/store"
)

// signInForLogout signs ada in through a browser and returns an ID token that the
// tenant issued to the client "web" for her.
func signInForLogout(t *testing.T, s *Server, tn store.Tenant, b *browser, issuer string) string {
	t.Helper()
	id := b.startLogin(issuer, authorizeQuery())
	if res, _ := b.post(issuer+"/login", loginForm(id, testPassword), "same-origin"); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("login = %d", res.StatusCode)
	}
	u, err := s.store.Users().GetByEmail(t.Context(), tn.ID, "ada@example.com")
	if err != nil {
		t.Fatalf("GetByEmail() unexpected error: %v", err)
	}
	payload, err := json.Marshal(oidc.IDTokenClaims{Issuer: issuer, Subject: u.ID.String(), Audience: "web",
		Expiry: s.deps.Now().Unix() + 600, IssuedAt: s.deps.Now().Unix()})
	if err != nil {
		t.Fatalf("encoding claims: %v", err)
	}
	token, err := s.signer.Sign(t.Context(), tn.ID, oidc.IDTokenSigningAlgorithm, oidc.IDTokenType, payload)
	if err != nil {
		t.Fatalf("Sign() unexpected error: %v", err)
	}
	return token
}

// hiddenFields returns the hidden fields of a page's form.
func hiddenFields(page string) url.Values {
	fields := url.Values{}
	for _, input := range strings.Split(page, `<input type="hidden" `)[1:] {
		name, _, _ := strings.Cut(strings.TrimPrefix(input, `name="`), `"`)
		_, value, _ := strings.Cut(input, `value="`)
		value, _, _ = strings.Cut(value, `"`)
		fields.Set(name, value)
	}
	return fields
}

func TestRPInitiatedLogout(t *testing.T) {
	t.Parallel()
	const issuer = "https://auth.example.com"
	s, tn := newLoginServer(t, issuer, "")
	b := newBrowser(t, s.Handler())
	idToken := signInForLogout(t, s, tn, b, issuer)

	query := url.Values{
		"id_token_hint":            {idToken},
		"post_logout_redirect_uri": {"https://app.example.com/signed-out"},
		"state":                    {"af0ifjsldkj"},
	}
	res, page := b.get(issuer + "/oauth2/logout?" + query.Encode())
	if res.StatusCode != http.StatusOK || !strings.Contains(page, "<title>Sign out</title>") ||
		!strings.Contains(page, "Web App") || !strings.Contains(page, "ada@example.com") ||
		!strings.Contains(page, `action="/logout"`) || !strings.Contains(page, `id="logout"`) {
		t.Fatalf("logout page = %d:\n%s", res.StatusCode, page)
	}
	if csp := res.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self' https://app.example.com;") {
		t.Errorf("Content-Security-Policy = %q, want the client's origin in form-action", csp)
	}
	fields := hiddenFields(page)
	if fields.Get("id_token_hint") != idToken || fields.Get("state") != "af0ifjsldkj" {
		t.Fatalf("hidden fields = %v", fields)
	}

	// The form must come from Clavis itself.
	if res, _ := b.post(issuer+"/logout", fields, "cross-site"); res.StatusCode != http.StatusForbidden {
		t.Errorf("cross-site sign-out = %d, want 403", res.StatusCode)
	}
	res, _ = b.post(issuer+"/logout", fields, "same-origin")
	if res.StatusCode != http.StatusSeeOther ||
		res.Header.Get("Location") != "https://app.example.com/signed-out?state=af0ifjsldkj" {
		t.Fatalf("sign-out = %d to %q", res.StatusCode, res.Header.Get("Location"))
	}
	if c := checkCookie(t, res, sessionCookieName(tn.ID)); c.MaxAge >= 0 || c.Value != "" {
		t.Errorf("session cookie after the sign-out = %+v, want it removed", c)
	}

	// The session ended: prompt=none needs a sign-in.
	none := authorizeQuery()
	none.Set("prompt", "none")
	res, _ = b.get(issuer + "/oauth2/authorize?" + none.Encode())
	if loc, err := url.Parse(res.Header.Get("Location")); err != nil || loc.Query().Get("error") != "login_required" {
		t.Errorf("authorize with prompt=none after the sign-out = %d to %q", res.StatusCode, res.Header.Get("Location"))
	}
	// Without a session, there is nothing to confirm.
	res, page = b.get(issuer + "/oauth2/logout")
	if res.StatusCode != http.StatusOK || !strings.Contains(page, "You are signed out") || strings.Contains(page, "<form") {
		t.Errorf("logout without a session = %d:\n%s", res.StatusCode, page)
	}
	if res, _ := b.get(issuer + "/oauth2/logout?" + query.Encode()); res.StatusCode != http.StatusSeeOther ||
		res.Header.Get("Location") != "https://app.example.com/signed-out?state=af0ifjsldkj" {
		t.Errorf("logout without a session = %d to %q, want the redirect at once", res.StatusCode,
			res.Header.Get("Location"))
	}
}

// OpenID Connect RP-Initiated Logout 1.0, section 3: a request whose
// redirect cannot be followed still lets the user sign out, but the browser
// stays at Clavis.
func TestRPInitiatedLogoutWithAnInvalidRequest(t *testing.T) {
	t.Parallel()
	const issuer = "https://auth.example.com"
	s, tn := newLoginServer(t, issuer, "")
	b := newBrowser(t, s.Handler())
	signInForLogout(t, s, tn, b, issuer)

	// Relying parties may send the request with POST too.
	form := url.Values{"post_logout_redirect_uri": {"https://app.example.com/signed-out"}, "state": {"s"}}
	res, page := b.post(issuer+"/oauth2/logout", form, "cross-site")
	if res.StatusCode != http.StatusOK || !strings.Contains(page, "cannot be completed as sent") ||
		!strings.Contains(page, "post_logout_redirect_uri needs an id_token_hint") || len(hiddenFields(page)) != 0 {
		t.Fatalf("logout page = %d:\n%s", res.StatusCode, page)
	}
	if csp := res.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self';") {
		t.Errorf("Content-Security-Policy = %q, want only the page's own origin in form-action", csp)
	}
	res, page = b.post(issuer+"/logout", url.Values{}, "same-origin")
	if res.StatusCode != http.StatusOK || !strings.Contains(page, "You are signed out") {
		t.Fatalf("sign-out = %d:\n%s", res.StatusCode, page)
	}
	if res, _ := b.get(issuer + "/oauth2/logout"); res.StatusCode != http.StatusOK {
		t.Errorf("logout after the sign-out = %d", res.StatusCode)
	}
	for _, method := range []string{http.MethodHead, http.MethodPut} {
		if rec := serve(t, s.Handler(), method, "/oauth2/logout"); rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /oauth2/logout = %d, want 405", method, rec.Code)
		}
	}
}
