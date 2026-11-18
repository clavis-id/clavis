package clavis

// The tests in this file carry out the attacks of RFC 9700 (OAuth 2.0
// Security Best Current Practice), section 4, against the whole server, as
// an attacker would, and check that each one fails. Each test says which
// defense stops the attack, and checks the legitimate request next to the
// forged one, so that a test cannot pass only because nothing works.

import (
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"clavisid.org/clavis/internal/app"
	"clavisid.org/clavis/internal/oauth"
	"clavisid.org/clavis/internal/oidc"
	"clavisid.org/clavis/store"
)

// attackIssuer is the issuer of the servers in these tests.
const attackIssuer = "https://auth.example.com"

// victimServer returns a login server for attackIssuer, as newLoginServer
// does, with the secret of its client "web".
func victimServer(t *testing.T) (*Server, store.Tenant, string) {
	t.Helper()
	s, tn := newLoginServer(t, attackIssuer, "")
	secret, err := app.RotateClientSecret(t.Context(), s.deps, tn.ID, "web")
	if err != nil {
		t.Fatalf("RotateClientSecret() unexpected error: %v", err)
	}
	return s, tn, secret
}

// createClient registers a client with the tenant and returns its secret,
// which is empty for a public client.
func createClient(t *testing.T, s *Server, tn store.Tenant, spec app.ClientSpec) string {
	t.Helper()
	_, secret, err := app.CreateClient(t.Context(), s.deps, tn.ID, spec)
	if err != nil {
		t.Fatalf("CreateClient(%s) unexpected error: %v", spec.ClientID, err)
	}
	return secret
}

// authorizationResponse signs ada in through a new browser with the
// authorization request query, and returns the authorization response.
func authorizationResponse(t *testing.T, s *Server, issuer string, query url.Values) url.Values {
	t.Helper()
	b := newBrowser(t, s.Handler())
	id := b.startLogin(issuer, query)
	res, _ := b.post(issuer+"/login", loginForm(id, testPassword), "same-origin")
	loc, err := url.Parse(res.Header.Get("Location"))
	if res.StatusCode != http.StatusSeeOther || err != nil || loc.Query().Get("code") == "" {
		t.Fatalf("login = %d to %q, want an authorization code", res.StatusCode, res.Header.Get("Location"))
	}
	return loc.Query()
}

// clientAuth returns the header with which a confidential client
// authenticates (client_secret_basic).
func clientAuth(clientID, secret string) http.Header {
	return http.Header{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte(clientID+":"+secret))}}
}

// tokenResponse is what these tests read from a token response.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
}

// requestToken sends a token request to the tenant of issuer and returns
// the response when it succeeds, or its error code.
func requestToken(t *testing.T, h http.Handler, issuer string, form url.Values, header http.Header,
) (tokens tokenResponse, errCode string) {
	t.Helper()
	rec := post(t, h, issuer+oidc.TokenPath, formContentType, form.Encode(), header)
	if rec.Code != http.StatusOK {
		return tokenResponse{}, errorCode(t, rec)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &tokens); err != nil {
		t.Fatalf("decoding %q: %v", rec.Body.String(), err)
	}
	return tokens, ""
}

// codeGrant returns a token request that redeems code, sent to
// redirectURI, with verifier, or without one when it is empty.
func codeGrant(code, redirectURI, verifier string) url.Values {
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI}}
	if verifier != "" {
		form.Set("code_verifier", verifier)
	}
	return form
}

// refreshGrant returns a token request that uses refreshToken.
func refreshGrant(refreshToken string) url.Values {
	return url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}}
}

// readClaims decodes the claims of a JWT into v without verifying it; the
// interoperability tests verify tokens.
func readClaims(token string, v any) error {
	_, payload, _ := strings.Cut(token, ".")
	payload, _, _ = strings.Cut(payload, ".")
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

// userinfoStatus returns the status of a userinfo request of the default
// tenant with the access token.
func userinfoStatus(t *testing.T, h http.Handler, accessToken string) int {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, oidc.UserinfoPath, http.NoBody)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

// TestAttackOpenRedirect sends the victim links to Clavis that name the
// attacker's site, hoping that Clavis forwards the victim there, maybe with
// an authorization code (RFC 9700, sections 4.1 and 4.11.2). Redirect URIs
// must equal a registered one, except for the port of a loopback IP literal
// (section 4.1.3), and a request whose client and redirect URI do not match
// gets an error page instead of a redirect, whatever else is wrong with it
// (RFC 6749, section 4.1.2.1). After logout, Clavis redirects only to a
// registered post-logout redirect URI of the client that a valid
// id_token_hint names (RP-Initiated Logout 1.0, section 3).
func TestAttackOpenRedirect(t *testing.T) {
	t.Parallel()
	const issuer = attackIssuer
	s, tn := newLoginServer(t, issuer, "")
	createClient(t, s, tn, app.ClientSpec{ClientID: "native", Type: store.ClientPublic,
		RedirectURIs: []string{"http://127.0.0.1/callback"}, SkipConsent: true})
	b := newBrowser(t, s.Handler())
	authorize := func(clientID, redirectURI string, edit func(url.Values)) response {
		t.Helper()
		q := authorizeQuery()
		q.Set("client_id", clientID)
		q.Set("redirect_uri", redirectURI)
		if edit != nil {
			edit(q)
		}
		res, _ := b.get(issuer + oidc.AuthorizationPath + "?" + q.Encode())
		return res
	}
	wantErrorPage := func(what string, res response) {
		t.Helper()
		if res.StatusCode != http.StatusBadRequest || res.Header.Get("Location") != "" {
			t.Errorf("%s: authorize = %d to %q, want an error page", what, res.StatusCode, res.Header.Get("Location"))
		}
	}

	for _, uri := range []string{
		"https://evil.example/callback",
		"https://app.example.com/callback/",
		"https://app.example.com/callbacks",
		"https://app.example.com/callback/../../evil",
		"https://app.example.com/%63allback",
		"https://app.example.com/callback?next=https://evil.example",
		"https://app.example.com/callback#evil",
		"https://APP.example.com/callback",
		"http://app.example.com/callback",
		"https://app.example.com:443/callback",
		"https://app.example.com:8443/callback",
		"https://app.example.com.evil.example/callback",
		"https://app.example.com@evil.example/callback",
		`https://evil.example\@app.example.com/callback`,
		"//evil.example/callback",
	} {
		wantErrorPage("redirect_uri "+uri, authorize("web", uri, nil))
	}
	for _, uri := range []string{
		"http://127.0.0.1:8080@evil.example/callback",
		"http://127.0.0.1.evil.example/callback",
		"http://127.0.0.1:8080/other",
		"http://127.0.0.2:8080/callback",
		"http://localhost:8080/callback",
		"https://127.0.0.1:8080/callback",
	} {
		wantErrorPage("redirect_uri "+uri, authorize("native", uri, nil))
	}
	wantErrorPage("unknown client", authorize("nobody", "https://evil.example/callback", nil))
	// Errors that Clavis reports to a registered redirect URI.
	for name, edit := range map[string]func(url.Values){
		"unsupported response_type": func(q url.Values) { q.Set("response_type", "token") },
		"prompt=none":               func(q url.Values) { q.Set("prompt", "none") },
	} {
		wantErrorPage(name, authorize("web", "https://evil.example/callback", edit))
		res := authorize("web", "https://app.example.com/callback", edit)
		if loc := res.Header.Get("Location"); res.StatusCode != http.StatusSeeOther ||
			!strings.HasPrefix(loc, "https://app.example.com/callback?error=") {
			t.Errorf("%s with the registered redirect URI = %d to %q, want an error response",
				name, res.StatusCode, loc)
		}
	}
	// A native app chooses its port.
	if res := authorize("native", "http://127.0.0.1:51004/callback", nil); res.StatusCode != http.StatusSeeOther ||
		!strings.HasPrefix(res.Header.Get("Location"), issuer+"/login?request=") {
		t.Errorf("loopback redirect URI = %d to %q, want the login page", res.StatusCode, res.Header.Get("Location"))
	}

	// The attacker can send the victim a logout request with any
	// parameters, and with an ID token of the attacker's own as the hint.
	idToken := signInForLogout(t, s, tn, b, issuer)
	logout := func(params url.Values) (get, post response) {
		t.Helper()
		get, _ = b.get(issuer + oidc.EndSessionPath + "?" + params.Encode())
		// The confirmation page drops what it cannot follow, but its form
		// is checked again in case the browser sends something else.
		post, _ = b.post(issuer+"/logout", params, "same-origin")
		return get, post
	}
	for name, params := range map[string]url.Values{
		"no id_token_hint":     {"post_logout_redirect_uri": {"https://app.example.com/signed-out"}},
		"invalid hint":         {"post_logout_redirect_uri": {"https://app.example.com/signed-out"}, "id_token_hint": {"x.y.z"}},
		"unregistered URI":     {"post_logout_redirect_uri": {"https://evil.example/signed-out"}, "id_token_hint": {idToken}},
		"login redirect URI":   {"post_logout_redirect_uri": {"https://app.example.com/callback"}, "id_token_hint": {idToken}},
		"longer URI":           {"post_logout_redirect_uri": {"https://app.example.com/signed-out?next=https://evil.example"}, "id_token_hint": {idToken}},
		"different host":       {"post_logout_redirect_uri": {"https://app.example.com.evil.example/signed-out"}, "id_token_hint": {idToken}},
		"userinfo in the host": {"post_logout_redirect_uri": {"https://app.example.com@evil.example/signed-out"}, "id_token_hint": {idToken}},
	} {
		get, post := logout(params)
		if get.StatusCode != http.StatusOK || get.Header.Get("Location") != "" ||
			post.StatusCode != http.StatusOK || post.Header.Get("Location") != "" {
			t.Errorf("%s: logout = %d to %q, confirmation = %d to %q; want no redirect", name, get.StatusCode,
				get.Header.Get("Location"), post.StatusCode, post.Header.Get("Location"))
		}
	}
	_, post := logout(url.Values{"post_logout_redirect_uri": {"https://app.example.com/signed-out"},
		"id_token_hint": {idToken}, "state": {"s"}})
	if post.StatusCode != http.StatusSeeOther || post.Header.Get("Location") != "https://app.example.com/signed-out?state=s" {
		t.Errorf("logout with a registered URI = %d to %q, want the redirect", post.StatusCode, post.Header.Get("Location"))
	}
}

// TestAttackMixUp is about a client that works with several authorization
// servers, and an attacker who makes it send a code from the honest one to
// the attacker's (RFC 9700, section 4.4). Clavis has an issuer per tenant,
// and a client may be registered with several tenants under one client_id.
// Every authorization response carries its issuer (RFC 9207, section 2),
// which the client compares with the issuer it sent the request to
// (section 4.4.2.1), and a code is valid only at the tenant that issued it.
func TestAttackMixUp(t *testing.T) {
	t.Parallel()
	const issuer = attackIssuer
	const other = issuer + "/t/acme"
	s, _, secret := victimServer(t)
	acme, err := app.CreateTenant(t.Context(), s.deps, s.keys.Rotate, "acme", "")
	if err != nil {
		t.Fatalf("CreateTenant() unexpected error: %v", err)
	}
	acmeSecret := createClient(t, s, acme, app.ClientSpec{ClientID: "web", Type: store.ClientConfidential,
		RedirectURIs: []string{"https://app.example.com/callback"}, SkipConsent: true})
	u, err := app.CreateUser(t.Context(), s.deps, acme.ID, app.UserSpec{Email: "ada@example.com"})
	if err != nil {
		t.Fatalf("CreateUser() unexpected error: %v", err)
	}
	if err := app.SetPassword(t.Context(), s.deps, s.passwords, u, testPassword); err != nil {
		t.Fatalf("SetPassword() unexpected error: %v", err)
	}
	h := s.Handler()

	for _, iss := range []string{issuer, other} {
		var metadata struct {
			Issuer       string `json:"issuer"`
			IssParameter bool   `json:"authorization_response_iss_parameter_supported"`
		}
		rec := serve(t, h, http.MethodGet, iss+oidc.DiscoveryPath)
		if err := json.Unmarshal(rec.Body.Bytes(), &metadata); err != nil || metadata.Issuer != iss || !metadata.IssParameter {
			t.Errorf("metadata of %s = %+v, %v; want the issuer parameter", iss, metadata, err)
		}
		if got := authorizationResponse(t, s, iss, authorizeQuery()).Get("iss"); got != iss {
			t.Errorf("iss of an authorization response of %s = %q", iss, got)
		}
		// Error responses carry it too.
		q := authorizeQuery()
		q.Set("response_type", "token")
		res, _ := newBrowser(t, h).get(iss + oidc.AuthorizationPath + "?" + q.Encode())
		if loc, err := url.Parse(res.Header.Get("Location")); err != nil || loc.Query().Get("error") == "" ||
			loc.Query().Get("iss") != iss {
			t.Errorf("error response of %s = %d to %q, want its issuer", iss, res.StatusCode, res.Header.Get("Location"))
		}
		// And so do responses that the browser posts to the client.
		q = authorizeQuery()
		q.Set("response_mode", "form_post")
		b := newBrowser(t, h)
		id := b.startLogin(iss, q)
		if _, page := b.post(iss+"/login", loginForm(id, testPassword), "same-origin"); !strings.Contains(page,
			`name="iss" value="`+iss+`"`) {
			t.Errorf("form post response of %s:\n%s", iss, page)
		}
	}

	// A code reaches the token endpoint of another tenant, where the client
	// has the same client_id.
	code := authorizationResponse(t, s, issuer, authorizeQuery()).Get("code")
	grant := codeGrant(code, "https://app.example.com/callback", testVerifier)
	if _, errCode := requestToken(t, h, other, grant, clientAuth("web", acmeSecret)); errCode != "invalid_grant" {
		t.Errorf("code of %s at %s = %q, want invalid_grant", issuer, other, errCode)
	}
	if _, errCode := requestToken(t, h, issuer, grant, clientAuth("web", secret)); errCode != "" {
		t.Errorf("code at its own tenant = %q, want tokens", errCode)
	}
}

// TestAttackPKCEDowngrade removes code_challenge from an authorization
// request of the victim, and later sends the resulting code to the token
// endpoint with the attacker's code_verifier (RFC 9700, section 4.8). Clavis
// requires PKCE unless the client is exempt (ADR 0018), and rejects a
// verifier for a code issued without a challenge (section 4.8.2). Clients
// learn from the metadata that Clavis supports PKCE, and with S256 only
// (section 4.7.1).
func TestAttackPKCEDowngrade(t *testing.T) {
	t.Parallel()
	const issuer = attackIssuer
	s, tn, secret := victimServer(t)
	legacySecret := createClient(t, s, tn, app.ClientSpec{ClientID: "legacy", Type: store.ClientConfidential,
		RedirectURIs: []string{"https://legacy.example.com/callback"}, SkipConsent: true, PKCEExempt: true})
	h := s.Handler()

	var metadata struct {
		Methods []string `json:"code_challenge_methods_supported"`
	}
	if err := json.Unmarshal(serve(t, h, http.MethodGet, oidc.DiscoveryPath).Body.Bytes(), &metadata); err != nil ||
		len(metadata.Methods) != 1 || metadata.Methods[0] != "S256" {
		t.Errorf("code_challenge_methods_supported = %q, %v; want S256 only", metadata.Methods, err)
	}

	// A client that must use PKCE gets no code without a challenge, or with
	// the plain method.
	for name, edit := range map[string]func(url.Values){
		"no code_challenge": func(q url.Values) { q.Del("code_challenge"); q.Del("code_challenge_method") },
		"plain method": func(q url.Values) {
			q.Set("code_challenge", testVerifier)
			q.Set("code_challenge_method", "plain")
		},
		"no method": func(q url.Values) { q.Del("code_challenge_method") },
	} {
		q := authorizeQuery()
		edit(q)
		res, _ := newBrowser(t, h).get(issuer + oidc.AuthorizationPath + "?" + q.Encode())
		if loc, err := url.Parse(res.Header.Get("Location")); err != nil || loc.Query().Get("error") != "invalid_request" {
			t.Errorf("%s: authorize = %d to %q, want invalid_request", name, res.StatusCode, res.Header.Get("Location"))
		}
	}

	// The exempt client gets a code without a challenge; a verifier sent
	// with it shows that the challenge was removed.
	q := authorizeQuery()
	q.Set("client_id", "legacy")
	q.Set("redirect_uri", "https://legacy.example.com/callback")
	q.Del("code_challenge")
	q.Del("code_challenge_method")
	code := authorizationResponse(t, s, issuer, q).Get("code")
	attackerVerifier := oauth.NewToken()
	auth := clientAuth("legacy", legacySecret)
	if _, errCode := requestToken(t, h, issuer, codeGrant(code, "https://legacy.example.com/callback", attackerVerifier),
		auth); errCode != "invalid_grant" {
		t.Errorf("code without a challenge, redeemed with a verifier = %q, want invalid_grant", errCode)
	}
	if _, errCode := requestToken(t, h, issuer, codeGrant(code, "https://legacy.example.com/callback", ""),
		auth); errCode != "" {
		t.Errorf("code without a challenge, redeemed without a verifier = %q, want tokens", errCode)
	}

	// A code issued with a challenge needs its verifier.
	code = authorizationResponse(t, s, issuer, authorizeQuery()).Get("code")
	auth = clientAuth("web", secret)
	for name, verifier := range map[string]string{"no verifier": "", "another verifier": attackerVerifier} {
		if _, errCode := requestToken(t, h, issuer, codeGrant(code, "https://app.example.com/callback", verifier),
			auth); errCode != "invalid_grant" {
			t.Errorf("code with a challenge, %s = %q, want invalid_grant", name, errCode)
		}
	}
	if _, errCode := requestToken(t, h, issuer, codeGrant(code, "https://app.example.com/callback", testVerifier),
		auth); errCode != "" {
		t.Errorf("code with its verifier = %q, want tokens", errCode)
	}
}

// TestAttackCodeInjection uses a stolen code: the attacker injects it into a
// session of their own with the legitimate client, or redeems it as another
// client, or with another redirect URI (RFC 9700, section 4.5). The code is
// bound to the client, the redirect URI and the PKCE challenge of the
// victim's request (section 4.5.3.1), and the ID token carries the victim's
// nonce, which a session of the attacker would not accept (section
// 4.5.3.2). Failed attempts leave the code to the victim.
func TestAttackCodeInjection(t *testing.T) {
	t.Parallel()
	const issuer = attackIssuer
	s, tn, secret := victimServer(t)
	mallorySecret := createClient(t, s, tn, app.ClientSpec{ClientID: "mallory", Type: store.ClientConfidential,
		RedirectURIs: []string{"https://mallory.example/callback"}, SkipConsent: true})
	h := s.Handler()
	code := authorizationResponse(t, s, issuer, authorizeQuery()).Get("code")

	for name, attempt := range map[string]struct {
		grant  url.Values
		header http.Header
	}{
		"the attacker's verifier": {codeGrant(code, "https://app.example.com/callback", oauth.NewToken()),
			clientAuth("web", secret)},
		"another client": {codeGrant(code, "https://app.example.com/callback", testVerifier),
			clientAuth("mallory", mallorySecret)},
		"another client and its redirect URI": {codeGrant(code, "https://mallory.example/callback", testVerifier),
			clientAuth("mallory", mallorySecret)},
		"another redirect URI": {codeGrant(code, "https://app.example.com/other", testVerifier),
			clientAuth("web", secret)},
	} {
		if _, errCode := requestToken(t, h, issuer, attempt.grant, attempt.header); errCode != "invalid_grant" {
			t.Errorf("code with %s = %q, want invalid_grant", name, errCode)
		}
	}

	tokens, errCode := requestToken(t, h, issuer, codeGrant(code, "https://app.example.com/callback", testVerifier),
		clientAuth("web", secret))
	if errCode != "" {
		t.Fatalf("the victim's client redeeming the code = %q, want tokens", errCode)
	}
	var claims struct {
		Nonce string `json:"nonce"`
	}
	if err := readClaims(tokens.IDToken, &claims); err != nil || claims.Nonce != authorizeQuery().Get("nonce") {
		t.Errorf("ID token nonce = %q, %v; want the nonce of the victim's request", claims.Nonce, err)
	}
}

// TestAttackCodeReplay redeems a code again, as an attacker who stole it
// after the client used it would. A code is redeemed once, and presenting
// it again revokes the tokens issued for it, since the attacker may hold
// them (RFC 6749, section 4.1.2; RFC 9700, section 4.2.4).
func TestAttackCodeReplay(t *testing.T) {
	t.Parallel()
	const issuer = attackIssuer
	s, _, secret := victimServer(t)
	h := s.Handler()
	q := authorizeQuery()
	q.Set("scope", "openid offline_access")
	grant := codeGrant(authorizationResponse(t, s, issuer, q).Get("code"), "https://app.example.com/callback",
		testVerifier)
	auth := clientAuth("web", secret)

	first, errCode := requestToken(t, h, issuer, grant, auth)
	if errCode != "" || first.RefreshToken == "" {
		t.Fatalf("redeeming the code = %+v, %q; want an access token and a refresh token", first, errCode)
	}
	if status := userinfoStatus(t, h, first.AccessToken); status != http.StatusOK {
		t.Fatalf("userinfo with the access token = %d", status)
	}

	if _, errCode := requestToken(t, h, issuer, grant, auth); errCode != "invalid_grant" {
		t.Errorf("redeeming the code again = %q, want invalid_grant", errCode)
	}
	if status := userinfoStatus(t, h, first.AccessToken); status != http.StatusUnauthorized {
		t.Errorf("userinfo with the access token after the replay = %d, want 401", status)
	}
	if _, errCode := requestToken(t, h, issuer, refreshGrant(first.RefreshToken), auth); errCode != "invalid_grant" {
		t.Errorf("refresh token after the replay = %q, want invalid_grant", errCode)
	}
}

// TestAttackRefreshTokenReplay uses a stolen refresh token of a public
// client, which has no secret to stop the attacker (RFC 9700, section
// 4.14.2). Refresh tokens rotate on every use: when the stolen token and the
// legitimate one are both used, the second use of the same token revokes
// the whole family, whoever presents it, with the access tokens issued from
// it (ADR 0021). A refresh token also keeps the scope that was granted, and
// that of a confidential client works only for that client (RFC 6749,
// section 6).
func TestAttackRefreshTokenReplay(t *testing.T) {
	t.Parallel()
	const issuer = attackIssuer
	s, tn, secret := victimServer(t)
	createClient(t, s, tn, app.ClientSpec{ClientID: "native", Type: store.ClientPublic,
		RedirectURIs: []string{"http://127.0.0.1/callback"}, SkipConsent: true})
	mallorySecret := createClient(t, s, tn, app.ClientSpec{ClientID: "mallory", Type: store.ClientConfidential,
		RedirectURIs: []string{"https://mallory.example/callback"}, SkipConsent: true})
	h := s.Handler()

	const redirectURI = "http://127.0.0.1:51004/callback"
	q := authorizeQuery()
	q.Set("client_id", "native")
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", "openid offline_access")
	grant := codeGrant(authorizationResponse(t, s, issuer, q).Get("code"), redirectURI, testVerifier)
	grant.Set("client_id", "native")
	issued, errCode := requestToken(t, h, issuer, grant, nil)
	if errCode != "" || issued.RefreshToken == "" {
		t.Fatalf("redeeming the code = %+v, %q; want a refresh token", issued, errCode)
	}
	refresh := func(token string, extra url.Values) (tokenResponse, string) {
		t.Helper()
		form := refreshGrant(token)
		form.Set("client_id", "native")
		maps.Copy(form, extra)
		return requestToken(t, h, issuer, form, nil)
	}

	// The scope cannot grow.
	if _, errCode := refresh(issued.RefreshToken, url.Values{"scope": {"openid offline_access profile"}}); errCode != "invalid_scope" {
		t.Errorf("refresh with a wider scope = %q, want invalid_scope", errCode)
	}
	// The attacker refreshes first, then the client does with the same token.
	stolen, errCode := refresh(issued.RefreshToken, nil)
	if errCode != "" || stolen.RefreshToken == "" {
		t.Fatalf("the attacker's refresh = %+v, %q; want new tokens", stolen, errCode)
	}
	if _, errCode := refresh(issued.RefreshToken, nil); errCode != "invalid_grant" {
		t.Errorf("the client's refresh with the replaced token = %q, want invalid_grant", errCode)
	}
	if _, errCode := refresh(stolen.RefreshToken, nil); errCode != "invalid_grant" {
		t.Errorf("the attacker's refresh token after the replay = %q, want invalid_grant", errCode)
	}
	for name, token := range map[string]string{"attacker's": stolen.AccessToken, "client's": issued.AccessToken} {
		if status := userinfoStatus(t, h, token); status != http.StatusUnauthorized {
			t.Errorf("userinfo with the %s access token after the replay = %d, want 401", name, status)
		}
	}

	// Another confidential client cannot use a refresh token of "web".
	q = authorizeQuery()
	q.Set("scope", "openid offline_access")
	auth := clientAuth("web", secret)
	tokens, errCode := requestToken(t, h, issuer, codeGrant(authorizationResponse(t, s, issuer, q).Get("code"),
		"https://app.example.com/callback", testVerifier), auth)
	if errCode != "" || tokens.RefreshToken == "" {
		t.Fatalf("redeeming the code of web = %+v, %q; want a refresh token", tokens, errCode)
	}
	if _, errCode := requestToken(t, h, issuer, refreshGrant(tokens.RefreshToken),
		clientAuth("mallory", mallorySecret)); errCode != "invalid_grant" {
		t.Errorf("refresh token of web used by mallory = %q, want invalid_grant", errCode)
	}
	if _, errCode := requestToken(t, h, issuer, refreshGrant(tokens.RefreshToken), auth); errCode != "" {
		t.Errorf("refresh token of web used by web = %q, want new tokens", errCode)
	}
}

// TestAttackLoginCSRF has a page of the attacker make the victim's browser
// sign in with the attacker's credentials, so that the victim works in the
// attacker's account without noticing (RFC 6749, section 10.12). Forms that
// change state accept only submissions from Clavis's own pages
// (http.CrossOriginProtection), and an authorization request belongs to
// the browser that started it (ADR 0013).
func TestAttackLoginCSRF(t *testing.T) {
	t.Parallel()
	const issuer = attackIssuer
	s, tn := newLoginServer(t, issuer, "")
	const malloryPassword = "mallory's own password"
	mallory, err := app.CreateUser(t.Context(), s.deps, tn.ID, app.UserSpec{Email: "mallory@example.com"})
	if err != nil {
		t.Fatalf("CreateUser() unexpected error: %v", err)
	}
	if err := app.SetPassword(t.Context(), s.deps, s.passwords, mallory, malloryPassword); err != nil {
		t.Fatalf("SetPassword() unexpected error: %v", err)
	}
	victim := newBrowser(t, s.Handler())
	credentials := func(id string) url.Values {
		form := url.Values{"email": {"mallory@example.com"}, "password": {malloryPassword}}
		if id != "" {
			form.Set("request", id)
		}
		return form
	}
	// The browser of these tests sends every cookie, like one that ignores
	// SameSite, so the binding cookie does not hide the cross-origin check.
	wantBlocked := func(what string, res response) {
		t.Helper()
		if res.StatusCode != http.StatusForbidden || res.Header.Get("Location") != "" || len(res.Cookies()) != 0 {
			t.Errorf("%s = %d to %q, cookies %v; want it blocked", what, res.StatusCode, res.Header.Get("Location"),
				res.Cookies())
		}
	}
	// Browsers without Fetch Metadata send only Origin.
	postWithOrigin := func(target string, form url.Values) response {
		t.Helper()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, target, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", formContentType)
		req.Header.Set("Origin", "https://evil.example")
		res, _ := victim.send(req)
		return res
	}

	// The attacker's page sends the victim's browser to the authorization
	// endpoint, then submits the login form from the attacker's site.
	id := victim.startLogin(issuer, authorizeQuery())
	res, _ := victim.post(issuer+"/login", credentials(id), "cross-site")
	wantBlocked("cross-site login", res)
	wantBlocked("login from another origin", postWithOrigin(issuer+"/login", credentials(id)))
	res, _ = victim.post(issuer+"/account/login", credentials(""), "cross-site")
	wantBlocked("cross-site account sign-in", res)
	wantBlocked("account sign-in from another origin", postWithOrigin(issuer+"/account/login", credentials("")))

	// A request that the attacker started in their own browser does not
	// belong to the victim's.
	attackerID := newBrowser(t, s.Handler()).startLogin(issuer, authorizeQuery())
	if res, _ := victim.post(issuer+"/login", credentials(attackerID), "same-origin"); res.StatusCode != http.StatusBadRequest ||
		res.Header.Get("Location") != "" {
		t.Errorf("login with the attacker's request = %d to %q, want 400", res.StatusCode, res.Header.Get("Location"))
	}

	// The victim's browser is signed in to nothing.
	none := authorizeQuery()
	none.Set("prompt", "none")
	res, _ = victim.get(issuer + oidc.AuthorizationPath + "?" + none.Encode())
	if loc, err := url.Parse(res.Header.Get("Location")); err != nil || loc.Query().Get("error") != "login_required" {
		t.Errorf("authorize with prompt=none after the attacks = %d to %q, want login_required", res.StatusCode,
			res.Header.Get("Location"))
	}
	// The same form, submitted from Clavis's own page, signs in.
	if res, _ := victim.post(issuer+"/login", credentials(id), "same-origin"); res.StatusCode != http.StatusSeeOther {
		t.Errorf("same-origin login = %d, want 303", res.StatusCode)
	}
}

// TestAttackClientImpersonatingUser registers a client whose client_id is
// the sub of a user, so that the tokens the client obtains for itself look
// like tokens of that user to a resource server (RFC 9700, section 4.15). A
// token that a client obtains for itself carries its client_id as sub, a
// user's sub is a UUID, and a client_id cannot be one (section 4.15.1).
// Userinfo answers only tokens of users.
func TestAttackClientImpersonatingUser(t *testing.T) {
	t.Parallel()
	const issuer = attackIssuer
	s, tn := newLoginServer(t, issuer, "")
	ada, err := s.store.Users().GetByEmail(t.Context(), tn.ID, "ada@example.com")
	if err != nil {
		t.Fatalf("GetByEmail() unexpected error: %v", err)
	}
	if _, err := app.CreateAPIResource(t.Context(), s.deps, tn.ID, app.APIResourceSpec{
		Identifier: "https://api.example.com", Scopes: []string{"orders:read"},
	}); err != nil {
		t.Fatalf("CreateAPIResource() unexpected error: %v", err)
	}
	worker := app.ClientSpec{Type: store.ClientConfidential, GrantTypes: []string{"client_credentials"},
		Scopes: []string{"orders:read"}}
	for _, id := range []string{ada.ID.String(), strings.ToUpper(ada.ID.String())} {
		spec := worker
		spec.ClientID = id
		if _, _, err := app.CreateClient(t.Context(), s.deps, tn.ID, spec); !errors.Is(err, oauth.ErrInvalidClientID) {
			t.Errorf("CreateClient(%s) = %v, want ErrInvalidClientID", id, err)
		}
	}

	worker.ClientID = "worker"
	secret := createClient(t, s, tn, worker)
	h := s.Handler()
	tokens, errCode := requestToken(t, h, issuer, url.Values{"grant_type": {"client_credentials"}},
		clientAuth("worker", secret))
	if errCode != "" {
		t.Fatalf("client credentials = %q, want a token", errCode)
	}
	var claims struct {
		Subject string `json:"sub"`
	}
	if err := readClaims(tokens.AccessToken, &claims); err != nil || claims.Subject != "worker" {
		t.Errorf("sub of the client's token = %q, %v; want its client_id", claims.Subject, err)
	}
	if status := userinfoStatus(t, h, tokens.AccessToken); status != http.StatusUnauthorized {
		t.Errorf("userinfo with the client's token = %d, want 401", status)
	}
}

// exchange is a request that a browser sent in visitEveryPage, and the
// response it got.
type exchange struct {
	method, path string
	status       int
	header       http.Header
}

// recordingHandler passes requests to h and records them with their
// responses.
type recordingHandler struct {
	h         http.Handler
	exchanges []exchange
}

func (rh *recordingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rec := httptest.NewRecorder()
	rh.h.ServeHTTP(rec, r)
	rh.exchanges = append(rh.exchanges, exchange{r.Method, r.URL.Path, rec.Code, rec.Header().Clone()})
	maps.Copy(w.Header(), rec.Header())
	w.WriteHeader(rec.Code)
	_, _ = w.Write(rec.Body.Bytes())
}

// visitEveryPage takes browsers through every hosted page: sign-in,
// consent, form post, signup, password reset, logout, the account pages and
// error pages. It returns the requests and responses, and fails the test
// when a page was not reached.
func visitEveryPage(t *testing.T) []exchange {
	t.Helper()
	const issuer = signupIssuer
	s, tn, mail := newSignupServer(t)
	createClient(t, s, tn, app.ClientSpec{ClientID: "partner", Type: store.ClientConfidential,
		RedirectURIs: []string{"https://partner.example.com/callback"}})
	rh := &recordingHandler{h: s.Handler()}
	code := func(address string) string {
		t.Helper()
		m := signupCode.FindStringSubmatch(mail.last(t, address).Text)
		if m == nil {
			t.Fatalf("no code in the message to %s", address)
		}
		return m[1]
	}

	// Sign-in, with an invalid request, a wrong password and a cross-site
	// form first.
	b := newBrowser(t, rh)
	b.get(issuer + oidc.AuthorizationPath + "?client_id=nobody")
	id := b.startLogin(issuer, authorizeQuery())
	b.get(issuer + "/login?request=" + id)
	b.post(issuer+"/login", loginForm(id, "wrong password"), "same-origin")
	b.post(issuer+"/login", loginForm(id, testPassword), "cross-site")
	b.get(issuer + "/signup?request=" + id)
	b.get(issuer + "/reset?request=" + id)
	b.post(issuer+"/login", loginForm(id, testPassword), "same-origin")

	// Signup up to the password page.
	b = newBrowser(t, rh)
	verification := b.startSignup("grace@example.com")
	b.get(issuer + "/signup/verify?verification=" + verification)
	b.post(issuer+"/signup/verify", url.Values{"verification": {verification}, "code": {code("grace@example.com")}},
		"same-origin")
	b.get(issuer + "/signup/password?verification=" + verification)

	// Password reset up to the password page.
	b = newBrowser(t, rh)
	_, verification = b.startReset(authorizeQuery(), "ada@example.com")
	b.get(issuer + "/reset/verify?verification=" + verification)
	b.post(issuer+"/reset/verify", url.Values{"verification": {verification}, "code": {code("ada@example.com")}},
		"same-origin")
	b.get(issuer + "/reset/password?verification=" + verification)

	// Consent with a form post response, then logout.
	b = newBrowser(t, rh)
	q := authorizeQuery()
	q.Set("client_id", "partner")
	q.Set("redirect_uri", "https://partner.example.com/callback")
	q.Set("response_mode", "form_post")
	id = b.startLogin(issuer, q)
	res, _ := b.post(issuer+"/login", loginForm(id, testPassword), "same-origin")
	b.get(res.Header.Get("Location"))
	b.post(issuer+"/consent", url.Values{"request": {id}, "decision": {"allow"}}, "same-origin")
	b.get(issuer + oidc.EndSessionPath)
	b.post(issuer+"/logout", url.Values{}, "same-origin")

	// The account pages.
	b = newBrowser(t, rh)
	b.get(issuer + "/account/login")
	b.signInToAccount()
	for _, page := range []string{"/account", "/account/password", "/account/applications"} {
		b.get(issuer + page)
	}

	pages := make(map[string]bool)
	for _, e := range rh.exchanges {
		if strings.HasPrefix(e.header.Get("Content-Type"), "text/html") {
			pages[e.method+" "+e.path] = e.status == http.StatusOK || pages[e.method+" "+e.path]
			pages[e.method+" error"] = pages[e.method+" error"] || e.status >= http.StatusBadRequest
		}
	}
	for _, want := range []string{
		"GET error", "POST error", "GET /login", "POST /login", "GET /signup", "GET /signup/verify",
		"GET /signup/password", "GET /reset", "GET /reset/verify", "GET /reset/password", "GET /consent",
		"POST /consent", "GET /oauth2/logout", "POST /logout", "GET /account/login", "GET /account",
		"GET /account/password", "GET /account/applications",
	} {
		if !pages[want] {
			t.Fatalf("no page answered %s; pages: %v", want, pages)
		}
	}
	return rh.exchanges
}

// TestAttackClickjacking frames Clavis's pages in a page of the attacker,
// which then leads the user to click or type in them unknowingly (RFC 9700,
// section 4.16). Every hosted page, error pages too, forbids framing with
// X-Frame-Options and with the frame-ancestors directive of its Content
// Security Policy.
func TestAttackClickjacking(t *testing.T) {
	t.Parallel()
	for _, e := range visitEveryPage(t) {
		if !strings.HasPrefix(e.header.Get("Content-Type"), "text/html") {
			continue
		}
		if e.header.Get("X-Frame-Options") != "DENY" ||
			!strings.Contains(e.header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
			t.Errorf("%s %s = %d, headers %v; want framing forbidden", e.method, e.path, e.status, e.header)
		}
	}
}

// TestAttackReferrerLeakage looks for codes, state and request IDs in the
// Referer header that a browser sends from Clavis's pages and redirects to
// other sites (RFC 9700, section 4.2). Pages and redirects send no referrer,
// and pages load nothing from other sites, so their addresses reach no one
// else (section 4.2.4).
func TestAttackReferrerLeakage(t *testing.T) {
	t.Parallel()
	redirects := 0
	for _, e := range visitEveryPage(t) {
		html := strings.HasPrefix(e.header.Get("Content-Type"), "text/html")
		if e.status == http.StatusSeeOther {
			redirects++
		}
		if (html || e.status == http.StatusSeeOther) && e.header.Get("Referrer-Policy") != "no-referrer" {
			t.Errorf("%s %s = %d, Referrer-Policy %q; want no-referrer", e.method, e.path, e.status,
				e.header.Get("Referrer-Policy"))
		}
		if !html {
			continue
		}
		csp := e.header.Get("Content-Security-Policy")
		if !strings.HasPrefix(csp, "default-src 'none';") {
			t.Errorf("%s %s: Content-Security-Policy = %q, want default-src 'none'", e.method, e.path, csp)
		}
		for directive := range strings.SplitSeq(csp, ";") {
			name, sources, _ := strings.Cut(strings.TrimSpace(directive), " ")
			if name != "script-src" && name != "style-src" && name != "img-src" {
				continue
			}
			for source := range strings.FieldsSeq(sources) {
				if source != "'self'" && !strings.HasPrefix(source, "'sha256-") {
					t.Errorf("%s %s: %s allows %s, want only Clavis's own resources", e.method, e.path, name, source)
				}
			}
		}
	}
	if redirects == 0 {
		t.Error("no redirect was checked")
	}
}

// TestAttackCredentialsForwardedByRedirect looks for a redirect that would
// make the browser post the user's password, or another form, to the next
// site again: 307 and 308 keep the method and the body, and 302 may. Every
// form that Clavis redirects after answers with 303 See Other (RFC 9700,
// section 4.12).
func TestAttackCredentialsForwardedByRedirect(t *testing.T) {
	t.Parallel()
	redirects := 0
	for _, e := range visitEveryPage(t) {
		if e.method != http.MethodPost || e.header.Get("Location") == "" {
			continue
		}
		redirects++
		if e.status != http.StatusSeeOther {
			t.Errorf("POST %s = %d to %q, want 303", e.path, e.status, e.header.Get("Location"))
		}
	}
	if redirects == 0 {
		t.Error("no redirect after a form was checked")
	}
}
