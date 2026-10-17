package clavis

import (
	"context"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"clavisid.org/clavis/internal/app"
	"clavisid.org/clavis/store"
)

// The interoperability tests drive Clavis with independent client
// libraries over HTTPS, as a relying party and a resource owner's browser
// would.

const interopRedirectURI = "https://client.example/callback"

// interopServer serves Clavis over TLS at its issuer and returns it with
// the issuer.
func interopServer(t *testing.T) (*Server, string, *http.Client) {
	t.Helper()
	var handler http.Handler
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(ts.Close)
	cfg := testConfig(t, openStore(t))
	cfg.Issuer = ts.URL
	s := mustNew(t, cfg)
	handler = s.Handler()
	return s, ts.URL, ts.Client()
}

// interopBrowser returns a client that keeps cookies like a browser and
// stops at redirects to the relying party.
func interopBrowser(t *testing.T, client *http.Client) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("creating a cookie jar: %v", err)
	}
	return &http.Client{
		Transport: client.Transport,
		Jar:       jar,
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			if req.URL.Host == "client.example" {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

// signIn plays the browser: it follows auth to the login page, signs in as
// ada and returns the authorization response that reaches the client.
func signIn(t *testing.T, browser *http.Client, authURL string) url.Values {
	t.Helper()
	res, err := browser.Get(authURL) //nolint:noctx // A test helper; the request ends with the test.
	if err != nil {
		t.Fatalf("GET the authorization URL: %v", err)
	}
	page := readBody(t, res)
	m := regexp.MustCompile(`name="request" value="([^"]+)"`).FindStringSubmatch(page)
	if res.StatusCode != http.StatusOK || m == nil {
		t.Fatalf("login page = %d:\n%s", res.StatusCode, page)
	}
	form := url.Values{"request": {m[1]}, "email": {"ada@example.com"}, "password": {testPassword}}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, res.Request.URL.String(),
		strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("building the login request: %v", err)
	}
	req.Header.Set("Content-Type", formContentType)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	res, err = browser.Do(req)
	if err != nil {
		t.Fatalf("POST the login form: %v", err)
	}
	readBody(t, res)
	loc, err := url.Parse(res.Header.Get("Location"))
	if res.StatusCode != http.StatusSeeOther || err != nil || loc.Host != "client.example" {
		t.Fatalf("login = %d to %q", res.StatusCode, res.Header.Get("Location"))
	}
	return loc.Query()
}

func readBody(t *testing.T, res *http.Response) string {
	t.Helper()
	defer res.Body.Close()
	var b strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := res.Body.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			return b.String()
		}
	}
}

func TestInteropAuthorizationCodeFlow(t *testing.T) {
	t.Parallel()
	s, issuer, httpClient := interopServer(t)
	ctx := oidc.ClientContext(t.Context(), httpClient)
	_, secret, err := app.CreateClient(t.Context(), s.deps, s.defaultTenant.ID, app.ClientSpec{
		ClientID: "rp", Type: store.ClientConfidential, RedirectURIs: []string{interopRedirectURI},
	})
	if err != nil {
		t.Fatalf("CreateClient() unexpected error: %v", err)
	}
	createUser(t, s, s.defaultTenant)

	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		t.Fatalf("discovering the provider: %v", err)
	}
	config := oauth2.Config{
		ClientID:     "rp",
		ClientSecret: secret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  interopRedirectURI,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
	verifier := oauth2.GenerateVerifier()
	response := signIn(t, interopBrowser(t, httpClient), config.AuthCodeURL("state-1",
		oauth2.S256ChallengeOption(verifier), oidc.Nonce("nonce-1")))
	if response.Get("state") != "state-1" || response.Get("iss") != issuer {
		t.Fatalf("authorization response = %v", response)
	}

	token, err := config.Exchange(ctx, response.Get("code"), oauth2.VerifierOption(verifier))
	if err != nil {
		t.Fatalf("exchanging the code: %v", err)
	}
	rawIDToken, _ := token.Extra("id_token").(string)
	idToken, err := provider.Verifier(&oidc.Config{ClientID: "rp"}).Verify(ctx, rawIDToken)
	if err != nil {
		t.Fatalf("verifying the ID token: %v", err)
	}
	if idToken.Nonce != "nonce-1" || idToken.Issuer != issuer {
		t.Errorf("ID token = %+v", idToken)
	}
	if err := idToken.VerifyAccessToken(token.AccessToken); err != nil {
		t.Errorf("at_hash does not match the access token: %v", err)
	}

	info, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
	if err != nil {
		t.Fatalf("calling userinfo: %v", err)
	}
	if info.Subject != idToken.Subject || info.Email != "ada@example.com" {
		t.Errorf("userinfo = %+v", info)
	}

	// Reusing the code fails and revokes the token issued for it.
	_, err = config.Exchange(ctx, response.Get("code"), oauth2.VerifierOption(verifier))
	var retrieveErr *oauth2.RetrieveError
	if !errors.As(err, &retrieveErr) || retrieveErr.ErrorCode != "invalid_grant" {
		t.Errorf("second exchange = %v, want invalid_grant", err)
	}
	if _, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(token)); err == nil {
		t.Error("userinfo accepted the token of a reused code")
	}
}

func TestInteropPublicClient(t *testing.T) {
	t.Parallel()
	s, issuer, httpClient := interopServer(t)
	ctx := oidc.ClientContext(t.Context(), httpClient)
	if _, _, err := app.CreateClient(t.Context(), s.deps, s.defaultTenant.ID, app.ClientSpec{
		ClientID: "native", Type: store.ClientPublic, RedirectURIs: []string{interopRedirectURI},
	}); err != nil {
		t.Fatalf("CreateClient() unexpected error: %v", err)
	}
	createUser(t, s, s.defaultTenant)
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		t.Fatalf("discovering the provider: %v", err)
	}
	endpoint := provider.Endpoint()
	endpoint.AuthStyle = oauth2.AuthStyleInParams
	config := oauth2.Config{ClientID: "native", Endpoint: endpoint, RedirectURL: interopRedirectURI,
		Scopes: []string{oidc.ScopeOpenID}}
	verifier := oauth2.GenerateVerifier()
	response := signIn(t, interopBrowser(t, httpClient), config.AuthCodeURL("s", oauth2.S256ChallengeOption(verifier)))
	token, err := config.Exchange(ctx, response.Get("code"), oauth2.VerifierOption(verifier))
	if err != nil {
		t.Fatalf("exchanging the code: %v", err)
	}
	if _, err := provider.Verifier(&oidc.Config{ClientID: "native"}).Verify(ctx, token.Extra("id_token").(string)); err != nil {
		t.Errorf("verifying the ID token: %v", err)
	}
}

func TestInteropSingleSignOn(t *testing.T) {
	t.Parallel()
	s, issuer, httpClient := interopServer(t)
	ctx := oidc.ClientContext(t.Context(), httpClient)
	_, secret, err := app.CreateClient(t.Context(), s.deps, s.defaultTenant.ID, app.ClientSpec{
		ClientID: "rp", Type: store.ClientConfidential, RedirectURIs: []string{interopRedirectURI},
	})
	if err != nil {
		t.Fatalf("CreateClient() unexpected error: %v", err)
	}
	createUser(t, s, s.defaultTenant)
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		t.Fatalf("discovering the provider: %v", err)
	}
	config := oauth2.Config{ClientID: "rp", ClientSecret: secret, Endpoint: provider.Endpoint(),
		RedirectURL: interopRedirectURI, Scopes: []string{oidc.ScopeOpenID}}
	verifier := provider.Verifier(&oidc.Config{ClientID: "rp"})
	exchange := func(response url.Values, codeVerifier string) (*oauth2.Token, *oidc.IDToken, string) {
		t.Helper()
		token, err := config.Exchange(ctx, response.Get("code"), oauth2.VerifierOption(codeVerifier))
		if err != nil {
			t.Fatalf("exchanging the code of %v: %v", response, err)
		}
		raw, _ := token.Extra("id_token").(string)
		idToken, err := verifier.Verify(ctx, raw)
		if err != nil {
			t.Fatalf("verifying the ID token: %v", err)
		}
		return token, idToken, raw
	}

	browser := interopBrowser(t, httpClient)
	codeVerifier := oauth2.GenerateVerifier()
	_, first, firstRaw := exchange(signIn(t, browser, config.AuthCodeURL("s1",
		oauth2.S256ChallengeOption(codeVerifier))), codeVerifier)
	type authClaims struct {
		ACR      string `json:"acr"`
		AuthTime int64  `json:"auth_time"`
	}
	var firstClaims authClaims
	if err := first.Claims(&firstClaims); err != nil || firstClaims.ACR != "https://clavisid.org/acr/password" ||
		firstClaims.AuthTime == 0 {
		t.Errorf("ID token claims = %+v, %v; want the password class and auth_time", firstClaims, err)
	}

	// The second request forbids interaction, names the user with the first
	// ID token and asks for the email address in the userinfo response.
	codeVerifier = oauth2.GenerateVerifier()
	authURL := config.AuthCodeURL("s2", oauth2.S256ChallengeOption(codeVerifier),
		oauth2.SetAuthURLParam("prompt", "none"),
		oauth2.SetAuthURLParam("max_age", "10000"),
		oauth2.SetAuthURLParam("id_token_hint", firstRaw),
		oauth2.SetAuthURLParam("claims", `{"userinfo":{"email":{"essential":true}}}`))
	res, err := browser.Get(authURL) //nolint:noctx // A test helper; the request ends with the test.
	if err != nil {
		t.Fatalf("GET the authorization URL: %v", err)
	}
	readBody(t, res)
	loc, err := url.Parse(res.Header.Get("Location"))
	if res.StatusCode != http.StatusSeeOther || err != nil || loc.Host != "client.example" || loc.Query().Get("code") == "" {
		t.Fatalf("authorize with a session = %d to %q, want a code", res.StatusCode, res.Header.Get("Location"))
	}
	token, second, _ := exchange(loc.Query(), codeVerifier)
	var secondClaims authClaims
	if err := second.Claims(&secondClaims); err != nil || second.Subject != first.Subject ||
		secondClaims != firstClaims {
		t.Errorf("second ID token sub %s, claims %+v, %v; want %s, %+v", second.Subject, secondClaims, err,
			first.Subject, firstClaims)
	}
	info, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
	if err != nil || info.Email != "ada@example.com" {
		t.Errorf("userinfo = %+v, %v; want the email address that the claims parameter asked for", info, err)
	}
}

func TestInteropClientCredentials(t *testing.T) {
	t.Parallel()
	s, issuer, httpClient := interopServer(t)
	ctx := context.WithValue(t.Context(), oauth2.HTTPClient, httpClient)
	if _, err := app.CreateAPIResource(t.Context(), s.deps, s.defaultTenant.ID, app.APIResourceSpec{
		Identifier: "https://api.example.com", Scopes: []string{"orders:read"},
	}); err != nil {
		t.Fatalf("CreateAPIResource() unexpected error: %v", err)
	}
	_, secret, err := app.CreateClient(t.Context(), s.deps, s.defaultTenant.ID, app.ClientSpec{
		ClientID: "worker", Type: store.ClientConfidential, GrantTypes: []string{"client_credentials"},
		Scopes: []string{"orders:read"},
	})
	if err != nil {
		t.Fatalf("CreateClient() unexpected error: %v", err)
	}
	for _, style := range []oauth2.AuthStyle{oauth2.AuthStyleInHeader, oauth2.AuthStyleInParams} {
		config := clientcredentials.Config{ClientID: "worker", ClientSecret: secret, TokenURL: issuer + "/oauth2/token",
			Scopes: []string{"orders:read"}, AuthStyle: style}
		token, err := config.Token(ctx)
		if err != nil {
			t.Fatalf("auth style %d: requesting a token: %v", style, err)
		}
		if token.TokenType != "Bearer" || token.AccessToken == "" || token.Extra("scope") != "orders:read" {
			t.Errorf("auth style %d: token = %+v", style, token)
		}
		payload, err := s.keys.Verify(t.Context(), s.defaultTenant.ID, token.AccessToken, "at+jwt")
		if err != nil || !strings.Contains(string(payload), `"aud":["https://api.example.com"]`) {
			t.Errorf("auth style %d: access token payload = %s, %v", style, payload, err)
		}
	}
	bad := clientcredentials.Config{ClientID: "worker", ClientSecret: "wrong", TokenURL: issuer + "/oauth2/token"}
	_, err = bad.Token(ctx)
	var retrieveErr *oauth2.RetrieveError
	if !errors.As(err, &retrieveErr) || retrieveErr.ErrorCode != "invalid_client" {
		t.Errorf("token with a wrong secret = %v, want invalid_client", err)
	}
}

// createUser creates ada@example.com with testPassword in a tenant.
func createUser(t *testing.T, s *Server, tn store.Tenant) store.User {
	t.Helper()
	u, err := app.CreateUser(t.Context(), s.deps, tn.ID, app.UserSpec{Email: "ada@example.com", EmailVerified: true})
	if err != nil {
		t.Fatalf("CreateUser() unexpected error: %v", err)
	}
	if err := app.SetPassword(t.Context(), s.deps, s.passwords, u, testPassword); err != nil {
		t.Fatalf("SetPassword() unexpected error: %v", err)
	}
	return u
}
