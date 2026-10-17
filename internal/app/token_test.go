package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
	"uuid"

	"clavisid.org/clavis/internal/oauth"
	"clavisid.org/clavis/internal/oidc"
	"clavisid.org/clavis/store"
)

// fakeSigner "signs" a token by encoding its tenant, algorithm and type in
// the header and its payload as is, so tests can read every claim without
// keys. Its tokens have the syntax of a compact JWS.
type fakeSigner struct{}

func (fakeSigner) Sign(_ context.Context, tenantID uuid.UUID, alg, typ string, payload []byte) (string, error) {
	header := strings.Join([]string{tenantID.String(), alg, typ}, " ")
	return base64.RawURLEncoding.EncodeToString([]byte(header)) + "." +
		base64.RawURLEncoding.EncodeToString(payload) + ".fake", nil
}

func (fakeSigner) Verify(_ context.Context, tenantID uuid.UUID, token, typ string) ([]byte, error) {
	header, payload, ok := fakeParts(token)
	if !ok || header[0] != tenantID.String() || header[2] != typ {
		return nil, fmt.Errorf("fake signature: %w", ErrInvalidToken)
	}
	return payload, nil
}

// fakeParts returns the tenant, algorithm and type, and the payload, of a
// token from fakeSigner.
func fakeParts(token string) (header []string, payload []byte, ok bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[2] != "fake" {
		return nil, nil, false
	}
	h, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, false
	}
	header = strings.Split(string(h), " ")
	payload, err = base64.RawURLEncoding.DecodeString(parts[1])
	return header, payload, err == nil && len(header) == 3
}

// decode returns the claims of a token from fakeSigner.
func decode[T any](t *testing.T, token string) (alg, typ string, claims T) {
	t.Helper()
	header, payload, ok := fakeParts(token)
	if !ok {
		t.Fatalf("token %q is not from fakeSigner", token)
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("decoding claims: %v", err)
	}
	return header[1], header[2], claims
}

// codeFor signs ada in through an authorization request and returns the code
// and the client.
func (f authzFixture) codeFor(t *testing.T, params url.Values) (string, store.Client) {
	t.Helper()
	p := f.start(t, params)
	login, err := CompletePasswordLogin(t.Context(), f.d, f.h, f.tenant, p, "ada@example.com", "correct horse", nil)
	if err != nil {
		t.Fatalf("CompletePasswordLogin() unexpected error: %v", err)
	}
	u, err := url.Parse(login.RedirectURI)
	if err != nil {
		t.Fatalf("parsing %q: %v", login.RedirectURI, err)
	}
	return u.Query().Get("code"), p.Client
}

func (f authzFixture) client(t *testing.T, clientID string) store.Client {
	t.Helper()
	c, err := f.d.Store.Clients().GetByClientID(t.Context(), f.tenant.ID, clientID)
	if err != nil {
		t.Fatalf("looking up client %s: %v", clientID, err)
	}
	return c
}

func codeRequest(code string) oauth.TokenRequest {
	return oauth.TokenRequest{
		GrantType:    oauth.GrantTypeAuthorizationCode,
		Code:         code,
		RedirectURI:  "https://app.example.com/callback",
		CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
	}
}

func wantOAuthError(t *testing.T, name string, err error, code string) {
	t.Helper()
	var oauthErr *oauth.Error
	if !errors.As(err, &oauthErr) || oauthErr.Code != code {
		t.Errorf("%s: error = %v, want %s", name, err, code)
	}
}

func TestAuthenticateClient(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	secret, err := RotateClientSecret(t.Context(), f.d, f.tenant.ID, "web")
	if err != nil {
		t.Fatalf("RotateClientSecret() unexpected error: %v", err)
	}
	for _, creds := range []oauth.ClientCredentials{
		{ClientID: "web", Secret: secret, Method: oauth.AuthMethodClientSecretBasic},
		{ClientID: "web", Secret: secret, Method: oauth.AuthMethodClientSecretPost},
		{ClientID: "spa", Method: oauth.AuthMethodNone},
	} {
		if c, err := AuthenticateClient(t.Context(), f.d, f.tenant.ID, creds); err != nil || c.ClientID != creds.ClientID {
			t.Errorf("AuthenticateClient(%s, %s) = %v, %v", creds.ClientID, creds.Method, c.ClientID, err)
		}
	}
	for name, creds := range map[string]oauth.ClientCredentials{
		"wrong secret":            {ClientID: "web", Secret: secret + "x", Method: oauth.AuthMethodClientSecretBasic},
		"confidential without":    {ClientID: "web", Method: oauth.AuthMethodNone},
		"public with a secret":    {ClientID: "spa", Secret: "s", Method: oauth.AuthMethodClientSecretPost},
		"unknown client":          {ClientID: "nobody", Method: oauth.AuthMethodNone},
		"client ID in other case": {ClientID: "WEB", Secret: secret, Method: oauth.AuthMethodClientSecretBasic},
	} {
		_, err := AuthenticateClient(t.Context(), f.d, f.tenant.ID, creds)
		wantOAuthError(t, name, err, oauth.ErrorInvalidClient)
	}
}

func TestExchangeCode(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	code, client := f.codeFor(t, webRequest())

	resp, err := ExchangeCode(t.Context(), f.d, fakeSigner{}, f.tenant, client, codeRequest(code))
	if err != nil {
		t.Fatalf("ExchangeCode() unexpected error: %v", err)
	}
	if resp.TokenType != "Bearer" || resp.ExpiresIn != int64(DefaultAccessTokenLifetime/time.Second) ||
		resp.Scope != "openid profile" || resp.IDToken == "" {
		t.Errorf("token response = %+v", resp)
	}
	alg, typ, at := decode[oidc.AccessTokenClaims](t, resp.AccessToken)
	if alg != "RS256" || typ != "at+jwt" || at.Issuer != testIssuer || at.Subject != f.user.ID.String() ||
		!slices.Equal(at.Audience, []string{testIssuer}) || at.ClientID != "web" || at.Scope != "openid profile" ||
		at.Expiry != f.now.Add(DefaultAccessTokenLifetime).Unix() || at.AuthTime != f.now.Unix() ||
		!slices.Equal(at.AMR, []string{"pwd"}) || at.JWTID == "" {
		t.Errorf("access token %s %s claims = %+v", alg, typ, at)
	}
	alg, typ, id := decode[oidc.IDTokenClaims](t, resp.IDToken)
	wantHash, _ := oidc.AccessTokenHash("RS256", resp.AccessToken)
	if alg != "RS256" || typ != "JWT" || id.Issuer != testIssuer || id.Subject != f.user.ID.String() ||
		id.Audience != "web" || id.Nonce != "n-0S6_WzA2Mj" || id.AuthTime != f.now.Unix() ||
		id.AccessTokenHash != wantHash || id.Expiry != f.now.Add(DefaultIDTokenLifetime).Unix() {
		t.Errorf("ID token %s %s claims = %+v", alg, typ, id)
	}
	record, err := f.d.Store.AccessTokens().Get(t.Context(), f.tenant.ID, at.JWTID)
	if err != nil || record.UserID != f.user.ID || record.ClientID != client.ID ||
		!bytes.Equal(record.CodeHash, oauth.HashToken(code)) || !record.RevokedAt.IsZero() {
		t.Errorf("access token record = %+v, %v", record, err)
	}

	// A second exchange fails and revokes the tokens of the first.
	var logs bytes.Buffer
	f.d.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	_, err = ExchangeCode(t.Context(), f.d, fakeSigner{}, f.tenant, client, codeRequest(code))
	wantOAuthError(t, "reused code", err, oauth.ErrorInvalidGrant)
	if record, err := f.d.Store.AccessTokens().Get(t.Context(), f.tenant.ID, at.JWTID); err != nil || record.RevokedAt.IsZero() {
		t.Errorf("access token after the code was reused = %+v, %v; want it revoked", record, err)
	}
	if !strings.Contains(logs.String(), "authorization code reused") || strings.Contains(logs.String(), code) {
		t.Errorf("logs = %s", logs.String())
	}
}

func TestExchangeCodeRejectsInvalidRequests(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	legacyParams := webRequest()
	legacyParams.Set("client_id", "legacy")
	legacyParams.Set("redirect_uri", "https://legacy.example.com/callback")
	legacyParams.Del("code_challenge")
	legacyParams.Del("code_challenge_method")

	tests := []struct {
		name   string
		params url.Values
		client string
		edit   func(*oauth.TokenRequest)
		code   string
	}{
		{"missing code", webRequest(), "web", func(r *oauth.TokenRequest) { r.Code = "" }, oauth.ErrorInvalidRequest},
		{"unknown code", webRequest(), "web", func(r *oauth.TokenRequest) { r.Code = oauth.NewToken() }, oauth.ErrorInvalidGrant},
		{"another client", webRequest(), "legacy", func(*oauth.TokenRequest) {}, oauth.ErrorInvalidGrant},
		{"missing redirect_uri", webRequest(), "web", func(r *oauth.TokenRequest) { r.RedirectURI = "" }, oauth.ErrorInvalidGrant},
		{"other redirect_uri", webRequest(), "web", func(r *oauth.TokenRequest) { r.RedirectURI = "https://app.example.com/other?x=1" }, oauth.ErrorInvalidGrant},
		{"missing verifier", webRequest(), "web", func(r *oauth.TokenRequest) { r.CodeVerifier = "" }, oauth.ErrorInvalidGrant},
		{"wrong verifier", webRequest(), "web", func(r *oauth.TokenRequest) { r.CodeVerifier = strings.Repeat("a", 43) }, oauth.ErrorInvalidGrant},
		{"verifier without challenge", legacyParams, "legacy", func(r *oauth.TokenRequest) {
			r.RedirectURI = "https://legacy.example.com/callback"
		}, oauth.ErrorInvalidGrant},
		{"client without the grant", webRequest(), "service", func(*oauth.TokenRequest) {}, oauth.ErrorUnauthorizedClient},
	}
	for _, tt := range tests {
		code, _ := f.codeFor(t, tt.params)
		r := codeRequest(code)
		tt.edit(&r)
		_, err := ExchangeCode(t.Context(), f.d, fakeSigner{}, f.tenant, f.client(t, tt.client), r)
		wantOAuthError(t, tt.name, err, tt.code)
	}

	// A code that was refused for these reasons is still unused.
	code, client := f.codeFor(t, webRequest())
	bad := codeRequest(code)
	bad.CodeVerifier = strings.Repeat("a", 43)
	if _, err := ExchangeCode(t.Context(), f.d, fakeSigner{}, f.tenant, client, bad); err == nil {
		t.Fatal("ExchangeCode() with a wrong verifier succeeded")
	}
	if _, err := ExchangeCode(t.Context(), f.d, fakeSigner{}, f.tenant, client, codeRequest(code)); err != nil {
		t.Errorf("ExchangeCode() after a refused attempt = %v, want nil", err)
	}

	// The legacy client without PKCE, and an OAuth request that named no
	// redirect URI.
	code, legacy := f.codeFor(t, legacyParams)
	r := codeRequest(code)
	r.RedirectURI, r.CodeVerifier = "https://legacy.example.com/callback", ""
	if _, err := ExchangeCode(t.Context(), f.d, fakeSigner{}, f.tenant, legacy, r); err != nil {
		t.Errorf("ExchangeCode() for the exempt client = %v, want nil", err)
	}
	spaParams := webRequest()
	spaParams.Set("client_id", "spa")
	spaParams.Del("redirect_uri")
	spaParams.Set("scope", "profile")
	code, spa := f.codeFor(t, spaParams)
	r = codeRequest(code)
	r.RedirectURI = ""
	resp, err := ExchangeCode(t.Context(), f.d, fakeSigner{}, f.tenant, spa, r)
	if err != nil || resp.IDToken != "" {
		t.Errorf("ExchangeCode() of an OAuth request = %+v, %v; want an access token only", resp, err)
	}
}

func TestExchangeCodeChecksExpiryAndUser(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	code, client := f.codeFor(t, webRequest())
	*f.now = f.now.Add(AuthorizationCodeLifetime)
	_, err := ExchangeCode(t.Context(), f.d, fakeSigner{}, f.tenant, client, codeRequest(code))
	wantOAuthError(t, "expired code", err, oauth.ErrorInvalidGrant)

	code, client = f.codeFor(t, webRequest())
	if err := DeleteUser(t.Context(), f.d, f.tenant.ID, "ada@example.com"); err != nil {
		t.Fatalf("DeleteUser() unexpected error: %v", err)
	}
	_, err = ExchangeCode(t.Context(), f.d, fakeSigner{}, f.tenant, client, codeRequest(code))
	wantOAuthError(t, "deleted user", err, oauth.ErrorInvalidGrant)
}

func TestClientCredentialsToken(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	service := f.client(t, "service")
	request := oauth.TokenRequest{GrantType: oauth.GrantTypeClientCredentials}
	_, err := ClientCredentialsToken(t.Context(), f.d, fakeSigner{}, f.tenant, service, request)
	wantOAuthError(t, "scope without a resource", err, oauth.ErrorInvalidScope)

	if _, err := CreateAPIResource(t.Context(), f.d, f.tenant.ID, APIResourceSpec{
		Identifier: "https://api.example.com", Scopes: []string{"api:read", "api:write"},
	}); err != nil {
		t.Fatalf("CreateAPIResource() unexpected error: %v", err)
	}
	resp, err := ClientCredentialsToken(t.Context(), f.d, fakeSigner{}, f.tenant, service, request)
	if err != nil || resp.IDToken != "" || resp.Scope != "api:read" {
		t.Fatalf("ClientCredentialsToken() = %+v, %v", resp, err)
	}
	_, _, at := decode[oidc.AccessTokenClaims](t, resp.AccessToken)
	if at.Subject != "service" || at.ClientID != "service" || !slices.Equal(at.Audience, []string{"https://api.example.com"}) ||
		at.AuthTime != 0 || at.AMR != nil {
		t.Errorf("access token claims = %+v", at)
	}
	if record, err := f.d.Store.AccessTokens().Get(t.Context(), f.tenant.ID, at.JWTID); err != nil || record.UserID != uuid.Nil() {
		t.Errorf("access token record = %+v, %v", record, err)
	}

	for name, tt := range map[string]struct {
		client string
		scopes []string
		code   string
	}{
		"OpenID scope":         {"service", []string{"openid"}, oauth.ErrorInvalidScope},
		"scope not allowed":    {"service", []string{"api:write"}, oauth.ErrorInvalidScope},
		"public client":        {"spa", nil, oauth.ErrorUnauthorizedClient},
		"client without grant": {"web", nil, oauth.ErrorUnauthorizedClient},
	} {
		_, err := ClientCredentialsToken(t.Context(), f.d, fakeSigner{}, f.tenant, f.client(t, tt.client),
			oauth.TokenRequest{GrantType: oauth.GrantTypeClientCredentials, Scopes: tt.scopes})
		wantOAuthError(t, name, err, tt.code)
	}
}

func TestTokensForAPIScopesAndUser(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	if _, err := CreateAPIResource(t.Context(), f.d, f.tenant.ID, APIResourceSpec{
		Identifier: "https://api.example.com/orders", Scopes: []string{"orders:read"},
	}); err != nil {
		t.Fatalf("CreateAPIResource() unexpected error: %v", err)
	}
	if _, _, err := CreateClient(t.Context(), f.d, f.tenant.ID, ClientSpec{
		ClientID: "shop", Type: store.ClientPublic, SkipConsent: true, RedirectURIs: []string{"https://app.example.com/callback"},
		GrantTypes: []string{oauth.GrantTypeAuthorizationCode, oauth.GrantTypeRefreshToken},
		Scopes:     []string{"openid", "email", "orders:read", "offline_access", "undefined:scope"},
	}); err != nil {
		t.Fatalf("CreateClient() unexpected error: %v", err)
	}
	params := webRequest()
	params.Set("client_id", "shop")
	params.Set("scope", "openid orders:read offline_access")
	code, shop := f.codeFor(t, params)
	resp, err := ExchangeCode(t.Context(), f.d, fakeSigner{}, f.tenant, shop, codeRequest(code))
	if err != nil {
		t.Fatalf("ExchangeCode() unexpected error: %v", err)
	}
	_, _, at := decode[oidc.AccessTokenClaims](t, resp.AccessToken)
	if resp.Scope != "openid orders:read offline_access" || resp.RefreshToken == "" ||
		!slices.Equal(at.Audience, []string{testIssuer, "https://api.example.com/orders"}) {
		t.Errorf("scope %q, refresh token %q, aud %v", resp.Scope, resp.RefreshToken, at.Audience)
	}

	// A scope that no resource defines is refused at the authorization
	// endpoint.
	params.Set("scope", "openid undefined:scope")
	_, err = StartAuthorization(t.Context(), f.d, fakeSigner{}, f.tenant, params, testBinding, nil)
	var redirect *RedirectError
	if !errors.As(err, &redirect) || redirect.Err.Code != oauth.ErrorInvalidScope {
		t.Errorf("StartAuthorization() with an undefined scope = %v, want invalid_scope", err)
	}
}

func TestUserInfo(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	ada := f.user
	ada.Profile = store.Profile{
		Name: "Ada Lovelace", GivenName: "Ada", PhoneNumber: "+44 20 7946 0000",
		Address: store.Address{Locality: "London", Country: "GB"},
	}
	if _, _, err := CreateClient(t.Context(), f.d, f.tenant.ID, ClientSpec{
		ClientID: "all", Type: store.ClientConfidential, PKCEExempt: true, SkipConsent: true,
		RedirectURIs: []string{"https://app.example.com/callback"},
		Scopes:       []string{"openid", "profile", "email", "address", "phone"},
	}); err != nil {
		t.Fatalf("CreateClient() unexpected error: %v", err)
	}
	// The fixture user has no profile; replace it with one that has.
	if err := f.d.Store.Users().Delete(t.Context(), f.tenant.ID, ada.ID); err != nil {
		t.Fatalf("deleting the user: %v", err)
	}
	if err := f.d.Store.Users().Create(t.Context(), ada); err != nil {
		t.Fatalf("creating the user: %v", err)
	}
	if err := SetPassword(t.Context(), f.d, f.h, ada, "correct horse"); err != nil {
		t.Fatalf("SetPassword() unexpected error: %v", err)
	}

	tokenFor := func(scope string) TokenResponse {
		t.Helper()
		params := webRequest()
		params.Set("client_id", "all")
		params.Set("scope", scope)
		params.Del("code_challenge")
		params.Del("code_challenge_method")
		code, client := f.codeFor(t, params)
		r := codeRequest(code)
		r.CodeVerifier = ""
		resp, err := ExchangeCode(t.Context(), f.d, fakeSigner{}, f.tenant, client, r)
		if err != nil {
			t.Fatalf("ExchangeCode() unexpected error: %v", err)
		}
		return resp
	}

	claims, err := UserInfo(t.Context(), f.d, fakeSigner{}, f.tenant, tokenFor("openid profile email address phone").AccessToken)
	if err != nil {
		t.Fatalf("UserInfo() unexpected error: %v", err)
	}
	want := map[string]any{
		"sub": ada.ID.String(), "name": "Ada Lovelace", "given_name": "Ada", "updated_at": ada.UpdatedAt.Unix(),
		"email": "ada@example.com", "email_verified": false, "address": ada.Profile.Address,
		"phone_number": "+44 20 7946 0000", "phone_number_verified": false,
	}
	if fmt.Sprint(claims) != fmt.Sprint(want) {
		t.Errorf("UserInfo() =\n%v\nwant\n%v", claims, want)
	}
	claims, err = UserInfo(t.Context(), f.d, fakeSigner{}, f.tenant, tokenFor("openid").AccessToken)
	if err != nil || len(claims) != 1 || claims["sub"] != ada.ID.String() {
		t.Errorf("UserInfo() with only openid = %v, %v; want only sub", claims, err)
	}

	valid := tokenFor("openid email").AccessToken
	alg, typ, at := decode[oidc.AccessTokenClaims](t, valid)
	resign := func(edit func(*oidc.AccessTokenClaims)) string {
		c := at
		edit(&c)
		token, err := sign(t.Context(), fakeSigner{}, f.tenant.ID, alg, typ, c)
		if err != nil {
			t.Fatalf("signing: %v", err)
		}
		return token
	}
	for name, tt := range map[string]struct {
		token string
		code  string
	}{
		"not a token":     {"garbage", oauth.ErrorInvalidToken},
		"other issuer":    {resign(func(c *oidc.AccessTokenClaims) { c.Issuer = "https://evil.example" }), oauth.ErrorInvalidToken},
		"other audience":  {resign(func(c *oidc.AccessTokenClaims) { c.Audience = []string{"https://api.example.com"} }), oauth.ErrorInvalidToken},
		"expired":         {resign(func(c *oidc.AccessTokenClaims) { c.Expiry = f.now.Unix() }), oauth.ErrorInvalidToken},
		"unknown jti":     {resign(func(c *oidc.AccessTokenClaims) { c.JWTID = uuid.NewV7().String() }), oauth.ErrorInvalidToken},
		"other subject":   {resign(func(c *oidc.AccessTokenClaims) { c.Subject = uuid.NewV7().String() }), oauth.ErrorInvalidToken},
		"without openid":  {resign(func(c *oidc.AccessTokenClaims) { c.Scope = "email" }), oauth.ErrorInsufficientScope},
		"ID token as one": {tokenFor("openid").IDToken, oauth.ErrorInvalidToken},
	} {
		_, err := UserInfo(t.Context(), f.d, fakeSigner{}, f.tenant, tt.token)
		wantOAuthError(t, name, err, tt.code)
	}

	// A revoked token, then a valid token of a deleted user.
	record, err := f.d.Store.AccessTokens().Get(t.Context(), f.tenant.ID, at.JWTID)
	if err != nil {
		t.Fatalf("looking up the token: %v", err)
	}
	if _, err := f.d.Store.AccessTokens().RevokeByCode(t.Context(), f.tenant.ID, record.CodeHash, *f.now); err != nil {
		t.Fatalf("RevokeByCode() unexpected error: %v", err)
	}
	_, err = UserInfo(t.Context(), f.d, fakeSigner{}, f.tenant, valid)
	wantOAuthError(t, "revoked token", err, oauth.ErrorInvalidToken)
	other := tokenFor("openid").AccessToken
	if err := f.d.Store.Users().Delete(t.Context(), f.tenant.ID, ada.ID); err != nil {
		t.Fatalf("deleting the user: %v", err)
	}
	_, err = UserInfo(t.Context(), f.d, fakeSigner{}, f.tenant, other)
	wantOAuthError(t, "deleted user", err, oauth.ErrorInvalidToken)
}

func TestPurgeExpiredDeletesAccessTokens(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	code, client := f.codeFor(t, webRequest())
	resp, err := ExchangeCode(t.Context(), f.d, fakeSigner{}, f.tenant, client, codeRequest(code))
	if err != nil {
		t.Fatalf("ExchangeCode() unexpected error: %v", err)
	}
	_, _, at := decode[oidc.AccessTokenClaims](t, resp.AccessToken)
	*f.now = f.now.Add(DefaultAccessTokenLifetime)
	if err := PurgeExpired(t.Context(), f.d); err != nil {
		t.Fatalf("PurgeExpired() unexpected error: %v", err)
	}
	if _, err := f.d.Store.AccessTokens().Get(t.Context(), f.tenant.ID, at.JWTID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("the expired access token record = %v, want it deleted", err)
	}
}
