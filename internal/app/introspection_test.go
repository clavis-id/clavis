package app

import (
	"bytes"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"clavisid.org/clavis/internal/oauth"
	"clavisid.org/clavis/internal/oidc"
	"clavisid.org/clavis/store"
)

func (f authzFixture) revoke(t *testing.T, clientID, token string) error {
	t.Helper()
	return RevokeToken(t.Context(), f.d, fakeSigner{}, f.tenant, f.client(t, clientID), token)
}

func (f authzFixture) introspect(t *testing.T, clientID, token string) Introspection {
	t.Helper()
	got, err := IntrospectToken(t.Context(), f.d, fakeSigner{}, f.tenant, f.client(t, clientID), token)
	if err != nil {
		t.Fatalf("IntrospectToken() unexpected error: %v", err)
	}
	return got
}

// wantInactive checks that the response says only that the token is not
// active (RFC 7662, section 2.2).
func wantInactive(t *testing.T, name string, got Introspection) {
	t.Helper()
	if !onlyInactive(got) {
		t.Errorf("%s: introspection = %+v, want only active=false", name, got)
	}
}

func onlyInactive(i Introspection) bool {
	return !i.Active && i.Scope == "" && i.ClientID == "" && i.TokenType == "" && i.Expiry == 0 &&
		i.IssuedAt == 0 && i.Subject == "" && i.Audience == nil && i.Issuer == "" && i.JWTID == ""
}

func TestRevokeRefreshToken(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	var logs bytes.Buffer
	f.d.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	first, web := f.refreshTokenFor(t, offlineRequest())
	second, err := f.refresh(t, web, first.RefreshToken)
	if err != nil {
		t.Fatalf("RefreshToken() unexpected error: %v", err)
	}

	// Another client may not revoke it, and the token keeps working.
	wantOAuthError(t, "another client", f.revoke(t, "legacy", second.RefreshToken), oauth.ErrorUnauthorizedClient)
	if _, err := UserInfo(t.Context(), f.d, fakeSigner{}, f.tenant, second.AccessToken); err != nil {
		t.Fatalf("UserInfo() after a refused revocation = %v", err)
	}

	// Revoking a replaced token ends the family too (ADR 0022), with the
	// access tokens issued from it.
	if err := f.revoke(t, "web", first.RefreshToken); err != nil {
		t.Fatalf("RevokeToken() unexpected error: %v", err)
	}
	_, err = f.refresh(t, web, second.RefreshToken)
	wantOAuthError(t, "refresh after the revocation", err, oauth.ErrorInvalidGrant)
	f.wantRevoked(t, "after the revocation", first.AccessToken, second.AccessToken)
	if !strings.Contains(logs.String(), "revoked refresh token family") || !strings.Contains(logs.String(), "revoked_access_tokens=2") ||
		strings.Contains(logs.String(), "refresh token reused") {
		t.Errorf("logs do not report the revocation:\n%s", logs.String())
	}
	// Revoking it again needs nothing.
	if err := f.revoke(t, "web", second.RefreshToken); err != nil {
		t.Errorf("RevokeToken() of a revoked token = %v, want nil", err)
	}

	// A public client revokes its own tokens with its client ID only.
	spa := with(with(webRequest(), "client_id", "spa"), "redirect_uri", "http://127.0.0.1/callback")
	resp, client := f.refreshTokenFor(t, with(spa, "scope", "profile"))
	if err := f.revoke(t, "spa", resp.RefreshToken); err != nil {
		t.Fatalf("RevokeToken() of a public client = %v", err)
	}
	_, err = f.refresh(t, client, resp.RefreshToken)
	wantOAuthError(t, "refresh after a public client revoked it", err, oauth.ErrorInvalidGrant)
}

func TestRevokeAccessToken(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	resp, web := f.refreshTokenFor(t, offlineRequest())
	wantOAuthError(t, "another client", f.revoke(t, "legacy", resp.AccessToken), oauth.ErrorUnauthorizedClient)
	if err := f.revoke(t, "web", resp.AccessToken); err != nil {
		t.Fatalf("RevokeToken() unexpected error: %v", err)
	}
	f.wantRevoked(t, "after the revocation", resp.AccessToken)
	// RFC 7009, section 2.1, lets the refresh token stay; Clavis keeps it.
	if _, err := f.refresh(t, web, resp.RefreshToken); err != nil {
		t.Errorf("RefreshToken() after revoking the access token = %v, want nil", err)
	}

	// Tokens that are invalid, unknown or of another tenant need nothing
	// (RFC 7009, section 2.2).
	other := f
	other.tenant.ID = f.d.NewID()
	foreign, _, _ := strings.Cut(resp.AccessToken, ".")
	foreignToken, _ := fakeSigner{}.Sign(t.Context(), other.tenant.ID, "RS256", oidc.AccessTokenType, []byte(`{}`))
	for name, token := range map[string]string{
		"unknown refresh token": oauth.NewToken(),
		"malformed JWT":         foreign + ".x.y",
		"another tenant":        foreignToken,
	} {
		if err := f.revoke(t, "web", token); err != nil {
			t.Errorf("%s: RevokeToken() = %v, want nil", name, err)
		}
	}
	// An access token whose record was deleted after it expired.
	fresh, _ := f.refreshTokenFor(t, offlineRequest())
	*f.now = f.now.Add(DefaultAccessTokenLifetime)
	if err := PurgeExpired(t.Context(), f.d); err != nil {
		t.Fatalf("PurgeExpired() unexpected error: %v", err)
	}
	if err := f.revoke(t, "web", fresh.AccessToken); err != nil {
		t.Errorf("RevokeToken() of a deleted access token = %v, want nil", err)
	}
}

// introspectionFixture adds two API resources, a client that requests
// their scopes and gets tokens, and the server of one of them.
func introspectionFixture(t *testing.T) (f authzFixture, resp TokenResponse) {
	t.Helper()
	f = newAuthzFixture(t)
	for _, spec := range []APIResourceSpec{
		{Identifier: "https://api.example.com/orders", Scopes: []string{"orders:read"}},
		{Identifier: "https://api.example.com/billing", Scopes: []string{"billing:read"}},
	} {
		if _, err := CreateAPIResource(t.Context(), f.d, f.tenant.ID, spec); err != nil {
			t.Fatalf("CreateAPIResource() unexpected error: %v", err)
		}
	}
	for _, spec := range []ClientSpec{
		{ClientID: "shop", Type: store.ClientConfidential, SkipConsent: true,
			RedirectURIs: []string{"https://app.example.com/callback"},
			Scopes:       []string{"openid", "orders:read", "billing:read", "offline_access"}},
		{ClientID: "orders-api", Type: store.ClientConfidential, GrantTypes: []string{oauth.GrantTypeClientCredentials},
			ResourceServerFor: []string{"https://api.example.com/orders", "https://api.example.com/orders"}},
	} {
		if _, _, err := CreateClient(t.Context(), f.d, f.tenant.ID, spec); err != nil {
			t.Fatalf("CreateClient(%s) unexpected error: %v", spec.ClientID, err)
		}
	}
	resp, _ = f.refreshTokenFor(t, with(with(webRequest(), "client_id", "shop"),
		"scope", "openid orders:read billing:read offline_access"))
	return f, resp
}

func TestIntrospectAccessToken(t *testing.T) {
	t.Parallel()
	f, resp := introspectionFixture(t)
	_, _, at := decode[oidc.AccessTokenClaims](t, resp.AccessToken)

	// The client the token was issued to sees all of it.
	got := f.introspect(t, "shop", resp.AccessToken)
	want := Introspection{
		Active: true, Scope: "openid orders:read billing:read offline_access", ClientID: "shop", TokenType: "Bearer",
		Expiry: at.Expiry, IssuedAt: at.IssuedAt, Subject: f.user.ID.String(),
		Audience: []string{testIssuer, "https://api.example.com/orders", "https://api.example.com/billing"},
		Issuer:   testIssuer, JWTID: at.JWTID,
	}
	if !equalIntrospection(got, want) {
		t.Errorf("introspection by the client = %+v, want %+v", got, want)
	}
	// The server of the orders API sees its own audience and scope only.
	got = f.introspect(t, "orders-api", resp.AccessToken)
	want.Scope, want.Audience = "orders:read", []string{"https://api.example.com/orders"}
	if !equalIntrospection(got, want) {
		t.Errorf("introspection by the resource server = %+v, want %+v", got, want)
	}
	// Any other client learns nothing.
	wantInactive(t, "another client", f.introspect(t, "web", resp.AccessToken))

	// A token that a client obtained for itself has no user.
	if _, err := CreateAPIResource(t.Context(), f.d, f.tenant.ID, APIResourceSpec{
		Identifier: "https://api.example.com/catalog", Scopes: []string{"api:read"},
	}); err != nil {
		t.Fatalf("CreateAPIResource() unexpected error: %v", err)
	}
	own, err := ClientCredentialsToken(t.Context(), f.d, fakeSigner{}, f.tenant, f.client(t, "service"),
		oauth.TokenRequest{GrantType: oauth.GrantTypeClientCredentials})
	if err != nil {
		t.Fatalf("ClientCredentialsToken() unexpected error: %v", err)
	}
	if got := f.introspect(t, "service", own.AccessToken); !got.Active || got.Subject != "service" ||
		got.Scope != "api:read" {
		t.Errorf("introspection of a client credentials token = %+v", got)
	}
}

func equalIntrospection(a, b Introspection) bool {
	return a.Active == b.Active && a.Scope == b.Scope && a.ClientID == b.ClientID && a.TokenType == b.TokenType &&
		a.Expiry == b.Expiry && a.IssuedAt == b.IssuedAt && a.Subject == b.Subject &&
		slices.Equal(a.Audience, b.Audience) && a.Issuer == b.Issuer && a.JWTID == b.JWTID
}

func TestIntrospectInactiveAccessTokens(t *testing.T) {
	t.Parallel()
	f, resp := introspectionFixture(t)
	wantInactive(t, "malformed token", f.introspect(t, "shop", "a.b.c"))

	disabled := f
	disabled.d.Store = disabledUserStore{f.d.Store}
	got, err := IntrospectToken(t.Context(), disabled.d, fakeSigner{}, f.tenant, f.client(t, "shop"), resp.AccessToken)
	if err != nil {
		t.Fatalf("IntrospectToken() unexpected error: %v", err)
	}
	wantInactive(t, "token of a disabled user", got)

	if err := f.revoke(t, "shop", resp.AccessToken); err != nil {
		t.Fatalf("RevokeToken() unexpected error: %v", err)
	}
	wantInactive(t, "revoked token", f.introspect(t, "shop", resp.AccessToken))
	wantInactive(t, "revoked token for the resource server", f.introspect(t, "orders-api", resp.AccessToken))

	fresh, _ := f.refreshTokenFor(t, with(with(webRequest(), "client_id", "shop"), "scope", "openid offline_access"))
	*f.now = f.now.Add(DefaultAccessTokenLifetime)
	wantInactive(t, "expired token", f.introspect(t, "shop", fresh.AccessToken))
}

func TestIntrospectRefreshToken(t *testing.T) {
	t.Parallel()
	f, first := introspectionFixture(t)
	shop := f.client(t, "shop")
	issued := *f.now
	got := f.introspect(t, "shop", first.RefreshToken)
	want := Introspection{
		Active: true, Scope: "openid orders:read billing:read offline_access", ClientID: "shop",
		Expiry: issued.Add(DefaultRefreshTokenIdleLifetime).Unix(), IssuedAt: issued.Unix(),
		Subject: f.user.ID.String(), Issuer: testIssuer,
	}
	if !equalIntrospection(got, want) {
		t.Errorf("introspection of a refresh token = %+v, want %+v", got, want)
	}
	// Refresh tokens are for their client only, resource servers included.
	wantInactive(t, "resource server", f.introspect(t, "orders-api", first.RefreshToken))
	wantInactive(t, "unknown token", f.introspect(t, "shop", oauth.NewToken()))

	// A replaced token is inactive, and introspecting it is not reuse.
	second, err := f.refresh(t, shop, first.RefreshToken)
	if err != nil {
		t.Fatalf("RefreshToken() unexpected error: %v", err)
	}
	wantInactive(t, "replaced token", f.introspect(t, "shop", first.RefreshToken))
	if got := f.introspect(t, "shop", second.RefreshToken); !got.Active {
		t.Errorf("introspection of the current token after introspecting a replaced one = %+v", got)
	}

	*f.now = f.now.Add(DefaultRefreshTokenIdleLifetime)
	wantInactive(t, "expired token", f.introspect(t, "shop", second.RefreshToken))
}

func TestIntrospectionNeedsAConfidentialClient(t *testing.T) {
	t.Parallel()
	f, resp := introspectionFixture(t)
	_, err := IntrospectToken(t.Context(), f.d, fakeSigner{}, f.tenant, f.client(t, "spa"), resp.AccessToken)
	wantOAuthError(t, "public client", err, oauth.ErrorInvalidClient)
}

func TestResourceServerClients(t *testing.T) {
	t.Parallel()
	f, _ := introspectionFixture(t)
	if got := f.client(t, "orders-api").ResourceServerFor; !slices.Equal(got, []string{"https://api.example.com/orders"}) {
		t.Errorf("ResourceServerFor = %q, want the orders API once", got)
	}
	for name, spec := range map[string]ClientSpec{
		"unknown resource": {ClientID: "a", Type: store.ClientConfidential, GrantTypes: []string{oauth.GrantTypeClientCredentials},
			ResourceServerFor: []string{"https://api.example.com/unknown"}},
		"public client": {ClientID: "b", Type: store.ClientPublic, RedirectURIs: []string{"http://127.0.0.1/callback"},
			ResourceServerFor: []string{"https://api.example.com/orders"}},
		"too many": {ClientID: "c", Type: store.ClientConfidential, GrantTypes: []string{oauth.GrantTypeClientCredentials},
			ResourceServerFor: manyResources()},
	} {
		if _, _, err := CreateClient(t.Context(), f.d, f.tenant.ID, spec); !errors.Is(err, ErrInvalidClientMetadata) {
			t.Errorf("%s: CreateClient() = %v, want ErrInvalidClientMetadata", name, err)
		}
	}
}

func manyResources() []string {
	list := make([]string, MaxResources+1)
	for i := range list {
		list[i] = "https://api.example.com/" + strings.Repeat("r", i+1)
	}
	return list
}
