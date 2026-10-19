package app

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"log/slog"
	"net/url"
	"strings"
	"testing"
	"time"
	"uuid"

	"clavisid.org/clavis/internal/oauth"
	"clavisid.org/clavis/internal/oidc"
	"clavisid.org/clavis/store"
)

// exchangeWith answers params from the session whose cookie hashes to
// sessionHash and exchanges the code.
func (f authzFixture) exchangeWith(t *testing.T, params url.Values, sessionHash []byte) TokenResponse {
	t.Helper()
	a, err := f.startWith(t, params, sessionHash)
	if err != nil || a.Response.RedirectURI == "" {
		t.Fatalf("StartAuthorization() = %+v, %v; want a code", a, err)
	}
	resp, err := ExchangeCode(t.Context(), f.d, fakeSigner{}, f.tenant, f.client(t, "web"),
		codeRequest(a.Response.Params.Get("code")))
	if err != nil {
		t.Fatalf("ExchangeCode() unexpected error: %v", err)
	}
	return resp
}

// ADR 0023: ending a session ends its online access, which is its pending
// codes and the access tokens of codes that started no refresh token
// family. Offline access and other sessions stay.
func TestLogout(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	var logs bytes.Buffer
	f.d.Logger = slog.New(slog.NewTextHandler(&logs, nil))

	sessionHash, response := f.signIn(t, webRequest())
	online, err := ExchangeCode(t.Context(), f.d, fakeSigner{}, f.tenant, f.client(t, "web"),
		codeRequest(response.Get("code")))
	if err != nil {
		t.Fatalf("ExchangeCode() unexpected error: %v", err)
	}
	offline := f.exchangeWith(t, with(webRequest(), "scope", "openid offline_access"), sessionHash)
	pending, err := f.startWith(t, webRequest(), sessionHash)
	if err != nil {
		t.Fatalf("StartAuthorization() unexpected error: %v", err)
	}
	otherSession, otherResponse := f.signIn(t, webRequest())
	other, err := ExchangeCode(t.Context(), f.d, fakeSigner{}, f.tenant, f.client(t, "web"),
		codeRequest(otherResponse.Get("code")))
	if err != nil {
		t.Fatalf("ExchangeCode() unexpected error: %v", err)
	}

	params := url.Values{
		"id_token_hint":            {online.IDToken},
		"post_logout_redirect_uri": {"https://app.example.com/signed-out"},
		"state":                    {"af0ifjsldkj"},
	}
	l, err := StartLogout(t.Context(), f.d, fakeSigner{}, f.tenant, params, sessionHash)
	if err != nil || !l.Confirm || l.Account != "ada@example.com" || l.Client.ClientID != "web" || l.Problem != "" ||
		l.ResponseURI() != "https://app.example.com/signed-out?state=af0ifjsldkj" {
		t.Fatalf("StartLogout() = %+v, %v", l, err)
	}
	// StartLogout changes nothing.
	if _, err := f.d.Store.Sessions().GetByTokenHash(t.Context(), f.tenant.ID, sessionHash); err != nil {
		t.Fatalf("the session after StartLogout() = %v, want it to remain", err)
	}

	l, err = CompleteLogout(t.Context(), f.d, fakeSigner{}, f.tenant, params, sessionHash)
	if err != nil || l.ResponseURI() != "https://app.example.com/signed-out?state=af0ifjsldkj" {
		t.Fatalf("CompleteLogout() = %+v, %v", l, err)
	}
	if _, err := f.d.Store.Sessions().GetByTokenHash(t.Context(), f.tenant.ID, sessionHash); !errors.Is(err,
		store.ErrNotFound) {
		t.Errorf("the session after CompleteLogout() = %v, want ErrNotFound", err)
	}
	if _, err := f.d.Store.AuthorizationCodes().Get(t.Context(), f.tenant.ID,
		oauth.HashToken(pending.Response.Params.Get("code"))); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("the pending code after CompleteLogout() = %v, want ErrNotFound", err)
	}
	f.wantRevoked(t, "online access", online.AccessToken)
	for name, at := range map[string]string{"offline access": offline.AccessToken, "another session": other.AccessToken} {
		if _, err := UserInfo(t.Context(), f.d, fakeSigner{}, f.tenant, at); err != nil {
			t.Errorf("%s: UserInfo() after the logout = %v, want the token to work", name, err)
		}
	}
	if _, err := f.refresh(t, f.client(t, "web"), offline.RefreshToken); err != nil {
		t.Errorf("refreshing offline access after the logout = %v, want it to work", err)
	}
	if _, err := f.d.Store.Sessions().GetByTokenHash(t.Context(), f.tenant.ID, otherSession); err != nil {
		t.Errorf("another session after the logout = %v, want it to remain", err)
	}
	for _, want := range []string{"user signed out", "client_id=web", "deleted_authorization_codes=1",
		"revoked_access_tokens=1"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("logs do not contain %q:\n%s", want, logs.String())
		}
	}

	// The browser has no session now: nothing to confirm, and the logout
	// still returns to the client.
	l, err = StartLogout(t.Context(), f.d, fakeSigner{}, f.tenant, params, sessionHash)
	if err != nil || l.Confirm || l.ResponseURI() == "" {
		t.Errorf("StartLogout() after the logout = %+v, %v; want a redirect without confirmation", l, err)
	}
}

func TestLogoutRequests(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	idToken, _ := f.idTokenFor(t, webRequest())
	sign := func(tenantID uuid.UUID, typ string, claims oidc.IDTokenClaims) string {
		t.Helper()
		payload, err := json.Marshal(claims)
		if err != nil {
			t.Fatalf("encoding claims: %v", err)
		}
		token, _ := fakeSigner{}.Sign(t.Context(), tenantID, "RS256", typ, payload)
		return token
	}
	_, _, claims := decode[oidc.IDTokenClaims](t, idToken)
	expired := claims
	expired.Expiry = f.now.Add(-24 * time.Hour).Unix()
	unknownClient := claims
	unknownClient.Audience = "unknown"
	const uri = "https://app.example.com/signed-out"

	for _, tt := range []struct {
		name     string
		params   url.Values
		redirect string
		problem  string
	}{
		{"no parameters", nil, "", ""},
		{"hint only", url.Values{"id_token_hint": {idToken}}, "", ""},
		{"client_id only", url.Values{"client_id": {"web"}}, "", ""},
		{"hint and client_id", url.Values{"id_token_hint": {idToken}, "client_id": {"web"},
			"post_logout_redirect_uri": {uri}}, uri, ""},
		// OpenID Connect RP-Initiated Logout 1.0, section 2: the hint may
		// have expired.
		{"expired hint", url.Values{"id_token_hint": {sign(f.tenant.ID, oidc.IDTokenType, expired)},
			"post_logout_redirect_uri": {uri}}, uri, ""},
		{"redirect without a hint", url.Values{"post_logout_redirect_uri": {uri}, "client_id": {"web"}}, "",
			"post_logout_redirect_uri needs an id_token_hint"},
		{"unregistered redirect", url.Values{"id_token_hint": {idToken},
			"post_logout_redirect_uri": {"https://app.example.com/other"}}, "", "is not registered"},
		{"query added to the redirect", url.Values{"id_token_hint": {idToken},
			"post_logout_redirect_uri": {uri + "?foo=bar"}}, "", "is not registered"},
		{"another client", url.Values{"id_token_hint": {idToken}, "client_id": {"spa"}}, "",
			"client_id is not the client"},
		{"not a token", url.Values{"id_token_hint": {"a.b.c"}}, "", "not an ID token that this provider issued"},
		{"hint of another tenant", url.Values{"id_token_hint": {sign(uuid.NewV7(), oidc.IDTokenType, claims)}}, "",
			"not an ID token that this provider issued"},
		{"access token as a hint", url.Values{"id_token_hint": {sign(f.tenant.ID, oidc.AccessTokenType, claims)}}, "",
			"not an ID token that this provider issued"},
		{"hint for an unknown client", url.Values{"id_token_hint": {sign(f.tenant.ID, oidc.IDTokenType,
			unknownClient)}}, "", "not an ID token that this provider issued"},
		{"repeated state", url.Values{"id_token_hint": {idToken}, "post_logout_redirect_uri": {uri},
			"state": {"a", "b"}}, "", "state is repeated"},
	} {
		l, err := StartLogout(t.Context(), f.d, fakeSigner{}, f.tenant, tt.params, nil)
		switch {
		case err != nil:
			t.Errorf("%s: StartLogout() unexpected error: %v", tt.name, err)
		case l.Confirm || l.RedirectURI != tt.redirect || (tt.problem == "") != (l.Problem == "") ||
			!strings.Contains(l.Problem, tt.problem) || (l.RedirectURI == "" && l.State != ""):
			t.Errorf("%s: StartLogout() = %+v, want redirect %q and problem %q", tt.name, l, tt.redirect, tt.problem)
		}
	}
}
