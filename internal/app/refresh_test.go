package app

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"uuid"

	"clavisid.org/clavis/internal/oauth"
	"clavisid.org/clavis/internal/oidc"
	"clavisid.org/clavis/store"
)

// offlineRequest returns a request of the web client for offline access.
func offlineRequest() url.Values {
	return with(webRequest(), "scope", "openid profile offline_access")
}

// refreshTokenFor exchanges a code for params and returns the token
// response, which must include a refresh token, and the client.
func (f authzFixture) refreshTokenFor(t *testing.T, params url.Values) (TokenResponse, store.Client) {
	t.Helper()
	code, client := f.codeFor(t, params)
	r := codeRequest(code)
	r.RedirectURI = params.Get("redirect_uri")
	resp, err := ExchangeCode(t.Context(), f.d, fakeSigner{}, f.tenant, client, r)
	if err != nil || resp.RefreshToken == "" {
		t.Fatalf("ExchangeCode() = %+v, %v; want a refresh token", resp, err)
	}
	return resp, client
}

// refresh sends a refresh_token token request of client.
func (f authzFixture) refresh(t *testing.T, client store.Client, token string, scopes ...string) (TokenResponse, error) {
	t.Helper()
	return RefreshToken(t.Context(), f.d, fakeSigner{}, f.tenant, client, oauth.TokenRequest{
		GrantType: oauth.GrantTypeRefreshToken, RefreshToken: token, Scopes: scopes,
	})
}

// wantRevoked checks that UserInfo refuses every access token.
func (f authzFixture) wantRevoked(t *testing.T, name string, accessTokens ...string) {
	t.Helper()
	for i, at := range accessTokens {
		if _, err := UserInfo(t.Context(), f.d, fakeSigner{}, f.tenant, at); err == nil {
			t.Errorf("%s: UserInfo() accepted access token %d", name, i)
		}
	}
}

func TestExchangeCodeIssuesRefreshTokens(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	if _, _, err := CreateClient(t.Context(), f.d, f.tenant.ID, ClientSpec{
		ClientID: "online", Type: store.ClientConfidential, SkipConsent: true,
		RedirectURIs: []string{"https://app.example.com/callback"},
		GrantTypes:   []string{oauth.GrantTypeAuthorizationCode},
		Scopes:       []string{"openid", "profile", "offline_access"},
	}); err != nil {
		t.Fatalf("CreateClient() unexpected error: %v", err)
	}
	spa := with(with(webRequest(), "client_id", "spa"), "redirect_uri", "http://127.0.0.1/callback")
	for _, tt := range []struct {
		name    string
		params  url.Values
		refresh bool
		scope   string
	}{
		{"OpenID request with offline_access", offlineRequest(), true, "openid profile offline_access"},
		// OpenID Connect Core 1.0, section 11.
		{"OpenID request without offline_access", webRequest(), false, "openid profile"},
		// ADR 0014: by client policy.
		{"OAuth request", with(spa, "scope", "profile"), true, "profile"},
		{"client without the refresh token grant", with(with(offlineRequest(), "client_id", "online"),
			"redirect_uri", "https://app.example.com/callback"), false, "openid profile"},
	} {
		code, client := f.codeFor(t, tt.params)
		r := codeRequest(code)
		r.RedirectURI = tt.params.Get("redirect_uri")
		resp, err := ExchangeCode(t.Context(), f.d, fakeSigner{}, f.tenant, client, r)
		if err != nil || (resp.RefreshToken != "") != tt.refresh || resp.Scope != tt.scope {
			t.Errorf("%s: ExchangeCode() = %+v, %v; want refresh token %v and scope %q",
				tt.name, resp, err, tt.refresh, tt.scope)
		}
	}
}

func TestOfflineAccessNeedsConsent(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	p, sessionHash := f.loginForConsent(t, partnerRequest())
	f.consent(t, p.Request.ID, sessionHash, true)
	// The grant holds openid and profile; offline access asks again.
	offline := with(partnerRequest(), "scope", "openid profile offline_access")
	a, err := f.startWith(t, offline, sessionHash)
	if err != nil || !a.Consent {
		t.Fatalf("StartAuthorization() for offline access = %+v, %v; want consent", a, err)
	}
	q := f.consent(t, a.RequestID, sessionHash, true)
	r := codeRequest(q.Get("code"))
	r.RedirectURI = "https://partner.example.com/callback"
	resp, err := ExchangeCode(t.Context(), f.d, fakeSigner{}, f.tenant, f.client(t, "partner"), r)
	if err != nil || resp.RefreshToken == "" || resp.Scope != "openid profile offline_access" {
		t.Errorf("ExchangeCode() after consent = %+v, %v; want a refresh token", resp, err)
	}
}

// TestConsentShowsOfflineAccessWhenTheClientGetsIt checks that the consent
// page lists offline access exactly when the client gets a refresh token
// (ADR 0021).
func TestConsentShowsOfflineAccessWhenTheClientGetsIt(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	if _, _, err := CreateClient(t.Context(), f.d, f.tenant.ID, ClientSpec{
		ClientID: "online", Type: store.ClientConfidential,
		RedirectURIs: []string{"https://partner.example.com/callback"},
		GrantTypes:   []string{oauth.GrantTypeAuthorizationCode},
		Scopes:       []string{"openid", "profile", "offline_access"},
	}); err != nil {
		t.Fatalf("CreateClient() unexpected error: %v", err)
	}
	oauthRequest := with(partnerRequest(), "scope", "profile")
	oauthRequest.Del("nonce")
	for _, tt := range []struct {
		name    string
		params  url.Values
		consent []string
		refresh bool
	}{
		// ADR 0014: an OAuth request gets a refresh token by client policy.
		{"OAuth request", oauthRequest, []string{"profile", "offline_access"}, true},
		{"OpenID request with offline_access", with(partnerRequest(), "scope", "offline_access openid"),
			[]string{"offline_access", "openid"}, true},
		{"client without the refresh token grant", with(with(partnerRequest(), "client_id", "online"),
			"scope", "openid offline_access"), []string{"openid"}, false},
	} {
		p, sessionHash := f.loginForConsent(t, tt.params)
		c, err := FindConsent(t.Context(), f.d, f.tenant.ID, p.Request.ID, testBinding, sessionHash)
		if err != nil {
			t.Fatalf("%s: FindConsent() unexpected error: %v", tt.name, err)
		}
		var scopes []string
		for _, s := range c.Scopes {
			scopes = append(scopes, s.Scope)
		}
		if !slices.Equal(scopes, tt.consent) {
			t.Errorf("%s: consent page scopes = %q, want %q", tt.name, scopes, tt.consent)
		}
		q := f.consent(t, p.Request.ID, sessionHash, true)
		r := codeRequest(q.Get("code"))
		r.RedirectURI = "https://partner.example.com/callback"
		resp, err := ExchangeCode(t.Context(), f.d, fakeSigner{}, f.tenant, p.Client, r)
		if err != nil || (resp.RefreshToken != "") != tt.refresh {
			t.Errorf("%s: ExchangeCode() = %+v, %v; want refresh token %v", tt.name, resp, err, tt.refresh)
		}
		if tt.name != "OAuth request" {
			continue
		}
		// The grant records offline access, so the same request needs no
		// consent the next time.
		if g, err := f.partnerGrant(t); err != nil || !slices.Contains(g.Scopes, "offline_access") {
			t.Errorf("grant after an OAuth request = %+v, %v; want offline_access", g, err)
		}
		if a, err := f.startWith(t, oauthRequest, sessionHash); err != nil || a.Response.RedirectURI == "" {
			t.Errorf("StartAuthorization() of the same OAuth request = %+v, %v; want a code", a, err)
		}
	}
}

func TestRefreshToken(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	var logs bytes.Buffer
	f.d.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	authTime := *f.now
	first, client := f.refreshTokenFor(t, with(offlineRequest(), "claims", `{"id_token":{"email":null}}`))
	_, _, firstID := decode[oidc.IDTokenClaims](t, first.IDToken)

	*f.now = f.now.Add(time.Hour)
	second, err := f.refresh(t, client, first.RefreshToken)
	if err != nil {
		t.Fatalf("RefreshToken() unexpected error: %v", err)
	}
	if second.RefreshToken == "" || second.RefreshToken == first.RefreshToken || second.AccessToken == first.AccessToken ||
		second.Scope != "openid profile offline_access" || second.TokenType != "Bearer" {
		t.Errorf("refresh response = %+v", second)
	}
	_, _, at := decode[oidc.AccessTokenClaims](t, second.AccessToken)
	if at.Subject != f.user.ID.String() || at.IssuedAt != f.now.Unix() || at.AuthTime != authTime.Unix() ||
		at.Scope != "openid profile offline_access" {
		t.Errorf("access token claims = %+v", at)
	}
	record, err := f.d.Store.AccessTokens().Get(t.Context(), f.tenant.ID, at.JWTID)
	if err != nil || record.CodeHash == nil {
		t.Errorf("access token record = %+v, %v; want the hash of the code", record, err)
	}
	// OpenID Connect Core 1.0, section 12.2.
	_, _, id := decode[oidc.IDTokenClaims](t, second.IDToken)
	wantHash, _ := oidc.AccessTokenHash("RS256", second.AccessToken)
	if id.Issuer != firstID.Issuer || id.Subject != firstID.Subject || id.Audience != firstID.Audience ||
		id.AuthTime != authTime.Unix() || id.IssuedAt != f.now.Unix() || id.Nonce != "" ||
		id.AccessTokenHash != wantHash || id.ACR != firstID.ACR {
		t.Errorf("ID token claims = %+v, first ID token %+v", id, firstID)
	}
	_, _, idClaims := decode[map[string]any](t, second.IDToken)
	if idClaims["email"] != "ada@example.com" {
		t.Errorf("ID token claims = %v, want the requested email", idClaims)
	}
	if _, err := UserInfo(t.Context(), f.d, fakeSigner{}, f.tenant, second.AccessToken); err != nil {
		t.Errorf("UserInfo() with the new access token = %v", err)
	}
	if !strings.Contains(logs.String(), "grant_type=refresh_token") || strings.Contains(logs.String(), first.RefreshToken) {
		t.Errorf("logs = %s", logs.String())
	}

	// The token can be refreshed again, and the scope can narrow.
	third, err := f.refresh(t, client, second.RefreshToken, "openid")
	if err != nil || third.Scope != "openid" || third.IDToken == "" {
		t.Fatalf("RefreshToken() narrowed to openid = %+v, %v", third, err)
	}
	fourth, err := f.refresh(t, client, third.RefreshToken, "profile")
	if err != nil || fourth.Scope != "profile" || fourth.IDToken != "" {
		t.Fatalf("RefreshToken() without openid = %+v, %v; want no ID token", fourth, err)
	}
	// The family keeps the scope that was granted.
	fifth, err := f.refresh(t, client, fourth.RefreshToken)
	if err != nil || fifth.Scope != "openid profile offline_access" {
		t.Fatalf("RefreshToken() without a scope = %+v, %v", fifth, err)
	}
	_, err = f.refresh(t, client, fifth.RefreshToken, "openid", "email")
	wantOAuthError(t, "a scope that was not granted", err, oauth.ErrorInvalidScope)
	if _, err := f.refresh(t, client, fifth.RefreshToken); err != nil {
		t.Errorf("RefreshToken() after a refused scope = %v, want nil", err)
	}
}

func TestRefreshTokenReuseRevokesTheFamily(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	var logs bytes.Buffer
	f.d.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	first, client := f.refreshTokenFor(t, offlineRequest())
	second, err := f.refresh(t, client, first.RefreshToken)
	if err != nil {
		t.Fatalf("RefreshToken() unexpected error: %v", err)
	}
	// Another family of the same user and client is not affected.
	other, _ := f.refreshTokenFor(t, offlineRequest())

	_, err = f.refresh(t, client, first.RefreshToken)
	wantOAuthError(t, "reused refresh token", err, oauth.ErrorInvalidGrant)
	_, err = f.refresh(t, client, second.RefreshToken)
	wantOAuthError(t, "current token of a revoked family", err, oauth.ErrorInvalidGrant)
	f.wantRevoked(t, "after the reuse", first.AccessToken, second.AccessToken)
	if !strings.Contains(logs.String(), "refresh token reused") || !strings.Contains(logs.String(), "revoked_access_tokens=2") {
		t.Errorf("logs do not report the reuse:\n%s", logs.String())
	}
	if _, err := f.refresh(t, client, other.RefreshToken); err != nil {
		t.Errorf("RefreshToken() of another family = %v, want nil", err)
	}
}

func TestConcurrentRefreshesRevokeTheFamily(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	first, client := f.refreshTokenFor(t, offlineRequest())

	// ADR 0014: no grace period, so a second use of the token is reuse even
	// when it comes at the same moment.
	var wg sync.WaitGroup
	responses := make([]TokenResponse, 8)
	errs := make([]error, len(responses))
	for i := range responses {
		wg.Go(func() { responses[i], errs[i] = f.refresh(t, client, first.RefreshToken) })
	}
	wg.Wait()
	var succeeded []TokenResponse
	for i, err := range errs {
		if err == nil {
			succeeded = append(succeeded, responses[i])
			continue
		}
		wantOAuthError(t, "concurrent refresh", err, oauth.ErrorInvalidGrant)
	}
	if len(succeeded) != 1 {
		t.Fatalf("%d concurrent refreshes succeeded, want 1", len(succeeded))
	}
	_, err := f.refresh(t, client, succeeded[0].RefreshToken)
	wantOAuthError(t, "the token of the refresh that succeeded", err, oauth.ErrorInvalidGrant)
	f.wantRevoked(t, "after concurrent refreshes", first.AccessToken, succeeded[0].AccessToken)
}

func TestRefreshTokenRejectsInvalidRequests(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	first, web := f.refreshTokenFor(t, offlineRequest())
	for name, tt := range map[string]struct {
		client string
		token  string
		code   string
	}{
		"missing token":          {"web", "", oauth.ErrorInvalidRequest},
		"unknown token":          {"web", oauth.NewToken(), oauth.ErrorInvalidGrant},
		"token of another":       {"legacy", first.RefreshToken, oauth.ErrorInvalidGrant},
		"client without grant":   {"service", first.RefreshToken, oauth.ErrorUnauthorizedClient},
		"access token presented": {"web", first.AccessToken, oauth.ErrorInvalidGrant},
	} {
		_, err := f.refresh(t, f.client(t, tt.client), tt.token)
		wantOAuthError(t, name, err, tt.code)
	}
	// Refused requests leave the token usable.
	if _, err := f.refresh(t, web, first.RefreshToken); err != nil {
		t.Errorf("RefreshToken() after refused requests = %v, want nil", err)
	}
}

func TestRefreshTokenLifetimes(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	if _, _, err := CreateClient(t.Context(), f.d, f.tenant.ID, ClientSpec{
		ClientID: "short", Type: store.ClientConfidential, SkipConsent: true,
		RedirectURIs: []string{"https://app.example.com/callback"},
		Lifetimes:    store.TokenLifetimes{RefreshTokenIdle: time.Hour, RefreshTokenAbsolute: 150 * time.Minute},
	}); err != nil {
		t.Fatalf("CreateClient() unexpected error: %v", err)
	}
	start := *f.now

	// The default idle lifetime.
	idle, web := f.refreshTokenFor(t, offlineRequest())
	*f.now = start.Add(DefaultRefreshTokenIdleLifetime)
	_, err := f.refresh(t, web, idle.RefreshToken)
	wantOAuthError(t, "token unused for the idle lifetime", err, oauth.ErrorInvalidGrant)

	// Each refresh extends the idle lifetime, up to the absolute lifetime.
	*f.now = start
	resp, short := f.refreshTokenFor(t, with(offlineRequest(), "client_id", "short"))
	for _, after := range []time.Duration{50 * time.Minute, 100 * time.Minute} {
		*f.now = start.Add(after)
		if resp, err = f.refresh(t, short, resp.RefreshToken); err != nil {
			t.Fatalf("RefreshToken() after %v unexpected error: %v", after, err)
		}
	}
	_, family, err := f.d.Store.RefreshTokens().Get(t.Context(), f.tenant.ID, oauth.HashToken(resp.RefreshToken))
	if err != nil || !family.IdleExpiresAt.Equal(start.Add(150*time.Minute)) {
		t.Errorf("family idle expiry = %v, %v; want the absolute expiry %v", family.IdleExpiresAt, err,
			start.Add(150*time.Minute))
	}
	*f.now = start.Add(150 * time.Minute)
	_, err = f.refresh(t, short, resp.RefreshToken)
	wantOAuthError(t, "token past the absolute lifetime", err, oauth.ErrorInvalidGrant)
}

// disabledUserStore reports every user as disabled.
type disabledUserStore struct{ store.Store }

func (s disabledUserStore) Users() store.Users { return disabledUsers{s.Store.Users()} }

type disabledUsers struct{ store.Users }

func (u disabledUsers) Get(ctx context.Context, tenantID, id uuid.UUID) (store.User, error) {
	user, err := u.Users.Get(ctx, tenantID, id)
	user.Status = store.UserDisabled
	return user, err
}

func TestRefreshTokenNeedsAnActiveUser(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	resp, client := f.refreshTokenFor(t, offlineRequest())
	disabled := f
	disabled.d.Store = disabledUserStore{f.d.Store}
	_, err := disabled.refresh(t, client, resp.RefreshToken)
	wantOAuthError(t, "disabled user", err, oauth.ErrorInvalidGrant)

	if err := DeleteUser(t.Context(), f.d, f.tenant.ID, "ada@example.com"); err != nil {
		t.Fatalf("DeleteUser() unexpected error: %v", err)
	}
	_, err = f.refresh(t, client, resp.RefreshToken)
	wantOAuthError(t, "deleted user", err, oauth.ErrorInvalidGrant)
}

func TestCodeReplayRevokesRefreshTokens(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	code, client := f.codeFor(t, offlineRequest())
	first, err := ExchangeCode(t.Context(), f.d, fakeSigner{}, f.tenant, client, codeRequest(code))
	if err != nil || first.RefreshToken == "" {
		t.Fatalf("ExchangeCode() = %+v, %v; want a refresh token", first, err)
	}
	second, err := f.refresh(t, client, first.RefreshToken)
	if err != nil {
		t.Fatalf("RefreshToken() unexpected error: %v", err)
	}
	// RFC 6749, section 4.1.2: the tokens issued from the code include the
	// refreshed ones.
	_, err = ExchangeCode(t.Context(), f.d, fakeSigner{}, f.tenant, client, codeRequest(code))
	wantOAuthError(t, "replayed code", err, oauth.ErrorInvalidGrant)
	_, err = f.refresh(t, client, second.RefreshToken)
	wantOAuthError(t, "refresh token of a replayed code", err, oauth.ErrorInvalidGrant)
	f.wantRevoked(t, "after the code replay", first.AccessToken, second.AccessToken)
}

func TestRevokeGrantRevokesRefreshTokens(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	var logs bytes.Buffer
	f.d.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	p, sessionHash := f.loginForConsent(t, with(partnerRequest(), "scope", "openid offline_access"))
	q := f.consent(t, p.Request.ID, sessionHash, true)
	r := codeRequest(q.Get("code"))
	r.RedirectURI = "https://partner.example.com/callback"
	partner := f.client(t, "partner")
	resp, err := ExchangeCode(t.Context(), f.d, fakeSigner{}, f.tenant, partner, r)
	if err != nil || resp.RefreshToken == "" {
		t.Fatalf("ExchangeCode() = %+v, %v; want a refresh token", resp, err)
	}
	if err := RevokeGrant(t.Context(), f.d, f.tenant.ID, "ada@example.com", "partner"); err != nil {
		t.Fatalf("RevokeGrant() unexpected error: %v", err)
	}
	_, err = f.refresh(t, partner, resp.RefreshToken)
	wantOAuthError(t, "refresh token of a revoked grant", err, oauth.ErrorInvalidGrant)
	if !strings.Contains(logs.String(), "revoked_refresh_token_families=1") {
		t.Errorf("logs do not report the revoked family:\n%s", logs.String())
	}
}

func TestPurgeExpiredDeletesRefreshTokens(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	var logs bytes.Buffer
	f.d.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	resp, _ := f.refreshTokenFor(t, offlineRequest())
	hash := oauth.HashToken(resp.RefreshToken)
	*f.now = f.now.Add(DefaultRefreshTokenIdleLifetime - time.Second)
	if err := PurgeExpired(t.Context(), f.d); err != nil {
		t.Fatalf("PurgeExpired() unexpected error: %v", err)
	}
	if _, _, err := f.d.Store.RefreshTokens().Get(t.Context(), f.tenant.ID, hash); err != nil {
		t.Errorf("a refresh token that has not expired = %v, want it kept", err)
	}
	*f.now = f.now.Add(time.Second)
	if err := PurgeExpired(t.Context(), f.d); err != nil {
		t.Fatalf("PurgeExpired() unexpected error: %v", err)
	}
	if _, _, err := f.d.Store.RefreshTokens().Get(t.Context(), f.tenant.ID, hash); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("the expired refresh token = %v, want it deleted", err)
	}
	if !strings.Contains(logs.String(), "refresh_token_families=1") {
		t.Errorf("logs do not report the deleted family:\n%s", logs.String())
	}
}

// racingStore runs race once, right after the first successful rotation of
// a refresh token, redemption of a code or revocation of access tokens by
// user and client: the moment when a concurrent request can interleave.
type racingStore struct {
	store.Store
	race func()
	once *sync.Once
}

func newRacingStore(s store.Store, race func()) racingStore {
	return racingStore{Store: s, race: race, once: &sync.Once{}}
}

func (s racingStore) RefreshTokens() store.RefreshTokens {
	return racingRefreshTokens{s.Store.RefreshTokens(), s}
}

func (s racingStore) AuthorizationCodes() store.AuthorizationCodes {
	return racingCodes{s.Store.AuthorizationCodes(), s}
}

func (s racingStore) AccessTokens() store.AccessTokens {
	return racingAccessTokens{s.Store.AccessTokens(), s}
}

type racingRefreshTokens struct {
	store.RefreshTokens
	s racingStore
}

func (r racingRefreshTokens) Rotate(ctx context.Context, tenantID uuid.UUID, hash []byte, next store.RefreshToken) error {
	err := r.RefreshTokens.Rotate(ctx, tenantID, hash, next)
	if err == nil {
		r.s.once.Do(r.s.race)
	}
	return err
}

type racingCodes struct {
	store.AuthorizationCodes
	s racingStore
}

func (c racingCodes) Redeem(ctx context.Context, tenantID uuid.UUID, hash []byte, at time.Time) error {
	err := c.AuthorizationCodes.Redeem(ctx, tenantID, hash, at)
	if err == nil {
		c.s.once.Do(c.s.race)
	}
	return err
}

type racingAccessTokens struct {
	store.AccessTokens
	s racingStore
}

func (a racingAccessTokens) RevokeByUserAndClient(ctx context.Context, tenantID, userID, clientID uuid.UUID,
	at time.Time,
) (int64, error) {
	n, err := a.AccessTokens.RevokeByUserAndClient(ctx, tenantID, userID, clientID, at)
	if err == nil {
		a.s.once.Do(a.s.race)
	}
	return n, err
}

// TestReuseRightAfterARotation presents a refresh token again between its
// rotation and the response: the refresh that rotated it must not deliver
// usable tokens (ADR 0021).
func TestReuseRightAfterARotation(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	first, client := f.refreshTokenFor(t, offlineRequest())
	racing := f
	racing.d.Store = newRacingStore(f.d.Store, func() {
		_, err := f.refresh(t, client, first.RefreshToken)
		wantOAuthError(t, "the token presented again", err, oauth.ErrorInvalidGrant)
	})
	resp, err := racing.refresh(t, client, first.RefreshToken)
	if err != nil {
		t.Fatalf("RefreshToken() unexpected error: %v", err)
	}
	_, err = f.refresh(t, client, resp.RefreshToken)
	wantOAuthError(t, "the new token", err, oauth.ErrorInvalidGrant)
	f.wantRevoked(t, "after the reuse", resp.AccessToken)
}

// TestCodeReplayRightAfterARedemption replays a code between its redemption
// and the response: the exchange that redeemed it must not deliver usable
// tokens (ADR 0021).
func TestCodeReplayRightAfterARedemption(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	code, client := f.codeFor(t, offlineRequest())
	racing := f
	racing.d.Store = newRacingStore(f.d.Store, func() {
		_, err := ExchangeCode(t.Context(), f.d, fakeSigner{}, f.tenant, client, codeRequest(code))
		wantOAuthError(t, "the replayed code", err, oauth.ErrorInvalidGrant)
	})
	resp, err := ExchangeCode(t.Context(), racing.d, fakeSigner{}, f.tenant, client, codeRequest(code))
	if err != nil || resp.RefreshToken == "" {
		t.Fatalf("ExchangeCode() = %+v, %v; want a refresh token", resp, err)
	}
	_, err = f.refresh(t, client, resp.RefreshToken)
	wantOAuthError(t, "the refresh token", err, oauth.ErrorInvalidGrant)
	f.wantRevoked(t, "after the replay", resp.AccessToken)
}

// TestRefreshDuringRevokeGrant refreshes between the steps of RevokeGrant: the
// refresh must fail or deliver tokens that end up revoked (ADR 0021).
func TestRefreshDuringRevokeGrant(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	p, sessionHash := f.loginForConsent(t, with(partnerRequest(), "scope", "openid offline_access"))
	q := f.consent(t, p.Request.ID, sessionHash, true)
	r := codeRequest(q.Get("code"))
	r.RedirectURI = "https://partner.example.com/callback"
	partner := f.client(t, "partner")
	first, err := ExchangeCode(t.Context(), f.d, fakeSigner{}, f.tenant, partner, r)
	if err != nil {
		t.Fatalf("ExchangeCode() unexpected error: %v", err)
	}
	var during TokenResponse
	racing := f
	racing.d.Store = newRacingStore(f.d.Store, func() { during, _ = f.refresh(t, partner, first.RefreshToken) })
	if err := RevokeGrant(t.Context(), racing.d, f.tenant.ID, "ada@example.com", "partner"); err != nil {
		t.Fatalf("RevokeGrant() unexpected error: %v", err)
	}
	f.wantRevoked(t, "after the revocation", first.AccessToken)
	if during.AccessToken != "" {
		f.wantRevoked(t, "the refresh during the revocation", during.AccessToken)
	}
}
