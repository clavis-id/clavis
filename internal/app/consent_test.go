package app

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
	"uuid"

	"clavisid.org/clavis/internal/oauth"
	"clavisid.org/clavis/store"
)

// partnerRequest returns a valid authorization request of the partner
// client, which asks for consent.
func partnerRequest() url.Values {
	params := webRequest()
	params.Set("client_id", "partner")
	params.Set("redirect_uri", "https://partner.example.com/callback")
	return params
}

// loginForConsent signs ada in for params and returns the request, which
// waits for consent, and the hash of the new session cookie.
func (f authzFixture) loginForConsent(t *testing.T, params url.Values) (p PendingAuthorization, sessionHash []byte) {
	t.Helper()
	p = f.start(t, params)
	login, err := CompletePasswordLogin(t.Context(), f.d, f.h, f.tenant, p, "ada@example.com", "correct horse", nil)
	if err != nil {
		t.Fatalf("CompletePasswordLogin() unexpected error: %v", err)
	}
	if !login.Consent || login.RedirectURI != "" || login.SessionToken == "" {
		t.Fatalf("CompletePasswordLogin() = %+v, want a session and a request that waits for consent", login)
	}
	return p, oauth.HashToken(login.SessionToken)
}

// consent finds the consent of request id and answers it.
func (f authzFixture) consent(t *testing.T, id string, sessionHash []byte, allow bool) url.Values {
	t.Helper()
	c, err := FindConsent(t.Context(), f.d, f.tenant.ID, id, testBinding, sessionHash)
	if err != nil {
		t.Fatalf("FindConsent() unexpected error: %v", err)
	}
	uri, err := CompleteConsent(t.Context(), f.d, f.tenant, c, allow)
	if err != nil {
		t.Fatalf("CompleteConsent() unexpected error: %v", err)
	}
	u, err := url.Parse(uri)
	if err != nil || !strings.HasPrefix(uri, "https://partner.example.com/callback?") {
		t.Fatalf("CompleteConsent() = %q, want a response to the partner client", uri)
	}
	return u.Query()
}

// partnerGrant returns the grant of ada for the partner client.
func (f authzFixture) partnerGrant(t *testing.T) (store.Grant, error) {
	t.Helper()
	return f.d.Store.Grants().Get(t.Context(), f.tenant.ID, f.user.ID, f.client(t, "partner").ID)
}

func TestConsentAfterSignIn(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	var logs bytes.Buffer
	f.d.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	p, sessionHash := f.loginForConsent(t, partnerRequest())

	c, err := FindConsent(t.Context(), f.d, f.tenant.ID, p.Request.ID, testBinding, sessionHash)
	if err != nil {
		t.Fatalf("FindConsent() unexpected error: %v", err)
	}
	if c.User.ID != f.user.ID || c.Client.ClientID != "partner" || c.Session.UserID != f.user.ID ||
		!slices.Equal(c.Scopes, []ConsentScope{{Scope: "openid"}, {Scope: "profile"}}) {
		t.Errorf("FindConsent() = %+v", c)
	}
	q := f.consent(t, p.Request.ID, sessionHash, true)
	if q.Get("code") == "" || q.Get("state") != "af0ifjsldkj" || q.Get("iss") != testIssuer {
		t.Errorf("authorization response = %v", q)
	}
	code, err := f.d.Store.AuthorizationCodes().Get(t.Context(), f.tenant.ID, oauth.HashToken(q.Get("code")))
	if err != nil || code.SessionID != c.Session.ID || code.UserID != f.user.ID || !slices.Equal(code.Scopes, []string{"openid", "profile"}) {
		t.Errorf("issued code = %+v, %v", code, err)
	}
	g, err := f.partnerGrant(t)
	if err != nil || !slices.Equal(g.Scopes, []string{"openid", "profile"}) || !g.CreatedAt.Equal(*f.now) {
		t.Errorf("grant = %+v, %v", g, err)
	}
	if !strings.Contains(logs.String(), "user allowed a client") {
		t.Errorf("logs do not report the consent:\n%s", logs.String())
	}

	// The grant answers the next request from the session at once.
	if a, err := f.startWith(t, partnerRequest(), sessionHash); err != nil || a.RedirectURI == "" || a.Consent {
		t.Errorf("StartAuthorization() with a grant = %+v, %v; want an authorization response", a, err)
	}
	// The request is single use.
	if _, err := FindConsent(t.Context(), f.d, f.tenant.ID, p.Request.ID, testBinding, sessionHash); !errors.Is(err, ErrAuthorizationRequestNotFound) {
		t.Errorf("FindConsent() after the decision = %v, want ErrAuthorizationRequestNotFound", err)
	}
	if _, err := CompleteConsent(t.Context(), f.d, f.tenant, c, true); !errors.Is(err, ErrAuthorizationRequestNotFound) {
		t.Errorf("a second CompleteConsent() = %v, want ErrAuthorizationRequestNotFound", err)
	}
}

func TestConsentForNewScopes(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	p, sessionHash := f.loginForConsent(t, with(partnerRequest(), "scope", "openid"))
	f.consent(t, p.Request.ID, sessionHash, true)

	// A request for a scope beyond the grant asks again, for the whole
	// request, and the grant gains the new scope. A claim requested
	// individually counts as the scope that carries it.
	params := with(partnerRequest(), "scope", "openid profile")
	params.Set("claims", `{"userinfo":{"email":null}}`)
	a, err := f.startWith(t, params, sessionHash)
	if err != nil || !a.Consent || a.RequestID == "" {
		t.Fatalf("StartAuthorization() with a new scope = %+v, %v; want a request that waits for consent", a, err)
	}
	c, err := FindConsent(t.Context(), f.d, f.tenant.ID, a.RequestID, testBinding, sessionHash)
	if err != nil || !slices.Equal(c.Scopes, []ConsentScope{{Scope: "openid"}, {Scope: "profile"}, {Scope: "email"}}) {
		t.Fatalf("FindConsent() = %+v, %v", c.Scopes, err)
	}
	f.consent(t, a.RequestID, sessionHash, true)
	if g, err := f.partnerGrant(t); err != nil || !slices.Equal(g.Scopes, []string{"openid", "profile", "email"}) {
		t.Errorf("grant = %+v, %v; want the scopes of both requests", g, err)
	}

	// A request for fewer scopes than the grant needs no consent.
	if a, err := f.startWith(t, with(partnerRequest(), "scope", "openid email"), sessionHash); err != nil || a.RedirectURI == "" {
		t.Errorf("StartAuthorization() within the grant = %+v, %v; want an authorization response", a, err)
	}
}

func TestConsentDenied(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	p, sessionHash := f.loginForConsent(t, partnerRequest())
	q := f.consent(t, p.Request.ID, sessionHash, false)
	if q.Get("error") != oauth.ErrorAccessDenied || q.Has("code") || q.Get("state") != "af0ifjsldkj" ||
		q.Get("iss") != testIssuer {
		t.Errorf("authorization response = %v, want access_denied", q)
	}
	if _, err := f.partnerGrant(t); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("grant after a denial = %v, want none", err)
	}
	// The session stays, and the next request asks again.
	if a, err := f.startWith(t, partnerRequest(), sessionHash); err != nil || !a.Consent {
		t.Errorf("StartAuthorization() after a denial = %+v, %v; want consent", a, err)
	}
}

func TestPromptConsent(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	p, sessionHash := f.loginForConsent(t, partnerRequest())
	f.consent(t, p.Request.ID, sessionHash, true)

	// prompt=consent asks even with a grant, and even for a client that
	// skips consent, without a new sign-in.
	for _, params := range []url.Values{with(partnerRequest(), "prompt", "consent"), with(webRequest(), "prompt", "consent")} {
		a, err := f.startWith(t, params, sessionHash)
		if err != nil || !a.Consent {
			t.Errorf("StartAuthorization() of %s with prompt=consent = %+v, %v; want consent", params.Get("client_id"), a, err)
			continue
		}
		if _, err := FindConsent(t.Context(), f.d, f.tenant.ID, a.RequestID, testBinding, sessionHash); err != nil {
			t.Errorf("FindConsent() of %s unexpected error: %v", params.Get("client_id"), err)
		}
	}
	// Without a session, the user signs in first.
	p = f.start(t, with(webRequest(), "prompt", "consent"))
	login, err := CompletePasswordLogin(t.Context(), f.d, f.h, f.tenant, p, "ada@example.com", "correct horse", nil)
	if err != nil || !login.Consent {
		t.Errorf("CompletePasswordLogin() with prompt=consent = %+v, %v; want consent", login, err)
	}
}

func TestPromptNoneNeedsConsent(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	sessionHash, _ := f.signIn(t, webRequest())
	params := with(partnerRequest(), "prompt", "none")
	_, err := f.startWith(t, params, sessionHash)
	var redirect *RedirectError
	if !errors.As(err, &redirect) || redirect.Err.Code != oauth.ErrorConsentRequired ||
		!strings.HasPrefix(redirect.URI, "https://partner.example.com/callback?") {
		t.Fatalf("StartAuthorization() with prompt=none and no grant = %v, want consent_required", err)
	}
	a, err := f.startWith(t, partnerRequest(), sessionHash)
	if err != nil || !a.Consent {
		t.Fatalf("StartAuthorization() = %+v, %v; want consent", a, err)
	}
	f.consent(t, a.RequestID, sessionHash, true)
	if a, err := f.startWith(t, params, sessionHash); err != nil || a.RedirectURI == "" {
		t.Errorf("StartAuthorization() with prompt=none and a grant = %+v, %v; want a response", a, err)
	}
}

func TestFindConsentChecksTheBrowserAndSession(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	p, sessionHash := f.loginForConsent(t, partnerRequest())
	id := p.Request.ID

	// Another sign-in on the same browser replaces the session that
	// authenticated the request.
	other, err := CompletePasswordLogin(t.Context(), f.d, f.h, f.tenant, f.start(t, webRequest()), "ada@example.com",
		"correct horse", nil)
	if err != nil {
		t.Fatalf("CompletePasswordLogin() unexpected error: %v", err)
	}
	pending := f.start(t, webRequest())
	for name, tt := range map[string]struct {
		id               string
		binding, session []byte
	}{
		"another browser":       {id, oauth.HashToken("attacker"), sessionHash},
		"no session cookie":     {id, testBinding, nil},
		"another session":       {id, testBinding, oauth.HashToken(other.SessionToken)},
		"unknown session":       {id, testBinding, oauth.HashToken("unknown")},
		"a request for sign-in": {pending.Request.ID, testBinding, sessionHash},
	} {
		if _, err := FindConsent(t.Context(), f.d, f.tenant.ID, tt.id, tt.binding, tt.session); !errors.Is(err, ErrAuthorizationRequestNotFound) {
			t.Errorf("%s: FindConsent() = %v, want ErrAuthorizationRequestNotFound", name, err)
		}
	}

	// A request that waits for consent takes no second sign-in.
	if _, err := CompletePasswordLogin(t.Context(), f.d, f.h, f.tenant, p, "ada@example.com", "correct horse", nil); !errors.Is(err, ErrAuthorizationRequestNotFound) {
		t.Errorf("CompletePasswordLogin() of a request that waits for consent = %v, want ErrAuthorizationRequestNotFound", err)
	}

	// The session must still be valid.
	*f.now = f.now.Add(SessionIdleTimeout)
	if _, err := FindConsent(t.Context(), f.d, f.tenant.ID, id, testBinding, sessionHash); !errors.Is(err, ErrAuthorizationRequestNotFound) {
		t.Errorf("FindConsent() with an idle session = %v, want ErrAuthorizationRequestNotFound", err)
	}
}

func TestFindConsentRefusesDisabledUsers(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	p := f.start(t, partnerRequest())
	grace := f.user
	grace.ID, grace.Email, grace.Status = f.d.NewID(), "grace@example.com", store.UserDisabled
	if err := f.d.Store.Users().Create(t.Context(), grace); err != nil {
		t.Fatalf("creating a disabled user: %v", err)
	}
	token := oauth.NewToken()
	s := store.Session{ID: f.d.NewID(), TenantID: f.tenant.ID, TokenHash: oauth.HashToken(token), UserID: grace.ID,
		AuthTime: *f.now, CreatedAt: *f.now, LastSeenAt: *f.now, IdleExpiresAt: f.now.Add(time.Hour),
		ExpiresAt: f.now.Add(time.Hour)}
	if err := f.d.Store.Sessions().Create(t.Context(), s); err != nil {
		t.Fatalf("creating a session: %v", err)
	}
	if err := f.d.Store.AuthorizationRequests().SetSession(t.Context(), f.tenant.ID, p.Request.ID, s.ID); err != nil {
		t.Fatalf("SetSession() unexpected error: %v", err)
	}
	if _, err := FindConsent(t.Context(), f.d, f.tenant.ID, p.Request.ID, testBinding, s.TokenHash); !errors.Is(err, ErrAuthorizationRequestNotFound) {
		t.Errorf("FindConsent() for a disabled user = %v, want ErrAuthorizationRequestNotFound", err)
	}
}

func TestConsentScopesNameTheirResource(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	if _, err := CreateAPIResource(t.Context(), f.d, f.tenant.ID, APIResourceSpec{
		Identifier: "https://api.example.com/orders", Name: "Orders", Scopes: []string{"orders:read"},
	}); err != nil {
		t.Fatalf("CreateAPIResource() unexpected error: %v", err)
	}
	if _, _, err := CreateClient(t.Context(), f.d, f.tenant.ID, ClientSpec{
		ClientID: "shop", Type: store.ClientConfidential, RedirectURIs: []string{"https://partner.example.com/callback"},
		Scopes: []string{"openid", "orders:read"},
	}); err != nil {
		t.Fatalf("CreateClient() unexpected error: %v", err)
	}
	p, sessionHash := f.loginForConsent(t, with(with(partnerRequest(), "client_id", "shop"), "scope", "openid orders:read"))
	c, err := FindConsent(t.Context(), f.d, f.tenant.ID, p.Request.ID, testBinding, sessionHash)
	if err != nil || !slices.Equal(c.Scopes, []ConsentScope{{Scope: "openid"}, {Scope: "orders:read", Resource: "Orders"}}) {
		t.Errorf("FindConsent() scopes = %+v, %v", c.Scopes, err)
	}
}

func TestRevokeGrant(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	var logs bytes.Buffer
	f.d.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	p, sessionHash := f.loginForConsent(t, partnerRequest())
	q := f.consent(t, p.Request.ID, sessionHash, true)
	r := codeRequest(q.Get("code"))
	r.RedirectURI = "https://partner.example.com/callback"
	resp, err := ExchangeCode(t.Context(), f.d, fakeSigner{}, f.tenant, f.client(t, "partner"), r)
	if err != nil {
		t.Fatalf("ExchangeCode() unexpected error: %v", err)
	}

	grants, err := ListGrants(t.Context(), f.d, f.tenant.ID, "Ada@Example.com")
	if err != nil || len(grants) != 1 || grants[0].Client.ClientID != "partner" ||
		!slices.Equal(grants[0].Scopes, []string{"openid", "profile"}) {
		t.Fatalf("ListGrants() = %+v, %v", grants, err)
	}
	if err := RevokeGrant(t.Context(), f.d, f.tenant.ID, "ada@example.com", "partner"); err != nil {
		t.Fatalf("RevokeGrant() unexpected error: %v", err)
	}
	if _, err := UserInfo(t.Context(), f.d, fakeSigner{}, f.tenant, resp.AccessToken); err == nil {
		t.Error("UserInfo() accepted an access token of a revoked grant")
	}
	if !strings.Contains(logs.String(), "revoked grant") || !strings.Contains(logs.String(), "revoked_access_tokens=1") {
		t.Errorf("logs do not report the revocation:\n%s", logs.String())
	}
	if grants, err := ListGrants(t.Context(), f.d, f.tenant.ID, "ada@example.com"); err != nil || len(grants) != 0 {
		t.Errorf("ListGrants() after RevokeGrant() = %+v, %v; want none", grants, err)
	}
	// The next request asks again.
	if a, err := f.startWith(t, partnerRequest(), sessionHash); err != nil || !a.Consent {
		t.Errorf("StartAuthorization() after RevokeGrant() = %+v, %v; want consent", a, err)
	}

	for name, tt := range map[string]struct {
		email, clientID string
		want            error
	}{
		"no grant":       {"ada@example.com", "partner", ErrGrantNotFound},
		"unknown user":   {"grace@example.com", "partner", ErrUserNotFound},
		"unknown client": {"ada@example.com", "nobody", ErrClientNotFound},
	} {
		if err := RevokeGrant(t.Context(), f.d, f.tenant.ID, tt.email, tt.clientID); !errors.Is(err, tt.want) {
			t.Errorf("%s: RevokeGrant() = %v, want %v", name, err, tt.want)
		}
	}
	if _, err := ListGrants(t.Context(), f.d, f.tenant.ID, "grace@example.com"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("ListGrants() of an unknown user = %v, want ErrUserNotFound", err)
	}
}

func TestRevokeGrantStopsIssuedCodes(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	var logs bytes.Buffer
	f.d.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	p, sessionHash := f.loginForConsent(t, partnerRequest())
	q := f.consent(t, p.Request.ID, sessionHash, true)
	if err := RevokeGrant(t.Context(), f.d, f.tenant.ID, "ada@example.com", "partner"); err != nil {
		t.Fatalf("RevokeGrant() unexpected error: %v", err)
	}
	// A code issued before the revocation yields no tokens after it.
	r := codeRequest(q.Get("code"))
	r.RedirectURI = "https://partner.example.com/callback"
	_, err := ExchangeCode(t.Context(), f.d, fakeSigner{}, f.tenant, f.client(t, "partner"), r)
	wantOAuthError(t, "code of a revoked grant", err, oauth.ErrorInvalidGrant)
	if !strings.Contains(logs.String(), "deleted_authorization_codes=1") {
		t.Errorf("logs do not report the deleted code:\n%s", logs.String())
	}
}

// failingGrantStore fails to read or write grants.
type failingGrantStore struct{ store.Store }

func (f failingGrantStore) Grants() store.Grants { return failingGrants{f.Store.Grants()} }

type failingGrants struct{ store.Grants }

func (failingGrants) Get(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (store.Grant, error) {
	return store.Grant{}, errUnavailable
}

func (failingGrants) Put(context.Context, store.Grant) error { return errUnavailable }

func TestConsentReportsStoreFailures(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	p, sessionHash := f.loginForConsent(t, partnerRequest())
	c, err := FindConsent(t.Context(), f.d, f.tenant.ID, p.Request.ID, testBinding, sessionHash)
	if err != nil {
		t.Fatalf("FindConsent() unexpected error: %v", err)
	}
	pending := f.start(t, partnerRequest())
	f.d.Store = failingGrantStore{f.d.Store}
	var redirect *RedirectError
	if _, err := f.startWith(t, partnerRequest(), sessionHash); !errors.Is(err, errUnavailable) || errors.As(err, &redirect) {
		t.Errorf("StartAuthorization() = %v, want the store error", err)
	}
	if _, err := CompletePasswordLogin(t.Context(), f.d, f.h, f.tenant, pending, "ada@example.com", "correct horse", nil); !errors.Is(err, errUnavailable) {
		t.Errorf("CompletePasswordLogin() = %v, want the store error", err)
	}
	if _, err := CompleteConsent(t.Context(), f.d, f.tenant, c, true); !errors.Is(err, errUnavailable) {
		t.Errorf("CompleteConsent() = %v, want the store error", err)
	}
}
