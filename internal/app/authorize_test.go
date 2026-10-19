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

	"clavisid.org/clavis/internal/oauth"
	"clavisid.org/clavis/store"
)

// testChallenge is a valid S256 code challenge (RFC 7636, appendix B).
const testChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

const testIssuer = "https://auth.example.com/t/acme"

// authzFixture is a tenant with clients, a user whose password is
// "correct horse", and a clock that tests can move.
type authzFixture struct {
	d      Deps
	h      *fakeHasher
	tenant AuthorizationTenant
	user   store.User
	now    *time.Time
}

func newAuthzFixture(t *testing.T) authzFixture {
	t.Helper()
	f := authzFixture{h: &fakeHasher{}}
	d := newDeps(t, openStore(t))
	now := d.Now()
	f.now = &now
	d.Now = func() time.Time { return *f.now }
	f.d = d
	tn := newTenantForClients(t, d)
	f.tenant = AuthorizationTenant{ID: tn.ID, Issuer: testIssuer}
	// The clients skip consent, which only the tests of consent need; the
	// partner client asks for it (ADR 0020).
	for _, spec := range []ClientSpec{
		{ClientID: "web", Name: "Web app", Type: store.ClientConfidential, SkipConsent: true,
			RedirectURIs:           []string{"https://app.example.com/callback", "https://app.example.com/other?x=1"},
			PostLogoutRedirectURIs: []string{"https://app.example.com/signed-out"}},
		{ClientID: "spa", Type: store.ClientPublic, SkipConsent: true, RedirectURIs: []string{"http://127.0.0.1/callback"}},
		{ClientID: "legacy", Type: store.ClientConfidential, PKCEExempt: true, SkipConsent: true,
			RedirectURIs: []string{"https://legacy.example.com/callback"}},
		{ClientID: "partner", Name: "Partner app", Type: store.ClientConfidential,
			RedirectURIs: []string{"https://partner.example.com/callback"}},
		{ClientID: "service", Type: store.ClientConfidential, GrantTypes: []string{oauth.GrantTypeClientCredentials},
			Scopes: []string{"api:read"}},
	} {
		if _, _, err := CreateClient(t.Context(), d, tn.ID, spec); err != nil {
			t.Fatalf("CreateClient(%s) unexpected error: %v", spec.ClientID, err)
		}
	}
	u, err := CreateUser(t.Context(), d, tn.ID, UserSpec{Email: "ada@example.com"})
	if err != nil {
		t.Fatalf("CreateUser() unexpected error: %v", err)
	}
	if err := SetPassword(t.Context(), d, f.h, u, "correct horse"); err != nil {
		t.Fatalf("SetPassword() unexpected error: %v", err)
	}
	f.user = u
	return f
}

// webRequest returns a valid authorization request of the web client.
func webRequest() url.Values {
	return url.Values{
		"response_type":         {"code"},
		"client_id":             {"web"},
		"redirect_uri":          {"https://app.example.com/callback"},
		"scope":                 {"openid profile"},
		"state":                 {"af0ifjsldkj"},
		"nonce":                 {"n-0S6_WzA2Mj"},
		"code_challenge":        {testChallenge},
		"code_challenge_method": {"S256"},
	}
}

var testBinding = oauth.HashToken("browser")

func (f authzFixture) start(t *testing.T, params url.Values) PendingAuthorization {
	t.Helper()
	a, err := StartAuthorization(t.Context(), f.d, fakeSigner{}, f.tenant, params, testBinding, nil)
	if err != nil || a.RequestID == "" || a.Response.RedirectURI != "" {
		t.Fatalf("StartAuthorization() = %+v, %v; want a stored request", a, err)
	}
	p, err := FindAuthorizationRequest(t.Context(), f.d, f.tenant.ID, a.RequestID, testBinding)
	if err != nil {
		t.Fatalf("FindAuthorizationRequest() unexpected error: %v", err)
	}
	return p
}

func TestStartAuthorizationStoresTheRequest(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	p := f.start(t, webRequest())
	r := p.Request
	if p.Client.ClientID != "web" || r.ClientID != p.Client.ID || r.TenantID != f.tenant.ID ||
		r.RedirectURI != "https://app.example.com/callback" || !r.RedirectURIProvided ||
		!slices.Equal(r.Scopes, []string{"openid", "profile"}) || r.State != "af0ifjsldkj" ||
		r.Nonce != "n-0S6_WzA2Mj" || r.CodeChallenge != testChallenge || r.CodeChallengeMethod != "S256" ||
		!bytes.Equal(r.BindingHash, testBinding) || !r.CreatedAt.Equal(*f.now) ||
		!r.ExpiresAt.Equal(f.now.Add(AuthorizationRequestLifetime)) || !oauth.ValidRequestID(r.ID) {
		t.Errorf("stored request = %+v", r)
	}
}

func TestStartAuthorizationAcceptedVariants(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	tests := []struct {
		name  string
		edit  func(url.Values)
		check func(store.AuthorizationRequest) bool
	}{
		{"public client on a loopback port", func(p url.Values) {
			p.Set("client_id", "spa")
			p.Set("redirect_uri", "http://127.0.0.1:51004/callback")
		}, func(r store.AuthorizationRequest) bool { return r.RedirectURI == "http://127.0.0.1:51004/callback" }},
		{"exempt client without PKCE", func(p url.Values) {
			p.Set("client_id", "legacy")
			p.Set("redirect_uri", "https://legacy.example.com/callback")
			p.Del("code_challenge")
			p.Del("code_challenge_method")
		}, func(r store.AuthorizationRequest) bool { return r.CodeChallenge == "" && r.CodeChallengeMethod == "" }},
		{"OAuth request without redirect_uri", func(p url.Values) {
			p.Set("client_id", "spa")
			p.Del("redirect_uri")
			p.Set("scope", "profile")
		}, func(r store.AuthorizationRequest) bool {
			return r.RedirectURI == "http://127.0.0.1/callback" && !r.RedirectURIProvided
		}},
	}
	for _, tt := range tests {
		params := webRequest()
		tt.edit(params)
		a, err := StartAuthorization(t.Context(), f.d, fakeSigner{}, f.tenant, params, testBinding, nil)
		if err != nil {
			t.Errorf("%s: StartAuthorization() unexpected error: %v", tt.name, err)
			continue
		}
		p, err := FindAuthorizationRequest(t.Context(), f.d, f.tenant.ID, a.RequestID, testBinding)
		if err != nil || !tt.check(p.Request) {
			t.Errorf("%s: stored request = %+v, %v", tt.name, p.Request, err)
		}
	}
}

func TestStartAuthorizationShowsTargetErrors(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	for name, edit := range map[string]func(url.Values){
		"missing client_id":             func(p url.Values) { p.Del("client_id") },
		"unknown client":                func(p url.Values) { p.Set("client_id", "nobody") },
		"client ID in another case":     func(p url.Values) { p.Set("client_id", "WEB") },
		"unregistered redirect_uri":     func(p url.Values) { p.Set("redirect_uri", "https://evil.example/callback") },
		"redirect_uri with extra path":  func(p url.Values) { p.Set("redirect_uri", "https://app.example.com/callback/x") },
		"redirect_uri port on https":    func(p url.Values) { p.Set("redirect_uri", "https://app.example.com:444/callback") },
		"OIDC without redirect_uri":     func(p url.Values) { p.Del("redirect_uri") },
		"several registered and none":   func(p url.Values) { p.Del("redirect_uri"); p.Set("scope", "profile") },
		"client without redirect URIs":  func(p url.Values) { p.Set("client_id", "service"); p.Del("redirect_uri") },
		"repeated redirect_uri":         func(p url.Values) { p.Add("redirect_uri", "https://app.example.com/callback") },
		"invalid response_type as well": func(p url.Values) { p.Set("redirect_uri", "https://evil.example/"); p.Set("response_type", "token") },
	} {
		params := webRequest()
		edit(params)
		_, err := StartAuthorization(t.Context(), f.d, fakeSigner{}, f.tenant, params, testBinding, nil)
		var redirect *RedirectError
		if !errors.Is(err, oauth.ErrInvalidAuthorizationTarget) || errors.As(err, &redirect) {
			t.Errorf("%s: StartAuthorization() = %v, want ErrInvalidAuthorizationTarget", name, err)
		}
	}
}

func TestStartAuthorizationRedirectsErrors(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	tests := []struct {
		name  string
		edit  func(url.Values)
		code  string
		state bool
	}{
		{"implicit flow", func(p url.Values) { p.Set("response_type", "token") }, oauth.ErrorUnsupportedResponseType, true},
		{"invalid state", func(p url.Values) { p.Set("state", "a\nb") }, oauth.ErrorInvalidRequest, false},
		{"scope not allowed", func(p url.Values) { p.Set("scope", "openid admin") }, oauth.ErrorInvalidScope, true},
		{"missing PKCE", func(p url.Values) { p.Del("code_challenge"); p.Del("code_challenge_method") }, oauth.ErrorInvalidRequest, true},
		{"public client without PKCE", func(p url.Values) {
			p.Set("client_id", "spa")
			p.Set("redirect_uri", "http://127.0.0.1/callback")
			p.Del("code_challenge")
			p.Del("code_challenge_method")
		}, oauth.ErrorInvalidRequest, true},
		{"prompt none", func(p url.Values) { p.Set("prompt", "none") }, oauth.ErrorLoginRequired, true},
		{"client without the code grant", func(p url.Values) {
			p.Set("client_id", "service")
			p.Set("redirect_uri", "https://app.example.com/callback")
		}, "", false},
	}
	for _, tt := range tests {
		params := webRequest()
		tt.edit(params)
		_, err := StartAuthorization(t.Context(), f.d, fakeSigner{}, f.tenant, params, testBinding, nil)
		if tt.code == "" {
			// The service client has no redirect URIs, so its error is
			// shown rather than redirected.
			if !errors.Is(err, oauth.ErrInvalidAuthorizationTarget) {
				t.Errorf("%s: StartAuthorization() = %v, want ErrInvalidAuthorizationTarget", tt.name, err)
			}
			continue
		}
		var redirect *RedirectError
		var oauthErr *oauth.Error
		if !errors.As(err, &redirect) || redirect.Err.Code != tt.code || !errors.As(err, &oauthErr) ||
			!strings.Contains(err.Error(), tt.code) {
			t.Errorf("%s: StartAuthorization() = %v, want a redirected %s", tt.name, err, tt.code)
			continue
		}
		u, err := url.Parse(redirect.Response.URI())
		if err != nil || !strings.HasPrefix(redirect.Response.URI(), params.Get("redirect_uri")+"?") {
			t.Errorf("%s: redirect to %q, want the registered redirect URI", tt.name, redirect.Response.URI())
			continue
		}
		q := u.Query()
		if q.Get("error") != tt.code || q.Get("error_description") == "" || q.Get("iss") != testIssuer {
			t.Errorf("%s: response parameters = %v", tt.name, q)
		}
		if got, want := q.Get("state"), map[bool]string{true: "af0ifjsldkj"}[tt.state]; got != want || q.Has("state") != tt.state {
			t.Errorf("%s: state = %q, want %q", tt.name, got, want)
		}
	}
}

func TestErrorResponseKeepsTheRedirectQuery(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	params := webRequest()
	params.Set("redirect_uri", "https://app.example.com/other?x=1")
	params.Set("response_type", "token")
	_, err := StartAuthorization(t.Context(), f.d, fakeSigner{}, f.tenant, params, testBinding, nil)
	var redirect *RedirectError
	if !errors.As(err, &redirect) || !strings.HasPrefix(redirect.Response.URI(), "https://app.example.com/other?x=1&") {
		t.Errorf("StartAuthorization() = %v, want a redirect that keeps x=1", err)
	}
}

func TestFindAuthorizationRequestRefusesOtherBrowsersAndExpiredRequests(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	p := f.start(t, webRequest())
	id := p.Request.ID
	for name, binding := range map[string][]byte{
		"another browser":   oauth.HashToken("attacker"),
		"no binding cookie": nil,
		"truncated binding": testBinding[:16],
	} {
		if _, err := FindAuthorizationRequest(t.Context(), f.d, f.tenant.ID, id, binding); !errors.Is(err, ErrAuthorizationRequestNotFound) {
			t.Errorf("%s: FindAuthorizationRequest() = %v, want ErrAuthorizationRequestNotFound", name, err)
		}
	}
	for name, badID := range map[string]string{"malformed": "not-an-id", "unknown": oauth.NewRequestID()} {
		if _, err := FindAuthorizationRequest(t.Context(), f.d, f.tenant.ID, badID, testBinding); !errors.Is(err, ErrAuthorizationRequestNotFound) {
			t.Errorf("%s ID: FindAuthorizationRequest() = %v, want ErrAuthorizationRequestNotFound", name, err)
		}
	}
	var keys keyRecorder
	other, err := CreateTenant(t.Context(), f.d, keys.create, "other", "")
	if err != nil {
		t.Fatalf("CreateTenant() unexpected error: %v", err)
	}
	if _, err := FindAuthorizationRequest(t.Context(), f.d, other.ID, id, testBinding); !errors.Is(err, ErrAuthorizationRequestNotFound) {
		t.Errorf("FindAuthorizationRequest() through another tenant = %v, want ErrAuthorizationRequestNotFound", err)
	}

	*f.now = f.now.Add(AuthorizationRequestLifetime - time.Second)
	if _, err := FindAuthorizationRequest(t.Context(), f.d, f.tenant.ID, id, testBinding); err != nil {
		t.Errorf("FindAuthorizationRequest() just before expiry = %v, want nil", err)
	}
	*f.now = f.now.Add(time.Second)
	if _, err := FindAuthorizationRequest(t.Context(), f.d, f.tenant.ID, id, testBinding); !errors.Is(err, ErrAuthorizationRequestNotFound) {
		t.Errorf("FindAuthorizationRequest() at expiry = %v, want ErrAuthorizationRequestNotFound", err)
	}
}

func TestCompletePasswordLogin(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	p := f.start(t, webRequest())

	if _, err := CompletePasswordLogin(t.Context(), f.d, f.h, f.tenant, p, "ada@example.com", "wrong horse", nil); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("CompletePasswordLogin() with a wrong password = %v, want ErrInvalidCredentials", err)
	}
	// A failed attempt leaves the request for another one.
	if _, err := FindAuthorizationRequest(t.Context(), f.d, f.tenant.ID, p.Request.ID, testBinding); err != nil {
		t.Fatalf("FindAuthorizationRequest() after a failed attempt = %v, want nil", err)
	}

	login, err := CompletePasswordLogin(t.Context(), f.d, f.h, f.tenant, p, "Ada@Example.com", "correct horse", nil)
	if err != nil {
		t.Fatalf("CompletePasswordLogin() unexpected error: %v", err)
	}
	u, err := url.Parse(login.Response.URI())
	if err != nil || !strings.HasPrefix(login.Response.URI(), "https://app.example.com/callback?") {
		t.Fatalf("RedirectURI = %q", login.Response.URI())
	}
	q := u.Query()
	if q.Get("state") != "af0ifjsldkj" || q.Get("iss") != testIssuer || len(q) != 3 {
		t.Errorf("response parameters = %v", q)
	}

	code, err := f.d.Store.AuthorizationCodes().Get(t.Context(), f.tenant.ID, oauth.HashToken(q.Get("code")))
	if err != nil {
		t.Fatalf("looking up the issued code: %v", err)
	}
	session, err := f.d.Store.Sessions().GetByTokenHash(t.Context(), f.tenant.ID, oauth.HashToken(login.SessionToken))
	if err != nil {
		t.Fatalf("looking up the session: %v", err)
	}
	if code.ClientID != p.Client.ID || code.UserID != f.user.ID || code.SessionID != session.ID ||
		code.RedirectURI != p.Request.RedirectURI || !code.RedirectURIProvided ||
		!slices.Equal(code.Scopes, p.Request.Scopes) || code.Nonce != "n-0S6_WzA2Mj" ||
		code.CodeChallenge != testChallenge || code.CodeChallengeMethod != "S256" ||
		!code.AuthTime.Equal(*f.now) || !slices.Equal(code.AMR, []string{"pwd"}) ||
		!code.ExpiresAt.Equal(f.now.Add(AuthorizationCodeLifetime)) {
		t.Errorf("issued code = %+v", code)
	}
	if session.UserID != f.user.ID || !slices.Equal(session.AMR, []string{"pwd"}) ||
		!session.IdleExpiresAt.Equal(f.now.Add(SessionIdleTimeout)) ||
		!session.ExpiresAt.Equal(f.now.Add(SessionLifetime)) || !login.SessionExpiresAt.Equal(session.ExpiresAt) {
		t.Errorf("session = %+v", session)
	}

	// The request is single use.
	if _, err := FindAuthorizationRequest(t.Context(), f.d, f.tenant.ID, p.Request.ID, testBinding); !errors.Is(err, ErrAuthorizationRequestNotFound) {
		t.Errorf("FindAuthorizationRequest() after the login = %v, want ErrAuthorizationRequestNotFound", err)
	}
	if _, err := CompletePasswordLogin(t.Context(), f.d, f.h, f.tenant, p, "ada@example.com", "correct horse", nil); !errors.Is(err, ErrAuthorizationRequestNotFound) {
		t.Errorf("a second CompletePasswordLogin() = %v, want ErrAuthorizationRequestNotFound", err)
	}
}

func TestCompletePasswordLoginReplacesThePreviousSession(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	first, err := CompletePasswordLogin(t.Context(), f.d, f.h, f.tenant, f.start(t, webRequest()),
		"ada@example.com", "correct horse", oauth.HashToken("unknown session"))
	if err != nil {
		t.Fatalf("first CompletePasswordLogin() unexpected error: %v", err)
	}
	firstHash := oauth.HashToken(first.SessionToken)
	second, err := CompletePasswordLogin(t.Context(), f.d, f.h, f.tenant, f.start(t, webRequest()),
		"ada@example.com", "correct horse", firstHash)
	if err != nil {
		t.Fatalf("second CompletePasswordLogin() unexpected error: %v", err)
	}
	if second.SessionToken == first.SessionToken {
		t.Fatal("the second login kept the session token")
	}
	if _, err := f.d.Store.Sessions().GetByTokenHash(t.Context(), f.tenant.ID, firstHash); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("the previous session = %v, want it deleted", err)
	}
}

func TestCompletePasswordLoginWithoutStateOrPKCE(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	params := webRequest()
	params.Set("client_id", "legacy")
	params.Set("redirect_uri", "https://legacy.example.com/callback")
	for _, name := range []string{"state", "nonce", "code_challenge", "code_challenge_method"} {
		params.Del(name)
	}
	login, err := CompletePasswordLogin(t.Context(), f.d, f.h, f.tenant, f.start(t, params), "ada@example.com", "correct horse", nil)
	if err != nil {
		t.Fatalf("CompletePasswordLogin() unexpected error: %v", err)
	}
	u, _ := url.Parse(login.Response.URI())
	if q := u.Query(); q.Has("state") || q.Get("code") == "" {
		t.Errorf("response parameters = %v, want a code without state", q)
	}
}

func TestCompletePasswordLoginRefusesDisabledUsers(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	p := f.start(t, webRequest())
	disabled := f.user
	disabled.ID = f.d.NewID()
	disabled.Email = "grace@example.com"
	disabled.Status = store.UserDisabled
	if err := f.d.Store.Users().Create(t.Context(), disabled); err != nil {
		t.Fatalf("creating a disabled user: %v", err)
	}
	if err := SetPassword(t.Context(), f.d, f.h, disabled, "correct horse"); err != nil {
		t.Fatalf("SetPassword() unexpected error: %v", err)
	}
	if _, err := CompletePasswordLogin(t.Context(), f.d, f.h, f.tenant, p, "grace@example.com", "correct horse", nil); !errors.Is(err, ErrUserDisabled) {
		t.Errorf("CompletePasswordLogin() = %v, want ErrUserDisabled", err)
	}
}

// failingAuthzStore fails the writes of a sign-in.
type failingAuthzStore struct{ store.Store }

func (f failingAuthzStore) AuthorizationRequests() store.AuthorizationRequests {
	return failingRequests{f.Store.AuthorizationRequests()}
}

func (f failingAuthzStore) Sessions() store.Sessions { return failingSessions{f.Store.Sessions()} }

type failingRequests struct{ store.AuthorizationRequests }

func (failingRequests) Create(context.Context, store.AuthorizationRequest) error {
	return errUnavailable
}

type failingSessions struct{ store.Sessions }

func (failingSessions) Create(context.Context, store.Session) error { return errUnavailable }

func TestAuthorizationReportsStoreFailures(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	p := f.start(t, webRequest())
	f.d.Store = failingAuthzStore{f.d.Store}
	var redirect *RedirectError
	if _, err := StartAuthorization(t.Context(), f.d, fakeSigner{}, f.tenant, webRequest(), testBinding, nil); !errors.Is(err, errUnavailable) ||
		errors.As(err, &redirect) {
		t.Errorf("StartAuthorization() = %v, want the store error", err)
	}
	if _, err := CompletePasswordLogin(t.Context(), f.d, f.h, f.tenant, p, "ada@example.com", "correct horse", nil); !errors.Is(err, errUnavailable) {
		t.Errorf("CompletePasswordLogin() = %v, want the store error", err)
	}
}

func TestPurgeExpired(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	var logs bytes.Buffer
	f.d.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	start := *f.now
	pending := f.start(t, webRequest())
	login, err := CompletePasswordLogin(t.Context(), f.d, f.h, f.tenant, f.start(t, webRequest()),
		"ada@example.com", "correct horse", nil)
	if err != nil {
		t.Fatalf("CompletePasswordLogin() unexpected error: %v", err)
	}
	u, _ := url.Parse(login.Response.URI())
	codeHash := oauth.HashToken(u.Query().Get("code"))
	sessionHash := oauth.HashToken(login.SessionToken)
	exists := func() (request, code, session bool) {
		_, errR := f.d.Store.AuthorizationRequests().Get(t.Context(), f.tenant.ID, pending.Request.ID)
		_, errC := f.d.Store.AuthorizationCodes().Get(t.Context(), f.tenant.ID, codeHash)
		_, errS := f.d.Store.Sessions().GetByTokenHash(t.Context(), f.tenant.ID, sessionHash)
		return errR == nil, errC == nil, errS == nil
	}

	for _, step := range []struct {
		after                  time.Duration
		request, code, session bool
	}{
		{0, true, true, true},
		// The request has expired; the code has too, but it is retained.
		{AuthorizationRequestLifetime, false, true, true},
		// The session ends after a day without use.
		{SessionIdleTimeout, false, true, false},
		{AuthorizationCodeLifetime + AuthorizationCodeRetention - time.Second, false, true, false},
		{AuthorizationCodeLifetime + AuthorizationCodeRetention, false, false, false},
	} {
		*f.now = start.Add(step.after)
		if err := PurgeExpired(t.Context(), f.d); err != nil {
			t.Fatalf("PurgeExpired() after %v unexpected error: %v", step.after, err)
		}
		if r, c, s := exists(); r != step.request || c != step.code || s != step.session {
			t.Errorf("after %v: request, code and session exist = %v, %v, %v; want %v, %v, %v",
				step.after, r, c, s, step.request, step.code, step.session)
		}
	}
	if !strings.Contains(logs.String(), "deleted expired records") || !strings.Contains(logs.String(), "sessions=1") {
		t.Errorf("logs do not report the deletions:\n%s", logs.String())
	}
}

// failingPurgeStore fails to delete expired authorization requests.
type failingPurgeStore struct{ store.Store }

func (f failingPurgeStore) AuthorizationRequests() store.AuthorizationRequests {
	return failingPurgeRequests{f.Store.AuthorizationRequests()}
}

type failingPurgeRequests struct{ store.AuthorizationRequests }

func (failingPurgeRequests) DeleteExpired(context.Context, time.Time) (int64, error) {
	return 0, errUnavailable
}

func TestPurgeExpiredGoesOnAfterAFailure(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	login, err := CompletePasswordLogin(t.Context(), f.d, f.h, f.tenant, f.start(t, webRequest()),
		"ada@example.com", "correct horse", nil)
	if err != nil {
		t.Fatalf("CompletePasswordLogin() unexpected error: %v", err)
	}
	f.d.Store = failingPurgeStore{f.d.Store}
	*f.now = f.now.Add(SessionLifetime)
	if err := PurgeExpired(t.Context(), f.d); !errors.Is(err, errUnavailable) {
		t.Errorf("PurgeExpired() = %v, want the store error", err)
	}
	if _, err := f.d.Store.Sessions().GetByTokenHash(t.Context(), f.tenant.ID, oauth.HashToken(login.SessionToken)); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("the expired session = %v, want it deleted despite the failure", err)
	}
}

// OAuth 2.0 Form Post Response Mode, section 2: every response to a
// form_post request goes back as a form post, whether it carries a code or
// an error, and whether it comes at once or after the sign-in or consent.
func TestFormPostResponseMode(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	formPost := func(name string, resp AuthorizationResponse, want string) {
		t.Helper()
		if !resp.FormPost || resp.RedirectURI == "" || resp.Params.Get(want) == "" ||
			resp.Params.Get("state") != "af0ifjsldkj" || resp.Params.Get("iss") != testIssuer {
			t.Errorf("%s: response = %+v, want a form post with %s, state and iss", name, resp, want)
		}
	}
	params := with(webRequest(), "response_mode", "form_post")

	login, err := CompletePasswordLogin(t.Context(), f.d, f.h, f.tenant, f.start(t, params), "ada@example.com",
		"correct horse", nil)
	if err != nil {
		t.Fatalf("CompletePasswordLogin() unexpected error: %v", err)
	}
	formPost("after the sign-in", login.Response, "code")
	if login.Response.RedirectURI != "https://app.example.com/callback" {
		t.Errorf("RedirectURI = %q, want the registered redirect URI without the response", login.Response.RedirectURI)
	}
	sessionHash := oauth.HashToken(login.SessionToken)

	a, err := f.startWith(t, params, sessionHash)
	if err != nil {
		t.Fatalf("StartAuthorization() with a session unexpected error: %v", err)
	}
	formPost("single sign-on", a.Response, "code")

	var redirect *RedirectError
	_, err = f.startWith(t, with(with(webRequest(), "response_mode", "form_post"), "prompt", "none"), nil)
	if !errors.As(err, &redirect) {
		t.Fatalf("StartAuthorization() with prompt=none and no session = %v, want a *RedirectError", err)
	}
	formPost("error", redirect.Response, "error")

	p, consentSession := f.loginForConsent(t, with(partnerRequest(), "response_mode", "form_post"))
	c, err := FindConsent(t.Context(), f.d, f.tenant.ID, p.Request.ID, testBinding, consentSession)
	if err != nil {
		t.Fatalf("FindConsent() unexpected error: %v", err)
	}
	denied, err := CompleteConsent(t.Context(), f.d, f.tenant, c, false)
	if err != nil {
		t.Fatalf("CompleteConsent() unexpected error: %v", err)
	}
	formPost("denied consent", denied, "error")
}

// Responses go to the registered redirect URI, with the requested port of a
// loopback URI (RFC 8252, section 7.3). A port with a leading zero would not
// be written back as the request sent it, so it does not match.
func TestResponsesGoToTheRegisteredRedirectURI(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	params := with(with(webRequest(), "client_id", "spa"), "redirect_uri", "http://127.0.0.1:8080/callback")
	if p := f.start(t, params); p.Request.RedirectURI != "http://127.0.0.1:8080/callback" {
		t.Errorf("stored redirect URI = %q, want the registered one with port 8080", p.Request.RedirectURI)
	}
	var redirect *RedirectError
	_, err := f.startWith(t, with(params, "prompt", "none"), nil)
	if !errors.As(err, &redirect) || redirect.Response.RedirectURI != "http://127.0.0.1:8080/callback" {
		t.Errorf("error response = %v, want it sent to the registered URI with port 8080", err)
	}
	_, err = f.startWith(t, with(params, "redirect_uri", "http://127.0.0.1:08080/callback"), nil)
	if !errors.Is(err, oauth.ErrInvalidAuthorizationTarget) {
		t.Errorf("a port with a leading zero = %v, want ErrInvalidAuthorizationTarget", err)
	}
}
