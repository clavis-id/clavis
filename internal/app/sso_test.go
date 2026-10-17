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
	"clavisid.org/clavis/internal/oidc"
	"clavisid.org/clavis/store"
)

// signIn signs ada in through the web client and returns the hash of the
// new session cookie and the authorization response.
func (f authzFixture) signIn(t *testing.T, params url.Values) (sessionHash []byte, response url.Values) {
	t.Helper()
	login, err := CompletePasswordLogin(t.Context(), f.d, f.h, f.tenant, f.start(t, params),
		"ada@example.com", "correct horse", nil)
	if err != nil {
		t.Fatalf("CompletePasswordLogin() unexpected error: %v", err)
	}
	u, err := url.Parse(login.RedirectURI)
	if err != nil {
		t.Fatalf("parsing %q: %v", login.RedirectURI, err)
	}
	return oauth.HashToken(login.SessionToken), u.Query()
}

// startWith starts an authorization from a browser with the session whose
// cookie hashes to sessionHash.
func (f authzFixture) startWith(t *testing.T, params url.Values, sessionHash []byte) (Authorization, error) {
	t.Helper()
	return StartAuthorization(t.Context(), f.d, fakeSigner{}, f.tenant, params, testBinding, sessionHash)
}

// codeOf returns the code that an authorization response carries.
func (f authzFixture) codeOf(t *testing.T, responseURI string) store.AuthorizationCode {
	t.Helper()
	u, err := url.Parse(responseURI)
	if err != nil {
		t.Fatalf("parsing %q: %v", responseURI, err)
	}
	code, err := f.d.Store.AuthorizationCodes().Get(t.Context(), f.tenant.ID, oauth.HashToken(u.Query().Get("code")))
	if err != nil {
		t.Fatalf("looking up the code of %q: %v", responseURI, err)
	}
	return code
}

func TestSingleSignOn(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	var logs bytes.Buffer
	f.d.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	signedInAt := *f.now
	sessionHash, _ := f.signIn(t, webRequest())

	// Another client of the tenant gets a code without a sign-in.
	*f.now = f.now.Add(time.Hour)
	params := webRequest()
	params.Set("client_id", "spa")
	params.Set("redirect_uri", "http://127.0.0.1:51004/callback")
	params.Set("prompt", "none")
	a, err := f.startWith(t, params, sessionHash)
	if err != nil || a.RequestID != "" || !strings.HasPrefix(a.RedirectURI, "http://127.0.0.1:51004/callback?") {
		t.Fatalf("StartAuthorization() with a session = %+v, %v; want an authorization response", a, err)
	}
	u, _ := url.Parse(a.RedirectURI)
	if q := u.Query(); q.Get("state") != "af0ifjsldkj" || q.Get("iss") != testIssuer || len(q) != 3 {
		t.Errorf("response parameters = %v", q)
	}
	code := f.codeOf(t, a.RedirectURI)
	session, err := f.d.Store.Sessions().GetByTokenHash(t.Context(), f.tenant.ID, sessionHash)
	if err != nil {
		t.Fatalf("looking up the session: %v", err)
	}
	if code.UserID != f.user.ID || code.SessionID != session.ID || !code.AuthTime.Equal(signedInAt) ||
		!slices.Equal(code.AMR, []string{"pwd"}) || code.ACR != oidc.ACRPassword ||
		code.ClientID != f.client(t, "spa").ID || code.Nonce != "n-0S6_WzA2Mj" || code.CodeChallenge != testChallenge ||
		code.RedirectURI != "http://127.0.0.1:51004/callback" {
		t.Errorf("issued code = %+v", code)
	}
	// Using the session moves its idle expiry, but never past its lifetime.
	if !session.LastSeenAt.Equal(*f.now) || !session.IdleExpiresAt.Equal(f.now.Add(SessionIdleTimeout)) {
		t.Errorf("session after use = %+v", session)
	}
	if !strings.Contains(logs.String(), "user signed in with an existing session") {
		t.Errorf("logs do not report the reused session:\n%s", logs.String())
	}
	// Near the end of its lifetime, a session in use stops at its end.
	end := session.ExpiresAt
	if err := f.d.Store.Sessions().Touch(t.Context(), f.tenant.ID, session.ID, end.Add(-2*time.Hour),
		end.Add(-time.Minute)); err != nil {
		t.Fatalf("Touch() unexpected error: %v", err)
	}
	*f.now = end.Add(-time.Hour)
	if a, err := f.startWith(t, webRequest(), sessionHash); err != nil || a.RedirectURI == "" {
		t.Fatalf("StartAuthorization() near the end of the session = %+v, %v", a, err)
	}
	session, _ = f.d.Store.Sessions().GetByTokenHash(t.Context(), f.tenant.ID, sessionHash)
	if !session.IdleExpiresAt.Equal(session.ExpiresAt) {
		t.Errorf("idle expiry %v, want the end of the session %v", session.IdleExpiresAt, session.ExpiresAt)
	}
}

func TestSingleSignOnNeedsAUsableSession(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		// setup prepares the fixture and returns the session cookie hash to
		// send and the request.
		setup func(t *testing.T, f *authzFixture) ([]byte, url.Values)
	}{
		{"no session", func(*testing.T, *authzFixture) ([]byte, url.Values) {
			return nil, webRequest()
		}},
		{"unknown session", func(*testing.T, *authzFixture) ([]byte, url.Values) {
			return oauth.HashToken("unknown"), webRequest()
		}},
		{"prompt login", func(t *testing.T, f *authzFixture) ([]byte, url.Values) {
			h, _ := f.signIn(t, webRequest())
			return h, with(webRequest(), "prompt", "login")
		}},
		{"prompt select_account", func(t *testing.T, f *authzFixture) ([]byte, url.Values) {
			h, _ := f.signIn(t, webRequest())
			return h, with(webRequest(), "prompt", "select_account")
		}},
		{"max_age 0", func(t *testing.T, f *authzFixture) ([]byte, url.Values) {
			h, _ := f.signIn(t, webRequest())
			return h, with(webRequest(), "max_age", "0")
		}},
		{"authentication older than max_age", func(t *testing.T, f *authzFixture) ([]byte, url.Values) {
			h, _ := f.signIn(t, webRequest())
			*f.now = f.now.Add(61 * time.Second)
			return h, with(webRequest(), "max_age", "60")
		}},
		{"idle session", func(t *testing.T, f *authzFixture) ([]byte, url.Values) {
			h, _ := f.signIn(t, webRequest())
			*f.now = f.now.Add(SessionIdleTimeout)
			return h, webRequest()
		}},
		{"session past its lifetime", func(t *testing.T, f *authzFixture) ([]byte, url.Values) {
			h, _ := f.signIn(t, webRequest())
			s, _ := f.d.Store.Sessions().GetByTokenHash(t.Context(), f.tenant.ID, h)
			// Keep the session from going idle until its lifetime ends.
			if err := f.d.Store.Sessions().Touch(t.Context(), f.tenant.ID, s.ID, s.ExpiresAt, s.ExpiresAt.Add(time.Hour)); err != nil {
				t.Fatalf("Touch() unexpected error: %v", err)
			}
			*f.now = s.ExpiresAt
			return h, webRequest()
		}},
		{"disabled user", func(t *testing.T, f *authzFixture) ([]byte, url.Values) {
			grace := f.user
			grace.ID, grace.Email, grace.Status = f.d.NewID(), "grace@example.com", store.UserDisabled
			if err := f.d.Store.Users().Create(t.Context(), grace); err != nil {
				t.Fatalf("creating a disabled user: %v", err)
			}
			token := oauth.NewToken()
			s := store.Session{ID: f.d.NewID(), TenantID: f.tenant.ID, TokenHash: oauth.HashToken(token),
				UserID: grace.ID, AuthTime: *f.now, CreatedAt: *f.now, LastSeenAt: *f.now,
				IdleExpiresAt: f.now.Add(time.Hour), ExpiresAt: f.now.Add(time.Hour)}
			if err := f.d.Store.Sessions().Create(t.Context(), s); err != nil {
				t.Fatalf("creating a session: %v", err)
			}
			return s.TokenHash, webRequest()
		}},
		{"session of another tenant", func(t *testing.T, f *authzFixture) ([]byte, url.Values) {
			h, _ := f.signIn(t, webRequest())
			var keys keyRecorder
			other, err := CreateTenant(t.Context(), f.d, keys.create, "other", "")
			if err != nil {
				t.Fatalf("CreateTenant() unexpected error: %v", err)
			}
			if _, _, err := CreateClient(t.Context(), f.d, other.ID, ClientSpec{ClientID: "web", SkipConsent: true,
				Type: store.ClientConfidential, RedirectURIs: []string{"https://app.example.com/callback"}}); err != nil {
				t.Fatalf("CreateClient() unexpected error: %v", err)
			}
			f.tenant.ID = other.ID
			return h, webRequest()
		}},
	}
	for _, tt := range tests {
		for _, promptNone := range []bool{false, true} {
			f := newAuthzFixture(t)
			sessionHash, params := tt.setup(t, &f)
			if promptNone {
				if params.Get("prompt") != "" {
					continue
				}
				params.Set("prompt", "none")
			}
			a, err := StartAuthorization(t.Context(), f.d, fakeSigner{}, f.tenant, params, testBinding, sessionHash)
			if !promptNone {
				if err != nil || a.RequestID == "" || a.RedirectURI != "" {
					t.Errorf("%s: StartAuthorization() = %+v, %v; want a stored request for a sign-in", tt.name, a, err)
				}
				continue
			}
			var redirect *RedirectError
			if !errors.As(err, &redirect) || redirect.Err.Code != oauth.ErrorLoginRequired {
				t.Errorf("%s with prompt=none: StartAuthorization() = %+v, %v; want login_required", tt.name, a, err)
			}
		}
	}
}

func TestSingleSignOnWithinMaxAge(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	sessionHash, _ := f.signIn(t, webRequest())
	*f.now = f.now.Add(60 * time.Second)
	if a, err := f.startWith(t, with(webRequest(), "max_age", "60"), sessionHash); err != nil || a.RedirectURI == "" {
		t.Errorf("StartAuthorization() within max_age = %+v, %v; want an authorization response", a, err)
	}
}

// with returns params with name set to value.
func with(params url.Values, name, value string) url.Values {
	params.Set(name, value)
	return params
}

// idTokenFor signs ada in through params, exchanges the code and returns the
// ID token and the session cookie hash.
func (f authzFixture) idTokenFor(t *testing.T, params url.Values) (idToken string, sessionHash []byte) {
	t.Helper()
	sessionHash, response := f.signIn(t, params)
	r := codeRequest(response.Get("code"))
	r.RedirectURI = params.Get("redirect_uri")
	resp, err := ExchangeCode(t.Context(), f.d, fakeSigner{}, f.tenant, f.client(t, params.Get("client_id")), r)
	if err != nil {
		t.Fatalf("ExchangeCode() unexpected error: %v", err)
	}
	return resp.IDToken, sessionHash
}

func TestIDTokenHint(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	idToken, sessionHash := f.idTokenFor(t, webRequest())

	// OpenID Connect Core 1.0, section 3.1.2.1: a hint of the signed-in user
	// with prompt=none answers at once, even after the ID token expired.
	*f.now = f.now.Add(DefaultIDTokenLifetime + time.Hour)
	params := with(with(webRequest(), "prompt", "none"), "id_token_hint", idToken)
	if a, err := f.startWith(t, params, sessionHash); err != nil || a.RedirectURI == "" {
		t.Errorf("StartAuthorization() with the user's id_token_hint = %+v, %v; want a response", a, err)
	}

	// Without a session, the hint leads to the sign-in form, whose response
	// must come from the hinted user.
	a, err := f.startWith(t, with(webRequest(), "id_token_hint", idToken), nil)
	if err != nil || a.RequestID == "" {
		t.Fatalf("StartAuthorization() with a hint and no session = %+v, %v", a, err)
	}
	p, err := FindAuthorizationRequest(t.Context(), f.d, f.tenant.ID, a.RequestID, testBinding)
	if err != nil || p.Request.HintSubject != f.user.ID {
		t.Fatalf("stored request = %+v, %v; want the hinted user", p.Request, err)
	}
	if login, err := CompletePasswordLogin(t.Context(), f.d, f.h, f.tenant, p, "ada@example.com", "correct horse", nil); err != nil ||
		!strings.Contains(login.RedirectURI, "code=") {
		t.Errorf("CompletePasswordLogin() as the hinted user = %+v, %v; want a code", login, err)
	}
}

func TestIDTokenHintOfAnotherUser(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	grace, err := CreateUser(t.Context(), f.d, f.tenant.ID, UserSpec{Email: "grace@example.com"})
	if err != nil {
		t.Fatalf("CreateUser() unexpected error: %v", err)
	}
	if err := SetPassword(t.Context(), f.d, f.h, grace, "correct horse"); err != nil {
		t.Fatalf("SetPassword() unexpected error: %v", err)
	}
	adaToken, sessionHash := f.idTokenFor(t, webRequest())

	// Grace signs in on the same browser; the session is now hers.
	login, err := CompletePasswordLogin(t.Context(), f.d, f.h, f.tenant, f.start(t, webRequest()),
		"grace@example.com", "correct horse", sessionHash)
	if err != nil {
		t.Fatalf("CompletePasswordLogin() as grace unexpected error: %v", err)
	}
	graceSession := oauth.HashToken(login.SessionToken)

	_, err = f.startWith(t, with(with(webRequest(), "prompt", "none"), "id_token_hint", adaToken), graceSession)
	var redirect *RedirectError
	if !errors.As(err, &redirect) || redirect.Err.Code != oauth.ErrorLoginRequired {
		t.Errorf("StartAuthorization() with ada's hint in grace's session = %v, want login_required", err)
	}

	// Without prompt=none, the user may sign in; grace's sign-in still
	// cannot answer a request about ada.
	a, err := f.startWith(t, with(webRequest(), "id_token_hint", adaToken), graceSession)
	if err != nil || a.RequestID == "" {
		t.Fatalf("StartAuthorization() = %+v, %v; want a stored request", a, err)
	}
	p, err := FindAuthorizationRequest(t.Context(), f.d, f.tenant.ID, a.RequestID, testBinding)
	if err != nil {
		t.Fatalf("FindAuthorizationRequest() unexpected error: %v", err)
	}
	login, err = CompletePasswordLogin(t.Context(), f.d, f.h, f.tenant, p, "grace@example.com", "correct horse", graceSession)
	if err != nil {
		t.Fatalf("CompletePasswordLogin() unexpected error: %v", err)
	}
	u, _ := url.Parse(login.RedirectURI)
	if q := u.Query(); q.Get("error") != oauth.ErrorLoginRequired || q.Has("code") || q.Get("state") != "af0ifjsldkj" ||
		q.Get("iss") != testIssuer || login.SessionToken == "" {
		t.Errorf("CompletePasswordLogin() as another user = %+v; want login_required and a session", login)
	}
}

func TestIDTokenHintMustComeFromTheProviderAndClient(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	webToken, _ := f.idTokenFor(t, webRequest())
	_, _, claims := decode[oidc.IDTokenClaims](t, webToken)
	forge := func(edit func(*oidc.IDTokenClaims)) string {
		c := claims
		edit(&c)
		token, err := sign(t.Context(), fakeSigner{}, f.tenant.ID, "RS256", oidc.IDTokenType, c)
		if err != nil {
			t.Fatalf("signing: %v", err)
		}
		return token
	}
	otherTenant, err := sign(t.Context(), fakeSigner{}, uuid.NewV7(), "RS256", oidc.IDTokenType, claims)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	accessToken, err := sign(t.Context(), fakeSigner{}, f.tenant.ID, "RS256", oidc.AccessTokenType, claims)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	for name, hint := range map[string]string{
		"signed for another tenant": otherTenant,
		"an access token":           accessToken,
		"another issuer":            forge(func(c *oidc.IDTokenClaims) { c.Issuer = "https://other.example.com" }),
		"another client":            forge(func(c *oidc.IDTokenClaims) { c.Audience = "spa" }),
		"a subject that is no user": forge(func(c *oidc.IDTokenClaims) { c.Subject = "ada" }),
		"not a fake signature":      "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZGEifQ.c2ln",
	} {
		_, err := f.startWith(t, with(webRequest(), "id_token_hint", hint), nil)
		var redirect *RedirectError
		if !errors.As(err, &redirect) || redirect.Err.Code != oauth.ErrorInvalidRequest {
			t.Errorf("%s: StartAuthorization() = %v, want invalid_request", name, err)
		}
	}
}

func TestLoginHint(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	for hint, want := range map[string]string{
		"Ada@Example.com":   "ada@example.com",
		"not an address":    "",
		"+44 20 7946 0000":  "",
		"":                  "",
		"ada@example.com\t": "",
	} {
		params := webRequest()
		if hint != "" {
			params.Set("login_hint", hint)
		}
		a, err := f.startWith(t, params, nil)
		if err != nil {
			// A tab is a control character, which the parser refuses.
			if hint == "ada@example.com\t" {
				continue
			}
			t.Fatalf("StartAuthorization() with login_hint %q unexpected error: %v", hint, err)
		}
		p, err := FindAuthorizationRequest(t.Context(), f.d, f.tenant.ID, a.RequestID, testBinding)
		if err != nil || p.Request.LoginHint != want {
			t.Errorf("login_hint %q stored as %q, %v; want %q", hint, p.Request.LoginHint, err, want)
		}
	}
}

func TestClaimsParameter(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	params := with(webRequest(), "scope", "openid")
	params.Set("claims", `{"userinfo":{"email":{"essential":true},"phone_number":null,"unknown":null},
		"id_token":{"email_verified":null,"acr":{"essential":true,"values":["urn:other","`+oidc.ACRPassword+`"]}}}`)
	p := f.start(t, params)
	// The web client may not request the phone scope, so it gets no phone
	// claims; unknown claims are ignored.
	if !slices.Equal(p.Request.UserInfoClaims, []string{"email"}) ||
		!slices.Equal(p.Request.IDTokenClaims, []string{"email_verified"}) {
		t.Fatalf("stored claims = %v and %v", p.Request.UserInfoClaims, p.Request.IDTokenClaims)
	}
	login, err := CompletePasswordLogin(t.Context(), f.d, f.h, f.tenant, p, "ada@example.com", "correct horse", nil)
	if err != nil {
		t.Fatalf("CompletePasswordLogin() unexpected error: %v", err)
	}
	code := f.codeOf(t, login.RedirectURI)
	if !slices.Equal(code.UserInfoClaims, []string{"email"}) || !slices.Equal(code.IDTokenClaims, []string{"email_verified"}) {
		t.Fatalf("code claims = %v and %v", code.UserInfoClaims, code.IDTokenClaims)
	}
	u, _ := url.Parse(login.RedirectURI)
	resp, err := ExchangeCode(t.Context(), f.d, fakeSigner{}, f.tenant, p.Client, codeRequest(u.Query().Get("code")))
	if err != nil {
		t.Fatalf("ExchangeCode() unexpected error: %v", err)
	}
	_, _, idToken := decode[map[string]any](t, resp.IDToken)
	if idToken["email_verified"] != false || idToken["acr"] != oidc.ACRPassword || idToken["sub"] != f.user.ID.String() ||
		idToken["email"] != nil {
		t.Errorf("ID token claims = %v", idToken)
	}
	claims, err := UserInfo(t.Context(), f.d, fakeSigner{}, f.tenant, resp.AccessToken)
	if err != nil || claims["email"] != "ada@example.com" || claims["email_verified"] != nil || len(claims) != 2 {
		t.Errorf("UserInfo() = %v, %v; want sub and email", claims, err)
	}

	// The claims parameter belongs to OpenID Connect requests.
	params = with(webRequest(), "scope", "profile")
	params.Set("claims", `{"userinfo":{"email":null}}`)
	if p := f.start(t, params); len(p.Request.UserInfoClaims) != 0 {
		t.Errorf("stored claims of an OAuth request = %v, want none", p.Request.UserInfoClaims)
	}
}

func TestEssentialACR(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	for claims, wantErr := range map[string]bool{
		`{"id_token":{"acr":{"essential":true,"values":["urn:mfa"]}}}`:               true,
		`{"id_token":{"acr":{"essential":true,"value":"urn:mfa"}}}`:                  true,
		`{"id_token":{"acr":{"values":["urn:mfa"]}}}`:                                false,
		`{"id_token":{"acr":{"essential":true}}}`:                                    false,
		`{"id_token":{"acr":{"essential":true,"value":"` + oidc.ACRPassword + `"}}}`: false,
		`{"userinfo":{"acr":{"essential":true,"values":["urn:mfa"]}}}`:               false,
	} {
		_, err := f.startWith(t, with(webRequest(), "claims", claims), nil)
		var redirect *RedirectError
		switch {
		case wantErr && (!errors.As(err, &redirect) || redirect.Err.Code != oauth.ErrorAccessDenied):
			t.Errorf("claims %s: StartAuthorization() = %v, want access_denied", claims, err)
		case !wantErr && err != nil:
			t.Errorf("claims %s: StartAuthorization() unexpected error: %v", claims, err)
		}
	}
}

// failingSessionStore fails to read or touch sessions.
type failingSessionStore struct {
	store.Store
	touch bool
}

func (f failingSessionStore) Sessions() store.Sessions {
	return failingSessionReads{f.Store.Sessions(), f.touch}
}

type failingSessionReads struct {
	store.Sessions
	touch bool
}

func (f failingSessionReads) GetByTokenHash(ctx context.Context, tenantID uuid.UUID, hash []byte) (store.Session, error) {
	if f.touch {
		return f.Sessions.GetByTokenHash(ctx, tenantID, hash)
	}
	return store.Session{}, errUnavailable
}

func (failingSessionReads) Touch(context.Context, uuid.UUID, uuid.UUID, time.Time, time.Time) error {
	return errUnavailable
}

func TestSingleSignOnReportsStoreFailures(t *testing.T) {
	t.Parallel()
	for _, touch := range []bool{false, true} {
		f := newAuthzFixture(t)
		sessionHash, _ := f.signIn(t, webRequest())
		f.d.Store = failingSessionStore{f.d.Store, touch}
		var redirect *RedirectError
		if _, err := f.startWith(t, webRequest(), sessionHash); !errors.Is(err, errUnavailable) || errors.As(err, &redirect) {
			t.Errorf("StartAuthorization() with a failing store (touch %v) = %v, want the store error", touch, err)
		}
	}
}

func TestRequestedSubject(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	grace, err := CreateUser(t.Context(), f.d, f.tenant.ID, UserSpec{Email: "grace@example.com"})
	if err != nil {
		t.Fatalf("CreateUser() unexpected error: %v", err)
	}
	adaToken, sessionHash := f.idTokenFor(t, webRequest())
	ada := f.user.ID.String()
	subClaims := func(member string) string { return `{"id_token":{"sub":` + member + `}}` }

	tests := []struct {
		name   string
		claims string
		hint   bool
		// code is the expected error, or "" for an answer from ada's session.
		code string
	}{
		// OpenID Connect Core 1.0, section 5.5.1: tokens of another user,
		// even one with a session, are never an answer.
		{"another user", subClaims(`{"value":"` + grace.ID.String() + `"}`), false, oauth.ErrorLoginRequired},
		{"the signed-in user", subClaims(`{"value":"` + ada + `","essential":true}`), false, ""},
		{"the signed-in user among values", subClaims(`{"values":["` + ada + `"]}`), false, ""},
		{"not a user ID", subClaims(`{"value":"ada"}`), false, oauth.ErrorLoginRequired},
		{"a user ID in upper case", subClaims(`{"value":"` + strings.ToUpper(ada) + `"}`), false, oauth.ErrorLoginRequired},
		{"a number", subClaims(`{"value":42}`), false, oauth.ErrorLoginRequired},
		{"two users", subClaims(`{"values":["` + ada + `","` + grace.ID.String() + `"]}`), false, oauth.ErrorInvalidRequest},
		{"the hinted user", subClaims(`{"value":"` + ada + `"}`), true, ""},
		{"a user other than the hinted one", subClaims(`{"value":"` + grace.ID.String() + `"}`), true, oauth.ErrorLoginRequired},
		{"no value", subClaims(`{"essential":true}`), false, ""},
		{"a null value", subClaims(`{"value":null}`), false, ""},
		{"in the userinfo member", `{"userinfo":{"sub":{"value":"` + grace.ID.String() + `"}}}`, false, ""},
	}
	for _, tt := range tests {
		params := with(with(webRequest(), "prompt", "none"), "claims", tt.claims)
		if tt.hint {
			params.Set("id_token_hint", adaToken)
		}
		a, err := f.startWith(t, params, sessionHash)
		var redirect *RedirectError
		switch {
		case tt.code == "" && (err != nil || a.RedirectURI == ""):
			t.Errorf("%s: StartAuthorization() = %+v, %v; want an answer from the session", tt.name, a, err)
		case tt.code != "" && (!errors.As(err, &redirect) || redirect.Err.Code != tt.code):
			t.Errorf("%s: StartAuthorization() = %+v, %v; want %s", tt.name, a, err, tt.code)
		}
	}

	// Without prompt=none, the request waits for a sign-in, and only grace's
	// sign-in can answer it.
	a, err := f.startWith(t, with(webRequest(), "claims", subClaims(`{"value":"`+grace.ID.String()+`"}`)), sessionHash)
	if err != nil || a.RequestID == "" {
		t.Fatalf("StartAuthorization() = %+v, %v; want a stored request", a, err)
	}
	p, err := FindAuthorizationRequest(t.Context(), f.d, f.tenant.ID, a.RequestID, testBinding)
	if err != nil || p.Request.HintSubject != grace.ID {
		t.Fatalf("stored request = %+v, %v; want grace as the required user", p.Request, err)
	}
	login, err := CompletePasswordLogin(t.Context(), f.d, f.h, f.tenant, p, "ada@example.com", "correct horse", sessionHash)
	if err != nil {
		t.Fatalf("CompletePasswordLogin() unexpected error: %v", err)
	}
	u, _ := url.Parse(login.RedirectURI)
	if q := u.Query(); q.Get("error") != oauth.ErrorLoginRequired || q.Has("code") {
		t.Errorf("CompletePasswordLogin() as ada = %q, want login_required", login.RedirectURI)
	}
}
