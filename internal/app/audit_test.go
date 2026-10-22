package app

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"maps"
	"net/url"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
	"uuid"

	"clavisid.org/clavis/internal/oauth"
	"clavisid.org/clavis/store"
)

// eventsOf returns the audit events of a tenant with the given type, newest
// first.
func eventsOf(t *testing.T, d Deps, tenantID uuid.UUID, typ string) []store.AuditEvent {
	t.Helper()
	events, err := d.Store.AuditEvents().List(t.Context(), tenantID, store.AuditQuery{Type: typ,
		Limit: store.MaxPageSize})
	if err != nil {
		t.Fatalf("listing %s events: %v", typ, err)
	}
	return events
}

// lastEvent returns the newest audit event of a tenant with the given type.
func lastEvent(t *testing.T, d Deps, tenantID uuid.UUID, typ string) store.AuditEvent {
	t.Helper()
	events := eventsOf(t, d, tenantID, typ)
	if len(events) == 0 {
		t.Fatalf("no %s event", typ)
	}
	return events[0]
}

// wantEvent checks the fields of e that tests set; the zero values of want
// must match too, except ID, time and origin.
func wantEvent(t *testing.T, e, want store.AuditEvent) {
	t.Helper()
	if want.Details == nil {
		want.Details = map[string]string{}
	}
	if e.TenantID != want.TenantID || e.Type != want.Type || e.Actor != want.Actor || e.UserID != want.UserID ||
		e.ClientID != want.ClientID || e.SessionID != want.SessionID || !maps.Equal(e.Details, want.Details) {
		t.Errorf("%s event = %+v\nwant %+v", want.Type, e, want)
	}
}

func TestAuditRecordsTheOrigin(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	request := WithRequest(t.Context(), RequestInfo{IP: "203.0.113.7", UserAgent: "Mozilla/5.0\r\nInjected: yes"})

	if _, err := SignInToAccount(request, f.d, f.h, f.tenant.ID, "ada@example.com", "correct horse", nil); err != nil {
		t.Fatalf("SignInToAccount() unexpected error: %v", err)
	}
	e := lastEvent(t, f.d, f.tenant.ID, EventSignedIn)
	if e.IP != "203.0.113.7" || e.UserAgent != "Mozilla/5.0Injected: yes" || e.Actor != store.ActorUser ||
		!e.OccurredAt.Equal(*f.now) || e.ID == uuid.Nil() {
		t.Errorf("event of a request = %+v", e)
	}

	// The work of an operator names the operator, whatever the use case
	// would say, and has no address.
	f.partnerConsent(t)
	if err := RevokeGrant(AsOperator(t.Context()), f.d, f.tenant.ID, "ada@example.com", "partner"); err != nil {
		t.Fatalf("RevokeGrant() unexpected error: %v", err)
	}
	if e := lastEvent(t, f.d, f.tenant.ID, EventGrantRevoked); e.Actor != store.ActorOperator || e.IP != "" {
		t.Errorf("event of an operator = %+v", e)
	}

	// A request never acts as an operator, even on a context that was one.
	f.partnerConsent(t)
	ctx := WithRequest(AsOperator(t.Context()), RequestInfo{IP: "2001:db8::1"})
	if err := RevokeGrant(ctx, f.d, f.tenant.ID, "ada@example.com", "partner"); err != nil {
		t.Fatalf("RevokeGrant() unexpected error: %v", err)
	}
	if e := lastEvent(t, f.d, f.tenant.ID, EventGrantRevoked); e.Actor != store.ActorUser || e.IP != "2001:db8::1" {
		t.Errorf("event of a request on an operator's context = %+v", e)
	}
}

// partnerConsent signs ada in for the partner client, which asks for
// consent, and allows it, so ada has a grant for the client.
func (f authzFixture) partnerConsent(t *testing.T) {
	t.Helper()
	p, sessionHash := f.loginForConsent(t, partnerRequest())
	f.consent(t, p.Request.ID, sessionHash, true)
}

func TestCleanUserAgent(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ in, want string }{
		{"curl/8.9.1", "curl/8.9.1"},
		{"a\x00b\tc\x7fd\u0085e", "abcde"},
		{"bad \xff\xfe utf-8", "bad  utf-8"},
		{"rtl \u202eevil", "rtl evil"},
		{"line\u2028break", "linebreak"},
		{"", ""},
	} {
		if got := cleanUserAgent(tc.in); got != tc.want {
			t.Errorf("cleanUserAgent(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	long := strings.Repeat("a", maxUserAgentLength-1) + "\u00e9\u00e9"
	got := cleanUserAgent(long)
	if len(got) > maxUserAgentLength || !utf8.ValidString(got) || !strings.HasPrefix(long, got) ||
		len(got) < maxUserAgentLength-1 {
		t.Errorf("cleanUserAgent() of a long header = %d bytes, valid %v", len(got), utf8.ValidString(got))
	}
}

func FuzzCleanUserAgent(f *testing.F) {
	f.Add("Mozilla/5.0 (X11; Linux x86_64)")
	f.Add("a\r\nb\xff\u202e")
	f.Fuzz(func(t *testing.T, ua string) {
		got := cleanUserAgent(ua)
		if len(got) > maxUserAgentLength || !utf8.ValidString(got) || strings.ContainsAny(got, "\r\n\x00") {
			t.Errorf("cleanUserAgent(%q) = %q", ua, got)
		}
	})
}

// failingAuditStore fails every audit event.
type failingAuditStore struct{ store.Store }

func (failingAuditStore) AuditEvents() store.AuditEvents { return failingAuditEvents{} }

type failingAuditEvents struct{ store.AuditEvents }

func (failingAuditEvents) Create(context.Context, store.AuditEvent) error { return errUnavailable }

// An event that cannot be recorded is logged; the work it records stands.
func TestAuditFailuresAreLogged(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	var logs bytes.Buffer
	f.d.Store = failingAuditStore{f.d.Store}
	f.d.Logger = slog.New(slog.NewTextHandler(&logs, nil))

	if _, err := SignInToAccount(t.Context(), f.d, f.h, f.tenant.ID, "ada@example.com", "correct horse", nil); err != nil {
		t.Fatalf("SignInToAccount() = %v, want the sign-in to succeed", err)
	}
	if out := logs.String(); !strings.Contains(out, `msg="audit event not recorded"`) ||
		!strings.Contains(out, "type="+EventSignedIn) || !strings.Contains(out, errUnavailable.Error()) {
		t.Errorf("logs = %s", out)
	}
}

func TestSignInEvents(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	disabled := store.User{ID: f.d.NewID(), TenantID: f.tenant.ID, Email: "grace@example.com",
		Status: store.UserDisabled, CreatedAt: *f.now, UpdatedAt: *f.now}
	if err := f.d.Store.Users().Create(t.Context(), disabled); err != nil {
		t.Fatalf("creating a disabled user: %v", err)
	}
	if err := SetPassword(t.Context(), f.d, f.h, disabled, "correct horse"); err != nil {
		t.Fatalf("SetPassword() unexpected error: %v", err)
	}
	p := f.start(t, webRequest())
	failed := func(u uuid.UUID, reason string) store.AuditEvent {
		return store.AuditEvent{TenantID: f.tenant.ID, Type: EventSignInFailed, Actor: store.ActorAnonymous,
			UserID: u, ClientID: "web", Details: map[string]string{"method": "password", "reason": reason}}
	}
	for _, tc := range []struct {
		email, password string
		want            store.AuditEvent
	}{
		{"ada@example.com", "wrong horse", failed(f.user.ID, "invalid_credentials")},
		// The typed address of an unknown account is not recorded.
		{"nobody@example.com", "correct horse", failed(uuid.Nil(), "invalid_credentials")},
		{"grace@example.com", "correct horse", failed(disabled.ID, "user_disabled")},
	} {
		if _, err := CompletePasswordLogin(t.Context(), f.d, f.h, f.tenant, p, tc.email, tc.password, nil); err == nil {
			t.Fatalf("CompletePasswordLogin(%s) succeeded", tc.email)
		}
		e := lastEvent(t, f.d, f.tenant.ID, EventSignInFailed)
		wantEvent(t, e, tc.want)
		for _, v := range e.Details {
			if strings.Contains(v, tc.email) {
				t.Errorf("event = %+v, which holds the typed address", e)
			}
		}
	}

	login, err := CompletePasswordLogin(t.Context(), f.d, f.h, f.tenant, p, "ada@example.com", "correct horse", nil)
	if err != nil {
		t.Fatalf("CompletePasswordLogin() unexpected error: %v", err)
	}
	wantEvent(t, lastEvent(t, f.d, f.tenant.ID, EventSignedIn), store.AuditEvent{TenantID: f.tenant.ID,
		Type: EventSignedIn, Actor: store.ActorUser, UserID: f.user.ID, ClientID: "web", SessionID: login.sessionID,
		Details: map[string]string{"method": "password"}})

	// A single sign-on is no new sign-in.
	if _, err := f.startWith(t, webRequest(), oauth.HashToken(login.SessionToken)); err != nil {
		t.Fatalf("StartAuthorization() with the session unexpected error: %v", err)
	}
	if got := len(eventsOf(t, f.d, f.tenant.ID, EventSignedIn)); got != 1 {
		t.Errorf("%d sign-in events after a single sign-on, want 1", got)
	}

	// The account pages sign in without a client.
	if _, err := SignInToAccount(t.Context(), f.d, f.h, f.tenant.ID, "ada@example.com", "wrong horse", nil); err == nil {
		t.Fatal("SignInToAccount() with a wrong password succeeded")
	}
	wantEvent(t, lastEvent(t, f.d, f.tenant.ID, EventSignInFailed), store.AuditEvent{TenantID: f.tenant.ID,
		Type: EventSignInFailed, Actor: store.ActorAnonymous, UserID: f.user.ID,
		Details: map[string]string{"method": "password", "reason": "invalid_credentials"}})
	account, err := SignInToAccount(t.Context(), f.d, f.h, f.tenant.ID, "ada@example.com", "correct horse", nil)
	if err != nil {
		t.Fatalf("SignInToAccount() unexpected error: %v", err)
	}
	wantEvent(t, lastEvent(t, f.d, f.tenant.ID, EventSignedIn), store.AuditEvent{TenantID: f.tenant.ID,
		Type: EventSignedIn, Actor: store.ActorUser, UserID: f.user.ID, SessionID: account.sessionID,
		Details: map[string]string{"method": "password"}})
}

// A sign-in that races a password change ends its session (ADR 0027) and is
// a failure, not a sign-in.
func TestSignInDuringAPasswordChangeIsAFailedSignIn(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	h := pausingHasher{fakeHasher: f.h, verified: make(chan struct{}), resume: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		_, err := SignInToAccount(t.Context(), f.d, h, f.tenant.ID, "ada@example.com", "correct horse", nil)
		done <- err
	}()
	<-h.verified
	*f.now = f.now.Add(time.Second)
	if err := SetPassword(t.Context(), f.d, f.h, f.user, "new horse battery"); err != nil {
		t.Fatalf("SetPassword() unexpected error: %v", err)
	}
	close(h.resume)
	if err := <-done; !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("SignInToAccount() = %v, want ErrInvalidCredentials", err)
	}
	if n := len(eventsOf(t, f.d, f.tenant.ID, EventSignedIn)); n != 0 {
		t.Errorf("%d sign-in events, want none", n)
	}
	wantEvent(t, lastEvent(t, f.d, f.tenant.ID, EventSignInFailed), store.AuditEvent{TenantID: f.tenant.ID,
		Type: EventSignInFailed, Actor: store.ActorAnonymous, UserID: f.user.ID,
		Details: map[string]string{"method": "password", "reason": "invalid_credentials"}})
}

func TestSignOutEvents(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	// The client of a logout is the one its id_token_hint names.
	idToken, sessionHash := f.idTokenFor(t, webRequest())
	session, err := f.d.Store.Sessions().GetByTokenHash(t.Context(), f.tenant.ID, sessionHash)
	if err != nil {
		t.Fatalf("looking up the session: %v", err)
	}
	if _, err := CompleteLogout(t.Context(), f.d, fakeSigner{}, f.tenant, url.Values{"id_token_hint": {idToken}},
		sessionHash); err != nil {
		t.Fatalf("CompleteLogout() unexpected error: %v", err)
	}
	wantEvent(t, lastEvent(t, f.d, f.tenant.ID, EventSignedOut), store.AuditEvent{TenantID: f.tenant.ID,
		Type: EventSignedOut, Actor: store.ActorUser, UserID: f.user.ID, ClientID: "web", SessionID: session.ID})

	login, err := SignInToAccount(t.Context(), f.d, f.h, f.tenant.ID, "ada@example.com", "correct horse", nil)
	if err != nil {
		t.Fatalf("SignInToAccount() unexpected error: %v", err)
	}
	a, err := FindAccount(t.Context(), f.d, f.tenant.ID, oauth.HashToken(login.SessionToken))
	if err != nil {
		t.Fatalf("FindAccount() unexpected error: %v", err)
	}
	if err := SignOutOfAccount(t.Context(), f.d, a); err != nil {
		t.Fatalf("SignOutOfAccount() unexpected error: %v", err)
	}
	wantEvent(t, lastEvent(t, f.d, f.tenant.ID, EventSignedOut), store.AuditEvent{TenantID: f.tenant.ID,
		Type: EventSignedOut, Actor: store.ActorUser, UserID: f.user.ID, SessionID: a.Session.ID})

	// Another user who signs in on the browser signs the previous one out.
	grace, err := CreateUser(t.Context(), f.d, f.tenant.ID, UserSpec{Email: "grace@example.com"})
	if err != nil {
		t.Fatalf("CreateUser() unexpected error: %v", err)
	}
	if err := SetPassword(t.Context(), f.d, f.h, grace, "correct horse"); err != nil {
		t.Fatalf("SetPassword() unexpected error: %v", err)
	}
	previous, _ := f.signIn(t, webRequest())
	old, err := f.d.Store.Sessions().GetByTokenHash(t.Context(), f.tenant.ID, previous)
	if err != nil {
		t.Fatalf("looking up the session: %v", err)
	}
	if _, err := SignInToAccount(t.Context(), f.d, f.h, f.tenant.ID, "grace@example.com", "correct horse",
		previous); err != nil {
		t.Fatalf("SignInToAccount() unexpected error: %v", err)
	}
	wantEvent(t, lastEvent(t, f.d, f.tenant.ID, EventSignedOut), store.AuditEvent{TenantID: f.tenant.ID,
		Type: EventSignedOut, Actor: store.ActorAnonymous, UserID: f.user.ID, SessionID: old.ID,
		Details: map[string]string{"reason": "another_user_signed_in"}})
}

func TestAccountEvents(t *testing.T) {
	t.Parallel()
	f := newSignupFixture(t)
	f.h.minimumChars = 8
	created := lastEvent(t, f.d, f.tenant.ID, EventUserCreated)
	wantEvent(t, created, store.AuditEvent{TenantID: f.tenant.ID, Type: EventUserCreated,
		Actor: store.ActorOperator, UserID: f.user.ID})
	wantEvent(t, lastEvent(t, f.d, f.tenant.ID, EventPasswordChanged), store.AuditEvent{TenantID: f.tenant.ID,
		Type: EventPasswordChanged, Actor: store.ActorOperator, UserID: f.user.ID,
		Details: map[string]string{"how": "operator"}})

	login, err := SignInToAccount(t.Context(), f.d, f.h, f.tenant.ID, "ada@example.com", "correct horse", nil)
	if err != nil {
		t.Fatalf("SignInToAccount() unexpected error: %v", err)
	}
	a, err := FindAccount(t.Context(), f.d, f.tenant.ID, oauth.HashToken(login.SessionToken))
	if err != nil {
		t.Fatalf("FindAccount() unexpected error: %v", err)
	}
	if err := ChangePassword(t.Context(), f.d, f.h, a, "wrong horse", "new horse battery"); err == nil {
		t.Fatal("ChangePassword() with a wrong current password succeeded")
	}
	wantEvent(t, lastEvent(t, f.d, f.tenant.ID, EventPasswordChangeFailed), store.AuditEvent{
		TenantID: f.tenant.ID, Type: EventPasswordChangeFailed, Actor: store.ActorUser, UserID: f.user.ID,
		SessionID: a.Session.ID, Details: map[string]string{"reason": "invalid_credentials"}})
	*f.now = f.now.Add(time.Second)
	if err := ChangePassword(t.Context(), f.d, f.h, a, "correct horse", "new horse battery"); err != nil {
		t.Fatalf("ChangePassword() unexpected error: %v", err)
	}
	wantEvent(t, lastEvent(t, f.d, f.tenant.ID, EventPasswordChanged), store.AuditEvent{TenantID: f.tenant.ID,
		Type: EventPasswordChanged, Actor: store.ActorUser, UserID: f.user.ID, SessionID: a.Session.ID,
		Details: map[string]string{"how": "account"}})

	// The event names the claims that changed, never their values.
	p := a.User.Profile
	p.GivenName, p.Address.Locality = "Ada", "London"
	u, err := UpdateProfile(t.Context(), f.d, a.User, p)
	if err != nil {
		t.Fatalf("UpdateProfile() unexpected error: %v", err)
	}
	wantEvent(t, lastEvent(t, f.d, f.tenant.ID, EventProfileUpdated), store.AuditEvent{TenantID: f.tenant.ID,
		Type: EventProfileUpdated, Actor: store.ActorUser, UserID: f.user.ID,
		Details: map[string]string{"claims": "given_name address.locality"}})
	if _, err := UpdateProfile(t.Context(), f.d, u, u.Profile); err != nil {
		t.Fatalf("UpdateProfile() unexpected error: %v", err)
	}
	if n := len(eventsOf(t, f.d, f.tenant.ID, EventProfileUpdated)); n != 1 {
		t.Errorf("%d profile events after saving an unchanged profile, want 1", n)
	}

	*f.now = f.now.Add(time.Second)
	if _, err := CompletePasswordReset(t.Context(), f.d, f.h, f.verifiedReset(t), "reset horse battery"); err != nil {
		t.Fatalf("CompletePasswordReset() unexpected error: %v", err)
	}
	wantEvent(t, lastEvent(t, f.d, f.tenant.ID, EventPasswordChanged), store.AuditEvent{TenantID: f.tenant.ID,
		Type: EventPasswordChanged, Actor: store.ActorUser, UserID: f.user.ID,
		Details: map[string]string{"how": "reset"}})

	// A signup creates its user, who signs in.
	signup, err := CompleteSignup(t.Context(), f.d, f.h, f.tenant, f.verified(t, "grace@example.com"),
		"grace horse battery", nil, nil)
	if err != nil {
		t.Fatalf("CompleteSignup() unexpected error: %v", err)
	}
	grace, err := FindUser(t.Context(), f.d, f.tenant.ID, "grace@example.com")
	if err != nil {
		t.Fatalf("FindUser() unexpected error: %v", err)
	}
	wantEvent(t, lastEvent(t, f.d, f.tenant.ID, EventUserCreated), store.AuditEvent{TenantID: f.tenant.ID,
		Type: EventUserCreated, Actor: store.ActorUser, UserID: grace.ID})
	session, err := f.d.Store.Sessions().GetByTokenHash(t.Context(), f.tenant.ID, oauth.HashToken(signup.SessionToken))
	if err != nil {
		t.Fatalf("looking up the session: %v", err)
	}
	wantEvent(t, lastEvent(t, f.d, f.tenant.ID, EventSignedIn), store.AuditEvent{TenantID: f.tenant.ID,
		Type: EventSignedIn, Actor: store.ActorUser, UserID: grace.ID, SessionID: session.ID,
		Details: map[string]string{"method": "password"}})

	// The events of a deleted user stay.
	if err := DeleteUser(t.Context(), f.d, f.tenant.ID, "grace@example.com"); err != nil {
		t.Fatalf("DeleteUser() unexpected error: %v", err)
	}
	wantEvent(t, lastEvent(t, f.d, f.tenant.ID, EventUserDeleted), store.AuditEvent{TenantID: f.tenant.ID,
		Type: EventUserDeleted, Actor: store.ActorOperator, UserID: grace.ID})
	if n := len(eventsOf(t, f.d, f.tenant.ID, EventUserCreated)); n != 2 {
		t.Errorf("%d user creation events after a deletion, want 2", n)
	}
}

// A signup that answers its authorization request names the client.
func TestSignupEventsNameTheClient(t *testing.T) {
	t.Parallel()
	f := newSignupFixture(t)
	v := f.verified(t, "grace@example.com")
	p, err := FindAuthorizationRequest(t.Context(), f.d, f.tenant.ID, v.AuthorizationRequestID, testBinding)
	if err != nil {
		t.Fatalf("FindAuthorizationRequest() unexpected error: %v", err)
	}
	signup, err := CompleteSignup(t.Context(), f.d, f.h, f.tenant, v, "grace horse battery", &p, nil)
	if err != nil || !signup.Request {
		t.Fatalf("CompleteSignup() = %+v, %v; want a response to the request", signup, err)
	}
	if e := lastEvent(t, f.d, f.tenant.ID, EventSignedIn); e.ClientID != "web" || e.SessionID != signup.sessionID {
		t.Errorf("sign-in event = %+v, want the web client and the new session", e)
	}
}

func TestConsentAndGrantEvents(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	p, sessionHash := f.loginForConsent(t, partnerRequest())
	session, err := f.d.Store.Sessions().GetByTokenHash(t.Context(), f.tenant.ID, sessionHash)
	if err != nil {
		t.Fatalf("looking up the session: %v", err)
	}
	f.consent(t, p.Request.ID, sessionHash, false)
	consent := store.AuditEvent{TenantID: f.tenant.ID, Type: EventConsentDenied, Actor: store.ActorUser,
		UserID: f.user.ID, ClientID: "partner", SessionID: session.ID,
		Details: map[string]string{"scopes": "openid profile"}}
	wantEvent(t, lastEvent(t, f.d, f.tenant.ID, EventConsentDenied), consent)

	a, err := f.startWith(t, partnerRequest(), sessionHash)
	if err != nil || !a.Consent {
		t.Fatalf("StartAuthorization() = %+v, %v; want consent", a, err)
	}
	f.consent(t, a.RequestID, sessionHash, true)
	consent.Type = EventConsentAllowed
	wantEvent(t, lastEvent(t, f.d, f.tenant.ID, EventConsentAllowed), consent)

	if err := RevokeGrant(t.Context(), f.d, f.tenant.ID, "ada@example.com", "partner"); err != nil {
		t.Fatalf("RevokeGrant() unexpected error: %v", err)
	}
	wantEvent(t, lastEvent(t, f.d, f.tenant.ID, EventGrantRevoked), store.AuditEvent{TenantID: f.tenant.ID,
		Type: EventGrantRevoked, Actor: store.ActorUser, UserID: f.user.ID, ClientID: "partner"})
}

func TestTokenEvents(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)

	code, client := f.codeFor(t, webRequest())
	if _, err := ExchangeCode(t.Context(), f.d, fakeSigner{}, f.tenant, client, codeRequest(code)); err != nil {
		t.Fatalf("ExchangeCode() unexpected error: %v", err)
	}
	stored, err := f.d.Store.AuthorizationCodes().Get(t.Context(), f.tenant.ID, oauth.HashToken(code))
	if err != nil {
		t.Fatalf("looking up the code: %v", err)
	}
	if _, err := ExchangeCode(t.Context(), f.d, fakeSigner{}, f.tenant, client, codeRequest(code)); err == nil {
		t.Fatal("a replayed code succeeded")
	}
	wantEvent(t, lastEvent(t, f.d, f.tenant.ID, EventCodeReplayed), store.AuditEvent{TenantID: f.tenant.ID,
		Type: EventCodeReplayed, Actor: store.ActorClient, UserID: f.user.ID, ClientID: "web",
		SessionID: stored.SessionID})

	resp, client := f.refreshTokenFor(t, offlineRequest())
	_, family, err := f.d.Store.RefreshTokens().Get(t.Context(), f.tenant.ID, oauth.HashToken(resp.RefreshToken))
	if err != nil {
		t.Fatalf("looking up the refresh token: %v", err)
	}
	if _, err := f.refresh(t, client, resp.RefreshToken); err != nil {
		t.Fatalf("refresh unexpected error: %v", err)
	}
	if _, err := f.refresh(t, client, resp.RefreshToken); err == nil {
		t.Fatal("a reused refresh token succeeded")
	}
	wantEvent(t, lastEvent(t, f.d, f.tenant.ID, EventRefreshTokenReused), store.AuditEvent{TenantID: f.tenant.ID,
		Type: EventRefreshTokenReused, Actor: store.ActorClient, UserID: f.user.ID, ClientID: "web",
		SessionID: family.SessionID, Details: map[string]string{"refresh_token_family": family.ID.String()}})

	resp, _ = f.refreshTokenFor(t, offlineRequest())
	_, family, err = f.d.Store.RefreshTokens().Get(t.Context(), f.tenant.ID, oauth.HashToken(resp.RefreshToken))
	if err != nil {
		t.Fatalf("looking up the refresh token: %v", err)
	}
	if err := f.revoke(t, "web", resp.RefreshToken); err != nil {
		t.Fatalf("RevokeToken() unexpected error: %v", err)
	}
	wantEvent(t, lastEvent(t, f.d, f.tenant.ID, EventTokenRevoked), store.AuditEvent{TenantID: f.tenant.ID,
		Type: EventTokenRevoked, Actor: store.ActorClient, UserID: f.user.ID, ClientID: "web",
		SessionID: family.SessionID, Details: map[string]string{"token_type": "refresh_token",
			"refresh_token_family": family.ID.String()}})

	resp, _ = f.refreshTokenFor(t, offlineRequest())
	claims, ok, err := verifyAccessToken(t.Context(), fakeSigner{}, f.tenant, resp.AccessToken)
	if err != nil || !ok {
		t.Fatalf("verifyAccessToken() = %v, %v", ok, err)
	}
	if err := f.revoke(t, "web", resp.AccessToken); err != nil {
		t.Fatalf("RevokeToken() unexpected error: %v", err)
	}
	wantEvent(t, lastEvent(t, f.d, f.tenant.ID, EventTokenRevoked), store.AuditEvent{TenantID: f.tenant.ID,
		Type: EventTokenRevoked, Actor: store.ActorClient, UserID: f.user.ID, ClientID: "web",
		Details: map[string]string{"token_type": "access_token", "jti": claims.JWTID}})

	// Unknown tokens need nothing and are no event.
	before := len(eventsOf(t, f.d, f.tenant.ID, EventTokenRevoked))
	if err := f.revoke(t, "web", "unknown"); err != nil {
		t.Fatalf("RevokeToken() of an unknown token unexpected error: %v", err)
	}
	if n := len(eventsOf(t, f.d, f.tenant.ID, EventTokenRevoked)); n != before {
		t.Errorf("%d revocation events after an unknown token, want %d", n, before)
	}
}

func TestClientAndTenantEvents(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	wantEvent(t, lastEvent(t, f.d, f.tenant.ID, EventClientCreated), store.AuditEvent{TenantID: f.tenant.ID,
		Type: EventClientCreated, Actor: store.ActorOperator, ClientID: "service",
		Details: map[string]string{"type": "confidential", "pkce_exempt": "false", "skip_consent": "false"}})
	// ADR 0018: the exemption from PKCE is audited.
	var legacy store.AuditEvent
	for _, e := range eventsOf(t, f.d, f.tenant.ID, EventClientCreated) {
		if e.ClientID == "legacy" {
			legacy = e
		}
	}
	wantEvent(t, legacy, store.AuditEvent{TenantID: f.tenant.ID, Type: EventClientCreated,
		Actor: store.ActorOperator, ClientID: "legacy",
		Details: map[string]string{"type": "confidential", "pkce_exempt": "true", "skip_consent": "true"}})

	if _, err := RotateClientSecret(t.Context(), f.d, f.tenant.ID, "web"); err != nil {
		t.Fatalf("RotateClientSecret() unexpected error: %v", err)
	}
	wantEvent(t, lastEvent(t, f.d, f.tenant.ID, EventClientSecretRotated), store.AuditEvent{TenantID: f.tenant.ID,
		Type: EventClientSecretRotated, Actor: store.ActorOperator, ClientID: "web"})
	if err := DeleteClient(t.Context(), f.d, f.tenant.ID, "spa"); err != nil {
		t.Fatalf("DeleteClient() unexpected error: %v", err)
	}
	wantEvent(t, lastEvent(t, f.d, f.tenant.ID, EventClientDeleted), store.AuditEvent{TenantID: f.tenant.ID,
		Type: EventClientDeleted, Actor: store.ActorOperator, ClientID: "spa"})

	tn, err := TenantByID(t.Context(), f.d, f.tenant.ID)
	if err != nil {
		t.Fatalf("TenantByID() unexpected error: %v", err)
	}
	name, signup := "Acme Corporation", true
	if _, err := UpdateTenant(t.Context(), f.d, tn.Slug, TenantChanges{SignupEnabled: &signup}); err != nil {
		t.Fatalf("UpdateTenant() unexpected error: %v", err)
	}
	wantEvent(t, lastEvent(t, f.d, f.tenant.ID, EventTenantUpdated), store.AuditEvent{TenantID: f.tenant.ID,
		Type: EventTenantUpdated, Actor: store.ActorOperator, Details: map[string]string{"signup_enabled": "true"}})
	*f.now = f.now.Add(time.Second)
	if _, err := UpdateTenant(t.Context(), f.d, tn.Slug, TenantChanges{Name: &name}); err != nil {
		t.Fatalf("UpdateTenant() unexpected error: %v", err)
	}
	wantEvent(t, lastEvent(t, f.d, f.tenant.ID, EventTenantUpdated), store.AuditEvent{TenantID: f.tenant.ID,
		Type: EventTenantUpdated, Actor: store.ActorOperator, Details: map[string]string{"name": name}})
}

func TestChangedClaims(t *testing.T) {
	t.Parallel()
	before := store.Profile{Name: "Ada", PhoneNumber: "+441234567890", PhoneNumberVerified: true,
		Address: store.Address{Country: "UK"}}
	for _, tc := range []struct {
		change func(*store.Profile)
		want   string
	}{
		{func(*store.Profile) {}, ""},
		{func(p *store.Profile) { p.Name = "" }, "name"},
		{func(p *store.Profile) { p.Website, p.Address.Country = "https://ada.example", "GB" },
			"website address.country"},
		{func(p *store.Profile) { p.PhoneNumber, p.PhoneNumberVerified = "+441234567891", false },
			"phone_number phone_number_verified"},
	} {
		after := before
		tc.change(&after)
		if got := changedClaims(before, after); got != tc.want {
			t.Errorf("changedClaims() = %q, want %q", got, tc.want)
		}
	}
	// Every text claim of the profile is compared.
	var p store.Profile
	for i, c := range profileClaims(&p) {
		*c.value = "x"
		if got := changedClaims(store.Profile{}, p); !strings.HasSuffix(got, c.name) || strings.Count(got, " ") != i {
			t.Errorf("changedClaims() after setting %s = %q", c.name, got)
		}
	}
}

func TestPurgeAuditEvents(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	start := *f.now
	total := len(eventsOf(t, f.d, f.tenant.ID, ""))
	*f.now = start.Add(DefaultAuditRetention + time.Second)
	if _, err := SignInToAccount(t.Context(), f.d, f.h, f.tenant.ID, "ada@example.com", "correct horse", nil); err != nil {
		t.Fatalf("SignInToAccount() unexpected error: %v", err)
	}

	// No retention keeps every event.
	if err := PurgeAuditEvents(t.Context(), f.d, 0); err != nil {
		t.Fatalf("PurgeAuditEvents(0) unexpected error: %v", err)
	}
	if n := len(eventsOf(t, f.d, f.tenant.ID, "")); n != total+1 {
		t.Errorf("%d events after a purge without retention, want %d", n, total+1)
	}
	if err := PurgeAuditEvents(t.Context(), f.d, DefaultAuditRetention); err != nil {
		t.Fatalf("PurgeAuditEvents() unexpected error: %v", err)
	}
	events := eventsOf(t, f.d, f.tenant.ID, "")
	if len(events) != 1 || events[0].Type != EventSignedIn {
		t.Errorf("events after the purge = %+v, want the sign-in only", events)
	}

	f.d.Store = failingPurgeAuditStore{f.d.Store}
	if err := PurgeAuditEvents(t.Context(), f.d, DefaultAuditRetention); !errors.Is(err, errUnavailable) {
		t.Errorf("PurgeAuditEvents() = %v, want the store error", err)
	}
}

type failingPurgeAuditStore struct{ store.Store }

func (failingPurgeAuditStore) AuditEvents() store.AuditEvents { return failingPurgeAuditEvents{} }

type failingPurgeAuditEvents struct{ store.AuditEvents }

func (failingPurgeAuditEvents) DeleteBefore(context.Context, time.Time) (int64, error) {
	return 0, errUnavailable
}

func TestListAuditEvents(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	grace, err := CreateUser(t.Context(), f.d, f.tenant.ID, UserSpec{Email: "grace@example.com"})
	if err != nil {
		t.Fatalf("CreateUser() unexpected error: %v", err)
	}
	if err := DeleteUser(t.Context(), f.d, f.tenant.ID, "grace@example.com"); err != nil {
		t.Fatalf("DeleteUser() unexpected error: %v", err)
	}
	page, err := ListAuditEvents(t.Context(), f.d, f.tenant.ID, store.AuditQuery{Limit: store.MaxPageSize})
	if err != nil {
		t.Fatalf("ListAuditEvents() unexpected error: %v", err)
	}
	if len(page.Events) == 0 || page.Events[0].Type != EventUserDeleted || page.Events[0].UserID != grace.ID {
		t.Fatalf("newest event = %+v, want the deletion of grace", page.Events[0])
	}
	// The address of a deleted user is gone with the user.
	if _, ok := page.Emails[grace.ID]; ok || page.Emails[f.user.ID] != "ada@example.com" || len(page.Emails) != 1 {
		t.Errorf("Emails = %v, want only ada's address", page.Emails)
	}

	page, err = ListAuditEvents(t.Context(), f.d, f.tenant.ID, store.AuditQuery{UserID: f.user.ID,
		Type: EventUserCreated, Limit: 10})
	if err != nil || len(page.Events) != 1 || page.Events[0].UserID != f.user.ID {
		t.Errorf("ListAuditEvents() filtered = %+v, %v", page.Events, err)
	}
	if _, err := ListAuditEvents(t.Context(), f.d, f.tenant.ID, store.AuditQuery{}); !errors.Is(err, store.ErrInvalidArgument) {
		t.Errorf("ListAuditEvents() without a limit = %v, want ErrInvalidArgument", err)
	}
}
