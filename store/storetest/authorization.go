package storetest

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"
	"uuid"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"clavisid.org/clavis/store"
)

// authorizationFixture is a store with two tenants. Tenant a has a client
// and a user; tenant b has a client and a user of its own.
type authorizationFixture struct {
	s       store.Store
	a, b    store.Tenant
	client  store.Client
	user    store.User
	clientB store.Client
	userB   store.User
}

func newAuthorizationFixture(t *testing.T, open OpenFunc) authorizationFixture {
	t.Helper()
	f := authorizationFixture{s: open(t), a: newTenant("a"), b: newTenant("b")}
	mustCreate(t, f.s.Tenants(), f.a)
	mustCreate(t, f.s.Tenants(), f.b)
	f.client = newClient(f.a.ID, "app")
	f.clientB = newClient(f.b.ID, "app")
	mustCreateClient(t, f.s.Clients(), f.client)
	mustCreateClient(t, f.s.Clients(), f.clientB)
	f.user = newUser(f.a.ID, "ada@example.com")
	f.userB = newUser(f.b.ID, "ada@example.com")
	mustCreateUser(t, f.s.Users(), f.user)
	mustCreateUser(t, f.s.Users(), f.userB)
	return f
}

func runAuthorizationRequests(t *testing.T, open OpenFunc) {
	get := func(t *testing.T, f authorizationFixture, id string) (store.AuthorizationRequest, error) {
		t.Helper()
		return f.s.AuthorizationRequests().Get(t.Context(), f.a.ID, id)
	}

	t.Run("CreateGetAndDelete", func(t *testing.T) {
		t.Parallel()
		f := newAuthorizationFixture(t, open)
		want := newAuthorizationRequest(f.client)
		mustCreateAuthorizationRequest(t, f.s, want)
		got, err := get(t, f, want.ID)
		if err != nil {
			t.Fatalf("Get() unexpected error: %v", err)
		}
		if diff := cmp.Diff(normalizeAuthorizationRequest(want), got, cmpopts.EquateEmpty()); diff != "" {
			t.Errorf("Get() mismatch (-want +got):\n%s", diff)
		}
		if err := f.s.AuthorizationRequests().Delete(t.Context(), f.a.ID, want.ID); err != nil {
			t.Fatalf("Delete() unexpected error: %v", err)
		}
		if _, err := get(t, f, want.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get() after Delete() error = %v, want ErrNotFound", err)
		}
		// A request is single use: a second deletion fails.
		if err := f.s.AuthorizationRequests().Delete(t.Context(), f.a.ID, want.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("second Delete() error = %v, want ErrNotFound", err)
		}
	})

	t.Run("EmptyValuesAndExpiredRequests", func(t *testing.T) {
		t.Parallel()
		f := newAuthorizationFixture(t, open)
		want := newAuthorizationRequest(f.client)
		want.Scopes, want.State, want.Nonce, want.CodeChallenge, want.CodeChallengeMethod = nil, "", "", "", ""
		want.LoginHint, want.HintSubject, want.UserInfoClaims, want.IDTokenClaims = "", uuid.Nil(), nil, nil
		want.SessionID, want.ForceConsent = uuid.Nil(), false
		want.RedirectURIProvided = false
		want.ExpiresAt = want.CreatedAt.Add(-time.Second)
		mustCreateAuthorizationRequest(t, f.s, want)
		got, err := get(t, f, want.ID)
		if err != nil {
			t.Fatalf("Get() of an expired request unexpected error: %v", err)
		}
		if diff := cmp.Diff(normalizeAuthorizationRequest(want), got, cmpopts.EquateEmpty()); diff != "" {
			t.Errorf("Get() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("SetSession", func(t *testing.T) {
		t.Parallel()
		f := newAuthorizationFixture(t, open)
		r := newAuthorizationRequest(f.client)
		r.SessionID = uuid.Nil()
		mustCreateAuthorizationRequest(t, f.s, r)
		requests := f.s.AuthorizationRequests()
		session := uuid.NewV7()
		if err := requests.SetSession(t.Context(), f.b.ID, r.ID, session); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("SetSession() through another tenant = %v, want ErrNotFound", err)
		}
		if err := requests.SetSession(t.Context(), f.a.ID, r.ID, session); err != nil {
			t.Fatalf("SetSession() unexpected error: %v", err)
		}
		// A request gets a session once.
		if err := requests.SetSession(t.Context(), f.a.ID, r.ID, uuid.NewV7()); !errors.Is(err, store.ErrConflict) {
			t.Errorf("a second SetSession() = %v, want ErrConflict", err)
		}
		if got, err := get(t, f, r.ID); err != nil || got.SessionID != session {
			t.Errorf("Get() after SetSession() = %v, %v; want session %v", got.SessionID, err, session)
		}
		if err := requests.SetSession(t.Context(), f.a.ID, "missing", session); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("SetSession() of an unknown request = %v, want ErrNotFound", err)
		}
	})

	t.Run("NotFound", func(t *testing.T) {
		t.Parallel()
		f := newAuthorizationFixture(t, open)
		if _, err := get(t, f, "missing"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get() error = %v, want ErrNotFound", err)
		}
		if err := f.s.AuthorizationRequests().Delete(t.Context(), f.a.ID, "missing"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Delete() error = %v, want ErrNotFound", err)
		}
		ghost := newAuthorizationRequest(f.client)
		ghost.ClientID = uuid.NewV7()
		if err := f.s.AuthorizationRequests().Create(t.Context(), ghost); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Create() for an unknown client error = %v, want ErrNotFound", err)
		}
	})

	t.Run("ConflictOnDuplicateID", func(t *testing.T) {
		t.Parallel()
		f := newAuthorizationFixture(t, open)
		first := newAuthorizationRequest(f.client)
		mustCreateAuthorizationRequest(t, f.s, first)
		dup := newAuthorizationRequest(f.client)
		dup.ID = first.ID
		if err := f.s.AuthorizationRequests().Create(t.Context(), dup); !errors.Is(err, store.ErrConflict) {
			t.Errorf("Create() with a duplicate ID error = %v, want ErrConflict", err)
		}
	})

	t.Run("TenantIsolation", func(t *testing.T) {
		t.Parallel()
		f := newAuthorizationFixture(t, open)
		r := newAuthorizationRequest(f.client)
		mustCreateAuthorizationRequest(t, f.s, r)
		requests := f.s.AuthorizationRequests()
		if _, err := requests.Get(t.Context(), f.b.ID, r.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get() from another tenant error = %v, want ErrNotFound", err)
		}
		if err := requests.Delete(t.Context(), f.b.ID, r.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Delete() from another tenant error = %v, want ErrNotFound", err)
		}
		// A request cannot name the client of another tenant.
		foreign := newAuthorizationRequest(f.client)
		foreign.ClientID = f.clientB.ID
		if err := requests.Create(t.Context(), foreign); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Create() for the client of another tenant error = %v, want ErrNotFound", err)
		}
	})

	t.Run("DeletedWithTheClient", func(t *testing.T) {
		t.Parallel()
		f := newAuthorizationFixture(t, open)
		r := newAuthorizationRequest(f.client)
		mustCreateAuthorizationRequest(t, f.s, r)
		if err := f.s.Clients().Delete(t.Context(), f.a.ID, f.client.ID); err != nil {
			t.Fatalf("deleting the client: %v", err)
		}
		if _, err := get(t, f, r.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get() after deleting the client error = %v, want ErrNotFound", err)
		}
	})

	t.Run("DeleteExpired", func(t *testing.T) {
		t.Parallel()
		f := newAuthorizationFixture(t, open)
		now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
		expired, expiresNow, alive, otherTenant := newAuthorizationRequest(f.client),
			newAuthorizationRequest(f.client), newAuthorizationRequest(f.client), newAuthorizationRequest(f.clientB)
		expired.ExpiresAt = now.Add(-time.Minute)
		expiresNow.ExpiresAt = now
		alive.ExpiresAt = now.Add(time.Microsecond)
		otherTenant.ExpiresAt = now.Add(-time.Minute)
		for _, r := range []store.AuthorizationRequest{expired, expiresNow, alive, otherTenant} {
			mustCreateAuthorizationRequest(t, f.s, r)
		}
		n, err := f.s.AuthorizationRequests().DeleteExpired(t.Context(), now)
		if err != nil || n != 3 {
			t.Fatalf("DeleteExpired() = %d, %v; want 3 removed", n, err)
		}
		if _, err := get(t, f, alive.ID); err != nil {
			t.Errorf("Get() of the request that has not expired = %v, want nil", err)
		}
		for _, r := range []store.AuthorizationRequest{expired, expiresNow} {
			if _, err := get(t, f, r.ID); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("Get() of an expired request = %v, want ErrNotFound", err)
			}
		}
	})
}

func runSessions(t *testing.T, open OpenFunc) {
	get := func(t *testing.T, f authorizationFixture, hash []byte) (store.Session, error) {
		t.Helper()
		return f.s.Sessions().GetByTokenHash(t.Context(), f.a.ID, hash)
	}

	t.Run("CreateGetAndDelete", func(t *testing.T) {
		t.Parallel()
		f := newAuthorizationFixture(t, open)
		want := newSession(f.user)
		mustCreateSession(t, f.s, want)
		got, err := get(t, f, want.TokenHash)
		if err != nil {
			t.Fatalf("GetByTokenHash() unexpected error: %v", err)
		}
		if diff := cmp.Diff(normalizeSession(want), got, cmpopts.EquateEmpty()); diff != "" {
			t.Errorf("GetByTokenHash() mismatch (-want +got):\n%s", diff)
		}
		if err := f.s.Sessions().Delete(t.Context(), f.a.ID, want.ID); err != nil {
			t.Fatalf("Delete() unexpected error: %v", err)
		}
		if _, err := get(t, f, want.TokenHash); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetByTokenHash() after Delete() error = %v, want ErrNotFound", err)
		}
	})

	t.Run("EmptyValuesAndExpiredSessions", func(t *testing.T) {
		t.Parallel()
		f := newAuthorizationFixture(t, open)
		want := newSession(f.user)
		want.AMR, want.ACR = nil, ""
		want.ExpiresAt = want.CreatedAt.Add(-time.Second)
		mustCreateSession(t, f.s, want)
		got, err := get(t, f, want.TokenHash)
		if err != nil {
			t.Fatalf("GetByTokenHash() of an expired session unexpected error: %v", err)
		}
		if diff := cmp.Diff(normalizeSession(want), got, cmpopts.EquateEmpty()); diff != "" {
			t.Errorf("GetByTokenHash() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("Touch", func(t *testing.T) {
		t.Parallel()
		f := newAuthorizationFixture(t, open)
		want := newSession(f.user)
		mustCreateSession(t, f.s, want)
		want.LastSeenAt = want.LastSeenAt.Add(time.Hour + time.Nanosecond)
		want.IdleExpiresAt = want.LastSeenAt.Add(24 * time.Hour)
		if err := f.s.Sessions().Touch(t.Context(), f.a.ID, want.ID, want.LastSeenAt, want.IdleExpiresAt); err != nil {
			t.Fatalf("Touch() unexpected error: %v", err)
		}
		got, err := get(t, f, want.TokenHash)
		if err != nil {
			t.Fatalf("GetByTokenHash() unexpected error: %v", err)
		}
		if diff := cmp.Diff(normalizeSession(want), got, cmpopts.EquateEmpty()); diff != "" {
			t.Errorf("GetByTokenHash() after Touch() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("NotFound", func(t *testing.T) {
		t.Parallel()
		f := newAuthorizationFixture(t, open)
		if _, err := get(t, f, hashOf("missing")); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetByTokenHash() error = %v, want ErrNotFound", err)
		}
		now := time.Now()
		if err := f.s.Sessions().Touch(t.Context(), f.a.ID, uuid.NewV7(), now, now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Touch() error = %v, want ErrNotFound", err)
		}
		if err := f.s.Sessions().Delete(t.Context(), f.a.ID, uuid.NewV7()); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Delete() error = %v, want ErrNotFound", err)
		}
		ghost := newSession(f.user)
		ghost.UserID = uuid.NewV7()
		if err := f.s.Sessions().Create(t.Context(), ghost); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Create() for an unknown user error = %v, want ErrNotFound", err)
		}
	})

	t.Run("Conflicts", func(t *testing.T) {
		t.Parallel()
		f := newAuthorizationFixture(t, open)
		first := newSession(f.user)
		mustCreateSession(t, f.s, first)
		sameID := newSession(f.user)
		sameID.ID = first.ID
		if err := f.s.Sessions().Create(t.Context(), sameID); !errors.Is(err, store.ErrConflict) {
			t.Errorf("Create() with a duplicate ID error = %v, want ErrConflict", err)
		}
		// Token hashes are unique across tenants.
		sameToken := newSession(f.userB)
		sameToken.TokenHash = first.TokenHash
		if err := f.s.Sessions().Create(t.Context(), sameToken); !errors.Is(err, store.ErrConflict) {
			t.Errorf("Create() with a duplicate token hash error = %v, want ErrConflict", err)
		}
	})

	t.Run("TenantIsolation", func(t *testing.T) {
		t.Parallel()
		f := newAuthorizationFixture(t, open)
		s := newSession(f.user)
		mustCreateSession(t, f.s, s)
		sessions := f.s.Sessions()
		if _, err := sessions.GetByTokenHash(t.Context(), f.b.ID, s.TokenHash); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetByTokenHash() from another tenant error = %v, want ErrNotFound", err)
		}
		later := s.LastSeenAt.Add(time.Hour)
		if err := sessions.Touch(t.Context(), f.b.ID, s.ID, later, later); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Touch() from another tenant error = %v, want ErrNotFound", err)
		}
		if got, err := get(t, f, s.TokenHash); err != nil || !got.LastSeenAt.Equal(normalizeSession(s).LastSeenAt) {
			t.Errorf("GetByTokenHash() after Touch() from another tenant = %v, %v; want it unchanged", got.LastSeenAt, err)
		}
		if err := sessions.Delete(t.Context(), f.b.ID, s.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Delete() from another tenant error = %v, want ErrNotFound", err)
		}
		foreign := newSession(f.user)
		foreign.UserID = f.userB.ID
		if err := sessions.Create(t.Context(), foreign); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Create() for the user of another tenant error = %v, want ErrNotFound", err)
		}
	})

	t.Run("DeletedWithTheUser", func(t *testing.T) {
		t.Parallel()
		f := newAuthorizationFixture(t, open)
		s := newSession(f.user)
		mustCreateSession(t, f.s, s)
		if err := f.s.Users().Delete(t.Context(), f.a.ID, f.user.ID); err != nil {
			t.Fatalf("deleting the user: %v", err)
		}
		if _, err := get(t, f, s.TokenHash); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetByTokenHash() after deleting the user error = %v, want ErrNotFound", err)
		}
	})

	t.Run("DeleteExpired", func(t *testing.T) {
		t.Parallel()
		f := newAuthorizationFixture(t, open)
		now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
		session := func(idle, absolute time.Duration) store.Session {
			s := newSession(f.user)
			s.IdleExpiresAt, s.ExpiresAt = now.Add(idle), now.Add(absolute)
			return s
		}
		alive := session(time.Microsecond, time.Hour)
		expired := []store.Session{
			session(time.Hour, -time.Minute), // past its lifetime
			session(-time.Minute, time.Hour), // idle for too long
			session(0, time.Hour),            // idle expiry exactly now
			session(time.Hour, 0),            // lifetime exactly now
		}
		foreign := newSession(f.userB)
		foreign.ExpiresAt = now.Add(-time.Minute)
		for _, s := range append([]store.Session{alive, foreign}, expired...) {
			mustCreateSession(t, f.s, s)
		}
		n, err := f.s.Sessions().DeleteExpired(t.Context(), now)
		if err != nil || n != 5 {
			t.Fatalf("DeleteExpired() = %d, %v; want 5 removed", n, err)
		}
		if _, err := get(t, f, alive.TokenHash); err != nil {
			t.Errorf("GetByTokenHash() of the session that has not expired = %v, want nil", err)
		}
		for _, s := range expired {
			if _, err := get(t, f, s.TokenHash); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("GetByTokenHash() of an expired session = %v, want ErrNotFound", err)
			}
		}
	})
}

func runAuthorizationCodes(t *testing.T, open OpenFunc) {
	get := func(t *testing.T, f authorizationFixture, hash []byte) (store.AuthorizationCode, error) {
		t.Helper()
		return f.s.AuthorizationCodes().Get(t.Context(), f.a.ID, hash)
	}

	t.Run("CreateAndGet", func(t *testing.T) {
		t.Parallel()
		f := newAuthorizationFixture(t, open)
		want := newAuthorizationCode(f.client, f.user)
		mustCreateAuthorizationCode(t, f.s, want)
		got, err := get(t, f, want.Hash)
		if err != nil {
			t.Fatalf("Get() unexpected error: %v", err)
		}
		if diff := cmp.Diff(normalizeAuthorizationCode(want), got, cmpopts.EquateEmpty()); diff != "" {
			t.Errorf("Get() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("EmptyValuesAndExpiredCodes", func(t *testing.T) {
		t.Parallel()
		f := newAuthorizationFixture(t, open)
		want := newAuthorizationCode(f.client, f.user)
		want.Scopes, want.AMR, want.Nonce, want.ACR, want.CodeChallenge, want.CodeChallengeMethod = nil, nil, "", "", "", ""
		want.UserInfoClaims, want.IDTokenClaims = nil, nil
		want.ExpiresAt = want.CreatedAt.Add(-time.Second)
		mustCreateAuthorizationCode(t, f.s, want)
		got, err := get(t, f, want.Hash)
		if err != nil {
			t.Fatalf("Get() of an expired code unexpected error: %v", err)
		}
		if diff := cmp.Diff(normalizeAuthorizationCode(want), got, cmpopts.EquateEmpty()); diff != "" {
			t.Errorf("Get() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("NotFound", func(t *testing.T) {
		t.Parallel()
		f := newAuthorizationFixture(t, open)
		if _, err := get(t, f, hashOf("missing")); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get() error = %v, want ErrNotFound", err)
		}
		noClient := newAuthorizationCode(f.client, f.user)
		noClient.ClientID = uuid.NewV7()
		noUser := newAuthorizationCode(f.client, f.user)
		noUser.UserID = uuid.NewV7()
		for name, c := range map[string]store.AuthorizationCode{"client": noClient, "user": noUser} {
			if err := f.s.AuthorizationCodes().Create(t.Context(), c); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("Create() for an unknown %s error = %v, want ErrNotFound", name, err)
			}
		}
	})

	t.Run("ConflictOnDuplicateHash", func(t *testing.T) {
		t.Parallel()
		f := newAuthorizationFixture(t, open)
		first := newAuthorizationCode(f.client, f.user)
		mustCreateAuthorizationCode(t, f.s, first)
		dup := newAuthorizationCode(f.client, f.user)
		dup.Hash = first.Hash
		if err := f.s.AuthorizationCodes().Create(t.Context(), dup); !errors.Is(err, store.ErrConflict) {
			t.Errorf("Create() with a duplicate hash error = %v, want ErrConflict", err)
		}
	})

	t.Run("TenantIsolation", func(t *testing.T) {
		t.Parallel()
		f := newAuthorizationFixture(t, open)
		c := newAuthorizationCode(f.client, f.user)
		mustCreateAuthorizationCode(t, f.s, c)
		codes := f.s.AuthorizationCodes()
		if _, err := codes.Get(t.Context(), f.b.ID, c.Hash); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get() from another tenant error = %v, want ErrNotFound", err)
		}
		foreignClient := newAuthorizationCode(f.client, f.user)
		foreignClient.ClientID = f.clientB.ID
		foreignUser := newAuthorizationCode(f.client, f.user)
		foreignUser.UserID = f.userB.ID
		for name, c := range map[string]store.AuthorizationCode{"client": foreignClient, "user": foreignUser} {
			if err := codes.Create(t.Context(), c); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("Create() for the %s of another tenant error = %v, want ErrNotFound", name, err)
			}
		}
	})

	t.Run("DeletedWithTheClientOrTheUser", func(t *testing.T) {
		t.Parallel()
		f := newAuthorizationFixture(t, open)
		other := newClient(f.a.ID, "other")
		mustCreateClient(t, f.s.Clients(), other)
		byClient := newAuthorizationCode(other, f.user)
		byUser := newAuthorizationCode(f.client, f.user)
		mustCreateAuthorizationCode(t, f.s, byClient)
		mustCreateAuthorizationCode(t, f.s, byUser)
		if err := f.s.Clients().Delete(t.Context(), f.a.ID, other.ID); err != nil {
			t.Fatalf("deleting the client: %v", err)
		}
		if _, err := get(t, f, byClient.Hash); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get() after deleting the client error = %v, want ErrNotFound", err)
		}
		if _, err := get(t, f, byUser.Hash); err != nil {
			t.Fatalf("Get() of a code of another client unexpected error: %v", err)
		}
		if err := f.s.Users().Delete(t.Context(), f.a.ID, f.user.ID); err != nil {
			t.Fatalf("deleting the user: %v", err)
		}
		if _, err := get(t, f, byUser.Hash); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get() after deleting the user error = %v, want ErrNotFound", err)
		}
	})

	t.Run("DeleteExpired", func(t *testing.T) {
		t.Parallel()
		f := newAuthorizationFixture(t, open)
		before := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
		old, atLimit, recent, foreign := newAuthorizationCode(f.client, f.user), newAuthorizationCode(f.client, f.user),
			newAuthorizationCode(f.client, f.user), newAuthorizationCode(f.clientB, f.userB)
		old.ExpiresAt = before.Add(-time.Minute)
		atLimit.ExpiresAt = before
		recent.ExpiresAt = before.Add(time.Microsecond)
		foreign.ExpiresAt = before.Add(-time.Minute)
		for _, c := range []store.AuthorizationCode{old, atLimit, recent, foreign} {
			mustCreateAuthorizationCode(t, f.s, c)
		}
		n, err := f.s.AuthorizationCodes().DeleteExpired(t.Context(), before)
		if err != nil || n != 3 {
			t.Fatalf("DeleteExpired() = %d, %v; want 3 removed", n, err)
		}
		if _, err := get(t, f, recent.Hash); err != nil {
			t.Errorf("Get() of the code expiring after the limit = %v, want nil", err)
		}
		for _, c := range []store.AuthorizationCode{old, atLimit} {
			if _, err := get(t, f, c.Hash); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("Get() of a code expired before the limit = %v, want ErrNotFound", err)
			}
		}
	})
}

// hashOf returns the SHA-256 hash of s, standing in for a hashed token.
func hashOf(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

// newAuthorizationRequest returns a request of c with every field set.
func newAuthorizationRequest(c store.Client) store.AuthorizationRequest {
	created := time.Date(2026, 10, 16, 9, 30, 0, 123456789, time.UTC)
	id := uuid.NewV7().String()
	return store.AuthorizationRequest{
		ID:                  id,
		TenantID:            c.TenantID,
		ClientID:            c.ID,
		BindingHash:         hashOf("binding " + id),
		RedirectURI:         "http://127.0.0.1:51004/callback",
		RedirectURIProvided: true,
		Scopes:              []string{"openid", "profile"},
		State:               "af0ifjsldkj",
		Nonce:               "n-0S6_WzA2Mj",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		LoginHint:           "ada@example.com",
		// Not a reference: any user ID is stored as is.
		HintSubject:    uuid.NewV7(),
		UserInfoClaims: []string{"name", "email"},
		IDTokenClaims:  []string{"email"},
		ForceConsent:   true,
		// Not a reference either.
		SessionID: uuid.NewV7(),
		CreatedAt: created,
		ExpiresAt: created.Add(10 * time.Minute),
	}
}

func mustCreateAuthorizationRequest(t *testing.T, s store.Store, r store.AuthorizationRequest) {
	t.Helper()
	if err := s.AuthorizationRequests().Create(t.Context(), r); err != nil {
		t.Fatalf("Create() unexpected error: %v", err)
	}
}

// normalizeAuthorizationRequest returns r as a store returns it.
func normalizeAuthorizationRequest(r store.AuthorizationRequest) store.AuthorizationRequest {
	r.CreatedAt = r.CreatedAt.UTC().Truncate(time.Microsecond)
	r.ExpiresAt = r.ExpiresAt.UTC().Truncate(time.Microsecond)
	return r
}

// newSession returns a session of u with every field set.
func newSession(u store.User) store.Session {
	created := time.Date(2026, 10, 16, 9, 30, 0, 123456789, time.UTC)
	id := uuid.NewV7()
	return store.Session{
		ID:            id,
		TenantID:      u.TenantID,
		TokenHash:     hashOf("session " + id.String()),
		UserID:        u.ID,
		AuthTime:      created.Add(-time.Second),
		AMR:           []string{"pwd", "otp"},
		ACR:           "urn:example:acr:mfa",
		CreatedAt:     created,
		LastSeenAt:    created.Add(time.Minute),
		IdleExpiresAt: created.Add(24 * time.Hour),
		ExpiresAt:     created.Add(14 * 24 * time.Hour),
	}
}

func mustCreateSession(t *testing.T, s store.Store, session store.Session) {
	t.Helper()
	if err := s.Sessions().Create(t.Context(), session); err != nil {
		t.Fatalf("Create() unexpected error: %v", err)
	}
}

// normalizeSession returns s as a store returns it.
func normalizeSession(s store.Session) store.Session {
	for _, ts := range []*time.Time{&s.AuthTime, &s.CreatedAt, &s.LastSeenAt, &s.IdleExpiresAt, &s.ExpiresAt} {
		*ts = ts.UTC().Truncate(time.Microsecond)
	}
	return s
}

// newAuthorizationCode returns a code issued to c for u with every field
// set.
func newAuthorizationCode(c store.Client, u store.User) store.AuthorizationCode {
	created := time.Date(2026, 10, 16, 9, 31, 0, 123456789, time.UTC)
	return store.AuthorizationCode{
		Hash:                hashOf("code " + uuid.NewV7().String()),
		TenantID:            c.TenantID,
		ClientID:            c.ID,
		UserID:              u.ID,
		SessionID:           uuid.NewV7(),
		RedirectURI:         "https://app.example.com/callback",
		RedirectURIProvided: true,
		Scopes:              []string{"openid", "email"},
		Nonce:               "n-0S6_WzA2Mj",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		AuthTime:            created.Add(-time.Minute),
		AMR:                 []string{"pwd"},
		ACR:                 "urn:example:acr:pwd",
		UserInfoClaims:      []string{"name"},
		IDTokenClaims:       []string{"email", "email_verified"},
		CreatedAt:           created,
		ExpiresAt:           created.Add(time.Minute),
	}
}

func mustCreateAuthorizationCode(t *testing.T, s store.Store, c store.AuthorizationCode) {
	t.Helper()
	if err := s.AuthorizationCodes().Create(t.Context(), c); err != nil {
		t.Fatalf("Create() unexpected error: %v", err)
	}
}

// normalizeAuthorizationCode returns c as a store returns it.
func normalizeAuthorizationCode(c store.AuthorizationCode) store.AuthorizationCode {
	for _, ts := range []*time.Time{&c.AuthTime, &c.CreatedAt, &c.ExpiresAt} {
		*ts = ts.UTC().Truncate(time.Microsecond)
	}
	return c
}
