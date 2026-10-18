package storetest

import (
	"errors"
	"sync"
	"testing"
	"time"
	"uuid"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"clavisid.org/clavis/store"
)

func runRefreshTokens(t *testing.T, open OpenFunc) {
	t.Run("CreateAndGet", func(t *testing.T) {
		t.Parallel()
		f := newAuthorizationFixture(t, open)
		full, first := newRefreshTokenFamily(f.client, f.user)
		bare, bareToken := newRefreshTokenFamily(f.client, f.user)
		bare.SessionID, bare.CodeHash, bare.AMR, bare.ACR = uuid.Nil(), nil, nil, ""
		bare.UserInfoClaims, bare.IDTokenClaims = nil, nil
		for _, c := range []struct {
			family store.RefreshTokenFamily
			token  store.RefreshToken
		}{{full, first}, {bare, bareToken}} {
			mustCreateRefreshTokenFamily(t, f.s, c.family, c.token)
			token, family, err := f.s.RefreshTokens().Get(t.Context(), f.a.ID, c.token.Hash)
			if err != nil {
				t.Fatalf("Get() unexpected error: %v", err)
			}
			if diff := cmp.Diff(normalizeRefreshToken(c.token), token, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Get() token mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(normalizeRefreshTokenFamily(c.family), family, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Get() family mismatch (-want +got):\n%s", diff)
			}
		}
	})

	t.Run("NotFoundAndConflicts", func(t *testing.T) {
		t.Parallel()
		f := newAuthorizationFixture(t, open)
		tokens := f.s.RefreshTokens()
		family, first := newRefreshTokenFamily(f.client, f.user)
		mustCreateRefreshTokenFamily(t, f.s, family, first)
		if _, _, err := tokens.Get(t.Context(), f.a.ID, hashOf("missing")); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get() of an unknown token error = %v, want ErrNotFound", err)
		}
		if _, _, err := tokens.Get(t.Context(), f.b.ID, first.Hash); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get() through another tenant error = %v, want ErrNotFound", err)
		}

		sameID, sameIDToken := newRefreshTokenFamily(f.client, f.user)
		sameID.ID, sameIDToken.FamilyID = family.ID, family.ID
		sameHash, sameHashToken := newRefreshTokenFamily(f.client, f.user)
		sameHashToken.Hash = first.Hash
		for name, c := range map[string]struct {
			family store.RefreshTokenFamily
			token  store.RefreshToken
		}{"family ID": {sameID, sameIDToken}, "token hash": {sameHash, sameHashToken}} {
			if err := tokens.Create(t.Context(), c.family, c.token); !errors.Is(err, store.ErrConflict) {
				t.Errorf("Create() with a duplicate %s error = %v, want ErrConflict", name, err)
			}
		}
		// The family whose token was refused was not stored either.
		if err := tokens.RevokeFamily(t.Context(), f.a.ID, sameHash.ID, time.Now()); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("RevokeFamily() of the refused family error = %v, want ErrNotFound", err)
		}

		foreignClient, foreignClientToken := newRefreshTokenFamily(f.client, f.user)
		foreignClient.ClientID = f.clientB.ID
		foreignUser, foreignUserToken := newRefreshTokenFamily(f.client, f.user)
		foreignUser.UserID = f.userB.ID
		for name, c := range map[string]struct {
			family store.RefreshTokenFamily
			token  store.RefreshToken
		}{"client": {foreignClient, foreignClientToken}, "user": {foreignUser, foreignUserToken}} {
			if err := tokens.Create(t.Context(), c.family, c.token); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("Create() for the %s of another tenant error = %v, want ErrNotFound", name, err)
			}
		}
		other, otherToken := newRefreshTokenFamily(f.client, f.user)
		otherToken.FamilyID = uuid.NewV7()
		if err := tokens.Create(t.Context(), other, otherToken); !errors.Is(err, store.ErrInvalidArgument) {
			t.Errorf("Create() with a token of another family error = %v, want ErrInvalidArgument", err)
		}
	})

	t.Run("Rotate", func(t *testing.T) {
		t.Parallel()
		f := newAuthorizationFixture(t, open)
		tokens := f.s.RefreshTokens()
		family, first := newRefreshTokenFamily(f.client, f.user)
		mustCreateRefreshTokenFamily(t, f.s, family, first)
		second := nextRefreshToken(first)
		if err := tokens.Rotate(t.Context(), f.a.ID, first.Hash, second); err != nil {
			t.Fatalf("Rotate() unexpected error: %v", err)
		}
		got, _, err := tokens.Get(t.Context(), f.a.ID, first.Hash)
		if err != nil || !got.RotatedAt.Equal(second.IssuedAt.Truncate(time.Microsecond)) {
			t.Errorf("Get() of the rotated token = %v, %v; want RotatedAt %v", got.RotatedAt, err, second.IssuedAt)
		}
		got, gotFamily, err := tokens.Get(t.Context(), f.a.ID, second.Hash)
		if err != nil {
			t.Fatalf("Get() of the successor unexpected error: %v", err)
		}
		if diff := cmp.Diff(normalizeRefreshToken(second), got, cmpopts.EquateEmpty()); diff != "" {
			t.Errorf("Get() successor mismatch (-want +got):\n%s", diff)
		}
		wantFamily := family
		wantFamily.IdleExpiresAt = second.ExpiresAt
		if diff := cmp.Diff(normalizeRefreshTokenFamily(wantFamily), gotFamily, cmpopts.EquateEmpty()); diff != "" {
			t.Errorf("Get() family after Rotate() mismatch (-want +got):\n%s", diff)
		}

		// A rotated token cannot be rotated again, and its refused
		// successor is not stored.
		third := nextRefreshToken(first)
		if err := tokens.Rotate(t.Context(), f.a.ID, first.Hash, third); !errors.Is(err, store.ErrConflict) {
			t.Errorf("Rotate() of a rotated token error = %v, want ErrConflict", err)
		}
		if _, _, err := tokens.Get(t.Context(), f.a.ID, third.Hash); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get() of a refused successor = %v, want ErrNotFound", err)
		}

		otherFamily, otherFirst := newRefreshTokenFamily(f.client, f.user)
		mustCreateRefreshTokenFamily(t, f.s, otherFamily, otherFirst)
		foreign := nextRefreshToken(first)
		foreign.TenantID = f.b.ID
		for name, c := range map[string]struct {
			tenantID uuid.UUID
			hash     []byte
			next     store.RefreshToken
		}{
			"an unknown token":            {f.a.ID, hashOf("missing"), nextRefreshToken(second)},
			"a token of another family":   {f.a.ID, otherFirst.Hash, nextRefreshToken(second)},
			"a token of another tenant":   {f.b.ID, second.Hash, foreign},
			"a successor of a new family": {f.a.ID, second.Hash, nextRefreshToken(newRefreshTokenFamilyToken(f))},
		} {
			if err := tokens.Rotate(t.Context(), c.tenantID, c.hash, c.next); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("Rotate() of %s error = %v, want ErrNotFound", name, err)
			}
		}
		mismatch := nextRefreshToken(second)
		mismatch.TenantID = f.b.ID
		if err := tokens.Rotate(t.Context(), f.a.ID, second.Hash, mismatch); !errors.Is(err, store.ErrInvalidArgument) {
			t.Errorf("Rotate() with a successor of another tenant error = %v, want ErrInvalidArgument", err)
		}

		// The current token of a revoked family cannot be rotated.
		if err := tokens.RevokeFamily(t.Context(), f.a.ID, family.ID, time.Now()); err != nil {
			t.Fatalf("RevokeFamily() unexpected error: %v", err)
		}
		if err := tokens.Rotate(t.Context(), f.a.ID, second.Hash, nextRefreshToken(second)); !errors.Is(err, store.ErrConflict) {
			t.Errorf("Rotate() in a revoked family error = %v, want ErrConflict", err)
		}
		if got, _, err := tokens.Get(t.Context(), f.a.ID, second.Hash); err != nil || !got.RotatedAt.IsZero() {
			t.Errorf("Get() after a refused rotation = %v, %v; want a token that is not rotated", got.RotatedAt, err)
		}
	})

	t.Run("RotateOnce", func(t *testing.T) {
		t.Parallel()
		f := newAuthorizationFixture(t, open)
		tokens := f.s.RefreshTokens()
		family, first := newRefreshTokenFamily(f.client, f.user)
		mustCreateRefreshTokenFamily(t, f.s, family, first)

		var wg sync.WaitGroup
		successors := make([]store.RefreshToken, 8)
		errs := make([]error, len(successors))
		for i := range successors {
			successors[i] = nextRefreshToken(first)
			wg.Go(func() { errs[i] = tokens.Rotate(t.Context(), f.a.ID, first.Hash, successors[i]) })
		}
		wg.Wait()
		var succeeded, stored int
		for i, err := range errs {
			switch {
			case err == nil:
				succeeded++
			case !errors.Is(err, store.ErrConflict):
				t.Errorf("concurrent Rotate() error = %v, want nil or ErrConflict", err)
			}
			if _, _, err := tokens.Get(t.Context(), f.a.ID, successors[i].Hash); err == nil {
				stored++
			}
		}
		if succeeded != 1 || stored != 1 {
			t.Errorf("%d concurrent rotations succeeded and %d successors were stored, want 1 and 1", succeeded, stored)
		}
	})

	t.Run("RevokeFamily", func(t *testing.T) {
		t.Parallel()
		f := newAuthorizationFixture(t, open)
		tokens := f.s.RefreshTokens()
		family, first := newRefreshTokenFamily(f.client, f.user)
		mustCreateRefreshTokenFamily(t, f.s, family, first)
		at := time.Date(2026, 10, 17, 10, 0, 0, 0, time.UTC)
		if err := tokens.RevokeFamily(t.Context(), f.b.ID, family.ID, at); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("RevokeFamily() through another tenant error = %v, want ErrNotFound", err)
		}
		if err := tokens.RevokeFamily(t.Context(), f.a.ID, uuid.NewV7(), at); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("RevokeFamily() of an unknown family error = %v, want ErrNotFound", err)
		}
		for _, when := range []time.Time{at, at.Add(time.Hour)} {
			if err := tokens.RevokeFamily(t.Context(), f.a.ID, family.ID, when); err != nil {
				t.Fatalf("RevokeFamily() unexpected error: %v", err)
			}
		}
		// The family keeps the time of its first revocation.
		if _, got, err := tokens.Get(t.Context(), f.a.ID, first.Hash); err != nil || !got.RevokedAt.Equal(at) {
			t.Errorf("Get() after RevokeFamily() = %v, %v; want RevokedAt %v", got.RevokedAt, err, at)
		}
	})

	t.Run("RevokeByCode", func(t *testing.T) {
		t.Parallel()
		f := newAuthorizationFixture(t, open)
		tokens := f.s.RefreshTokens()
		revoked, revokedToken := newRefreshTokenFamily(f.client, f.user)
		kept, keptToken := newRefreshTokenFamily(f.client, f.user)
		mustCreateRefreshTokenFamily(t, f.s, revoked, revokedToken)
		mustCreateRefreshTokenFamily(t, f.s, kept, keptToken)
		at := time.Date(2026, 10, 17, 10, 0, 0, 0, time.UTC)
		if n, err := tokens.RevokeByCode(t.Context(), f.b.ID, revoked.CodeHash, at); err != nil || n != 0 {
			t.Errorf("RevokeByCode() through another tenant = %d, %v; want 0", n, err)
		}
		if n, err := tokens.RevokeByCode(t.Context(), f.a.ID, revoked.CodeHash, at); err != nil || n != 1 {
			t.Errorf("RevokeByCode() = %d, %v; want 1", n, err)
		}
		if n, err := tokens.RevokeByCode(t.Context(), f.a.ID, revoked.CodeHash, at.Add(time.Hour)); err != nil || n != 0 {
			t.Errorf("a second RevokeByCode() = %d, %v; want 0", n, err)
		}
		wantRevokedAt(t, f, revokedToken, at)
		wantRevokedAt(t, f, keptToken, time.Time{})
	})

	t.Run("RevokeByUserAndClient", func(t *testing.T) {
		t.Parallel()
		f := newAuthorizationFixture(t, open)
		tokens := f.s.RefreshTokens()
		other := newClient(f.a.ID, "other")
		mustCreateClient(t, f.s.Clients(), other)
		grace := newUser(f.a.ID, "grace@example.com")
		mustCreateUser(t, f.s.Users(), grace)
		var revoked, kept []store.RefreshToken
		for _, c := range []struct {
			client store.Client
			user   store.User
			revoke bool
		}{{f.client, f.user, true}, {f.client, f.user, true}, {other, f.user, false}, {f.client, grace, false}} {
			family, token := newRefreshTokenFamily(c.client, c.user)
			mustCreateRefreshTokenFamily(t, f.s, family, token)
			if c.revoke {
				revoked = append(revoked, token)
			} else {
				kept = append(kept, token)
			}
		}
		at := time.Date(2026, 10, 17, 10, 0, 0, 0, time.UTC)
		if n, err := tokens.RevokeByUserAndClient(t.Context(), f.b.ID, f.user.ID, f.client.ID, at); err != nil || n != 0 {
			t.Errorf("RevokeByUserAndClient() through another tenant = %d, %v; want 0", n, err)
		}
		if n, err := tokens.RevokeByUserAndClient(t.Context(), f.a.ID, f.user.ID, f.client.ID, at); err != nil || n != 2 {
			t.Errorf("RevokeByUserAndClient() = %d, %v; want 2", n, err)
		}
		if n, err := tokens.RevokeByUserAndClient(t.Context(), f.a.ID, f.user.ID, f.client.ID, at.Add(time.Hour)); err != nil || n != 0 {
			t.Errorf("a second RevokeByUserAndClient() = %d, %v; want 0", n, err)
		}
		for _, token := range revoked {
			wantRevokedAt(t, f, token, at)
		}
		for _, token := range kept {
			wantRevokedAt(t, f, token, time.Time{})
		}
	})

	t.Run("DeleteExpiredAndCascades", func(t *testing.T) {
		t.Parallel()
		f := newAuthorizationFixture(t, open)
		tokens := f.s.RefreshTokens()
		now := time.Date(2026, 10, 18, 9, 0, 0, 0, time.UTC)
		// expired ends now, idle has not been used in time, and alive has
		// a rotated token that expired and a current one that has not.
		expired, expiredToken := newRefreshTokenFamily(f.client, f.user)
		expired.ExpiresAt, expiredToken.ExpiresAt = now, now
		idle, idleToken := newRefreshTokenFamily(f.client, f.user)
		idle.IdleExpiresAt, idleToken.ExpiresAt = now, now
		alive, aliveFirst := newRefreshTokenFamily(f.client, f.user)
		aliveFirst.ExpiresAt = now
		foreign, foreignToken := newRefreshTokenFamily(f.clientB, f.userB)
		foreign.ExpiresAt, foreignToken.ExpiresAt = now, now
		for _, c := range []struct {
			family store.RefreshTokenFamily
			token  store.RefreshToken
		}{{expired, expiredToken}, {idle, idleToken}, {alive, aliveFirst}, {foreign, foreignToken}} {
			mustCreateRefreshTokenFamily(t, f.s, c.family, c.token)
		}
		aliveSecond := nextRefreshToken(aliveFirst)
		aliveSecond.ExpiresAt = now.Add(time.Microsecond)
		if err := tokens.Rotate(t.Context(), f.a.ID, aliveFirst.Hash, aliveSecond); err != nil {
			t.Fatalf("Rotate() unexpected error: %v", err)
		}

		if n, err := tokens.DeleteExpired(t.Context(), now); err != nil || n != 3 {
			t.Errorf("DeleteExpired() = %d, %v; want 3", n, err)
		}
		for name, hash := range map[string][]byte{
			"the token of an expired family":    expiredToken.Hash,
			"the token of an idle family":       idleToken.Hash,
			"an expired token of a live family": aliveFirst.Hash,
		} {
			if _, _, err := tokens.Get(t.Context(), f.a.ID, hash); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("Get() of %s after DeleteExpired() = %v, want ErrNotFound", name, err)
			}
		}
		if _, _, err := tokens.Get(t.Context(), f.a.ID, aliveSecond.Hash); err != nil {
			t.Errorf("Get() of a token that has not expired = %v", err)
		}

		if err := f.s.Clients().Delete(t.Context(), f.a.ID, f.client.ID); err != nil {
			t.Fatalf("deleting the client: %v", err)
		}
		if _, _, err := tokens.Get(t.Context(), f.a.ID, aliveSecond.Hash); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get() after deleting the client = %v, want ErrNotFound", err)
		}
		other := newClient(f.a.ID, "other")
		mustCreateClient(t, f.s.Clients(), other)
		family, token := newRefreshTokenFamily(other, f.user)
		mustCreateRefreshTokenFamily(t, f.s, family, token)
		if err := f.s.Users().Delete(t.Context(), f.a.ID, f.user.ID); err != nil {
			t.Fatalf("deleting the user: %v", err)
		}
		if _, _, err := tokens.Get(t.Context(), f.a.ID, token.Hash); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get() after deleting the user = %v, want ErrNotFound", err)
		}
	})
}

// newRefreshTokenFamily returns a family of c for u with every field set, and
// its first token.
func newRefreshTokenFamily(c store.Client, u store.User) (store.RefreshTokenFamily, store.RefreshToken) {
	created := time.Date(2026, 10, 17, 9, 31, 0, 123456789, time.UTC)
	f := store.RefreshTokenFamily{
		ID:             uuid.NewV7(),
		TenantID:       c.TenantID,
		ClientID:       c.ID,
		UserID:         u.ID,
		SessionID:      uuid.NewV7(),
		CodeHash:       hashOf("code " + uuid.NewV7().String()),
		Scopes:         []string{"openid", "offline_access"},
		AuthTime:       created.Add(-time.Minute),
		AMR:            []string{"pwd"},
		ACR:            "https://clavisid.org/acr/password",
		UserInfoClaims: []string{"name"},
		IDTokenClaims:  []string{"email"},
		CreatedAt:      created,
		IdleExpiresAt:  created.Add(7 * 24 * time.Hour),
		ExpiresAt:      created.Add(30 * 24 * time.Hour),
	}
	return f, store.RefreshToken{
		Hash:      hashOf("refresh " + uuid.NewV7().String()),
		TenantID:  c.TenantID,
		FamilyID:  f.ID,
		IssuedAt:  created,
		ExpiresAt: f.IdleExpiresAt,
	}
}

// newRefreshTokenFamilyToken returns the first token of a family that is not
// stored.
func newRefreshTokenFamilyToken(f authorizationFixture) store.RefreshToken {
	_, token := newRefreshTokenFamily(f.client, f.user)
	return token
}

// nextRefreshToken returns a successor of t, issued an hour later.
func nextRefreshToken(t store.RefreshToken) store.RefreshToken {
	issued := t.IssuedAt.Add(time.Hour)
	return store.RefreshToken{
		Hash:      hashOf("refresh " + uuid.NewV7().String()),
		TenantID:  t.TenantID,
		FamilyID:  t.FamilyID,
		IssuedAt:  issued,
		ExpiresAt: issued.Add(7 * 24 * time.Hour),
	}
}

func mustCreateRefreshTokenFamily(t *testing.T, s store.Store, f store.RefreshTokenFamily, token store.RefreshToken) {
	t.Helper()
	if err := s.RefreshTokens().Create(t.Context(), f, token); err != nil {
		t.Fatalf("Create() unexpected error: %v", err)
	}
}

// wantRevokedAt checks the revocation time of the family of a token.
func wantRevokedAt(t *testing.T, f authorizationFixture, token store.RefreshToken, at time.Time) {
	t.Helper()
	_, family, err := f.s.RefreshTokens().Get(t.Context(), token.TenantID, token.Hash)
	if err != nil || !family.RevokedAt.Equal(at) {
		t.Errorf("RevokedAt of family %s = %v, %v; want %v", family.ID, family.RevokedAt, err, at)
	}
}

func normalizeRefreshToken(t store.RefreshToken) store.RefreshToken {
	t.IssuedAt = t.IssuedAt.UTC().Truncate(time.Microsecond)
	t.ExpiresAt = t.ExpiresAt.UTC().Truncate(time.Microsecond)
	return t
}

func normalizeRefreshTokenFamily(f store.RefreshTokenFamily) store.RefreshTokenFamily {
	f.AuthTime = f.AuthTime.UTC().Truncate(time.Microsecond)
	f.CreatedAt = f.CreatedAt.UTC().Truncate(time.Microsecond)
	f.IdleExpiresAt = f.IdleExpiresAt.UTC().Truncate(time.Microsecond)
	f.ExpiresAt = f.ExpiresAt.UTC().Truncate(time.Microsecond)
	return f
}
