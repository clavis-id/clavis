package storetest

import (
	"errors"
	"testing"
	"time"
	"uuid"

	"clavisid.org/clavis/store"
)

// runUserRecords checks the methods that end every session and revoke every
// token of a user, which a password change or reset needs.
func runUserRecords(t *testing.T, open OpenFunc) {
	t.Run("SessionsDeleteByUser", func(t *testing.T) {
		t.Parallel()
		f := newAuthorizationFixture(t, open)
		grace := newUser(f.a.ID, "grace@example.com")
		mustCreateUser(t, f.s.Users(), grace)
		keep, other, last := newSession(f.user), newSession(f.user), newSession(f.user)
		kept := []store.Session{newSession(grace), newSession(f.userB)}
		for _, s := range append([]store.Session{keep, other, last}, kept...) {
			mustCreateSession(t, f.s, s)
		}
		sessions := f.s.Sessions()
		if n, err := sessions.DeleteByUser(t.Context(), f.b.ID, f.user.ID, uuid.Nil()); err != nil || n != 0 {
			t.Errorf("DeleteByUser() through another tenant = %d, %v; want 0", n, err)
		}
		if n, err := sessions.DeleteByUser(t.Context(), f.a.ID, f.user.ID, keep.ID); err != nil || n != 2 {
			t.Errorf("DeleteByUser() keeping one session = %d, %v; want 2", n, err)
		}
		if _, err := sessions.GetByTokenHash(t.Context(), f.a.ID, keep.TokenHash); err != nil {
			t.Errorf("the kept session = %v, want it stored", err)
		}
		for _, s := range []store.Session{other, last} {
			if _, err := sessions.GetByTokenHash(t.Context(), f.a.ID, s.TokenHash); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("a deleted session = %v, want ErrNotFound", err)
			}
		}
		if n, err := sessions.DeleteByUser(t.Context(), f.a.ID, f.user.ID, uuid.Nil()); err != nil || n != 1 {
			t.Errorf("DeleteByUser() keeping none = %d, %v; want 1", n, err)
		}
		for _, s := range kept {
			if _, err := sessions.GetByTokenHash(t.Context(), s.TenantID, s.TokenHash); err != nil {
				t.Errorf("a session of another user = %v, want it stored", err)
			}
		}
	})

	t.Run("CodesDeleteByUser", func(t *testing.T) {
		t.Parallel()
		f := newAuthorizationFixture(t, open)
		grace := newUser(f.a.ID, "grace@example.com")
		mustCreateUser(t, f.s.Users(), grace)
		pending, other, redeemed := newAuthorizationCode(f.client, f.user), newAuthorizationCode(f.client, f.user),
			newAuthorizationCode(f.client, f.user)
		kept := []store.AuthorizationCode{newAuthorizationCode(f.client, grace), newAuthorizationCode(f.clientB, f.userB)}
		for _, c := range append([]store.AuthorizationCode{pending, other, redeemed}, kept...) {
			mustCreateAuthorizationCode(t, f.s, c)
		}
		codes := f.s.AuthorizationCodes()
		if err := codes.Redeem(t.Context(), f.a.ID, redeemed.Hash, redeemed.CreatedAt); err != nil {
			t.Fatalf("Redeem() unexpected error: %v", err)
		}
		if n, err := codes.DeleteByUser(t.Context(), f.b.ID, f.user.ID); err != nil || n != 0 {
			t.Errorf("DeleteByUser() through another tenant = %d, %v; want 0", n, err)
		}
		if n, err := codes.DeleteByUser(t.Context(), f.a.ID, f.user.ID); err != nil || n != 2 {
			t.Errorf("DeleteByUser() = %d, %v; want the 2 codes not redeemed", n, err)
		}
		for _, c := range []store.AuthorizationCode{pending, other} {
			if _, err := codes.Get(t.Context(), f.a.ID, c.Hash); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("a deleted code = %v, want ErrNotFound", err)
			}
		}
		// A redeemed code stays, so a replay of it is still recognized.
		for _, c := range append([]store.AuthorizationCode{redeemed}, kept...) {
			if _, err := codes.Get(t.Context(), c.TenantID, c.Hash); err != nil {
				t.Errorf("a code that stays = %v, want it stored", err)
			}
		}
	})

	t.Run("AccessTokensRevokeByUser", func(t *testing.T) {
		t.Parallel()
		f := newAuthorizationFixture(t, open)
		tokens := f.s.AccessTokens()
		other := newClient(f.a.ID, "other")
		mustCreateClient(t, f.s.Clients(), other)
		grace := newUser(f.a.ID, "grace@example.com")
		mustCreateUser(t, f.s.Users(), grace)
		revoked := []store.AccessToken{newAccessToken(f.client, f.user.ID), newAccessToken(other, f.user.ID)}
		kept := []store.AccessToken{
			newAccessToken(f.client, grace.ID),   // another user
			newAccessToken(f.client, uuid.Nil()), // the client for itself
		}
		for _, tok := range append(append([]store.AccessToken{}, revoked...), kept...) {
			if err := tokens.Create(t.Context(), tok); err != nil {
				t.Fatalf("Create() unexpected error: %v", err)
			}
		}
		at := time.Date(2026, 10, 22, 10, 0, 0, 0, time.UTC)
		if n, err := tokens.RevokeByUser(t.Context(), f.b.ID, f.user.ID, at); err != nil || n != 0 {
			t.Errorf("RevokeByUser() through another tenant = %d, %v; want 0", n, err)
		}
		if n, err := tokens.RevokeByUser(t.Context(), f.a.ID, f.user.ID, at); err != nil || n != 2 {
			t.Errorf("RevokeByUser() = %d, %v; want 2", n, err)
		}
		// Revoked tokens keep the time of their first revocation.
		if n, err := tokens.RevokeByUser(t.Context(), f.a.ID, f.user.ID, at.Add(time.Hour)); err != nil || n != 0 {
			t.Errorf("a second RevokeByUser() = %d, %v; want 0", n, err)
		}
		for _, tok := range revoked {
			if got, err := tokens.Get(t.Context(), f.a.ID, tok.ID); err != nil || !got.RevokedAt.Equal(at) {
				t.Errorf("revoked token = %v, %v; want RevokedAt %v", got.RevokedAt, err, at)
			}
		}
		for _, tok := range kept {
			if got, err := tokens.Get(t.Context(), f.a.ID, tok.ID); err != nil || !got.RevokedAt.IsZero() {
				t.Errorf("token of another user = %v, %v; want it not revoked", got.RevokedAt, err)
			}
		}
	})

	t.Run("RefreshTokensRevokeByUser", func(t *testing.T) {
		t.Parallel()
		f := newAuthorizationFixture(t, open)
		other := newClient(f.a.ID, "other")
		mustCreateClient(t, f.s.Clients(), other)
		grace := newUser(f.a.ID, "grace@example.com")
		mustCreateUser(t, f.s.Users(), grace)
		var revoked, kept []store.RefreshToken
		for _, c := range []struct {
			client store.Client
			user   store.User
			revoke bool
		}{{f.client, f.user, true}, {other, f.user, true}, {f.client, grace, false}} {
			family, token := newRefreshTokenFamily(c.client, c.user)
			mustCreateRefreshTokenFamily(t, f.s, family, token)
			if c.revoke {
				revoked = append(revoked, token)
			} else {
				kept = append(kept, token)
			}
		}
		tokens := f.s.RefreshTokens()
		at := time.Date(2026, 10, 22, 10, 0, 0, 0, time.UTC)
		if n, err := tokens.RevokeByUser(t.Context(), f.b.ID, f.user.ID, at); err != nil || n != 0 {
			t.Errorf("RevokeByUser() through another tenant = %d, %v; want 0", n, err)
		}
		if n, err := tokens.RevokeByUser(t.Context(), f.a.ID, f.user.ID, at); err != nil || n != 2 {
			t.Errorf("RevokeByUser() = %d, %v; want 2", n, err)
		}
		if n, err := tokens.RevokeByUser(t.Context(), f.a.ID, f.user.ID, at.Add(time.Hour)); err != nil || n != 0 {
			t.Errorf("a second RevokeByUser() = %d, %v; want 0", n, err)
		}
		for _, token := range revoked {
			wantRevokedAt(t, f, token, at)
		}
		for _, token := range kept {
			wantRevokedAt(t, f, token, time.Time{})
		}
	})
}
