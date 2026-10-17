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

func runCodeRedemption(t *testing.T, open OpenFunc) {
	t.Run("RedeemOnce", func(t *testing.T) {
		t.Parallel()
		f := newAuthorizationFixture(t, open)
		c := newAuthorizationCode(f.client, f.user)
		mustCreateAuthorizationCode(t, f.s, c)
		codes := f.s.AuthorizationCodes()
		at := time.Date(2026, 10, 16, 9, 31, 10, 123456789, time.UTC)

		var wg sync.WaitGroup
		errs := make([]error, 8)
		for i := range errs {
			wg.Go(func() { errs[i] = codes.Redeem(t.Context(), f.a.ID, c.Hash, at) })
		}
		wg.Wait()
		var succeeded int
		for _, err := range errs {
			switch {
			case err == nil:
				succeeded++
			case !errors.Is(err, store.ErrConflict):
				t.Errorf("concurrent Redeem() error = %v, want nil or ErrConflict", err)
			}
		}
		if succeeded != 1 {
			t.Errorf("%d concurrent redemptions succeeded, want 1", succeeded)
		}
		got, err := codes.Get(t.Context(), f.a.ID, c.Hash)
		if err != nil || !got.RedeemedAt.Equal(at.Truncate(time.Microsecond)) || got.RedeemedAt.Location() != time.UTC {
			t.Errorf("Get() after Redeem() = %v, %v; want RedeemedAt %v", got.RedeemedAt, err, at)
		}
	})

	t.Run("RedeemNotFound", func(t *testing.T) {
		t.Parallel()
		f := newAuthorizationFixture(t, open)
		c := newAuthorizationCode(f.client, f.user)
		mustCreateAuthorizationCode(t, f.s, c)
		codes := f.s.AuthorizationCodes()
		if err := codes.Redeem(t.Context(), f.a.ID, hashOf("missing"), time.Now()); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Redeem() of an unknown code error = %v, want ErrNotFound", err)
		}
		if err := codes.Redeem(t.Context(), f.b.ID, c.Hash, time.Now()); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Redeem() through another tenant error = %v, want ErrNotFound", err)
		}
		if got, err := codes.Get(t.Context(), f.a.ID, c.Hash); err != nil || !got.RedeemedAt.IsZero() {
			t.Errorf("Get() = %v, %v; want a code that is not redeemed", got.RedeemedAt, err)
		}
	})
}

func runAccessTokens(t *testing.T, open OpenFunc) {
	t.Run("CreateAndGet", func(t *testing.T) {
		t.Parallel()
		f := newAuthorizationFixture(t, open)
		forUser := newAccessToken(f.client, f.user.ID)
		forClient := newAccessToken(f.client, uuid.Nil())
		forClient.CodeHash, forClient.Scopes = nil, nil
		for _, want := range []store.AccessToken{forUser, forClient} {
			if err := f.s.AccessTokens().Create(t.Context(), want); err != nil {
				t.Fatalf("Create() unexpected error: %v", err)
			}
			got, err := f.s.AccessTokens().Get(t.Context(), f.a.ID, want.ID)
			if err != nil {
				t.Fatalf("Get() unexpected error: %v", err)
			}
			if diff := cmp.Diff(normalizeAccessToken(want), got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Get() mismatch (-want +got):\n%s", diff)
			}
		}
	})

	t.Run("NotFoundAndConflicts", func(t *testing.T) {
		t.Parallel()
		f := newAuthorizationFixture(t, open)
		tokens := f.s.AccessTokens()
		first := newAccessToken(f.client, f.user.ID)
		if err := tokens.Create(t.Context(), first); err != nil {
			t.Fatalf("Create() unexpected error: %v", err)
		}
		if _, err := tokens.Get(t.Context(), f.a.ID, "missing"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get() error = %v, want ErrNotFound", err)
		}
		if _, err := tokens.Get(t.Context(), f.b.ID, first.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get() through another tenant error = %v, want ErrNotFound", err)
		}
		dup := newAccessToken(f.client, f.user.ID)
		dup.ID = first.ID
		if err := tokens.Create(t.Context(), dup); !errors.Is(err, store.ErrConflict) {
			t.Errorf("Create() with a duplicate ID error = %v, want ErrConflict", err)
		}
		foreignClient := newAccessToken(f.client, f.user.ID)
		foreignClient.ClientID = f.clientB.ID
		foreignUser := newAccessToken(f.client, f.userB.ID)
		for name, tok := range map[string]store.AccessToken{"client": foreignClient, "user": foreignUser} {
			if err := tokens.Create(t.Context(), tok); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("Create() for the %s of another tenant error = %v, want ErrNotFound", name, err)
			}
		}
	})

	t.Run("RevokeByCode", func(t *testing.T) {
		t.Parallel()
		f := newAuthorizationFixture(t, open)
		tokens := f.s.AccessTokens()
		code := hashOf("code")
		a, b, other := newAccessToken(f.client, f.user.ID), newAccessToken(f.client, f.user.ID), newAccessToken(f.client, f.user.ID)
		a.CodeHash, b.CodeHash, other.CodeHash = code, code, hashOf("other code")
		for _, tok := range []store.AccessToken{a, b, other} {
			if err := tokens.Create(t.Context(), tok); err != nil {
				t.Fatalf("Create() unexpected error: %v", err)
			}
		}
		at := time.Date(2026, 10, 16, 10, 0, 0, 0, time.UTC)
		if n, err := tokens.RevokeByCode(t.Context(), f.b.ID, code, at); err != nil || n != 0 {
			t.Errorf("RevokeByCode() through another tenant = %d, %v; want 0", n, err)
		}
		if n, err := tokens.RevokeByCode(t.Context(), f.a.ID, code, at); err != nil || n != 2 {
			t.Errorf("RevokeByCode() = %d, %v; want 2", n, err)
		}
		if n, err := tokens.RevokeByCode(t.Context(), f.a.ID, code, at.Add(time.Hour)); err != nil || n != 0 {
			t.Errorf("a second RevokeByCode() = %d, %v; want 0", n, err)
		}
		for _, tok := range []store.AccessToken{a, b} {
			if got, err := tokens.Get(t.Context(), f.a.ID, tok.ID); err != nil || !got.RevokedAt.Equal(at) {
				t.Errorf("revoked token = %v, %v; want RevokedAt %v", got.RevokedAt, err, at)
			}
		}
		if got, err := tokens.Get(t.Context(), f.a.ID, other.ID); err != nil || !got.RevokedAt.IsZero() {
			t.Errorf("token of another code = %v, %v; want it not revoked", got.RevokedAt, err)
		}
	})

	t.Run("RevokeByUserAndClient", func(t *testing.T) {
		t.Parallel()
		f := newAuthorizationFixture(t, open)
		tokens := f.s.AccessTokens()
		other := newClient(f.a.ID, "other")
		mustCreateClient(t, f.s.Clients(), other)
		grace := newUser(f.a.ID, "grace@example.com")
		mustCreateUser(t, f.s.Users(), grace)
		a, b := newAccessToken(f.client, f.user.ID), newAccessToken(f.client, f.user.ID)
		kept := []store.AccessToken{
			newAccessToken(other, f.user.ID),     // another client
			newAccessToken(f.client, grace.ID),   // another user
			newAccessToken(f.client, uuid.Nil()), // the client for itself
		}
		for _, tok := range append([]store.AccessToken{a, b}, kept...) {
			if err := tokens.Create(t.Context(), tok); err != nil {
				t.Fatalf("Create() unexpected error: %v", err)
			}
		}
		at := time.Date(2026, 10, 17, 10, 0, 0, 0, time.UTC)
		if n, err := tokens.RevokeByUserAndClient(t.Context(), f.b.ID, f.user.ID, f.client.ID, at); err != nil || n != 0 {
			t.Errorf("RevokeByUserAndClient() through another tenant = %d, %v; want 0", n, err)
		}
		if n, err := tokens.RevokeByUserAndClient(t.Context(), f.a.ID, f.user.ID, f.client.ID, at); err != nil || n != 2 {
			t.Errorf("RevokeByUserAndClient() = %d, %v; want 2", n, err)
		}
		// Revoked tokens keep the time of their first revocation.
		if n, err := tokens.RevokeByUserAndClient(t.Context(), f.a.ID, f.user.ID, f.client.ID, at.Add(time.Hour)); err != nil || n != 0 {
			t.Errorf("a second RevokeByUserAndClient() = %d, %v; want 0", n, err)
		}
		for _, tok := range []store.AccessToken{a, b} {
			if got, err := tokens.Get(t.Context(), f.a.ID, tok.ID); err != nil || !got.RevokedAt.Equal(at) {
				t.Errorf("revoked token = %v, %v; want RevokedAt %v", got.RevokedAt, err, at)
			}
		}
		for _, tok := range kept {
			if got, err := tokens.Get(t.Context(), f.a.ID, tok.ID); err != nil || !got.RevokedAt.IsZero() {
				t.Errorf("token of another user or client = %v, %v; want it not revoked", got.RevokedAt, err)
			}
		}
	})

	t.Run("DeleteExpiredAndCascades", func(t *testing.T) {
		t.Parallel()
		f := newAuthorizationFixture(t, open)
		tokens := f.s.AccessTokens()
		now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
		expired, alive, ofUser, foreign := newAccessToken(f.client, f.user.ID), newAccessToken(f.client, uuid.Nil()),
			newAccessToken(f.client, f.user.ID), newAccessToken(f.clientB, f.userB.ID)
		expired.ExpiresAt, alive.ExpiresAt, ofUser.ExpiresAt, foreign.ExpiresAt = now, now.Add(time.Microsecond), now.Add(time.Hour), now
		foreign.TenantID = f.b.ID
		for _, tok := range []store.AccessToken{expired, alive, ofUser, foreign} {
			if err := tokens.Create(t.Context(), tok); err != nil {
				t.Fatalf("Create() unexpected error: %v", err)
			}
		}
		if n, err := tokens.DeleteExpired(t.Context(), now); err != nil || n != 2 {
			t.Errorf("DeleteExpired() = %d, %v; want 2", n, err)
		}
		if _, err := tokens.Get(t.Context(), f.a.ID, alive.ID); err != nil {
			t.Errorf("Get() of a token that has not expired = %v", err)
		}
		if err := f.s.Users().Delete(t.Context(), f.a.ID, f.user.ID); err != nil {
			t.Fatalf("deleting the user: %v", err)
		}
		if _, err := tokens.Get(t.Context(), f.a.ID, ofUser.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get() after deleting the user = %v, want ErrNotFound", err)
		}
		if err := f.s.Clients().Delete(t.Context(), f.a.ID, f.client.ID); err != nil {
			t.Fatalf("deleting the client: %v", err)
		}
		if _, err := tokens.Get(t.Context(), f.a.ID, alive.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get() after deleting the client = %v, want ErrNotFound", err)
		}
	})
}

func runAPIResources(t *testing.T, open OpenFunc) {
	t.Run("CreateGetListAndDelete", func(t *testing.T) {
		t.Parallel()
		s := open(t)
		a, b := newTenant("a"), newTenant("b")
		mustCreate(t, s.Tenants(), a)
		mustCreate(t, s.Tenants(), b)
		resources := s.APIResources()
		orders, billing := newAPIResource(a.ID, "https://api.example.com/orders"), newAPIResource(a.ID, "https://api.example.com/billing")
		billing.Scopes = nil
		sameInB := newAPIResource(b.ID, "https://api.example.com/orders")
		for _, r := range []store.APIResource{orders, billing, sameInB} {
			if err := resources.Create(t.Context(), r); err != nil {
				t.Fatalf("Create(%s) unexpected error: %v", r.Identifier, err)
			}
		}
		got, err := resources.GetByIdentifier(t.Context(), a.ID, orders.Identifier)
		if err != nil {
			t.Fatalf("GetByIdentifier() unexpected error: %v", err)
		}
		if diff := cmp.Diff(normalizeAPIResource(orders), got, cmpopts.EquateEmpty()); diff != "" {
			t.Errorf("GetByIdentifier() mismatch (-want +got):\n%s", diff)
		}
		list, err := resources.List(t.Context(), a.ID, uuid.Nil(), 1)
		if err != nil || len(list) != 1 || list[0].ID != orders.ID {
			t.Fatalf("List() first page = %v, %v", list, err)
		}
		list, err = resources.List(t.Context(), a.ID, list[0].ID, store.MaxPageSize)
		if err != nil || len(list) != 1 || list[0].ID != billing.ID {
			t.Errorf("List() second page = %v, %v", list, err)
		}
		for _, limit := range []int{0, store.MaxPageSize + 1} {
			if _, err := resources.List(t.Context(), a.ID, uuid.Nil(), limit); !errors.Is(err, store.ErrInvalidArgument) {
				t.Errorf("List() with limit %d = %v, want ErrInvalidArgument", limit, err)
			}
		}
		if err := resources.Delete(t.Context(), b.ID, orders.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Delete() through another tenant = %v, want ErrNotFound", err)
		}
		if err := resources.Delete(t.Context(), a.ID, orders.ID); err != nil {
			t.Fatalf("Delete() unexpected error: %v", err)
		}
		if _, err := resources.GetByIdentifier(t.Context(), a.ID, orders.Identifier); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetByIdentifier() after Delete() = %v, want ErrNotFound", err)
		}
		if _, err := resources.GetByIdentifier(t.Context(), b.ID, orders.Identifier); err != nil {
			t.Errorf("GetByIdentifier() of the other tenant's resource = %v, want nil", err)
		}
	})

	t.Run("ConflictsAndUnknownTenant", func(t *testing.T) {
		t.Parallel()
		s := open(t)
		tn := newTenant("a")
		mustCreate(t, s.Tenants(), tn)
		resources := s.APIResources()
		first := newAPIResource(tn.ID, "https://api.example.com/orders")
		if err := resources.Create(t.Context(), first); err != nil {
			t.Fatalf("Create() unexpected error: %v", err)
		}
		sameID := newAPIResource(tn.ID, "https://api.example.com/other")
		sameID.ID = first.ID
		for name, r := range map[string]store.APIResource{
			"ID":         sameID,
			"identifier": newAPIResource(tn.ID, first.Identifier),
		} {
			if err := resources.Create(t.Context(), r); !errors.Is(err, store.ErrConflict) {
				t.Errorf("Create() with a duplicate %s error = %v, want ErrConflict", name, err)
			}
		}
		if err := resources.Create(t.Context(), newAPIResource(uuid.NewV7(), "https://x.example")); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Create() for an unknown tenant error = %v, want ErrNotFound", err)
		}
		if err := resources.Delete(t.Context(), tn.ID, uuid.NewV7()); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Delete() of an unknown resource error = %v, want ErrNotFound", err)
		}
	})
}

func newAccessToken(c store.Client, userID uuid.UUID) store.AccessToken {
	issued := time.Date(2026, 10, 16, 9, 31, 0, 123456789, time.UTC)
	return store.AccessToken{
		ID:             uuid.NewV7().String(),
		TenantID:       c.TenantID,
		ClientID:       c.ID,
		UserID:         userID,
		CodeHash:       hashOf("code " + uuid.NewV7().String()),
		Scopes:         []string{"openid", "orders:read"},
		UserInfoClaims: []string{"name"},
		IssuedAt:       issued,
		ExpiresAt:      issued.Add(10 * time.Minute),
	}
}

func normalizeAccessToken(t store.AccessToken) store.AccessToken {
	t.IssuedAt = t.IssuedAt.UTC().Truncate(time.Microsecond)
	t.ExpiresAt = t.ExpiresAt.UTC().Truncate(time.Microsecond)
	return t
}

func newAPIResource(tenantID uuid.UUID, identifier string) store.APIResource {
	created := time.Date(2026, 10, 16, 9, 0, 0, 123456789, time.UTC)
	return store.APIResource{
		ID:         uuid.NewV7(),
		TenantID:   tenantID,
		Identifier: identifier,
		Name:       "Orders API",
		Scopes:     []string{"orders:read", "orders:write"},
		CreatedAt:  created,
		UpdatedAt:  created.Add(time.Minute),
	}
}

func normalizeAPIResource(r store.APIResource) store.APIResource {
	r.CreatedAt = r.CreatedAt.UTC().Truncate(time.Microsecond)
	r.UpdatedAt = r.UpdatedAt.UTC().Truncate(time.Microsecond)
	return r
}
