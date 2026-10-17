// Package storetest is the contract suite for implementations of the store
// ports. An adapter is correct when it passes Run.
//
//	func TestContract(t *testing.T) {
//		storetest.Run(t, func(t *testing.T) store.Store {
//			return openEmptyStore(t)
//		})
//	}
package storetest

import (
	"errors"
	"fmt"
	"testing"
	"time"
	"uuid"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"clavisid.org/clavis/store"
)

// OpenFunc returns a new, empty store for one test. It must register any
// cleanup with t.Cleanup.
type OpenFunc func(t *testing.T) store.Store

// Run executes the contract suite. Every subtest receives its own store from
// open, so subtests run in parallel.
func Run(t *testing.T, open OpenFunc) {
	t.Helper()
	t.Run("Ping", func(t *testing.T) {
		t.Parallel()
		if err := open(t).Ping(t.Context()); err != nil {
			t.Fatalf("Ping() = %v, want nil", err)
		}
	})
	t.Run("Tenants", func(t *testing.T) {
		t.Parallel()
		runTenants(t, open)
	})
	t.Run("SigningKeys", func(t *testing.T) {
		t.Parallel()
		runSigningKeys(t, open)
	})
	t.Run("Clients", func(t *testing.T) {
		t.Parallel()
		runClients(t, open)
	})
	t.Run("Users", func(t *testing.T) {
		t.Parallel()
		runUsers(t, open)
	})
	t.Run("Passwords", func(t *testing.T) {
		t.Parallel()
		runPasswords(t, open)
	})
	t.Run("AuthorizationRequests", func(t *testing.T) {
		t.Parallel()
		runAuthorizationRequests(t, open)
	})
	t.Run("Sessions", func(t *testing.T) {
		t.Parallel()
		runSessions(t, open)
	})
	t.Run("AuthorizationCodes", func(t *testing.T) {
		t.Parallel()
		runAuthorizationCodes(t, open)
		runCodeRedemption(t, open)
	})
	t.Run("AccessTokens", func(t *testing.T) {
		t.Parallel()
		runAccessTokens(t, open)
	})
	t.Run("APIResources", func(t *testing.T) {
		t.Parallel()
		runAPIResources(t, open)
	})
	t.Run("Grants", func(t *testing.T) {
		t.Parallel()
		runGrants(t, open)
	})
}

func runTenants(t *testing.T, open OpenFunc) {
	t.Run("CreateAndGet", func(t *testing.T) {
		t.Parallel()
		tenants := open(t).Tenants()
		want := newTenant("acme")
		mustCreate(t, tenants, want)

		got, err := tenants.Get(t.Context(), want.ID)
		if err != nil {
			t.Fatalf("Get() unexpected error: %v", err)
		}
		if diff := cmp.Diff(normalize(want), got); diff != "" {
			t.Errorf("Get() mismatch (-want +got):\n%s", diff)
		}

		got, err = tenants.GetBySlug(t.Context(), want.Slug)
		if err != nil {
			t.Fatalf("GetBySlug() unexpected error: %v", err)
		}
		if diff := cmp.Diff(normalize(want), got); diff != "" {
			t.Errorf("GetBySlug() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("TimesAreUTCWithMicrosecondPrecision", func(t *testing.T) {
		t.Parallel()
		tenants := open(t).Tenants()
		tn := newTenant("zone")
		zone := time.FixedZone("UTC-3", -3*60*60)
		tn.CreatedAt = time.Date(2026, 10, 13, 9, 30, 15, 123456789, zone)
		tn.UpdatedAt = tn.CreatedAt.Add(time.Nanosecond)
		mustCreate(t, tenants, tn)

		got, err := tenants.Get(t.Context(), tn.ID)
		if err != nil {
			t.Fatalf("Get() unexpected error: %v", err)
		}
		want := time.Date(2026, 10, 13, 12, 30, 15, 123456000, time.UTC)
		for name, ts := range map[string]time.Time{"CreatedAt": got.CreatedAt, "UpdatedAt": got.UpdatedAt} {
			if !ts.Equal(want) || ts.Location() != time.UTC {
				t.Errorf("%s = %v, want %v in UTC", name, ts, want)
			}
		}
	})

	t.Run("NotFound", func(t *testing.T) {
		t.Parallel()
		tenants := open(t).Tenants()
		missing := uuid.NewV7()
		if _, err := tenants.Get(t.Context(), missing); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get() error = %v, want ErrNotFound", err)
		}
		if _, err := tenants.GetBySlug(t.Context(), "missing"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetBySlug() error = %v, want ErrNotFound", err)
		}
		if err := tenants.Delete(t.Context(), missing); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Delete() error = %v, want ErrNotFound", err)
		}
	})

	t.Run("ConflictOnDuplicateID", func(t *testing.T) {
		t.Parallel()
		tenants := open(t).Tenants()
		first := newTenant("first")
		mustCreate(t, tenants, first)
		dup := newTenant("second")
		dup.ID = first.ID
		if err := tenants.Create(t.Context(), dup); !errors.Is(err, store.ErrConflict) {
			t.Errorf("Create() with a duplicate ID error = %v, want ErrConflict", err)
		}
	})

	t.Run("ConflictOnDuplicateSlug", func(t *testing.T) {
		t.Parallel()
		tenants := open(t).Tenants()
		mustCreate(t, tenants, newTenant("acme"))
		if err := tenants.Create(t.Context(), newTenant("acme")); !errors.Is(err, store.ErrConflict) {
			t.Errorf("Create() with a duplicate slug error = %v, want ErrConflict", err)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		t.Parallel()
		tenants := open(t).Tenants()
		keep, drop := newTenant("keep"), newTenant("drop")
		mustCreate(t, tenants, keep)
		mustCreate(t, tenants, drop)
		if err := tenants.Delete(t.Context(), drop.ID); err != nil {
			t.Fatalf("Delete() unexpected error: %v", err)
		}
		if _, err := tenants.Get(t.Context(), drop.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get() after Delete() error = %v, want ErrNotFound", err)
		}
		if _, err := tenants.Get(t.Context(), keep.ID); err != nil {
			t.Errorf("Delete() removed another tenant: %v", err)
		}
		// The slug becomes available again.
		mustCreate(t, tenants, newTenant("drop"))
	})

	t.Run("ListPagesInIDOrder", func(t *testing.T) {
		t.Parallel()
		tenants := open(t).Tenants()
		var want []uuid.UUID
		for i := range 5 {
			tn := newTenant(fmt.Sprintf("tenant-%d", i))
			mustCreate(t, tenants, tn)
			want = append(want, tn.ID)
		}

		var got []uuid.UUID
		after := uuid.Nil()
		for {
			page, err := tenants.List(t.Context(), after, 2)
			if err != nil {
				t.Fatalf("List() unexpected error: %v", err)
			}
			if len(page) > 2 {
				t.Fatalf("List() returned %d records, want at most 2", len(page))
			}
			if len(page) == 0 {
				break
			}
			for _, tn := range page {
				got = append(got, tn.ID)
			}
			after = page[len(page)-1].ID
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("paged IDs mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("ListRejectsInvalidLimits", func(t *testing.T) {
		t.Parallel()
		tenants := open(t).Tenants()
		for _, limit := range []int{-1, 0, store.MaxPageSize + 1} {
			if _, err := tenants.List(t.Context(), uuid.Nil(), limit); !errors.Is(err, store.ErrInvalidArgument) {
				t.Errorf("List(limit=%d) error = %v, want ErrInvalidArgument", limit, err)
			}
		}
	})
}

func newTenant(slug string) store.Tenant {
	now := time.Now()
	return store.Tenant{
		ID:        uuid.NewV7(),
		Slug:      slug,
		Name:      "Tenant " + slug,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

func mustCreate(t *testing.T, tenants store.Tenants, tn store.Tenant) {
	t.Helper()
	if err := tenants.Create(t.Context(), tn); err != nil {
		t.Fatalf("Create(%q) unexpected error: %v", tn.Slug, err)
	}
}

// normalize returns tn as a store returns it: UTC times truncated to
// microseconds.
func normalize(tn store.Tenant) store.Tenant {
	tn.CreatedAt = tn.CreatedAt.UTC().Truncate(time.Microsecond)
	tn.UpdatedAt = tn.UpdatedAt.UTC().Truncate(time.Microsecond)
	return tn
}

func runSigningKeys(t *testing.T, open OpenFunc) {
	t.Run("CreateAndListInOrder", func(t *testing.T) {
		t.Parallel()
		s := open(t)
		tn := newTenant("acme")
		mustCreate(t, s.Tenants(), tn)

		base := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
		es2 := newSigningKey(tn.ID, "ES256", 2, base)
		rs1 := newSigningKey(tn.ID, "RS256", 1, base)
		es1 := newSigningKey(tn.ID, "ES256", 1, base)
		for _, k := range []store.SigningKey{es2, rs1, es1} {
			mustCreateKey(t, s.SigningKeys(), k)
		}

		got, err := s.SigningKeys().List(t.Context(), tn.ID)
		if err != nil {
			t.Fatalf("List() unexpected error: %v", err)
		}
		want := []store.SigningKey{normalizeKey(es1), normalizeKey(es2), normalizeKey(rs1)}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("List() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("ConflictOnDuplicateGeneration", func(t *testing.T) {
		t.Parallel()
		s := open(t)
		tn := newTenant("acme")
		mustCreate(t, s.Tenants(), tn)
		now := time.Now()
		mustCreateKey(t, s.SigningKeys(), newSigningKey(tn.ID, "RS256", 1, now))
		err := s.SigningKeys().Create(t.Context(), newSigningKey(tn.ID, "RS256", 1, now))
		if !errors.Is(err, store.ErrConflict) {
			t.Errorf("Create() with a duplicate generation error = %v, want ErrConflict", err)
		}
		// The same generation for another algorithm is allowed.
		mustCreateKey(t, s.SigningKeys(), newSigningKey(tn.ID, "ES256", 1, now))
	})

	t.Run("ConflictOnDuplicateKeyIDWithinTenant", func(t *testing.T) {
		t.Parallel()
		s := open(t)
		a, b := newTenant("a"), newTenant("b")
		mustCreate(t, s.Tenants(), a)
		mustCreate(t, s.Tenants(), b)
		now := time.Now()
		first := newSigningKey(a.ID, "RS256", 1, now)
		mustCreateKey(t, s.SigningKeys(), first)

		dup := newSigningKey(a.ID, "RS256", 2, now)
		dup.KeyID = first.KeyID
		if err := s.SigningKeys().Create(t.Context(), dup); !errors.Is(err, store.ErrConflict) {
			t.Errorf("Create() with a duplicate key ID error = %v, want ErrConflict", err)
		}
		other := newSigningKey(b.ID, "RS256", 1, now)
		other.KeyID = first.KeyID
		mustCreateKey(t, s.SigningKeys(), other)
	})

	t.Run("UnknownTenant", func(t *testing.T) {
		t.Parallel()
		s := open(t)
		err := s.SigningKeys().Create(t.Context(), newSigningKey(uuid.NewV7(), "RS256", 1, time.Now()))
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Create() for an unknown tenant error = %v, want ErrNotFound", err)
		}
	})

	t.Run("TenantIsolation", func(t *testing.T) {
		t.Parallel()
		s := open(t)
		a, b := newTenant("a"), newTenant("b")
		mustCreate(t, s.Tenants(), a)
		mustCreate(t, s.Tenants(), b)
		mustCreateKey(t, s.SigningKeys(), newSigningKey(a.ID, "RS256", 1, time.Now()))

		got, err := s.SigningKeys().List(t.Context(), b.ID)
		if err != nil {
			t.Fatalf("List() unexpected error: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("List() for tenant b returned %d keys of tenant a", len(got))
		}
	})

	t.Run("DeleteExpired", func(t *testing.T) {
		t.Parallel()
		s := open(t)
		a, b := newTenant("a"), newTenant("b")
		mustCreate(t, s.Tenants(), a)
		mustCreate(t, s.Tenants(), b)

		now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
		expired := newSigningKey(a.ID, "RS256", 1, now.Add(-72*time.Hour))
		expired.ExpiresAt = now.Add(-time.Hour)
		expiresNow := newSigningKey(b.ID, "RS256", 1, now.Add(-72*time.Hour))
		expiresNow.ExpiresAt = now
		alive := newSigningKey(a.ID, "RS256", 2, now)
		alive.ExpiresAt = now.Add(time.Microsecond)
		for _, k := range []store.SigningKey{expired, expiresNow, alive} {
			mustCreateKey(t, s.SigningKeys(), k)
		}

		n, err := s.SigningKeys().DeleteExpired(t.Context(), now)
		if err != nil {
			t.Fatalf("DeleteExpired() unexpected error: %v", err)
		}
		if n != 2 {
			t.Errorf("DeleteExpired() removed %d keys, want 2", n)
		}
		got, err := s.SigningKeys().List(t.Context(), a.ID)
		if err != nil {
			t.Fatalf("List() unexpected error: %v", err)
		}
		if len(got) != 1 || got[0].ID != alive.ID {
			t.Errorf("remaining keys = %v, want only %v", got, alive.ID)
		}
	})

	t.Run("DeletedWithTenant", func(t *testing.T) {
		t.Parallel()
		s := open(t)
		tn := newTenant("acme")
		mustCreate(t, s.Tenants(), tn)
		mustCreateKey(t, s.SigningKeys(), newSigningKey(tn.ID, "RS256", 1, time.Now()))
		if err := s.Tenants().Delete(t.Context(), tn.ID); err != nil {
			t.Fatalf("deleting tenant: %v", err)
		}
		got, err := s.SigningKeys().List(t.Context(), tn.ID)
		if err != nil {
			t.Fatalf("List() unexpected error: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("%d keys survived the deletion of their tenant", len(got))
		}
	})
}

// newSigningKey returns a key record with distinct key material. The bytes
// are placeholders: stores treat them as opaque.
func newSigningKey(tenantID uuid.UUID, alg string, generation int64, activatesAt time.Time) store.SigningKey {
	id := uuid.NewV7()
	return store.SigningKey{
		ID:              id,
		TenantID:        tenantID,
		Algorithm:       alg,
		Generation:      generation,
		KeyID:           "kid-" + id.String(),
		PublicKey:       []byte("public-" + id.String()),
		PrivateKey:      []byte("encrypted-" + id.String()),
		EncryptionKeyID: "local:0123456789abcdef",
		ActivatesAt:     activatesAt,
		RetiresAt:       activatesAt.Add(30 * 24 * time.Hour),
		ExpiresAt:       activatesAt.Add(32 * 24 * time.Hour),
		CreatedAt:       activatesAt.Add(-24 * time.Hour),
	}
}

func mustCreateKey(t *testing.T, keys store.SigningKeys, k store.SigningKey) {
	t.Helper()
	if err := keys.Create(t.Context(), k); err != nil {
		t.Fatalf("Create(%s generation %d) unexpected error: %v", k.Algorithm, k.Generation, err)
	}
}

// normalizeKey returns k as a store returns it.
func normalizeKey(k store.SigningKey) store.SigningKey {
	for _, ts := range []*time.Time{&k.ActivatesAt, &k.RetiresAt, &k.ExpiresAt, &k.CreatedAt} {
		*ts = ts.UTC().Truncate(time.Microsecond)
	}
	return k
}

func runClients(t *testing.T, open OpenFunc) {
	t.Run("CreateAndGet", func(t *testing.T) {
		t.Parallel()
		s := open(t)
		tn := newTenant("acme")
		mustCreate(t, s.Tenants(), tn)
		want := newClient(tn.ID, "web-app")
		mustCreateClient(t, s.Clients(), want)

		got, err := s.Clients().GetByClientID(t.Context(), tn.ID, want.ClientID)
		if err != nil {
			t.Fatalf("GetByClientID() unexpected error: %v", err)
		}
		if diff := cmp.Diff(normalizeClient(want), got, cmpopts.EquateEmpty()); diff != "" {
			t.Errorf("GetByClientID() mismatch (-want +got):\n%s", diff)
		}
		got, err = s.Clients().Get(t.Context(), tn.ID, want.ID)
		if err != nil {
			t.Fatalf("Get() unexpected error: %v", err)
		}
		if diff := cmp.Diff(normalizeClient(want), got, cmpopts.EquateEmpty()); diff != "" {
			t.Errorf("Get() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("PublicClientWithoutSecretOrLists", func(t *testing.T) {
		t.Parallel()
		s := open(t)
		tn := newTenant("acme")
		mustCreate(t, s.Tenants(), tn)
		now := time.Now()
		want := store.Client{
			ID:        uuid.NewV7(),
			TenantID:  tn.ID,
			ClientID:  "spa",
			Name:      "Single-page app",
			Type:      store.ClientPublic,
			CreatedAt: now,
			UpdatedAt: now,
		}
		mustCreateClient(t, s.Clients(), want)

		got, err := s.Clients().GetByClientID(t.Context(), tn.ID, want.ClientID)
		if err != nil {
			t.Fatalf("GetByClientID() unexpected error: %v", err)
		}
		if diff := cmp.Diff(normalizeClient(want), got, cmpopts.EquateEmpty()); diff != "" {
			t.Errorf("GetByClientID() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("ClientIDIsCaseSensitive", func(t *testing.T) {
		t.Parallel()
		s := open(t)
		tn := newTenant("acme")
		mustCreate(t, s.Tenants(), tn)
		mustCreateClient(t, s.Clients(), newClient(tn.ID, "app"))
		mustCreateClient(t, s.Clients(), newClient(tn.ID, "App"))
		if _, err := s.Clients().GetByClientID(t.Context(), tn.ID, "APP"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetByClientID() with another case error = %v, want ErrNotFound", err)
		}
	})

	t.Run("NotFound", func(t *testing.T) {
		t.Parallel()
		s := open(t)
		tn := newTenant("acme")
		mustCreate(t, s.Tenants(), tn)
		clients := s.Clients()
		if _, err := clients.GetByClientID(t.Context(), tn.ID, "missing"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetByClientID() error = %v, want ErrNotFound", err)
		}
		missing := uuid.NewV7()
		if _, err := clients.Get(t.Context(), tn.ID, missing); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get() error = %v, want ErrNotFound", err)
		}
		if err := clients.UpdateSecret(t.Context(), tn.ID, missing, []byte("hash"), time.Now()); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("UpdateSecret() error = %v, want ErrNotFound", err)
		}
		if err := clients.Delete(t.Context(), tn.ID, missing); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Delete() error = %v, want ErrNotFound", err)
		}
	})

	t.Run("ConflictOnDuplicateClientIDWithinTenant", func(t *testing.T) {
		t.Parallel()
		s := open(t)
		a, b := newTenant("a"), newTenant("b")
		mustCreate(t, s.Tenants(), a)
		mustCreate(t, s.Tenants(), b)
		mustCreateClient(t, s.Clients(), newClient(a.ID, "web-app"))
		if err := s.Clients().Create(t.Context(), newClient(a.ID, "web-app")); !errors.Is(err, store.ErrConflict) {
			t.Errorf("Create() with a duplicate client ID error = %v, want ErrConflict", err)
		}
		// Another tenant can use the same client ID.
		mustCreateClient(t, s.Clients(), newClient(b.ID, "web-app"))
	})

	t.Run("ConflictOnDuplicateID", func(t *testing.T) {
		t.Parallel()
		s := open(t)
		tn := newTenant("acme")
		mustCreate(t, s.Tenants(), tn)
		first := newClient(tn.ID, "first")
		mustCreateClient(t, s.Clients(), first)
		dup := newClient(tn.ID, "second")
		dup.ID = first.ID
		if err := s.Clients().Create(t.Context(), dup); !errors.Is(err, store.ErrConflict) {
			t.Errorf("Create() with a duplicate ID error = %v, want ErrConflict", err)
		}
	})

	t.Run("UnknownTenant", func(t *testing.T) {
		t.Parallel()
		s := open(t)
		if err := s.Clients().Create(t.Context(), newClient(uuid.NewV7(), "web-app")); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Create() for an unknown tenant error = %v, want ErrNotFound", err)
		}
	})

	t.Run("UpdateSecret", func(t *testing.T) {
		t.Parallel()
		s := open(t)
		tn := newTenant("acme")
		mustCreate(t, s.Tenants(), tn)
		c := newClient(tn.ID, "web-app")
		mustCreateClient(t, s.Clients(), c)

		updatedAt := c.UpdatedAt.Add(time.Hour)
		newHash := []byte("new-hash-" + c.ID.String())
		if err := s.Clients().UpdateSecret(t.Context(), tn.ID, c.ID, newHash, updatedAt); err != nil {
			t.Fatalf("UpdateSecret() unexpected error: %v", err)
		}
		got, err := s.Clients().GetByClientID(t.Context(), tn.ID, c.ClientID)
		if err != nil {
			t.Fatalf("GetByClientID() unexpected error: %v", err)
		}
		want := c
		want.SecretHash = newHash
		want.UpdatedAt = updatedAt
		if diff := cmp.Diff(normalizeClient(want), got, cmpopts.EquateEmpty()); diff != "" {
			t.Errorf("client after UpdateSecret() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		t.Parallel()
		s := open(t)
		tn := newTenant("acme")
		mustCreate(t, s.Tenants(), tn)
		keep, drop := newClient(tn.ID, "keep"), newClient(tn.ID, "drop")
		mustCreateClient(t, s.Clients(), keep)
		mustCreateClient(t, s.Clients(), drop)
		if err := s.Clients().Delete(t.Context(), tn.ID, drop.ID); err != nil {
			t.Fatalf("Delete() unexpected error: %v", err)
		}
		if _, err := s.Clients().GetByClientID(t.Context(), tn.ID, drop.ClientID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetByClientID() after Delete() error = %v, want ErrNotFound", err)
		}
		if _, err := s.Clients().GetByClientID(t.Context(), tn.ID, keep.ClientID); err != nil {
			t.Errorf("Delete() removed another client: %v", err)
		}
		// The client ID becomes available again.
		mustCreateClient(t, s.Clients(), newClient(tn.ID, "drop"))
	})

	t.Run("TenantIsolation", func(t *testing.T) {
		t.Parallel()
		s := open(t)
		a, b := newTenant("a"), newTenant("b")
		mustCreate(t, s.Tenants(), a)
		mustCreate(t, s.Tenants(), b)
		c := newClient(a.ID, "web-app")
		mustCreateClient(t, s.Clients(), c)
		clients := s.Clients()

		if _, err := clients.GetByClientID(t.Context(), b.ID, c.ClientID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetByClientID() through tenant b error = %v, want ErrNotFound", err)
		}
		if _, err := clients.Get(t.Context(), b.ID, c.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get() through tenant b error = %v, want ErrNotFound", err)
		}
		if got, err := clients.List(t.Context(), b.ID, uuid.Nil(), store.MaxPageSize); err != nil || len(got) != 0 {
			t.Errorf("List() for tenant b = %d clients, %v; want none", len(got), err)
		}
		if err := clients.UpdateSecret(t.Context(), b.ID, c.ID, []byte("other"), time.Now()); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("UpdateSecret() through tenant b error = %v, want ErrNotFound", err)
		}
		if err := clients.Delete(t.Context(), b.ID, c.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Delete() through tenant b error = %v, want ErrNotFound", err)
		}
		got, err := clients.GetByClientID(t.Context(), a.ID, c.ClientID)
		if err != nil {
			t.Fatalf("client of tenant a is gone: %v", err)
		}
		if diff := cmp.Diff(normalizeClient(c), got, cmpopts.EquateEmpty()); diff != "" {
			t.Errorf("client of tenant a changed through tenant b (-want +got):\n%s", diff)
		}
	})

	t.Run("ListPagesInIDOrderWithinTenant", func(t *testing.T) {
		t.Parallel()
		s := open(t)
		a, b := newTenant("a"), newTenant("b")
		mustCreate(t, s.Tenants(), a)
		mustCreate(t, s.Tenants(), b)
		var want []uuid.UUID
		for i := range 5 {
			c := newClient(a.ID, fmt.Sprintf("client-%d", i))
			mustCreateClient(t, s.Clients(), c)
			want = append(want, c.ID)
			// Clients of another tenant interleave in ID order.
			mustCreateClient(t, s.Clients(), newClient(b.ID, fmt.Sprintf("client-%d", i)))
		}

		var got []uuid.UUID
		after := uuid.Nil()
		for {
			page, err := s.Clients().List(t.Context(), a.ID, after, 2)
			if err != nil {
				t.Fatalf("List() unexpected error: %v", err)
			}
			if len(page) > 2 {
				t.Fatalf("List() returned %d records, want at most 2", len(page))
			}
			if len(page) == 0 {
				break
			}
			for _, c := range page {
				if c.TenantID != a.ID {
					t.Errorf("List() for tenant a returned client %s of tenant %s", c.ClientID, c.TenantID)
				}
				got = append(got, c.ID)
			}
			after = page[len(page)-1].ID
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("paged IDs mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("ListRejectsInvalidLimits", func(t *testing.T) {
		t.Parallel()
		s := open(t)
		tn := newTenant("acme")
		mustCreate(t, s.Tenants(), tn)
		for _, limit := range []int{-1, 0, store.MaxPageSize + 1} {
			if _, err := s.Clients().List(t.Context(), tn.ID, uuid.Nil(), limit); !errors.Is(err, store.ErrInvalidArgument) {
				t.Errorf("List(limit=%d) error = %v, want ErrInvalidArgument", limit, err)
			}
		}
	})

	t.Run("DeletedWithTenant", func(t *testing.T) {
		t.Parallel()
		s := open(t)
		tn := newTenant("acme")
		mustCreate(t, s.Tenants(), tn)
		mustCreateClient(t, s.Clients(), newClient(tn.ID, "web-app"))
		if err := s.Tenants().Delete(t.Context(), tn.ID); err != nil {
			t.Fatalf("deleting tenant: %v", err)
		}
		got, err := s.Clients().List(t.Context(), tn.ID, uuid.Nil(), store.MaxPageSize)
		if err != nil {
			t.Fatalf("List() unexpected error: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("%d clients survived the deletion of their tenant", len(got))
		}
	})
}

// newClient returns a confidential client record with every field set. The
// values are placeholders: stores do not validate them.
func newClient(tenantID uuid.UUID, clientID string) store.Client {
	id := uuid.NewV7()
	created := time.Date(2026, 10, 15, 9, 30, 0, 123456789, time.UTC)
	return store.Client{
		ID:                     id,
		TenantID:               tenantID,
		ClientID:               clientID,
		Name:                   "Client " + clientID,
		Type:                   store.ClientConfidential,
		SecretHash:             []byte("hash-" + id.String()),
		RedirectURIs:           []string{"https://app.example.com/callback", "http://127.0.0.1/callback"},
		PostLogoutRedirectURIs: []string{"https://app.example.com/"},
		GrantTypes:             []string{"authorization_code", "refresh_token"},
		Scopes:                 []string{"openid", "profile", "orders:read"},
		Lifetimes: store.TokenLifetimes{
			AccessToken:          15 * time.Minute,
			IDToken:              5 * time.Minute,
			RefreshTokenIdle:     72 * time.Hour,
			RefreshTokenAbsolute: 30 * 24 * time.Hour,
		},
		SkipConsent: true,
		PKCEExempt:  true,
		CreatedAt:   created,
		UpdatedAt:   created.Add(time.Minute),
	}
}

func mustCreateClient(t *testing.T, clients store.Clients, c store.Client) {
	t.Helper()
	if err := clients.Create(t.Context(), c); err != nil {
		t.Fatalf("Create(%q) unexpected error: %v", c.ClientID, err)
	}
}

// normalizeClient returns c as a store returns it.
func normalizeClient(c store.Client) store.Client {
	c.CreatedAt = c.CreatedAt.UTC().Truncate(time.Microsecond)
	c.UpdatedAt = c.UpdatedAt.UTC().Truncate(time.Microsecond)
	return c
}

func runUsers(t *testing.T, open OpenFunc) {
	t.Run("CreateAndGet", func(t *testing.T) {
		t.Parallel()
		s := open(t)
		tn := newTenant("acme")
		mustCreate(t, s.Tenants(), tn)
		want := newUser(tn.ID, "ada@example.com")
		mustCreateUser(t, s.Users(), want)

		got, err := s.Users().Get(t.Context(), tn.ID, want.ID)
		if err != nil {
			t.Fatalf("Get() unexpected error: %v", err)
		}
		if diff := cmp.Diff(normalizeUser(want), got); diff != "" {
			t.Errorf("Get() mismatch (-want +got):\n%s", diff)
		}
		got, err = s.Users().GetByEmail(t.Context(), tn.ID, want.Email)
		if err != nil {
			t.Fatalf("GetByEmail() unexpected error: %v", err)
		}
		if diff := cmp.Diff(normalizeUser(want), got); diff != "" {
			t.Errorf("GetByEmail() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("EmptyProfile", func(t *testing.T) {
		t.Parallel()
		s := open(t)
		tn := newTenant("acme")
		mustCreate(t, s.Tenants(), tn)
		want := newUser(tn.ID, "ada@example.com")
		want.Profile = store.Profile{}
		mustCreateUser(t, s.Users(), want)
		got, err := s.Users().Get(t.Context(), tn.ID, want.ID)
		if err != nil {
			t.Fatalf("Get() unexpected error: %v", err)
		}
		if diff := cmp.Diff(normalizeUser(want), got); diff != "" {
			t.Errorf("Get() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("EmailIsComparedExactly", func(t *testing.T) {
		t.Parallel()
		s := open(t)
		tn := newTenant("acme")
		mustCreate(t, s.Tenants(), tn)
		mustCreateUser(t, s.Users(), newUser(tn.ID, "ada@example.com"))
		if _, err := s.Users().GetByEmail(t.Context(), tn.ID, "Ada@example.com"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetByEmail() with another case error = %v, want ErrNotFound", err)
		}
	})

	t.Run("NotFound", func(t *testing.T) {
		t.Parallel()
		s := open(t)
		tn := newTenant("acme")
		mustCreate(t, s.Tenants(), tn)
		missing := uuid.NewV7()
		if _, err := s.Users().Get(t.Context(), tn.ID, missing); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get() error = %v, want ErrNotFound", err)
		}
		if _, err := s.Users().GetByEmail(t.Context(), tn.ID, "missing@example.com"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetByEmail() error = %v, want ErrNotFound", err)
		}
		if err := s.Users().Delete(t.Context(), tn.ID, missing); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Delete() error = %v, want ErrNotFound", err)
		}
	})

	t.Run("ConflictOnDuplicateEmailWithinTenant", func(t *testing.T) {
		t.Parallel()
		s := open(t)
		a, b := newTenant("a"), newTenant("b")
		mustCreate(t, s.Tenants(), a)
		mustCreate(t, s.Tenants(), b)
		mustCreateUser(t, s.Users(), newUser(a.ID, "ada@example.com"))
		if err := s.Users().Create(t.Context(), newUser(a.ID, "ada@example.com")); !errors.Is(err, store.ErrConflict) {
			t.Errorf("Create() with a duplicate email error = %v, want ErrConflict", err)
		}
		// Another tenant can have a user with the same email.
		mustCreateUser(t, s.Users(), newUser(b.ID, "ada@example.com"))
	})

	t.Run("ConflictOnDuplicateID", func(t *testing.T) {
		t.Parallel()
		s := open(t)
		tn := newTenant("acme")
		mustCreate(t, s.Tenants(), tn)
		first := newUser(tn.ID, "ada@example.com")
		mustCreateUser(t, s.Users(), first)
		dup := newUser(tn.ID, "grace@example.com")
		dup.ID = first.ID
		if err := s.Users().Create(t.Context(), dup); !errors.Is(err, store.ErrConflict) {
			t.Errorf("Create() with a duplicate ID error = %v, want ErrConflict", err)
		}
	})

	t.Run("UnknownTenant", func(t *testing.T) {
		t.Parallel()
		s := open(t)
		if err := s.Users().Create(t.Context(), newUser(uuid.NewV7(), "ada@example.com")); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Create() for an unknown tenant error = %v, want ErrNotFound", err)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		t.Parallel()
		s := open(t)
		tn := newTenant("acme")
		mustCreate(t, s.Tenants(), tn)
		keep, drop := newUser(tn.ID, "keep@example.com"), newUser(tn.ID, "drop@example.com")
		mustCreateUser(t, s.Users(), keep)
		mustCreateUser(t, s.Users(), drop)
		if err := s.Users().Delete(t.Context(), tn.ID, drop.ID); err != nil {
			t.Fatalf("Delete() unexpected error: %v", err)
		}
		if _, err := s.Users().Get(t.Context(), tn.ID, drop.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get() after Delete() error = %v, want ErrNotFound", err)
		}
		if _, err := s.Users().Get(t.Context(), tn.ID, keep.ID); err != nil {
			t.Errorf("Delete() removed another user: %v", err)
		}
		// The email becomes available again.
		mustCreateUser(t, s.Users(), newUser(tn.ID, "drop@example.com"))
	})

	t.Run("TenantIsolation", func(t *testing.T) {
		t.Parallel()
		s := open(t)
		a, b := newTenant("a"), newTenant("b")
		mustCreate(t, s.Tenants(), a)
		mustCreate(t, s.Tenants(), b)
		u := newUser(a.ID, "ada@example.com")
		mustCreateUser(t, s.Users(), u)
		users := s.Users()

		if _, err := users.Get(t.Context(), b.ID, u.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get() through tenant b error = %v, want ErrNotFound", err)
		}
		if _, err := users.GetByEmail(t.Context(), b.ID, u.Email); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetByEmail() through tenant b error = %v, want ErrNotFound", err)
		}
		if got, err := users.List(t.Context(), b.ID, uuid.Nil(), store.MaxPageSize); err != nil || len(got) != 0 {
			t.Errorf("List() for tenant b = %d users, %v; want none", len(got), err)
		}
		if err := users.Delete(t.Context(), b.ID, u.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Delete() through tenant b error = %v, want ErrNotFound", err)
		}
		if _, err := users.Get(t.Context(), a.ID, u.ID); err != nil {
			t.Errorf("user of tenant a is gone: %v", err)
		}
	})

	t.Run("ListPagesInIDOrderWithinTenant", func(t *testing.T) {
		t.Parallel()
		s := open(t)
		a, b := newTenant("a"), newTenant("b")
		mustCreate(t, s.Tenants(), a)
		mustCreate(t, s.Tenants(), b)
		var want []uuid.UUID
		for i := range 5 {
			u := newUser(a.ID, fmt.Sprintf("user-%d@example.com", i))
			mustCreateUser(t, s.Users(), u)
			want = append(want, u.ID)
			mustCreateUser(t, s.Users(), newUser(b.ID, fmt.Sprintf("user-%d@example.com", i)))
		}

		var got []uuid.UUID
		after := uuid.Nil()
		for {
			page, err := s.Users().List(t.Context(), a.ID, after, 2)
			if err != nil {
				t.Fatalf("List() unexpected error: %v", err)
			}
			if len(page) > 2 {
				t.Fatalf("List() returned %d records, want at most 2", len(page))
			}
			if len(page) == 0 {
				break
			}
			for _, u := range page {
				if u.TenantID != a.ID {
					t.Errorf("List() for tenant a returned user %s of tenant %s", u.ID, u.TenantID)
				}
				got = append(got, u.ID)
			}
			after = page[len(page)-1].ID
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("paged IDs mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("ListRejectsInvalidLimits", func(t *testing.T) {
		t.Parallel()
		s := open(t)
		tn := newTenant("acme")
		mustCreate(t, s.Tenants(), tn)
		for _, limit := range []int{-1, 0, store.MaxPageSize + 1} {
			if _, err := s.Users().List(t.Context(), tn.ID, uuid.Nil(), limit); !errors.Is(err, store.ErrInvalidArgument) {
				t.Errorf("List(limit=%d) error = %v, want ErrInvalidArgument", limit, err)
			}
		}
	})

	t.Run("DeletedWithTenant", func(t *testing.T) {
		t.Parallel()
		s := open(t)
		tn := newTenant("acme")
		mustCreate(t, s.Tenants(), tn)
		u := newUser(tn.ID, "ada@example.com")
		mustCreateUser(t, s.Users(), u)
		mustSetPassword(t, s.Passwords(), newPassword(u, "hash"))
		if err := s.Tenants().Delete(t.Context(), tn.ID); err != nil {
			t.Fatalf("deleting tenant: %v", err)
		}
		if got, err := s.Users().List(t.Context(), tn.ID, uuid.Nil(), store.MaxPageSize); err != nil || len(got) != 0 {
			t.Errorf("List() after deleting the tenant = %d users, %v; want none", len(got), err)
		}
		if _, err := s.Passwords().Get(t.Context(), tn.ID, u.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("password after deleting the tenant error = %v, want ErrNotFound", err)
		}
	})
}

func runPasswords(t *testing.T, open OpenFunc) {
	// setup returns a store with one user in tenant a and an empty tenant b.
	setup := func(t *testing.T) (store.Store, store.User, store.Tenant) {
		t.Helper()
		s := open(t)
		a, b := newTenant("a"), newTenant("b")
		mustCreate(t, s.Tenants(), a)
		mustCreate(t, s.Tenants(), b)
		u := newUser(a.ID, "ada@example.com")
		mustCreateUser(t, s.Users(), u)
		return s, u, b
	}
	get := func(t *testing.T, s store.Store, u store.User) store.Password {
		t.Helper()
		p, err := s.Passwords().Get(t.Context(), u.TenantID, u.ID)
		if err != nil {
			t.Fatalf("Get() unexpected error: %v", err)
		}
		return p
	}

	t.Run("SetAndGet", func(t *testing.T) {
		t.Parallel()
		s, u, _ := setup(t)
		want := newPassword(u, "$argon2id$v=19$m=19456,t=2,p=1$first")
		mustSetPassword(t, s.Passwords(), want)
		if diff := cmp.Diff(normalizePassword(want), get(t, s, u)); diff != "" {
			t.Errorf("Get() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("SetReplaces", func(t *testing.T) {
		t.Parallel()
		s, u, _ := setup(t)
		mustSetPassword(t, s.Passwords(), newPassword(u, "first"))
		second := newPassword(u, "second")
		second.SetAt = second.SetAt.Add(time.Hour)
		mustSetPassword(t, s.Passwords(), second)
		if diff := cmp.Diff(normalizePassword(second), get(t, s, u)); diff != "" {
			t.Errorf("Get() after a second Set() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("NotFound", func(t *testing.T) {
		t.Parallel()
		s, u, _ := setup(t)
		if _, err := s.Passwords().Get(t.Context(), u.TenantID, u.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get() for a user without a password error = %v, want ErrNotFound", err)
		}
		if err := s.Passwords().Rehash(t.Context(), u.TenantID, u.ID, "old", "new"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Rehash() for a user without a password error = %v, want ErrNotFound", err)
		}
		ghost := u
		ghost.ID = uuid.NewV7()
		if err := s.Passwords().Set(t.Context(), newPassword(ghost, "hash")); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Set() for an unknown user error = %v, want ErrNotFound", err)
		}
	})

	t.Run("Rehash", func(t *testing.T) {
		t.Parallel()
		s, u, _ := setup(t)
		first := newPassword(u, "old-hash")
		mustSetPassword(t, s.Passwords(), first)
		if err := s.Passwords().Rehash(t.Context(), u.TenantID, u.ID, "old-hash", "new-hash"); err != nil {
			t.Fatalf("Rehash() unexpected error: %v", err)
		}
		want := normalizePassword(first)
		want.Hash = "new-hash"
		if diff := cmp.Diff(want, get(t, s, u)); diff != "" {
			t.Errorf("Get() after Rehash() mismatch (-want +got):\n%s", diff)
		}

		// A rehash based on a hash that changed in the meantime fails.
		if err := s.Passwords().Rehash(t.Context(), u.TenantID, u.ID, "old-hash", "stale"); !errors.Is(err, store.ErrConflict) {
			t.Errorf("Rehash() of a changed hash error = %v, want ErrConflict", err)
		}
		if got := get(t, s, u); got.Hash != "new-hash" {
			t.Errorf("a failed Rehash() changed the hash to %q", got.Hash)
		}
	})

	t.Run("TenantIsolation", func(t *testing.T) {
		t.Parallel()
		s, u, other := setup(t)
		mustSetPassword(t, s.Passwords(), newPassword(u, "hash-a"))

		through := newPassword(u, "hash-b")
		through.TenantID = other.ID
		if err := s.Passwords().Set(t.Context(), through); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Set() through tenant b error = %v, want ErrNotFound", err)
		}
		if _, err := s.Passwords().Get(t.Context(), other.ID, u.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get() through tenant b error = %v, want ErrNotFound", err)
		}
		if err := s.Passwords().Rehash(t.Context(), other.ID, u.ID, "hash-a", "hash-b"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Rehash() through tenant b error = %v, want ErrNotFound", err)
		}
		if got := get(t, s, u); got.Hash != "hash-a" {
			t.Errorf("the password changed through tenant b: %q", got.Hash)
		}

		// A user of tenant b cannot take a password for the user of tenant a.
		bob := newUser(other.ID, "bob@example.com")
		mustCreateUser(t, s.Users(), bob)
		mismatched := newPassword(u, "hash-c")
		mismatched.TenantID = other.ID
		if err := s.Passwords().Set(t.Context(), mismatched); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Set() with the user of another tenant error = %v, want ErrNotFound", err)
		}
	})

	t.Run("DeletedWithUser", func(t *testing.T) {
		t.Parallel()
		s, u, _ := setup(t)
		mustSetPassword(t, s.Passwords(), newPassword(u, "hash"))
		if err := s.Users().Delete(t.Context(), u.TenantID, u.ID); err != nil {
			t.Fatalf("deleting user: %v", err)
		}
		if _, err := s.Passwords().Get(t.Context(), u.TenantID, u.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get() after deleting the user error = %v, want ErrNotFound", err)
		}
	})
}

// newUser returns an active user record with every profile claim set.
func newUser(tenantID uuid.UUID, email string) store.User {
	created := time.Date(2026, 10, 15, 9, 30, 0, 123456789, time.UTC)
	return store.User{
		ID:            uuid.NewV7(),
		TenantID:      tenantID,
		Email:         email,
		EmailVerified: true,
		Status:        store.UserActive,
		Profile: store.Profile{
			Name:                "Ada Lovelace",
			GivenName:           "Ada",
			FamilyName:          "Lovelace",
			MiddleName:          "Augusta",
			Nickname:            "ada",
			PreferredUsername:   "ada.l",
			ProfileURL:          "https://example.com/ada",
			Picture:             "https://example.com/ada.png",
			Website:             "https://ada.example.com",
			Gender:              "female",
			Birthdate:           "1815-12-10",
			Zoneinfo:            "Europe/London",
			Locale:              "en-GB",
			PhoneNumber:         "+44 20 7946 0000",
			PhoneNumberVerified: true,
			Address: store.Address{
				Formatted:     "12 St James's Square, London",
				StreetAddress: "12 St James's Square",
				Locality:      "London",
				Region:        "England",
				PostalCode:    "SW1Y 4JH",
				Country:       "GB",
			},
		},
		CreatedAt: created,
		UpdatedAt: created.Add(time.Minute),
	}
}

func mustCreateUser(t *testing.T, users store.Users, u store.User) {
	t.Helper()
	if err := users.Create(t.Context(), u); err != nil {
		t.Fatalf("Create(%q) unexpected error: %v", u.Email, err)
	}
}

// normalizeUser returns u as a store returns it.
func normalizeUser(u store.User) store.User {
	u.CreatedAt = u.CreatedAt.UTC().Truncate(time.Microsecond)
	u.UpdatedAt = u.UpdatedAt.UTC().Truncate(time.Microsecond)
	return u
}

func newPassword(u store.User, hash string) store.Password {
	return store.Password{
		TenantID: u.TenantID,
		UserID:   u.ID,
		Hash:     hash,
		SetAt:    time.Date(2026, 10, 15, 10, 0, 0, 987654321, time.UTC),
	}
}

func mustSetPassword(t *testing.T, passwords store.Passwords, p store.Password) {
	t.Helper()
	if err := passwords.Set(t.Context(), p); err != nil {
		t.Fatalf("Set() unexpected error: %v", err)
	}
}

// normalizePassword returns p as a store returns it.
func normalizePassword(p store.Password) store.Password {
	p.SetAt = p.SetAt.UTC().Truncate(time.Microsecond)
	return p
}
