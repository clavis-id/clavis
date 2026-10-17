package storetest

import (
	"errors"
	"testing"
	"time"
	"uuid"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"clavisid.org/clavis/store"
)

func runGrants(t *testing.T, open OpenFunc) {
	get := func(t *testing.T, f authorizationFixture, userID, clientID uuid.UUID) (store.Grant, error) {
		t.Helper()
		return f.s.Grants().Get(t.Context(), f.a.ID, userID, clientID)
	}

	t.Run("PutGetListAndDelete", func(t *testing.T) {
		t.Parallel()
		f := newAuthorizationFixture(t, open)
		first := newGrant(f.user, f.client)
		mustPutGrant(t, f.s, first)
		got, err := get(t, f, f.user.ID, f.client.ID)
		if err != nil {
			t.Fatalf("Get() unexpected error: %v", err)
		}
		if diff := cmp.Diff(normalizeGrant(first), got, cmpopts.EquateEmpty()); diff != "" {
			t.Errorf("Get() mismatch (-want +got):\n%s", diff)
		}

		// A second Put replaces the scopes and the update time, and keeps
		// the ID and the creation time of the grant.
		update := newGrant(f.user, f.client)
		update.Scopes = []string{"openid", "profile", "email"}
		update.CreatedAt = first.CreatedAt.Add(time.Hour)
		update.UpdatedAt = first.UpdatedAt.Add(time.Hour)
		mustPutGrant(t, f.s, update)
		want := first
		want.Scopes, want.UpdatedAt = update.Scopes, update.UpdatedAt
		got, err = get(t, f, f.user.ID, f.client.ID)
		if err != nil {
			t.Fatalf("Get() after the second Put() unexpected error: %v", err)
		}
		if diff := cmp.Diff(normalizeGrant(want), got, cmpopts.EquateEmpty()); diff != "" {
			t.Errorf("Get() after the second Put() mismatch (-want +got):\n%s", diff)
		}

		other := newClient(f.a.ID, "other")
		mustCreateClient(t, f.s.Clients(), other)
		second := newGrant(f.user, other)
		second.CreatedAt = first.CreatedAt.Add(time.Minute)
		second.Scopes = nil
		mustPutGrant(t, f.s, second)
		list, err := f.s.Grants().List(t.Context(), f.a.ID, f.user.ID)
		if err != nil {
			t.Fatalf("List() unexpected error: %v", err)
		}
		if diff := cmp.Diff([]store.Grant{normalizeGrant(want), normalizeGrant(second)}, list, cmpopts.EquateEmpty()); diff != "" {
			t.Errorf("List() mismatch (-want +got):\n%s", diff)
		}

		if err := f.s.Grants().Delete(t.Context(), f.a.ID, f.user.ID, f.client.ID); err != nil {
			t.Fatalf("Delete() unexpected error: %v", err)
		}
		if _, err := get(t, f, f.user.ID, f.client.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get() after Delete() = %v, want ErrNotFound", err)
		}
		if err := f.s.Grants().Delete(t.Context(), f.a.ID, f.user.ID, f.client.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("a second Delete() = %v, want ErrNotFound", err)
		}
	})

	t.Run("NotFound", func(t *testing.T) {
		t.Parallel()
		f := newAuthorizationFixture(t, open)
		if _, err := get(t, f, f.user.ID, f.client.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get() error = %v, want ErrNotFound", err)
		}
		if list, err := f.s.Grants().List(t.Context(), f.a.ID, f.user.ID); err != nil || len(list) != 0 {
			t.Errorf("List() = %v, %v; want no grants", list, err)
		}
		noUser := newGrant(f.user, f.client)
		noUser.UserID = uuid.NewV7()
		noClient := newGrant(f.user, f.client)
		noClient.ClientID = uuid.NewV7()
		for name, g := range map[string]store.Grant{"user": noUser, "client": noClient} {
			if err := f.s.Grants().Put(t.Context(), g); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("Put() for an unknown %s = %v, want ErrNotFound", name, err)
			}
		}
	})

	t.Run("TenantIsolation", func(t *testing.T) {
		t.Parallel()
		f := newAuthorizationFixture(t, open)
		g := newGrant(f.user, f.client)
		mustPutGrant(t, f.s, g)
		grants := f.s.Grants()
		if _, err := grants.Get(t.Context(), f.b.ID, f.user.ID, f.client.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get() from another tenant = %v, want ErrNotFound", err)
		}
		if list, err := grants.List(t.Context(), f.b.ID, f.user.ID); err != nil || len(list) != 0 {
			t.Errorf("List() from another tenant = %v, %v; want no grants", list, err)
		}
		if err := grants.Delete(t.Context(), f.b.ID, f.user.ID, f.client.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Delete() from another tenant = %v, want ErrNotFound", err)
		}
		foreignUser := newGrant(f.user, f.client)
		foreignUser.UserID = f.userB.ID
		foreignClient := newGrant(f.user, f.client)
		foreignClient.ClientID = f.clientB.ID
		for name, g := range map[string]store.Grant{"user": foreignUser, "client": foreignClient} {
			if err := grants.Put(t.Context(), g); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("Put() for the %s of another tenant = %v, want ErrNotFound", name, err)
			}
		}
	})

	t.Run("DeletedWithTheUserOrTheClient", func(t *testing.T) {
		t.Parallel()
		f := newAuthorizationFixture(t, open)
		other := newClient(f.a.ID, "other")
		mustCreateClient(t, f.s.Clients(), other)
		mustPutGrant(t, f.s, newGrant(f.user, f.client))
		mustPutGrant(t, f.s, newGrant(f.user, other))
		if err := f.s.Clients().Delete(t.Context(), f.a.ID, other.ID); err != nil {
			t.Fatalf("deleting the client: %v", err)
		}
		if _, err := get(t, f, f.user.ID, other.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get() after deleting the client = %v, want ErrNotFound", err)
		}
		if _, err := get(t, f, f.user.ID, f.client.ID); err != nil {
			t.Fatalf("Get() of the grant of another client unexpected error: %v", err)
		}
		if err := f.s.Users().Delete(t.Context(), f.a.ID, f.user.ID); err != nil {
			t.Fatalf("deleting the user: %v", err)
		}
		if _, err := get(t, f, f.user.ID, f.client.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get() after deleting the user = %v, want ErrNotFound", err)
		}
	})
}

// newGrant returns a grant of u to c with every field set.
func newGrant(u store.User, c store.Client) store.Grant {
	created := time.Date(2026, 10, 17, 9, 30, 0, 123456789, time.UTC)
	return store.Grant{
		ID:        uuid.NewV7(),
		TenantID:  u.TenantID,
		UserID:    u.ID,
		ClientID:  c.ID,
		Scopes:    []string{"openid", "profile"},
		CreatedAt: created,
		UpdatedAt: created.Add(time.Second),
	}
}

func mustPutGrant(t *testing.T, s store.Store, g store.Grant) {
	t.Helper()
	if err := s.Grants().Put(t.Context(), g); err != nil {
		t.Fatalf("Put() unexpected error: %v", err)
	}
}

// normalizeGrant returns g as a store returns it.
func normalizeGrant(g store.Grant) store.Grant {
	g.CreatedAt = g.CreatedAt.UTC().Truncate(time.Microsecond)
	g.UpdatedAt = g.UpdatedAt.UTC().Truncate(time.Microsecond)
	return g
}
