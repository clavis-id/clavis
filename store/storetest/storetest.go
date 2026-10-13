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

	"github.com/clavis-id/clavis/store"
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
