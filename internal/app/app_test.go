package app

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"
	"uuid"

	"github.com/clavis-id/clavis/store"
	"github.com/clavis-id/clavis/store/sqlite"
)

func newDeps(t *testing.T, s store.Store) Deps {
	t.Helper()
	return Deps{
		Store:  s,
		Logger: slog.New(slog.DiscardHandler),
		Now:    func() time.Time { return time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC) },
		NewID:  uuid.NewV7,
	}
}

func openStore(t *testing.T) *sqlite.Store {
	t.Helper()
	s, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "clavis.db"))
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestEnsureDefaultTenantCreatesOnce(t *testing.T) {
	t.Parallel()
	d := newDeps(t, openStore(t))

	first, err := EnsureDefaultTenant(t.Context(), d)
	if err != nil {
		t.Fatalf("first call unexpected error: %v", err)
	}
	if first.Slug != DefaultTenantSlug || !first.CreatedAt.Equal(d.Now()) {
		t.Errorf("created tenant = %+v, want slug %q created at %v", first, DefaultTenantSlug, d.Now())
	}

	second, err := EnsureDefaultTenant(t.Context(), d)
	if err != nil {
		t.Fatalf("second call unexpected error: %v", err)
	}
	if second.ID != first.ID {
		t.Errorf("second call returned tenant %v, want the existing %v", second.ID, first.ID)
	}
}

func TestEnsureDefaultTenantIsSafeUnderConcurrency(t *testing.T) {
	t.Parallel()
	d := newDeps(t, openStore(t))

	const callers = 8
	ids := make([]uuid.UUID, callers)
	errs := make([]error, callers)
	var wg sync.WaitGroup
	for i := range callers {
		wg.Go(func() {
			var tn store.Tenant
			tn, errs[i] = EnsureDefaultTenant(t.Context(), d)
			ids[i] = tn.ID
		})
	}
	wg.Wait()

	for i := range callers {
		if errs[i] != nil {
			t.Fatalf("caller %d unexpected error: %v", i, errs[i])
		}
		if ids[i] != ids[0] {
			t.Errorf("caller %d got tenant %v, want %v", i, ids[i], ids[0])
		}
	}
}

// failingStore returns a fixed error from every tenant lookup.
type failingStore struct{}

func (failingStore) Tenants() store.Tenants     { return failingTenants{} }
func (failingStore) Ping(context.Context) error { return nil }

type failingTenants struct{ store.Tenants }

var errUnavailable = errors.New("database unavailable")

func (failingTenants) GetBySlug(context.Context, string) (store.Tenant, error) {
	return store.Tenant{}, errUnavailable
}

func TestEnsureDefaultTenantReportsStoreErrors(t *testing.T) {
	t.Parallel()
	_, err := EnsureDefaultTenant(t.Context(), newDeps(t, failingStore{}))
	if !errors.Is(err, errUnavailable) {
		t.Errorf("error = %v, want it to wrap the store error", err)
	}
}
