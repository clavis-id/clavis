// Package app implements the Clavis use cases on top of the storage ports.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
	"uuid"

	"github.com/clavis-id/clavis/store"
)

// DefaultTenantSlug is the slug of the tenant served at the root issuer.
const DefaultTenantSlug = "default"

// Deps holds the dependencies shared by the use cases. Now and NewID are
// injected so tests control time and identifiers.
type Deps struct {
	Store  store.Store
	Logger *slog.Logger
	Now    func() time.Time
	NewID  func() uuid.UUID
}

// EnsureDefaultTenant returns the default tenant, creating it the first time
// Clavis starts on an empty store. It is safe to call concurrently from
// several instances sharing a store.
func EnsureDefaultTenant(ctx context.Context, d Deps) (store.Tenant, error) {
	tenants := d.Store.Tenants()
	t, err := tenants.GetBySlug(ctx, DefaultTenantSlug)
	if err == nil {
		return t, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return store.Tenant{}, fmt.Errorf("looking up the default tenant: %w", err)
	}

	now := d.Now()
	t = store.Tenant{
		ID:        d.NewID(),
		Slug:      DefaultTenantSlug,
		Name:      "Default",
		CreatedAt: now,
		UpdatedAt: now,
	}
	switch err := tenants.Create(ctx, t); {
	case err == nil:
		d.Logger.LogAttrs(ctx, slog.LevelInfo, "created the default tenant",
			slog.String("tenant_id", t.ID.String()))
		return t, nil
	case errors.Is(err, store.ErrConflict):
		// Another instance created it first.
		t, err := tenants.GetBySlug(ctx, DefaultTenantSlug)
		if err != nil {
			return store.Tenant{}, fmt.Errorf("looking up the default tenant: %w", err)
		}
		return t, nil
	default:
		return store.Tenant{}, fmt.Errorf("creating the default tenant: %w", err)
	}
}
