// Package store defines the storage ports of Clavis.
//
// Clavis ships two adapters, store/sqlite and store/postgres. Other databases
// can be supported by implementing the interfaces in this package; an
// implementation is correct when it passes the contract suite in
// store/storetest.
//
// Records are plain values. Adapters persist them as given and do not apply
// business rules beyond uniqueness; validation happens before a record
// reaches the store. Times are stored with microsecond precision and returned
// in UTC.
package store

import (
	"context"
	"errors"
	"time"
	"uuid"
)

// Errors returned by every adapter. Adapters wrap them, so callers must test
// with errors.Is.
var (
	// ErrNotFound reports that no record matches the request.
	ErrNotFound = errors.New("store: not found")
	// ErrConflict reports that a write would violate a uniqueness constraint.
	ErrConflict = errors.New("store: conflict")
	// ErrInvalidArgument reports a request the store cannot serve, such as a
	// page size outside the allowed range.
	ErrInvalidArgument = errors.New("store: invalid argument")
)

// MaxPageSize is the largest page that a List method returns.
const MaxPageSize = 1000

// Store gives access to every storage port.
type Store interface {
	// Tenants returns the tenant repository.
	Tenants() Tenants
	// Ping reports whether the underlying database is reachable.
	Ping(ctx context.Context) error
}

// Tenant is an isolated user directory with its own issuer.
type Tenant struct {
	// ID is a version 7 UUID assigned on creation.
	ID uuid.UUID
	// Slug is the unique, URL-safe name used in the tenant's issuer path.
	Slug string
	// Name is a human-readable display name.
	Name      string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Tenants stores tenants.
type Tenants interface {
	// Create inserts t. It returns ErrConflict when the ID or the slug is
	// already in use.
	Create(ctx context.Context, t Tenant) error
	// Get returns the tenant with the given ID, or ErrNotFound.
	Get(ctx context.Context, id uuid.UUID) (Tenant, error)
	// GetBySlug returns the tenant with the given slug, or ErrNotFound.
	GetBySlug(ctx context.Context, slug string) (Tenant, error)
	// List returns up to limit tenants with an ID greater than after, in
	// ascending ID order. Pass uuid.Nil() for the first page and the last ID
	// of a page to get the next one. limit must be between 1 and
	// MaxPageSize, otherwise List returns ErrInvalidArgument.
	List(ctx context.Context, after uuid.UUID, limit int) ([]Tenant, error)
	// Delete removes the tenant with the given ID, or returns ErrNotFound.
	Delete(ctx context.Context, id uuid.UUID) error
}
