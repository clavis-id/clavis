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
	// SigningKeys returns the signing key repository.
	SigningKeys() SigningKeys
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

// SigningKey is a key pair that signs tokens for one tenant and one
// algorithm. Its lifecycle is fixed when it is created: it is published from
// creation, signs between ActivatesAt and RetiresAt, and stays published
// until ExpiresAt so tokens it signed can still be verified.
type SigningKey struct {
	// ID is a version 7 UUID assigned on creation.
	ID       uuid.UUID
	TenantID uuid.UUID
	// Algorithm is the JWS algorithm, such as "RS256".
	Algorithm string
	// Generation increases by one with every rotation of a tenant's keys for
	// an algorithm. It is unique per tenant and algorithm, which prevents
	// two instances from creating the same successor.
	Generation int64
	// KeyID is the "kid" published in the JWK set. It is unique per tenant.
	KeyID string
	// PublicKey is the public key in PKIX, ASN.1 DER form.
	PublicKey []byte
	// PrivateKey is the PKCS #8 private key encrypted by the key
	// encryption key named by EncryptionKeyID.
	PrivateKey      []byte
	EncryptionKeyID string
	ActivatesAt     time.Time
	RetiresAt       time.Time
	ExpiresAt       time.Time
	CreatedAt       time.Time
}

// SigningKeys stores signing keys.
type SigningKeys interface {
	// Create inserts k. It returns ErrConflict when the ID, the key ID within
	// the tenant, or the generation for the tenant and algorithm is already
	// in use, and ErrNotFound when the tenant does not exist.
	Create(ctx context.Context, k SigningKey) error
	// List returns every key of a tenant, ordered by algorithm and then by
	// generation.
	List(ctx context.Context, tenantID uuid.UUID) ([]SigningKey, error)
	// DeleteExpired removes the keys of every tenant whose ExpiresAt is not
	// after now, and returns how many were removed.
	DeleteExpired(ctx context.Context, now time.Time) (int64, error)
}
