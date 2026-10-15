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
// in UTC, durations with second precision. Empty lists may come back as nil
// or as empty slices.
//
// Strings must not contain U+0000. PostgreSQL cannot store it in text or JSON
// values and fails the write, while SQLite stores it, so callers reject it
// before a record reaches the store; an adapter's behavior with it is
// undefined.
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
	// Clients returns the client repository.
	Clients() Clients
	// Users returns the user repository.
	Users() Users
	// Passwords returns the password repository.
	Passwords() Passwords
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

// ClientType says whether a client can keep a secret (RFC 6749, section 2.1).
type ClientType string

const (
	// ClientConfidential is a client that authenticates with a secret, such
	// as a web application that runs on a server.
	ClientConfidential ClientType = "confidential"
	// ClientPublic is a client that cannot keep a secret, such as a
	// single-page or native application.
	ClientPublic ClientType = "public"
)

// Client is an application registered with a tenant.
type Client struct {
	// ID is a version 7 UUID assigned on creation.
	ID       uuid.UUID
	TenantID uuid.UUID
	// ClientID is the OAuth client identifier, unique within the tenant.
	ClientID string
	// Name is a human-readable display name.
	Name string
	Type ClientType
	// SecretHash is the SHA-256 hash of the client secret, or nil for a
	// public client.
	SecretHash             []byte
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	// GrantTypes lists the OAuth grant types the client may use, such as
	// "authorization_code".
	GrantTypes []string
	// Scopes lists the scopes the client may request.
	Scopes []string
	// Lifetimes overrides the default lifetimes of the tokens issued to the
	// client.
	Lifetimes TokenLifetimes
	// SkipConsent lets the client obtain tokens without asking the user for
	// consent, which suits first-party clients.
	SkipConsent bool
	// PKCEExempt lets a confidential client send authorization requests
	// without PKCE.
	PKCEExempt bool
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// TokenLifetimes holds the lifetimes of the tokens issued to a client. A zero
// value selects the default lifetime.
type TokenLifetimes struct {
	AccessToken          time.Duration
	IDToken              time.Duration
	RefreshTokenIdle     time.Duration
	RefreshTokenAbsolute time.Duration
}

// Clients stores clients. Every method works within one tenant, so a client
// is never reached through another tenant.
type Clients interface {
	// Create inserts c. It returns ErrConflict when the ID, or the client ID
	// within the tenant, is already in use, and ErrNotFound when the tenant
	// does not exist.
	Create(ctx context.Context, c Client) error
	// GetByClientID returns the client of a tenant with the given client ID,
	// or ErrNotFound.
	GetByClientID(ctx context.Context, tenantID uuid.UUID, clientID string) (Client, error)
	// List returns up to limit clients of a tenant with an ID greater than
	// after, in ascending ID order. Paging and limits work as in
	// Tenants.List.
	List(ctx context.Context, tenantID, after uuid.UUID, limit int) ([]Client, error)
	// UpdateSecret replaces the secret hash of the client of a tenant with the
	// given ID and sets its UpdatedAt, or returns ErrNotFound.
	UpdateSecret(ctx context.Context, tenantID, id uuid.UUID, secretHash []byte, updatedAt time.Time) error
	// Delete removes the client of a tenant with the given ID, or returns
	// ErrNotFound.
	Delete(ctx context.Context, tenantID, id uuid.UUID) error
}

// UserStatus says whether a user can sign in.
type UserStatus string

const (
	// UserActive is a user who can sign in.
	UserActive UserStatus = "active"
	// UserDisabled is a user who cannot sign in.
	UserDisabled UserStatus = "disabled"
)

// User is a person with an account in a tenant.
type User struct {
	// ID is a version 7 UUID assigned on creation.
	ID       uuid.UUID
	TenantID uuid.UUID
	// Email is unique within the tenant. Adapters compare it exactly, so
	// callers normalize it first.
	Email         string
	EmailVerified bool
	Status        UserStatus
	Profile       Profile
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// Profile holds the standard OpenID Connect claims about a user, other than
// sub and the email claims (OpenID Connect Core 1.0, section 5.1). Empty
// values are unset. Adapters store a Profile as a JSON object with the names
// in its field tags. Like every string in a record, its values must not
// contain U+0000 (see the package documentation).
type Profile struct {
	Name              string `json:"name,omitzero"`
	GivenName         string `json:"given_name,omitzero"`
	FamilyName        string `json:"family_name,omitzero"`
	MiddleName        string `json:"middle_name,omitzero"`
	Nickname          string `json:"nickname,omitzero"`
	PreferredUsername string `json:"preferred_username,omitzero"`
	// ProfileURL is the "profile" claim: the URL of the user's profile page.
	ProfileURL          string  `json:"profile,omitzero"`
	Picture             string  `json:"picture,omitzero"`
	Website             string  `json:"website,omitzero"`
	Gender              string  `json:"gender,omitzero"`
	Birthdate           string  `json:"birthdate,omitzero"`
	Zoneinfo            string  `json:"zoneinfo,omitzero"`
	Locale              string  `json:"locale,omitzero"`
	PhoneNumber         string  `json:"phone_number,omitzero"`
	PhoneNumberVerified bool    `json:"phone_number_verified,omitzero"`
	Address             Address `json:"address,omitzero"`
}

// Address is the "address" claim (OpenID Connect Core 1.0, section 5.1.1).
type Address struct {
	Formatted     string `json:"formatted,omitzero"`
	StreetAddress string `json:"street_address,omitzero"`
	Locality      string `json:"locality,omitzero"`
	Region        string `json:"region,omitzero"`
	PostalCode    string `json:"postal_code,omitzero"`
	Country       string `json:"country,omitzero"`
}

// Users stores users. Every method works within one tenant.
type Users interface {
	// Create inserts u. It returns ErrConflict when the ID, or the email
	// within the tenant, is already in use, and ErrNotFound when the tenant
	// does not exist.
	Create(ctx context.Context, u User) error
	// Get returns the user of a tenant with the given ID, or ErrNotFound.
	Get(ctx context.Context, tenantID, id uuid.UUID) (User, error)
	// GetByEmail returns the user of a tenant with the given email, or
	// ErrNotFound.
	GetByEmail(ctx context.Context, tenantID uuid.UUID, email string) (User, error)
	// List returns up to limit users of a tenant with an ID greater than
	// after, in ascending ID order. Paging and limits work as in
	// Tenants.List.
	List(ctx context.Context, tenantID, after uuid.UUID, limit int) ([]User, error)
	// Delete removes the user of a tenant with the given ID together with
	// the user's credentials, or returns ErrNotFound.
	Delete(ctx context.Context, tenantID, id uuid.UUID) error
}

// Password is the password credential of a user.
type Password struct {
	TenantID uuid.UUID
	UserID   uuid.UUID
	// Hash is a PHC string, which names its algorithm and parameters.
	Hash string
	// SetAt is when the user set this password. Replacing the hash of the
	// same password, as a rehash on login does, keeps it.
	SetAt time.Time
}

// Passwords stores the passwords of users. A user has at most one.
type Passwords interface {
	// Set stores p, replacing the user's previous password. It returns
	// ErrNotFound when the user does not exist in the tenant.
	Set(ctx context.Context, p Password) error
	// Get returns the password of a user of a tenant, or ErrNotFound when
	// the user has none.
	Get(ctx context.Context, tenantID, userID uuid.UUID) (Password, error)
	// Rehash replaces the hash of a user's password with newHash only while
	// it still equals oldHash, so a rehash never overwrites a password set
	// in the meantime. It returns ErrConflict when the hash has changed and
	// ErrNotFound when the user has no password.
	Rehash(ctx context.Context, tenantID, userID uuid.UUID, oldHash, newHash string) error
}
