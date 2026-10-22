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
	// AuthorizationRequests returns the authorization request repository.
	AuthorizationRequests() AuthorizationRequests
	// Sessions returns the browser session repository.
	Sessions() Sessions
	// AuthorizationCodes returns the authorization code repository.
	AuthorizationCodes() AuthorizationCodes
	// AccessTokens returns the access token repository.
	AccessTokens() AccessTokens
	// RefreshTokens returns the refresh token repository.
	RefreshTokens() RefreshTokens
	// APIResources returns the API resource repository.
	APIResources() APIResources
	// Grants returns the grant repository.
	Grants() Grants
	// Brandings returns the branding repository.
	Brandings() Brandings
	// EmailVerifications returns the email verification repository.
	EmailVerifications() EmailVerifications
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
	Name string
	// SignupEnabled lets people create their own accounts on the tenant's
	// hosted pages (ADR 0026).
	SignupEnabled bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
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
	// Update stores the name, the settings and UpdatedAt of the tenant with
	// the ID of t; the slug and CreatedAt never change. It returns
	// ErrNotFound for an unknown tenant.
	Update(ctx context.Context, t Tenant) error
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
	// ResourceServerFor lists the identifiers of the API resources whose
	// server the client is. It may introspect the access tokens issued for
	// them (ADR 0022).
	ResourceServerFor []string
	CreatedAt         time.Time
	UpdatedAt         time.Time
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
	// Get returns the client of a tenant with the given ID, or ErrNotFound.
	Get(ctx context.Context, tenantID, id uuid.UUID) (Client, error)
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
	// Update stores EmailVerified, Status, Profile and UpdatedAt of the user
	// of a tenant with the ID of u; the email address and CreatedAt never
	// change. It returns ErrNotFound for an unknown user.
	Update(ctx context.Context, u User) error
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

// AuthorizationRequest is a validated authorization request that waits for
// the user to sign in (ADR 0013).
type AuthorizationRequest struct {
	// ID is a random 128-bit value in unpadded base64url. The browser
	// carries it through the hosted pages.
	ID       string
	TenantID uuid.UUID
	// ClientID is the ID of the client record, not the OAuth client
	// identifier.
	ClientID uuid.UUID
	// BindingHash is the SHA-256 hash of the binding cookie of the browser
	// that sent the request.
	BindingHash []byte
	// RedirectURI is where the response goes. RedirectURIProvided says
	// whether the request named it or Clavis chose the only registered one.
	RedirectURI         string
	RedirectURIProvided bool
	Scopes              []string
	State               string
	Nonce               string
	// CodeChallenge and CodeChallengeMethod are empty when the request has
	// no PKCE challenge.
	CodeChallenge       string
	CodeChallengeMethod string
	// LoginHint is the email address to suggest on the sign-in form, or
	// empty.
	LoginHint string
	// HintSubject is the user who alone may answer the request, named by its
	// id_token_hint or by the sub claim it requests with a value, or the zero
	// UUID. It is not a reference: the user may have been deleted since.
	HintSubject uuid.UUID
	// UserInfoClaims and IDTokenClaims name the claims that the request asks
	// for individually, for the userinfo response and the ID token.
	UserInfoClaims []string
	IDTokenClaims  []string
	// ForceConsent reports whether the request carries prompt=consent, which
	// asks for consent even when a grant covers the request (ADR 0020).
	ForceConsent bool
	// SessionID is the session of the user who authenticated for the
	// request, which waits for the user's consent, or the zero UUID until
	// then. It is not a reference: the session may have ended since.
	SessionID uuid.UUID
	// ResponseMode is how the response goes back to the client: query or
	// form_post (OAuth 2.0 Form Post Response Mode).
	ResponseMode string
	// UILocales is the request's ui_locales parameter, the user's preferred
	// languages for the hosted pages, or empty (ADR 0025).
	UILocales string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// AuthorizationRequests stores authorization requests. Every method works
// within one tenant.
type AuthorizationRequests interface {
	// Create inserts r. It returns ErrConflict when the ID is in use, and
	// ErrNotFound when the client does not exist in the tenant.
	Create(ctx context.Context, r AuthorizationRequest) error
	// Get returns the request of a tenant with the given ID, or ErrNotFound.
	// It returns expired requests too; callers check ExpiresAt.
	Get(ctx context.Context, tenantID uuid.UUID, id string) (AuthorizationRequest, error)
	// SetSession records the session of the user who authenticated for the
	// request of a tenant with the given ID. A request gets a session once:
	// SetSession returns ErrConflict when the request has one already, so of
	// several concurrent callers exactly one succeeds, and ErrNotFound when
	// there is no such request.
	SetSession(ctx context.Context, tenantID uuid.UUID, id string, sessionID uuid.UUID) error
	// Delete removes the request of a tenant with the given ID, or returns
	// ErrNotFound. When several callers delete the same request at once,
	// exactly one succeeds, which makes a request single use.
	Delete(ctx context.Context, tenantID uuid.UUID, id string) error
	// DeleteExpired removes the requests of every tenant whose ExpiresAt is
	// not after now, and returns how many were removed.
	DeleteExpired(ctx context.Context, now time.Time) (int64, error)
}

// Session is a browser session: a user who signed in to a tenant (ADR 0013).
type Session struct {
	// ID is a version 7 UUID assigned on creation.
	ID       uuid.UUID
	TenantID uuid.UUID
	// TokenHash is the SHA-256 hash of the session cookie value. It is
	// unique.
	TokenHash []byte
	UserID    uuid.UUID
	// AuthTime is when the user authenticated.
	AuthTime time.Time
	// AMR lists the authentication methods used, such as "pwd" (RFC 8176).
	AMR []string
	// ACR is the authentication context class reference, or empty.
	ACR        string
	CreatedAt  time.Time
	LastSeenAt time.Time
	// IdleExpiresAt is when the session ends unless it is used again, and
	// ExpiresAt is when it ends regardless.
	IdleExpiresAt time.Time
	ExpiresAt     time.Time
}

// Sessions stores browser sessions. Every method works within one tenant.
type Sessions interface {
	// Create inserts s. It returns ErrConflict when the ID or the token hash
	// is in use, and ErrNotFound when the user does not exist in the tenant.
	Create(ctx context.Context, s Session) error
	// GetByTokenHash returns the session of a tenant with the given token
	// hash, or ErrNotFound. It returns expired sessions too; callers check
	// the expiry times.
	GetByTokenHash(ctx context.Context, tenantID uuid.UUID, tokenHash []byte) (Session, error)
	// Touch records that the session of a tenant with the given ID was used
	// at lastSeenAt and moves its IdleExpiresAt to idleExpiresAt. It returns
	// ErrNotFound when there is no such session.
	Touch(ctx context.Context, tenantID, id uuid.UUID, lastSeenAt, idleExpiresAt time.Time) error
	// Delete removes the session of a tenant with the given ID, or returns
	// ErrNotFound.
	Delete(ctx context.Context, tenantID, id uuid.UUID) error
	// DeleteByUser removes the sessions of a user of a tenant, except the
	// session with the ID keep, and returns how many were removed. Pass the
	// zero UUID to remove every session.
	DeleteByUser(ctx context.Context, tenantID, userID, keep uuid.UUID) (int64, error)
	// DeleteExpired removes the sessions of every tenant whose ExpiresAt or
	// IdleExpiresAt is not after now, and returns how many were removed.
	DeleteExpired(ctx context.Context, now time.Time) (int64, error)
}

// AuthorizationCode is an authorization code issued to a client, bound to
// the request it answers (ADR 0014).
type AuthorizationCode struct {
	// Hash is the SHA-256 hash of the code, which identifies it. The code
	// itself is never stored.
	Hash     []byte
	TenantID uuid.UUID
	// ClientID is the ID of the client record.
	ClientID  uuid.UUID
	UserID    uuid.UUID
	SessionID uuid.UUID
	// RedirectURI and RedirectURIProvided are those of the authorization
	// request, which the token request must match.
	RedirectURI         string
	RedirectURIProvided bool
	Scopes              []string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	AuthTime            time.Time
	AMR                 []string
	ACR                 string
	// UserInfoClaims and IDTokenClaims are those of the authorization
	// request.
	UserInfoClaims []string
	IDTokenClaims  []string
	CreatedAt      time.Time
	ExpiresAt      time.Time
	// RedeemedAt is when the code was exchanged for tokens, or zero. Create
	// ignores it; Redeem sets it.
	RedeemedAt time.Time
}

// AuthorizationCodes stores authorization codes. Every method works within
// one tenant.
type AuthorizationCodes interface {
	// Create inserts c. It returns ErrConflict when the hash is in use, and
	// ErrNotFound when the client or the user does not exist in the tenant.
	Create(ctx context.Context, c AuthorizationCode) error
	// Get returns the code of a tenant with the given hash, or ErrNotFound.
	// It returns expired and redeemed codes too; callers check ExpiresAt and
	// RedeemedAt.
	Get(ctx context.Context, tenantID uuid.UUID, hash []byte) (AuthorizationCode, error)
	// Redeem marks the code of a tenant with the given hash as redeemed at
	// the given time. It returns ErrConflict when the code was redeemed
	// already, so of several concurrent callers exactly one succeeds, and
	// ErrNotFound when there is no such code.
	Redeem(ctx context.Context, tenantID uuid.UUID, hash []byte, at time.Time) error
	// DeleteByUserAndClient removes the codes of a tenant that were issued to
	// the client for the user, and returns how many were removed.
	DeleteByUserAndClient(ctx context.Context, tenantID, userID, clientID uuid.UUID) (int64, error)
	// DeleteBySession removes the codes of a tenant that were issued in the
	// session with the given ID and not redeemed yet, and returns how many
	// were removed. Redeemed codes stay, so that replays are still detected.
	DeleteBySession(ctx context.Context, tenantID, sessionID uuid.UUID) (int64, error)
	// DeleteByUser removes the codes of a tenant that were issued to the
	// user and not redeemed yet, and returns how many were removed.
	DeleteByUser(ctx context.Context, tenantID, userID uuid.UUID) (int64, error)
	// MoveSession moves the codes of a tenant that were issued in the session
	// with the ID from to the session with the ID to, and returns how many it
	// moved.
	MoveSession(ctx context.Context, tenantID, from, to uuid.UUID) (int64, error)
	// DeleteExpired removes the codes of every tenant whose ExpiresAt is not
	// after before, and returns how many were removed. Callers keep expired
	// codes for a while by passing a time in the past.
	DeleteExpired(ctx context.Context, before time.Time) (int64, error)
}

// AccessToken is the record of an issued JWT access token. The token itself
// is not stored; the record lets Clavis revoke it before it expires.
type AccessToken struct {
	// ID is the token's jti claim.
	ID       string
	TenantID uuid.UUID
	// ClientID is the ID of the client record.
	ClientID uuid.UUID
	// UserID is the zero UUID for a token that a client obtained for itself.
	UserID uuid.UUID
	// CodeHash is the hash of the authorization code that the token derives
	// from, directly or through refresh tokens, or nil.
	CodeHash []byte
	Scopes   []string
	// UserInfoClaims names the claims that the authorization request asked
	// for individually, which the userinfo response includes.
	UserInfoClaims []string
	IssuedAt       time.Time
	ExpiresAt      time.Time
	// RevokedAt is when the token was revoked, or zero.
	RevokedAt time.Time
}

// AccessTokens stores the records of issued access tokens. Every method
// works within one tenant, except DeleteExpired.
type AccessTokens interface {
	// Create inserts t. It returns ErrConflict when the ID is in use, and
	// ErrNotFound when the client, or a user that is set, does not exist in
	// the tenant.
	Create(ctx context.Context, t AccessToken) error
	// Get returns the token of a tenant with the given ID, or ErrNotFound.
	// It returns expired and revoked tokens too.
	Get(ctx context.Context, tenantID uuid.UUID, id string) (AccessToken, error)
	// Revoke revokes the token of a tenant with the given ID at the given
	// time, or returns ErrNotFound. A revoked token keeps the time of its
	// first revocation.
	Revoke(ctx context.Context, tenantID uuid.UUID, id string, at time.Time) error
	// RevokeBySession revokes, at the given time, the tokens of a tenant
	// that are not revoked yet and derive from a code issued in the session
	// with the given ID that started no refresh token family, and returns
	// how many it revoked. These are the session's online access: tokens of
	// a refresh token family are offline access, which outlives the session
	// (ADR 0021). Codes that were deleted are not found.
	RevokeBySession(ctx context.Context, tenantID, sessionID uuid.UUID, at time.Time) (int64, error)
	// RevokeByCode revokes, at the given time, the tokens of a tenant that
	// were issued for the code with the given hash and are not revoked yet,
	// and returns how many it revoked.
	RevokeByCode(ctx context.Context, tenantID uuid.UUID, codeHash []byte, at time.Time) (int64, error)
	// RevokeByUserAndClient revokes, at the given time, the tokens of a
	// tenant that were issued to the client for the user and are not revoked
	// yet, and returns how many it revoked.
	RevokeByUserAndClient(ctx context.Context, tenantID, userID, clientID uuid.UUID, at time.Time) (int64, error)
	// RevokeByUser revokes, at the given time, the tokens of a tenant that
	// were issued for the user and are not revoked yet, and returns how many
	// it revoked.
	RevokeByUser(ctx context.Context, tenantID, userID uuid.UUID, at time.Time) (int64, error)
	// DeleteExpired removes the tokens of every tenant whose ExpiresAt is not
	// after now, and returns how many were removed.
	DeleteExpired(ctx context.Context, now time.Time) (int64, error)
}

// RefreshTokenFamily is the chain of refresh tokens that one authorization
// grant yields (ADR 0014, ADR 0021). Each refresh replaces the current token
// of the family with a successor; presenting a replaced token revokes the
// whole family. The family keeps what its tokens grant.
type RefreshTokenFamily struct {
	// ID is a version 7 UUID assigned on creation.
	ID       uuid.UUID
	TenantID uuid.UUID
	// ClientID is the ID of the client record.
	ClientID uuid.UUID
	UserID   uuid.UUID
	// SessionID is the session in which the user authenticated, or the zero
	// UUID. It is not a reference: the family can outlive the session.
	SessionID uuid.UUID
	// CodeHash is the hash of the authorization code that the family was
	// issued for, or nil.
	CodeHash []byte
	Scopes   []string
	AuthTime time.Time
	AMR      []string
	ACR      string
	// UserInfoClaims and IDTokenClaims are those of the authorization
	// request.
	UserInfoClaims []string
	IDTokenClaims  []string
	CreatedAt      time.Time
	// IdleExpiresAt is when the family ends unless its current token is
	// used, and ExpiresAt is when it ends regardless.
	IdleExpiresAt time.Time
	ExpiresAt     time.Time
	// RevokedAt is when the family was revoked, or zero. Create ignores it.
	RevokedAt time.Time
}

// RefreshToken is a refresh token of a family. The token itself is never
// stored.
type RefreshToken struct {
	// Hash is the SHA-256 hash of the token, which identifies it.
	Hash      []byte
	TenantID  uuid.UUID
	FamilyID  uuid.UUID
	IssuedAt  time.Time
	ExpiresAt time.Time
	// RotatedAt is when the token was replaced by its successor, or zero.
	// Create and Rotate ignore it for the tokens they insert.
	RotatedAt time.Time
}

// RefreshTokens stores refresh tokens and their families. Every method works
// within one tenant, except DeleteExpired.
type RefreshTokens interface {
	// Create inserts the family f with its first token t, which must belong
	// to f. It returns ErrConflict when the ID of f or the hash of t is in
	// use, ErrNotFound when the client or the user does not exist in the
	// tenant, and ErrInvalidArgument when t does not belong to f.
	Create(ctx context.Context, f RefreshTokenFamily, t RefreshToken) error
	// Get returns the token of a tenant with the given hash and its family,
	// or ErrNotFound. It returns rotated, expired and revoked tokens too;
	// callers check RotatedAt and the times of the token and the family.
	Get(ctx context.Context, tenantID uuid.UUID, hash []byte) (RefreshToken, RefreshTokenFamily, error)
	// Rotate replaces the token of a tenant with the given hash by next,
	// which must belong to the same family. In one transaction it marks the
	// token as rotated at next.IssuedAt, moves the IdleExpiresAt of the
	// family to next.ExpiresAt and inserts next. It returns ErrConflict when
	// the token was rotated already, so of several concurrent callers exactly
	// one succeeds, or when the family was revoked, and ErrNotFound when the
	// family of next has no token with that hash.
	Rotate(ctx context.Context, tenantID uuid.UUID, hash []byte, next RefreshToken) error
	// RevokeFamily revokes the family of a tenant with the given ID at the
	// given time, or returns ErrNotFound. A revoked family keeps the time of
	// its first revocation.
	RevokeFamily(ctx context.Context, tenantID, id uuid.UUID, at time.Time) error
	// RevokeByCode revokes, at the given time, the families of a tenant that
	// were issued for the code with the given hash and are not revoked yet,
	// and returns how many it revoked.
	RevokeByCode(ctx context.Context, tenantID uuid.UUID, codeHash []byte, at time.Time) (int64, error)
	// RevokeByUserAndClient revokes, at the given time, the families of a
	// tenant that were issued to the client for the user and are not revoked
	// yet, and returns how many it revoked.
	RevokeByUserAndClient(ctx context.Context, tenantID, userID, clientID uuid.UUID, at time.Time) (int64, error)
	// RevokeByUser revokes, at the given time, the families of a tenant that
	// were issued for the user and are not revoked yet, and returns how many
	// it revoked.
	RevokeByUser(ctx context.Context, tenantID, userID uuid.UUID, at time.Time) (int64, error)
	// DeleteExpired removes the tokens of every tenant whose ExpiresAt is not
	// after now, then the families whose ExpiresAt or IdleExpiresAt is not
	// after now, with any tokens they still have. It returns how many
	// families were removed.
	DeleteExpired(ctx context.Context, now time.Time) (int64, error)
}

// APIResource is an API that accepts access tokens issued by a tenant. Its
// identifier becomes the aud claim of tokens that grant its scopes
// (ADR 0014).
type APIResource struct {
	// ID is a version 7 UUID assigned on creation.
	ID       uuid.UUID
	TenantID uuid.UUID
	// Identifier is an absolute URI, unique within the tenant.
	Identifier string
	// Name is a human-readable display name.
	Name string
	// Scopes lists the scopes the resource defines.
	Scopes    []string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// APIResources stores API resources. Every method works within one tenant.
type APIResources interface {
	// Create inserts r. It returns ErrConflict when the ID, or the
	// identifier within the tenant, is already in use, and ErrNotFound when
	// the tenant does not exist.
	Create(ctx context.Context, r APIResource) error
	// GetByIdentifier returns the resource of a tenant with the given
	// identifier, or ErrNotFound.
	GetByIdentifier(ctx context.Context, tenantID uuid.UUID, identifier string) (APIResource, error)
	// List returns up to limit resources of a tenant with an ID greater than
	// after, in ascending ID order. Paging and limits work as in
	// Tenants.List.
	List(ctx context.Context, tenantID, after uuid.UUID, limit int) ([]APIResource, error)
	// Delete removes the resource of a tenant with the given ID, or returns
	// ErrNotFound.
	Delete(ctx context.Context, tenantID, id uuid.UUID) error
}

// Grant records the scopes that a user allowed a client (ADR 0020). A tenant
// has at most one grant per user and client.
type Grant struct {
	// ID is a version 7 UUID assigned on creation.
	ID       uuid.UUID
	TenantID uuid.UUID
	UserID   uuid.UUID
	// ClientID is the ID of the client record.
	ClientID  uuid.UUID
	Scopes    []string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Grants stores grants. Every method works within one tenant.
type Grants interface {
	// Get returns the grant of a tenant for the user and client, or
	// ErrNotFound.
	Get(ctx context.Context, tenantID, userID, clientID uuid.UUID) (Grant, error)
	// Put stores g as the grant of its user and client. When they have a
	// grant already, Put replaces its scopes and update time, and keeps its
	// ID and creation time. It returns ErrNotFound when the user or the
	// client does not exist in the tenant.
	Put(ctx context.Context, g Grant) error
	// List returns the grants of a user of a tenant, oldest first.
	List(ctx context.Context, tenantID, userID uuid.UUID) ([]Grant, error)
	// Delete removes the grant of a tenant for the user and client, or
	// returns ErrNotFound.
	Delete(ctx context.Context, tenantID, userID, clientID uuid.UUID) error
}

// Branding is how the hosted pages of a tenant look (ADR 0025).
type Branding struct {
	TenantID uuid.UUID
	Theme    Theme
	// LogoType is the media type of the tenant's logo, such as image/png,
	// or empty when the tenant has no logo. LogoHash identifies the logo's
	// content.
	LogoType  string
	LogoHash  string
	UpdatedAt time.Time
}

// Theme holds the values that a tenant gives to the CSS custom properties
// of the hosted pages. Empty values keep the defaults.
type Theme struct {
	// Light and Dark are the colors of the light and dark color schemes.
	Light ThemeColors `json:"light,omitzero"`
	Dark  ThemeColors `json:"dark,omitzero"`
	// Radius is the corner radius in CSS pixels, or nil for the default.
	Radius *int `json:"radius,omitzero"`
}

// ThemeColors are the colors of one color scheme, each as #rrggbb.
type ThemeColors struct {
	Accent     string `json:"accent,omitzero"`
	AccentText string `json:"accent_text,omitzero"`
	Background string `json:"background,omitzero"`
	Surface    string `json:"surface,omitzero"`
	Text       string `json:"text,omitzero"`
	Muted      string `json:"muted,omitzero"`
	Border     string `json:"border,omitzero"`
	Error      string `json:"error,omitzero"`
}

// ThemeColor is one color of a ThemeColors, named as in its JSON form.
type ThemeColor struct {
	Name  string
	Value string
}

// List returns the colors of c with their names, in a fixed order.
func (c ThemeColors) List() []ThemeColor {
	return []ThemeColor{
		{"accent", c.Accent}, {"accent_text", c.AccentText}, {"background", c.Background},
		{"surface", c.Surface}, {"text", c.Text}, {"muted", c.Muted}, {"border", c.Border}, {"error", c.Error},
	}
}

// Set sets the color named name, as List names it, and reports whether
// that name exists.
func (c *ThemeColors) Set(name, value string) bool {
	field, ok := map[string]*string{
		"accent": &c.Accent, "accent_text": &c.AccentText, "background": &c.Background, "surface": &c.Surface,
		"text": &c.Text, "muted": &c.Muted, "border": &c.Border, "error": &c.Error,
	}[name]
	if ok {
		*field = value
	}
	return ok
}

// Logo is the image that a tenant's hosted pages show.
type Logo struct {
	// ContentType is the media type, such as image/png.
	ContentType string
	Data        []byte
	// Hash identifies the content, for example in the logo's URL.
	Hash string
}

// Brandings stores the branding of tenants, at most one per tenant. A
// tenant without a stored branding uses the defaults.
type Brandings interface {
	// Get returns the branding of a tenant, without its logo's data, or
	// ErrNotFound.
	Get(ctx context.Context, tenantID uuid.UUID) (Branding, error)
	// GetLogo returns the logo of a tenant, or ErrNotFound when it has
	// none.
	GetLogo(ctx context.Context, tenantID uuid.UUID) (Logo, error)
	// PutTheme sets the theme of a tenant and keeps its logo. It returns
	// ErrNotFound for an unknown tenant.
	PutTheme(ctx context.Context, tenantID uuid.UUID, theme Theme, updatedAt time.Time) error
	// PutLogo sets the logo of a tenant and keeps its theme. It returns
	// ErrNotFound for an unknown tenant.
	PutLogo(ctx context.Context, tenantID uuid.UUID, logo Logo, updatedAt time.Time) error
	// DeleteLogo removes the logo of a tenant and keeps its theme. It
	// returns ErrNotFound when the tenant has no logo.
	DeleteLogo(ctx context.Context, tenantID uuid.UUID, updatedAt time.Time) error
	// Delete removes the branding of a tenant, or returns ErrNotFound.
	Delete(ctx context.Context, tenantID uuid.UUID) error
}

// EmailVerificationPurpose names what an email verification proves the
// address for.
type EmailVerificationPurpose string

// Purposes of email verifications.
const (
	// VerifySignup proves the address of a new account (ADR 0026).
	VerifySignup EmailVerificationPurpose = "signup"
	// VerifyPasswordReset proves the address of an account whose password
	// the user resets (ADR 0027).
	VerifyPasswordReset EmailVerificationPurpose = "reset"
)

// EmailVerification is a one-time code and link sent to an email address,
// with which a user proves to receive its mail (ADR 0026). Only hashes of
// the code and the link token are stored. A verification belongs to the
// browser that asked for it.
type EmailVerification struct {
	// ID is a random 128-bit identifier in unpadded base64url, like the ID of
	// an authorization request.
	ID       string
	TenantID uuid.UUID
	Purpose  EmailVerificationPurpose
	// Email is the normalized address.
	Email string
	// CodeHash and LinkHash are the hashes of the code and of the link's
	// token.
	CodeHash []byte
	LinkHash []byte
	// BindingHash is the hash of the browser's binding cookie (ADR 0013).
	BindingHash []byte
	// AuthorizationRequestID is the authorization request that the user
	// returns to afterwards, or empty.
	AuthorizationRequestID string
	// Attempts counts the codes submitted.
	Attempts int
	// VerifiedAt is when the user proved the address, or the zero time.
	VerifiedAt time.Time
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

// EmailVerifications stores email verifications.
type EmailVerifications interface {
	// Create inserts v. It returns ErrConflict when the ID is in use, and
	// ErrNotFound when the tenant does not exist.
	Create(ctx context.Context, v EmailVerification) error
	// Get returns the verification of a tenant with the given ID, or
	// ErrNotFound. It returns expired verifications too; callers check
	// ExpiresAt.
	Get(ctx context.Context, tenantID uuid.UUID, id string) (EmailVerification, error)
	// AddAttempt adds one to the attempts of the verification of a tenant
	// with the given ID, unless it is verified, and returns the new count.
	// Concurrent callers each get a different count. It returns ErrNotFound
	// when there is no such verification, or when it is verified.
	AddAttempt(ctx context.Context, tenantID uuid.UUID, id string) (int, error)
	// MarkVerified sets VerifiedAt of the verification of a tenant with the
	// given ID. It returns ErrNotFound when there is no such verification,
	// or when it is verified already.
	MarkVerified(ctx context.Context, tenantID uuid.UUID, id string, at time.Time) error
	// Delete removes the verification of a tenant with the given ID, or
	// returns ErrNotFound. When several callers delete the same verification
	// at once, exactly one succeeds.
	Delete(ctx context.Context, tenantID uuid.UUID, id string) error
	// DeleteExpired removes the verifications of every tenant whose
	// ExpiresAt is not after now, and returns how many were removed.
	DeleteExpired(ctx context.Context, now time.Time) (int64, error)
}
