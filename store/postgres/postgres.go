// Package postgres stores Clavis data in PostgreSQL.
//
// Several Clavis instances can share one database, which makes this the
// adapter for highly available deployments.
package postgres

import (
	"context"
	"embed"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io/fs"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"

	"clavisid.org/clavis/store"
	"clavisid.org/clavis/store/postgres/internal/db"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// migrationLockID is the PostgreSQL advisory lock that serializes schema
// migrations across Clavis instances. It differs from goose's default so other
// applications that use goose in the same database do not contend for it.
const migrationLockID int64 = 0x636c61766973 // "clavis" in ASCII

// SQLSTATE codes mapped to store errors.
const (
	foreignKeyViolation = "23503"
	uniqueViolation     = "23505"
)

// Store is a store.Store backed by PostgreSQL. It is safe for concurrent use.
type Store struct {
	pool        *pgxpool.Pool
	ownsPool    bool
	tenants     tenants
	signingKeys signingKeys
	clients     clients
	users       users
	passwords   passwords
	authzReqs   authorizationRequests
	sessions    sessions
	codes       authorizationCodes
	tokens      accessTokens
	refresh     refreshTokens
	resources   apiResources
	grants      grants
	brandings   brandings
	emailVerifs emailVerifications
}

var _ store.Store = (*Store)(nil)

type options struct {
	migrate bool
}

// Option configures Open and New.
type Option func(*options)

// WithoutMigrations skips applying pending migrations on Open and New. Use it
// when migrations run as a separate deployment step through Store.Migrate.
func WithoutMigrations() Option {
	return func(o *options) { o.migrate = false }
}

// Open connects to the database described by dsn, a PostgreSQL connection
// URL or keyword/value string, and applies pending migrations unless
// WithoutMigrations is given. Close releases the connection pool.
func Open(ctx context.Context, dsn string, opts ...Option) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		// The error can echo the DSN, which may hold a password.
		return nil, errors.New("postgres: invalid connection string")
	}
	s, err := New(ctx, pool, opts...)
	if err != nil {
		pool.Close()
		return nil, err
	}
	s.ownsPool = true
	return s, nil
}

// New uses an existing connection pool, which stays owned by the caller:
// Close does not close it. Pending migrations are applied unless
// WithoutMigrations is given.
func New(ctx context.Context, pool *pgxpool.Pool, opts ...Option) (*Store, error) {
	o := options{migrate: true}
	for _, opt := range opts {
		opt(&o)
	}
	q := db.New(pool)
	s := &Store{
		pool:        pool,
		tenants:     tenants{q: q},
		signingKeys: signingKeys{q: q},
		clients:     clients{q: q},
		users:       users{q: q},
		passwords:   passwords{q: q},
		authzReqs:   authorizationRequests{q: q},
		sessions:    sessions{q: q},
		codes:       authorizationCodes{q: q},
		tokens:      accessTokens{q: q},
		refresh:     refreshTokens{pool: pool, q: q},
		resources:   apiResources{q: q},
		grants:      grants{q: q},
		brandings:   brandings{q: q},
		emailVerifs: emailVerifications{q: q},
	}
	if err := s.Ping(ctx); err != nil {
		return nil, err
	}
	if o.migrate {
		if err := s.Migrate(ctx); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Migrate applies every pending schema migration. An advisory lock makes
// instances that start at the same time apply migrations one after another.
func (s *Store) Migrate(ctx context.Context) error {
	return s.migrateTo(ctx, -1)
}

// migrateTo applies the pending migrations up to and including version, or
// all of them when version is negative.
func (s *Store) migrateTo(ctx context.Context, version int64) error {
	fsys, err := fs.Sub(migrationFiles, "migrations")
	if err != nil {
		return fmt.Errorf("postgres: loading migrations: %w", err)
	}
	locker, err := lock.NewPostgresSessionLocker(lock.WithLockID(migrationLockID))
	if err != nil {
		return fmt.Errorf("postgres: preparing migration lock: %w", err)
	}
	sqlDB := stdlib.OpenDBFromPool(s.pool)
	defer sqlDB.Close()
	p, err := goose.NewProvider(goose.DialectPostgres, sqlDB, fsys, goose.WithSessionLocker(locker))
	if err != nil {
		return fmt.Errorf("postgres: preparing migrations: %w", err)
	}
	if version < 0 {
		_, err = p.Up(ctx)
	} else {
		_, err = p.UpTo(ctx, version)
	}
	if err != nil {
		return fmt.Errorf("postgres: applying migrations: %w", err)
	}
	return nil
}

// Close releases the connection pool when the Store created it with Open.
func (s *Store) Close() {
	if s.ownsPool {
		s.pool.Close()
	}
}

// Ping reports whether the database is reachable.
func (s *Store) Ping(ctx context.Context) error {
	if err := s.pool.Ping(ctx); err != nil {
		return fmt.Errorf("postgres: ping: %w", err)
	}
	return nil
}

// Tenants returns the tenant repository.
func (s *Store) Tenants() store.Tenants { return s.tenants }

// SigningKeys returns the signing key repository.
func (s *Store) SigningKeys() store.SigningKeys { return s.signingKeys }

// Clients returns the client repository.
func (s *Store) Clients() store.Clients { return s.clients }

// Users returns the user repository.
func (s *Store) Users() store.Users { return s.users }

// Passwords returns the password repository.
func (s *Store) Passwords() store.Passwords { return s.passwords }

// AuthorizationRequests returns the authorization request repository.
func (s *Store) AuthorizationRequests() store.AuthorizationRequests { return s.authzReqs }

// Sessions returns the browser session repository.
func (s *Store) Sessions() store.Sessions { return s.sessions }

// AuthorizationCodes returns the authorization code repository.
func (s *Store) AuthorizationCodes() store.AuthorizationCodes { return s.codes }

// AccessTokens returns the access token repository.
func (s *Store) AccessTokens() store.AccessTokens { return s.tokens }

// RefreshTokens returns the refresh token repository.
func (s *Store) RefreshTokens() store.RefreshTokens { return s.refresh }

// APIResources returns the API resource repository.
func (s *Store) APIResources() store.APIResources { return s.resources }

// Grants returns the grant repository.
func (s *Store) Grants() store.Grants { return s.grants }

// Brandings returns the branding repository.
func (s *Store) Brandings() store.Brandings { return s.brandings }

// EmailVerifications returns the email verification repository.
func (s *Store) EmailVerifications() store.EmailVerifications { return s.emailVerifs }

type tenants struct {
	q *db.Queries
}

func (r tenants) Create(ctx context.Context, t store.Tenant) error {
	err := r.q.CreateTenant(ctx, db.CreateTenantParams{
		ID:            t.ID,
		Slug:          t.Slug,
		Name:          t.Name,
		SignupEnabled: t.SignupEnabled,
		CreatedAt:     t.CreatedAt,
		UpdatedAt:     t.UpdatedAt,
	})
	return mapError("creating tenant", err)
}

func (r tenants) Get(ctx context.Context, id uuid.UUID) (store.Tenant, error) {
	row, err := r.q.GetTenant(ctx, id)
	if err != nil {
		return store.Tenant{}, mapError("getting tenant", err)
	}
	return tenantFromRow(row), nil
}

func (r tenants) GetBySlug(ctx context.Context, slug string) (store.Tenant, error) {
	row, err := r.q.GetTenantBySlug(ctx, slug)
	if err != nil {
		return store.Tenant{}, mapError("getting tenant by slug", err)
	}
	return tenantFromRow(row), nil
}

func (r tenants) List(ctx context.Context, after uuid.UUID, limit int) ([]store.Tenant, error) {
	if limit < 1 || limit > store.MaxPageSize {
		return nil, fmt.Errorf("postgres: listing tenants: %w: limit %d is outside [1, %d]",
			store.ErrInvalidArgument, limit, store.MaxPageSize)
	}
	rows, err := r.q.ListTenants(ctx, db.ListTenantsParams{After: after, PageSize: int32(limit)})
	if err != nil {
		return nil, mapError("listing tenants", err)
	}
	out := make([]store.Tenant, 0, len(rows))
	for _, row := range rows {
		out = append(out, tenantFromRow(row))
	}
	return out, nil
}

func (r tenants) Update(ctx context.Context, t store.Tenant) error {
	n, err := r.q.UpdateTenant(ctx, db.UpdateTenantParams{
		Name:          t.Name,
		SignupEnabled: t.SignupEnabled,
		UpdatedAt:     t.UpdatedAt,
		ID:            t.ID,
	})
	if err != nil {
		return mapError("updating tenant", err)
	}
	if n == 0 {
		return fmt.Errorf("postgres: updating tenant: %w", store.ErrNotFound)
	}
	return nil
}

func (r tenants) Delete(ctx context.Context, id uuid.UUID) error {
	n, err := r.q.DeleteTenant(ctx, id)
	if err != nil {
		return mapError("deleting tenant", err)
	}
	if n == 0 {
		return fmt.Errorf("postgres: deleting tenant: %w", store.ErrNotFound)
	}
	return nil
}

func tenantFromRow(row db.Tenant) store.Tenant {
	return store.Tenant{
		ID:            row.ID,
		Slug:          row.Slug,
		Name:          row.Name,
		SignupEnabled: row.SignupEnabled,
		CreatedAt:     row.CreatedAt.UTC(),
		UpdatedAt:     row.UpdatedAt.UTC(),
	}
}

type signingKeys struct {
	q *db.Queries
}

func (r signingKeys) Create(ctx context.Context, k store.SigningKey) error {
	err := r.q.CreateSigningKey(ctx, db.CreateSigningKeyParams{
		ID:              k.ID,
		TenantID:        k.TenantID,
		Algorithm:       k.Algorithm,
		Generation:      k.Generation,
		KeyID:           k.KeyID,
		PublicKey:       k.PublicKey,
		PrivateKey:      k.PrivateKey,
		EncryptionKeyID: k.EncryptionKeyID,
		ActivatesAt:     k.ActivatesAt,
		RetiresAt:       k.RetiresAt,
		ExpiresAt:       k.ExpiresAt,
		CreatedAt:       k.CreatedAt,
	})
	return mapError("creating signing key", err)
}

func (r signingKeys) List(ctx context.Context, tenantID uuid.UUID) ([]store.SigningKey, error) {
	rows, err := r.q.ListSigningKeys(ctx, tenantID)
	if err != nil {
		return nil, mapError("listing signing keys", err)
	}
	out := make([]store.SigningKey, 0, len(rows))
	for _, row := range rows {
		out = append(out, store.SigningKey{
			ID:              row.ID,
			TenantID:        row.TenantID,
			Algorithm:       row.Algorithm,
			Generation:      row.Generation,
			KeyID:           row.KeyID,
			PublicKey:       row.PublicKey,
			PrivateKey:      row.PrivateKey,
			EncryptionKeyID: row.EncryptionKeyID,
			ActivatesAt:     row.ActivatesAt.UTC(),
			RetiresAt:       row.RetiresAt.UTC(),
			ExpiresAt:       row.ExpiresAt.UTC(),
			CreatedAt:       row.CreatedAt.UTC(),
		})
	}
	return out, nil
}

func (r signingKeys) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	n, err := r.q.DeleteExpiredSigningKeys(ctx, now)
	if err != nil {
		return 0, mapError("deleting expired signing keys", err)
	}
	return n, nil
}

type clients struct {
	q *db.Queries
}

func (r clients) Create(ctx context.Context, c store.Client) error {
	err := r.q.CreateClient(ctx, db.CreateClientParams{
		ID:                                  c.ID,
		TenantID:                            c.TenantID,
		ClientID:                            c.ClientID,
		Name:                                c.Name,
		Type:                                string(c.Type),
		SecretHash:                          c.SecretHash,
		RedirectUris:                        orEmpty(c.RedirectURIs),
		PostLogoutRedirectUris:              orEmpty(c.PostLogoutRedirectURIs),
		GrantTypes:                          orEmpty(c.GrantTypes),
		Scopes:                              orEmpty(c.Scopes),
		AccessTokenLifetimeSeconds:          seconds(c.Lifetimes.AccessToken),
		IDTokenLifetimeSeconds:              seconds(c.Lifetimes.IDToken),
		RefreshTokenIdleLifetimeSeconds:     seconds(c.Lifetimes.RefreshTokenIdle),
		RefreshTokenAbsoluteLifetimeSeconds: seconds(c.Lifetimes.RefreshTokenAbsolute),
		SkipConsent:                         c.SkipConsent,
		PkceExempt:                          c.PKCEExempt,
		CreatedAt:                           c.CreatedAt,
		UpdatedAt:                           c.UpdatedAt,
		ResourceServerFor:                   orEmpty(c.ResourceServerFor),
	})
	return mapError("creating client", err)
}

func (r clients) Get(ctx context.Context, tenantID, id uuid.UUID) (store.Client, error) {
	row, err := r.q.GetClient(ctx, db.GetClientParams{TenantID: tenantID, ID: id})
	if err != nil {
		return store.Client{}, mapError("getting client", err)
	}
	return clientFromRow(row), nil
}

func (r clients) GetByClientID(ctx context.Context, tenantID uuid.UUID, clientID string) (store.Client, error) {
	row, err := r.q.GetClientByClientID(ctx, db.GetClientByClientIDParams{TenantID: tenantID, ClientID: clientID})
	if err != nil {
		return store.Client{}, mapError("getting client", err)
	}
	return clientFromRow(row), nil
}

func (r clients) List(ctx context.Context, tenantID, after uuid.UUID, limit int) ([]store.Client, error) {
	if limit < 1 || limit > store.MaxPageSize {
		return nil, fmt.Errorf("postgres: listing clients: %w: limit %d is outside [1, %d]",
			store.ErrInvalidArgument, limit, store.MaxPageSize)
	}
	rows, err := r.q.ListClients(ctx, db.ListClientsParams{TenantID: tenantID, After: after, PageSize: int32(limit)})
	if err != nil {
		return nil, mapError("listing clients", err)
	}
	out := make([]store.Client, 0, len(rows))
	for _, row := range rows {
		out = append(out, clientFromRow(row))
	}
	return out, nil
}

func (r clients) UpdateSecret(ctx context.Context, tenantID, id uuid.UUID, secretHash []byte, updatedAt time.Time) error {
	n, err := r.q.UpdateClientSecret(ctx, db.UpdateClientSecretParams{
		SecretHash: secretHash,
		UpdatedAt:  updatedAt,
		TenantID:   tenantID,
		ID:         id,
	})
	if err != nil {
		return mapError("updating client secret", err)
	}
	if n == 0 {
		return fmt.Errorf("postgres: updating client secret: %w", store.ErrNotFound)
	}
	return nil
}

func (r clients) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	n, err := r.q.DeleteClient(ctx, db.DeleteClientParams{TenantID: tenantID, ID: id})
	if err != nil {
		return mapError("deleting client", err)
	}
	if n == 0 {
		return fmt.Errorf("postgres: deleting client: %w", store.ErrNotFound)
	}
	return nil
}

func clientFromRow(row db.Client) store.Client {
	return store.Client{
		ID:                     row.ID,
		TenantID:               row.TenantID,
		ClientID:               row.ClientID,
		Name:                   row.Name,
		Type:                   store.ClientType(row.Type),
		SecretHash:             row.SecretHash,
		RedirectURIs:           row.RedirectUris,
		PostLogoutRedirectURIs: row.PostLogoutRedirectUris,
		GrantTypes:             row.GrantTypes,
		Scopes:                 row.Scopes,
		Lifetimes: store.TokenLifetimes{
			AccessToken:          time.Duration(row.AccessTokenLifetimeSeconds) * time.Second,
			IDToken:              time.Duration(row.IDTokenLifetimeSeconds) * time.Second,
			RefreshTokenIdle:     time.Duration(row.RefreshTokenIdleLifetimeSeconds) * time.Second,
			RefreshTokenAbsolute: time.Duration(row.RefreshTokenAbsoluteLifetimeSeconds) * time.Second,
		},
		SkipConsent:       row.SkipConsent,
		PKCEExempt:        row.PkceExempt,
		ResourceServerFor: row.ResourceServerFor,
		CreatedAt:         row.CreatedAt.UTC(),
		UpdatedAt:         row.UpdatedAt.UTC(),
	}
}

type users struct {
	q *db.Queries
}

func (r users) Create(ctx context.Context, u store.User) error {
	profile, err := json.Marshal(u.Profile)
	if err != nil {
		return fmt.Errorf("postgres: creating user: encoding the profile: %w", err)
	}
	err = r.q.CreateUser(ctx, db.CreateUserParams{
		ID:            u.ID,
		TenantID:      u.TenantID,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		Status:        string(u.Status),
		Profile:       profile,
		CreatedAt:     u.CreatedAt,
		UpdatedAt:     u.UpdatedAt,
	})
	return mapError("creating user", err)
}

func (r users) Get(ctx context.Context, tenantID, id uuid.UUID) (store.User, error) {
	row, err := r.q.GetUser(ctx, db.GetUserParams{TenantID: tenantID, ID: id})
	if err != nil {
		return store.User{}, mapError("getting user", err)
	}
	return userFromRow(row)
}

func (r users) GetByEmail(ctx context.Context, tenantID uuid.UUID, email string) (store.User, error) {
	row, err := r.q.GetUserByEmail(ctx, db.GetUserByEmailParams{TenantID: tenantID, Email: email})
	if err != nil {
		return store.User{}, mapError("getting user by email", err)
	}
	return userFromRow(row)
}

func (r users) List(ctx context.Context, tenantID, after uuid.UUID, limit int) ([]store.User, error) {
	if limit < 1 || limit > store.MaxPageSize {
		return nil, fmt.Errorf("postgres: listing users: %w: limit %d is outside [1, %d]",
			store.ErrInvalidArgument, limit, store.MaxPageSize)
	}
	rows, err := r.q.ListUsers(ctx, db.ListUsersParams{TenantID: tenantID, After: after, PageSize: int32(limit)})
	if err != nil {
		return nil, mapError("listing users", err)
	}
	out := make([]store.User, 0, len(rows))
	for _, row := range rows {
		u, err := userFromRow(row)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, nil
}

func (r users) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	n, err := r.q.DeleteUser(ctx, db.DeleteUserParams{TenantID: tenantID, ID: id})
	if err != nil {
		return mapError("deleting user", err)
	}
	if n == 0 {
		return fmt.Errorf("postgres: deleting user: %w", store.ErrNotFound)
	}
	return nil
}

func userFromRow(row db.User) (store.User, error) {
	var profile store.Profile
	if err := json.Unmarshal(row.Profile, &profile); err != nil {
		return store.User{}, fmt.Errorf("postgres: corrupt profile of user %s: %w", row.ID, err)
	}
	return store.User{
		ID:            row.ID,
		TenantID:      row.TenantID,
		Email:         row.Email,
		EmailVerified: row.EmailVerified,
		Status:        store.UserStatus(row.Status),
		Profile:       profile,
		CreatedAt:     row.CreatedAt.UTC(),
		UpdatedAt:     row.UpdatedAt.UTC(),
	}, nil
}

type passwords struct {
	q *db.Queries
}

func (r passwords) Set(ctx context.Context, p store.Password) error {
	n, err := r.q.SetPassword(ctx, db.SetPasswordParams{
		UserID:   p.UserID,
		TenantID: p.TenantID,
		Hash:     p.Hash,
		SetAt:    p.SetAt,
	})
	if err != nil {
		return mapError("setting password", err)
	}
	if n == 0 {
		// The user has a password in another tenant.
		return fmt.Errorf("postgres: setting password: %w", store.ErrNotFound)
	}
	return nil
}

func (r passwords) Get(ctx context.Context, tenantID, userID uuid.UUID) (store.Password, error) {
	row, err := r.q.GetPassword(ctx, db.GetPasswordParams{TenantID: tenantID, UserID: userID})
	if err != nil {
		return store.Password{}, mapError("getting password", err)
	}
	return store.Password{TenantID: row.TenantID, UserID: row.UserID, Hash: row.Hash, SetAt: row.SetAt.UTC()}, nil
}

func (r passwords) Rehash(ctx context.Context, tenantID, userID uuid.UUID, oldHash, newHash string) error {
	n, err := r.q.RehashPassword(ctx, db.RehashPasswordParams{
		NewHash:  newHash,
		TenantID: tenantID,
		UserID:   userID,
		OldHash:  oldHash,
	})
	if err != nil {
		return mapError("rehashing password", err)
	}
	if n > 0 {
		return nil
	}
	if _, err := r.Get(ctx, tenantID, userID); err != nil {
		return err
	}
	return fmt.Errorf("postgres: rehashing password: the hash changed: %w", store.ErrConflict)
}

// orEmpty returns an empty slice for nil, which pgx would otherwise send as
// NULL to a NOT NULL array column.
func orEmpty(list []string) []string {
	if list == nil {
		return []string{}
	}
	return list
}

// seconds converts a duration to whole seconds, the precision of stored
// durations.
func seconds(d time.Duration) int64 { return int64(d / time.Second) }

// mapError translates driver errors into the store sentinel errors.
func mapError(op string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("postgres: %s: %w", op, store.ErrNotFound)
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case uniqueViolation:
			return fmt.Errorf("postgres: %s: %w", op, store.ErrConflict)
		case foreignKeyViolation:
			return fmt.Errorf("postgres: %s: referenced record: %w", op, store.ErrNotFound)
		}
	}
	return fmt.Errorf("postgres: %s: %w", op, err)
}
