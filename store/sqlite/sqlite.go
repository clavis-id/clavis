// Package sqlite stores Clavis data in an embedded SQLite database.
//
// The database runs in WAL mode with foreign keys enforced. It suits a single
// Clavis instance; use store/postgres to run several instances against the
// same data.
package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"strings"
	"time"
	"uuid"

	"github.com/pressly/goose/v3"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"

	"clavisid.org/clavis/store"
	"clavisid.org/clavis/store/sqlite/internal/db"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// pragmas configure every connection. WAL lets readers proceed during
// writes, and busy_timeout makes concurrent writers wait instead of failing.
var pragmas = []string{
	"foreign_keys(1)",
	"journal_mode(WAL)",
	"synchronous(NORMAL)",
	"busy_timeout(5000)",
}

// Store is a store.Store backed by SQLite. It is safe for concurrent use.
type Store struct {
	db          *sql.DB
	tenants     tenants
	signingKeys signingKeys
	clients     clients
	users       users
	passwords   passwords
	authzReqs   authorizationRequests
	sessions    sessions
	codes       authorizationCodes
	tokens      accessTokens
	resources   apiResources
}

var _ store.Store = (*Store)(nil)

type options struct {
	migrate bool
}

// Option configures Open.
type Option func(*options)

// WithoutMigrations skips applying pending migrations on Open. Use it when
// migrations run as a separate deployment step through Store.Migrate.
func WithoutMigrations() Option {
	return func(o *options) { o.migrate = false }
}

// Open opens the database file at path, creating it if needed, and applies
// pending migrations unless WithoutMigrations is given.
func Open(ctx context.Context, path string, opts ...Option) (*Store, error) {
	o := options{migrate: true}
	for _, opt := range opts {
		opt(&o)
	}
	if path == "" || path == ":memory:" || strings.HasPrefix(path, "file:") {
		// An in-memory database would be private to each pooled connection.
		return nil, fmt.Errorf("sqlite: invalid database path %q: use the path of a file", path)
	}
	if err := createPrivate(path); err != nil {
		return nil, err
	}

	query := url.Values{"_txlock": {"immediate"}}
	for _, p := range pragmas {
		query.Add("_pragma", p)
	}
	conn, err := sql.Open("sqlite", "file:"+uriPathEscaper.Replace(path)+"?"+query.Encode())
	if err != nil {
		return nil, fmt.Errorf("sqlite: opening %s: %w", path, err)
	}
	q := db.New(conn)
	s := &Store{
		db:          conn,
		tenants:     tenants{q: q},
		signingKeys: signingKeys{q: q},
		clients:     clients{q: q},
		users:       users{q: q},
		passwords:   passwords{q: q},
		authzReqs:   authorizationRequests{q: q},
		sessions:    sessions{q: q},
		codes:       authorizationCodes{q: q},
		tokens:      accessTokens{q: q},
		resources:   apiResources{q: q},
	}

	if err := s.Ping(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if o.migrate {
		if err := s.Migrate(ctx); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	return s, nil
}

// uriPathEscaper percent-encodes the characters that SQLite URIs treat
// specially, so SQLite opens exactly the file at the given path.
var uriPathEscaper = strings.NewReplacer("%", "%25", "?", "%3F", "#", "%23")

// createPrivate creates the database file readable and writable only by its
// owner, unless it already exists. SQLite gives its journal files the same
// permissions, so data never becomes readable by other local users.
func createPrivate(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // The path is chosen by the operator.
	switch {
	case err == nil:
		if err := f.Close(); err != nil {
			return fmt.Errorf("sqlite: creating %s: %w", path, err)
		}
		return nil
	case errors.Is(err, fs.ErrExist):
		return nil
	default:
		return fmt.Errorf("sqlite: creating %s: %w", path, err)
	}
}

// Migrate applies every pending schema migration.
func (s *Store) Migrate(ctx context.Context) error {
	return s.migrateTo(ctx, -1)
}

// migrateTo applies the pending migrations up to and including version, or
// all of them when version is negative.
func (s *Store) migrateTo(ctx context.Context, version int64) error {
	fsys, err := fs.Sub(migrationFiles, "migrations")
	if err != nil {
		return fmt.Errorf("sqlite: loading migrations: %w", err)
	}
	p, err := goose.NewProvider(goose.DialectSQLite3, s.db, fsys)
	if err != nil {
		return fmt.Errorf("sqlite: preparing migrations: %w", err)
	}
	if version < 0 {
		_, err = p.Up(ctx)
	} else {
		_, err = p.UpTo(ctx, version)
	}
	if err != nil {
		return fmt.Errorf("sqlite: applying migrations: %w", err)
	}
	return nil
}

// Close closes the database.
func (s *Store) Close() error {
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("sqlite: closing: %w", err)
	}
	return nil
}

// Ping reports whether the database is reachable.
func (s *Store) Ping(ctx context.Context) error {
	if err := s.db.PingContext(ctx); err != nil {
		return fmt.Errorf("sqlite: ping: %w", err)
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

// APIResources returns the API resource repository.
func (s *Store) APIResources() store.APIResources { return s.resources }

type tenants struct {
	q *db.Queries
}

func (r tenants) Create(ctx context.Context, t store.Tenant) error {
	err := r.q.CreateTenant(ctx, db.CreateTenantParams{
		ID:        t.ID.String(),
		Slug:      t.Slug,
		Name:      t.Name,
		CreatedAt: t.CreatedAt.UnixMicro(),
		UpdatedAt: t.UpdatedAt.UnixMicro(),
	})
	return mapError("creating tenant", err)
}

func (r tenants) Get(ctx context.Context, id uuid.UUID) (store.Tenant, error) {
	row, err := r.q.GetTenant(ctx, id.String())
	if err != nil {
		return store.Tenant{}, mapError("getting tenant", err)
	}
	return tenantFromRow(row)
}

func (r tenants) GetBySlug(ctx context.Context, slug string) (store.Tenant, error) {
	row, err := r.q.GetTenantBySlug(ctx, slug)
	if err != nil {
		return store.Tenant{}, mapError("getting tenant by slug", err)
	}
	return tenantFromRow(row)
}

func (r tenants) List(ctx context.Context, after uuid.UUID, limit int) ([]store.Tenant, error) {
	if limit < 1 || limit > store.MaxPageSize {
		return nil, fmt.Errorf("sqlite: listing tenants: %w: limit %d is outside [1, %d]",
			store.ErrInvalidArgument, limit, store.MaxPageSize)
	}
	rows, err := r.q.ListTenants(ctx, db.ListTenantsParams{After: after.String(), PageSize: int64(limit)})
	if err != nil {
		return nil, mapError("listing tenants", err)
	}
	out := make([]store.Tenant, 0, len(rows))
	for _, row := range rows {
		t, err := tenantFromRow(row)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

func (r tenants) Delete(ctx context.Context, id uuid.UUID) error {
	n, err := r.q.DeleteTenant(ctx, id.String())
	if err != nil {
		return mapError("deleting tenant", err)
	}
	if n == 0 {
		return fmt.Errorf("sqlite: deleting tenant: %w", store.ErrNotFound)
	}
	return nil
}

func tenantFromRow(row db.Tenant) (store.Tenant, error) {
	id, err := uuid.Parse(row.ID)
	if err != nil {
		return store.Tenant{}, fmt.Errorf("sqlite: corrupt tenant id %q: %w", row.ID, err)
	}
	return store.Tenant{
		ID:        id,
		Slug:      row.Slug,
		Name:      row.Name,
		CreatedAt: time.UnixMicro(row.CreatedAt).UTC(),
		UpdatedAt: time.UnixMicro(row.UpdatedAt).UTC(),
	}, nil
}

type signingKeys struct {
	q *db.Queries
}

func (r signingKeys) Create(ctx context.Context, k store.SigningKey) error {
	err := r.q.CreateSigningKey(ctx, db.CreateSigningKeyParams{
		ID:              k.ID.String(),
		TenantID:        k.TenantID.String(),
		Algorithm:       k.Algorithm,
		Generation:      k.Generation,
		KeyID:           k.KeyID,
		PublicKey:       k.PublicKey,
		PrivateKey:      k.PrivateKey,
		EncryptionKeyID: k.EncryptionKeyID,
		ActivatesAt:     k.ActivatesAt.UnixMicro(),
		RetiresAt:       k.RetiresAt.UnixMicro(),
		ExpiresAt:       k.ExpiresAt.UnixMicro(),
		CreatedAt:       k.CreatedAt.UnixMicro(),
	})
	return mapError("creating signing key", err)
}

func (r signingKeys) List(ctx context.Context, tenantID uuid.UUID) ([]store.SigningKey, error) {
	rows, err := r.q.ListSigningKeys(ctx, tenantID.String())
	if err != nil {
		return nil, mapError("listing signing keys", err)
	}
	out := make([]store.SigningKey, 0, len(rows))
	for _, row := range rows {
		id, err := uuid.Parse(row.ID)
		if err != nil {
			return nil, fmt.Errorf("sqlite: corrupt signing key id %q: %w", row.ID, err)
		}
		out = append(out, store.SigningKey{
			ID:              id,
			TenantID:        tenantID,
			Algorithm:       row.Algorithm,
			Generation:      row.Generation,
			KeyID:           row.KeyID,
			PublicKey:       row.PublicKey,
			PrivateKey:      row.PrivateKey,
			EncryptionKeyID: row.EncryptionKeyID,
			ActivatesAt:     time.UnixMicro(row.ActivatesAt).UTC(),
			RetiresAt:       time.UnixMicro(row.RetiresAt).UTC(),
			ExpiresAt:       time.UnixMicro(row.ExpiresAt).UTC(),
			CreatedAt:       time.UnixMicro(row.CreatedAt).UTC(),
		})
	}
	return out, nil
}

func (r signingKeys) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	n, err := r.q.DeleteExpiredSigningKeys(ctx, now.UnixMicro())
	if err != nil {
		return 0, mapError("deleting expired signing keys", err)
	}
	return n, nil
}

type clients struct {
	q *db.Queries
}

func (r clients) Create(ctx context.Context, c store.Client) error {
	lists := make([]string, 4)
	for i, list := range [][]string{c.RedirectURIs, c.PostLogoutRedirectURIs, c.GrantTypes, c.Scopes} {
		// A nil slice is encoded as an empty array.
		b, err := json.Marshal(list)
		if err != nil {
			return fmt.Errorf("sqlite: creating client: encoding a list: %w", err)
		}
		lists[i] = string(b)
	}
	err := r.q.CreateClient(ctx, db.CreateClientParams{
		ID:                                  c.ID.String(),
		TenantID:                            c.TenantID.String(),
		ClientID:                            c.ClientID,
		Name:                                c.Name,
		Type:                                string(c.Type),
		SecretHash:                          c.SecretHash,
		RedirectUris:                        lists[0],
		PostLogoutRedirectUris:              lists[1],
		GrantTypes:                          lists[2],
		Scopes:                              lists[3],
		AccessTokenLifetimeSeconds:          seconds(c.Lifetimes.AccessToken),
		IDTokenLifetimeSeconds:              seconds(c.Lifetimes.IDToken),
		RefreshTokenIdleLifetimeSeconds:     seconds(c.Lifetimes.RefreshTokenIdle),
		RefreshTokenAbsoluteLifetimeSeconds: seconds(c.Lifetimes.RefreshTokenAbsolute),
		SkipConsent:                         boolInt(c.SkipConsent),
		PkceExempt:                          boolInt(c.PKCEExempt),
		CreatedAt:                           c.CreatedAt.UnixMicro(),
		UpdatedAt:                           c.UpdatedAt.UnixMicro(),
	})
	return mapError("creating client", err)
}

func (r clients) Get(ctx context.Context, tenantID, id uuid.UUID) (store.Client, error) {
	row, err := r.q.GetClient(ctx, db.GetClientParams{TenantID: tenantID.String(), ID: id.String()})
	if err != nil {
		return store.Client{}, mapError("getting client", err)
	}
	return clientFromRow(row)
}

func (r clients) GetByClientID(ctx context.Context, tenantID uuid.UUID, clientID string) (store.Client, error) {
	row, err := r.q.GetClientByClientID(ctx, db.GetClientByClientIDParams{
		TenantID: tenantID.String(),
		ClientID: clientID,
	})
	if err != nil {
		return store.Client{}, mapError("getting client", err)
	}
	return clientFromRow(row)
}

func (r clients) List(ctx context.Context, tenantID, after uuid.UUID, limit int) ([]store.Client, error) {
	if limit < 1 || limit > store.MaxPageSize {
		return nil, fmt.Errorf("sqlite: listing clients: %w: limit %d is outside [1, %d]",
			store.ErrInvalidArgument, limit, store.MaxPageSize)
	}
	rows, err := r.q.ListClients(ctx, db.ListClientsParams{
		TenantID: tenantID.String(),
		After:    after.String(),
		PageSize: int64(limit),
	})
	if err != nil {
		return nil, mapError("listing clients", err)
	}
	out := make([]store.Client, 0, len(rows))
	for _, row := range rows {
		c, err := clientFromRow(row)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

func (r clients) UpdateSecret(ctx context.Context, tenantID, id uuid.UUID, secretHash []byte, updatedAt time.Time) error {
	n, err := r.q.UpdateClientSecret(ctx, db.UpdateClientSecretParams{
		SecretHash: secretHash,
		UpdatedAt:  updatedAt.UnixMicro(),
		TenantID:   tenantID.String(),
		ID:         id.String(),
	})
	if err != nil {
		return mapError("updating client secret", err)
	}
	if n == 0 {
		return fmt.Errorf("sqlite: updating client secret: %w", store.ErrNotFound)
	}
	return nil
}

func (r clients) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	n, err := r.q.DeleteClient(ctx, db.DeleteClientParams{TenantID: tenantID.String(), ID: id.String()})
	if err != nil {
		return mapError("deleting client", err)
	}
	if n == 0 {
		return fmt.Errorf("sqlite: deleting client: %w", store.ErrNotFound)
	}
	return nil
}

func clientFromRow(row db.Client) (store.Client, error) {
	id, err := uuid.Parse(row.ID)
	if err != nil {
		return store.Client{}, fmt.Errorf("sqlite: corrupt client id %q: %w", row.ID, err)
	}
	tenantID, err := uuid.Parse(row.TenantID)
	if err != nil {
		return store.Client{}, fmt.Errorf("sqlite: corrupt tenant id %q of client %s: %w", row.TenantID, id, err)
	}
	var lists [4][]string
	for i, encoded := range []string{row.RedirectUris, row.PostLogoutRedirectUris, row.GrantTypes, row.Scopes} {
		if err := json.Unmarshal([]byte(encoded), &lists[i]); err != nil {
			return store.Client{}, fmt.Errorf("sqlite: corrupt list in client %s: %w", id, err)
		}
	}
	return store.Client{
		ID:                     id,
		TenantID:               tenantID,
		ClientID:               row.ClientID,
		Name:                   row.Name,
		Type:                   store.ClientType(row.Type),
		SecretHash:             row.SecretHash,
		RedirectURIs:           lists[0],
		PostLogoutRedirectURIs: lists[1],
		GrantTypes:             lists[2],
		Scopes:                 lists[3],
		Lifetimes: store.TokenLifetimes{
			AccessToken:          time.Duration(row.AccessTokenLifetimeSeconds) * time.Second,
			IDToken:              time.Duration(row.IDTokenLifetimeSeconds) * time.Second,
			RefreshTokenIdle:     time.Duration(row.RefreshTokenIdleLifetimeSeconds) * time.Second,
			RefreshTokenAbsolute: time.Duration(row.RefreshTokenAbsoluteLifetimeSeconds) * time.Second,
		},
		SkipConsent: row.SkipConsent != 0,
		PKCEExempt:  row.PkceExempt != 0,
		CreatedAt:   time.UnixMicro(row.CreatedAt).UTC(),
		UpdatedAt:   time.UnixMicro(row.UpdatedAt).UTC(),
	}, nil
}

type users struct {
	q *db.Queries
}

func (r users) Create(ctx context.Context, u store.User) error {
	profile, err := json.Marshal(u.Profile)
	if err != nil {
		return fmt.Errorf("sqlite: creating user: encoding the profile: %w", err)
	}
	err = r.q.CreateUser(ctx, db.CreateUserParams{
		ID:            u.ID.String(),
		TenantID:      u.TenantID.String(),
		Email:         u.Email,
		EmailVerified: boolInt(u.EmailVerified),
		Status:        string(u.Status),
		Profile:       string(profile),
		CreatedAt:     u.CreatedAt.UnixMicro(),
		UpdatedAt:     u.UpdatedAt.UnixMicro(),
	})
	return mapError("creating user", err)
}

func (r users) Get(ctx context.Context, tenantID, id uuid.UUID) (store.User, error) {
	row, err := r.q.GetUser(ctx, db.GetUserParams{TenantID: tenantID.String(), ID: id.String()})
	if err != nil {
		return store.User{}, mapError("getting user", err)
	}
	return userFromRow(row)
}

func (r users) GetByEmail(ctx context.Context, tenantID uuid.UUID, email string) (store.User, error) {
	row, err := r.q.GetUserByEmail(ctx, db.GetUserByEmailParams{TenantID: tenantID.String(), Email: email})
	if err != nil {
		return store.User{}, mapError("getting user by email", err)
	}
	return userFromRow(row)
}

func (r users) List(ctx context.Context, tenantID, after uuid.UUID, limit int) ([]store.User, error) {
	if limit < 1 || limit > store.MaxPageSize {
		return nil, fmt.Errorf("sqlite: listing users: %w: limit %d is outside [1, %d]",
			store.ErrInvalidArgument, limit, store.MaxPageSize)
	}
	rows, err := r.q.ListUsers(ctx, db.ListUsersParams{
		TenantID: tenantID.String(),
		After:    after.String(),
		PageSize: int64(limit),
	})
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
	n, err := r.q.DeleteUser(ctx, db.DeleteUserParams{TenantID: tenantID.String(), ID: id.String()})
	if err != nil {
		return mapError("deleting user", err)
	}
	if n == 0 {
		return fmt.Errorf("sqlite: deleting user: %w", store.ErrNotFound)
	}
	return nil
}

func userFromRow(row db.User) (store.User, error) {
	id, err := uuid.Parse(row.ID)
	if err != nil {
		return store.User{}, fmt.Errorf("sqlite: corrupt user id %q: %w", row.ID, err)
	}
	tenantID, err := uuid.Parse(row.TenantID)
	if err != nil {
		return store.User{}, fmt.Errorf("sqlite: corrupt tenant id %q of user %s: %w", row.TenantID, id, err)
	}
	var profile store.Profile
	if err := json.Unmarshal([]byte(row.Profile), &profile); err != nil {
		return store.User{}, fmt.Errorf("sqlite: corrupt profile of user %s: %w", id, err)
	}
	return store.User{
		ID:            id,
		TenantID:      tenantID,
		Email:         row.Email,
		EmailVerified: row.EmailVerified != 0,
		Status:        store.UserStatus(row.Status),
		Profile:       profile,
		CreatedAt:     time.UnixMicro(row.CreatedAt).UTC(),
		UpdatedAt:     time.UnixMicro(row.UpdatedAt).UTC(),
	}, nil
}

type passwords struct {
	q *db.Queries
}

func (r passwords) Set(ctx context.Context, p store.Password) error {
	n, err := r.q.SetPassword(ctx, db.SetPasswordParams{
		UserID:   p.UserID.String(),
		TenantID: p.TenantID.String(),
		Hash:     p.Hash,
		SetAt:    p.SetAt.UnixMicro(),
	})
	if err != nil {
		return mapError("setting password", err)
	}
	if n == 0 {
		// The user has a password in another tenant.
		return fmt.Errorf("sqlite: setting password: %w", store.ErrNotFound)
	}
	return nil
}

func (r passwords) Get(ctx context.Context, tenantID, userID uuid.UUID) (store.Password, error) {
	row, err := r.q.GetPassword(ctx, db.GetPasswordParams{TenantID: tenantID.String(), UserID: userID.String()})
	if err != nil {
		return store.Password{}, mapError("getting password", err)
	}
	return store.Password{
		TenantID: tenantID,
		UserID:   userID,
		Hash:     row.Hash,
		SetAt:    time.UnixMicro(row.SetAt).UTC(),
	}, nil
}

func (r passwords) Rehash(ctx context.Context, tenantID, userID uuid.UUID, oldHash, newHash string) error {
	n, err := r.q.RehashPassword(ctx, db.RehashPasswordParams{
		NewHash:  newHash,
		TenantID: tenantID.String(),
		UserID:   userID.String(),
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
	return fmt.Errorf("sqlite: rehashing password: the hash changed: %w", store.ErrConflict)
}

// seconds converts a duration to whole seconds, the precision of stored
// durations.
func seconds(d time.Duration) int64 { return int64(d / time.Second) }

func boolInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// mapError translates driver errors into the store sentinel errors.
func mapError(op string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("sqlite: %s: %w", op, store.ErrNotFound)
	}
	var se *sqlite.Error
	if errors.As(err, &se) {
		switch se.Code() {
		case sqlite3.SQLITE_CONSTRAINT_UNIQUE, sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY:
			return fmt.Errorf("sqlite: %s: %w", op, store.ErrConflict)
		case sqlite3.SQLITE_CONSTRAINT_FOREIGNKEY:
			return fmt.Errorf("sqlite: %s: referenced record: %w", op, store.ErrNotFound)
		}
	}
	return fmt.Errorf("sqlite: %s: %w", op, err)
}
