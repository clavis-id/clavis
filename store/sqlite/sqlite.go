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
	if path == "" || strings.ContainsAny(path, "?#") {
		return nil, fmt.Errorf("sqlite: invalid database path %q", path)
	}
	if err := createPrivate(path); err != nil {
		return nil, err
	}

	query := url.Values{"_txlock": {"immediate"}}
	for _, p := range pragmas {
		query.Add("_pragma", p)
	}
	conn, err := sql.Open("sqlite", "file:"+path+"?"+query.Encode())
	if err != nil {
		return nil, fmt.Errorf("sqlite: opening %s: %w", path, err)
	}
	q := db.New(conn)
	s := &Store{db: conn, tenants: tenants{q: q}, signingKeys: signingKeys{q: q}}

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
	fsys, err := fs.Sub(migrationFiles, "migrations")
	if err != nil {
		return fmt.Errorf("sqlite: loading migrations: %w", err)
	}
	p, err := goose.NewProvider(goose.DialectSQLite3, s.db, fsys)
	if err != nil {
		return fmt.Errorf("sqlite: preparing migrations: %w", err)
	}
	if _, err := p.Up(ctx); err != nil {
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
