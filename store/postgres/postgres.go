// Package postgres stores Clavis data in PostgreSQL.
//
// Several Clavis instances can share one database, which makes this the
// adapter for highly available deployments.
package postgres

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"uuid"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/clavis-id/clavis/store"
	"github.com/clavis-id/clavis/store/postgres/internal/db"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// uniqueViolation is the SQLSTATE for unique and primary key violations.
const uniqueViolation = "23505"

// Store is a store.Store backed by PostgreSQL. It is safe for concurrent use.
type Store struct {
	pool     *pgxpool.Pool
	ownsPool bool
	tenants  tenants
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
	s := &Store{pool: pool, tenants: tenants{q: db.New(pool)}}
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

// Migrate applies every pending schema migration.
func (s *Store) Migrate(ctx context.Context) error {
	fsys, err := fs.Sub(migrationFiles, "migrations")
	if err != nil {
		return fmt.Errorf("postgres: loading migrations: %w", err)
	}
	sqlDB := stdlib.OpenDBFromPool(s.pool)
	defer sqlDB.Close()
	p, err := goose.NewProvider(goose.DialectPostgres, sqlDB, fsys)
	if err != nil {
		return fmt.Errorf("postgres: preparing migrations: %w", err)
	}
	if _, err := p.Up(ctx); err != nil {
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

type tenants struct {
	q *db.Queries
}

func (r tenants) Create(ctx context.Context, t store.Tenant) error {
	err := r.q.CreateTenant(ctx, db.CreateTenantParams{
		ID:        t.ID,
		Slug:      t.Slug,
		Name:      t.Name,
		CreatedAt: t.CreatedAt,
		UpdatedAt: t.UpdatedAt,
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
		ID:        row.ID,
		Slug:      row.Slug,
		Name:      row.Name,
		CreatedAt: row.CreatedAt.UTC(),
		UpdatedAt: row.UpdatedAt.UTC(),
	}
}

// mapError translates driver errors into the store sentinel errors.
func mapError(op string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("postgres: %s: %w", op, store.ErrNotFound)
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
		return fmt.Errorf("postgres: %s: %w", op, store.ErrConflict)
	}
	return fmt.Errorf("postgres: %s: %w", op, err)
}
