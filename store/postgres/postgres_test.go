package postgres_test

import (
	"context"
	"crypto/rand"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/clavis-id/clavis/store"
	"github.com/clavis-id/clavis/store/postgres"
	"github.com/clavis-id/clavis/store/storetest"
)

// adminDSNVar names the environment variable with a connection URL for a
// PostgreSQL server where the tests may create and drop databases. Run
// `make test-postgres` to start one in Docker.
const adminDSNVar = "CLAVIS_TEST_POSTGRES_DSN"

// createMu serializes CREATE DATABASE statements, which copy the template
// database and can conflict when run concurrently.
var createMu sync.Mutex

// openEmpty creates a new database, opens a Store on it and drops the
// database when the test ends.
func openEmpty(t *testing.T, opts ...postgres.Option) *postgres.Store {
	t.Helper()
	admin := os.Getenv(adminDSNVar)
	if admin == "" {
		t.Skipf("set %s to run PostgreSQL tests (see make test-postgres)", adminDSNVar)
	}
	u, err := url.Parse(admin)
	if err != nil {
		t.Fatalf("%s must be a connection URL: %v", adminDSNVar, err)
	}

	ctx := t.Context()
	conn, err := pgx.Connect(ctx, admin)
	if err != nil {
		t.Fatalf("connecting to the admin database: %v", err)
	}
	name := pgx.Identifier{"clavis_test_" + strings.ToLower(rand.Text())}.Sanitize()
	createMu.Lock()
	_, err = conn.Exec(ctx, "CREATE DATABASE "+name)
	createMu.Unlock()
	if err != nil {
		t.Fatalf("creating test database: %v", err)
	}

	u.Path = "/" + strings.Trim(name, `"`)
	s, err := postgres.Open(ctx, u.String(), opts...)
	if err != nil {
		t.Fatalf("Open() unexpected error: %v", err)
	}
	t.Cleanup(func() {
		// t.Context is already canceled when cleanup functions run.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		s.Close()
		if _, err := conn.Exec(ctx, "DROP DATABASE "+name+" WITH (FORCE)"); err != nil {
			t.Errorf("dropping test database: %v", err)
		}
		_ = conn.Close(ctx)
	})
	return s
}

func TestContract(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T) store.Store { return openEmpty(t) })
}

func TestMigrationsAreIdempotent(t *testing.T) {
	t.Parallel()
	s := openEmpty(t)
	if err := s.Migrate(t.Context()); err != nil {
		t.Fatalf("second Migrate() unexpected error: %v", err)
	}
}

func TestWithoutMigrations(t *testing.T) {
	t.Parallel()
	s := openEmpty(t, postgres.WithoutMigrations())
	if _, err := s.Tenants().List(t.Context(), [16]byte{}, 1); err == nil {
		t.Fatal("List() succeeded before migrations ran, want an error")
	}
	if err := s.Migrate(t.Context()); err != nil {
		t.Fatalf("Migrate() unexpected error: %v", err)
	}
	if _, err := s.Tenants().List(t.Context(), [16]byte{}, 1); err != nil {
		t.Errorf("List() after Migrate() unexpected error: %v", err)
	}
}

func TestOpenHidesConnectionStringErrors(t *testing.T) {
	t.Parallel()
	_, err := postgres.Open(t.Context(), "postgres://user:s3cret@[::1")
	if err == nil {
		t.Fatal("Open() succeeded with a malformed connection string")
	}
	if strings.Contains(err.Error(), "s3cret") {
		t.Errorf("Open() error %q leaks the password", err)
	}
}
