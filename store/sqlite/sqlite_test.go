package sqlite_test

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"clavisid.org/clavis/store"
	"clavisid.org/clavis/store/sqlite"
	"clavisid.org/clavis/store/storetest"
)

func open(t *testing.T, path string, opts ...sqlite.Option) *sqlite.Store {
	t.Helper()
	s, err := sqlite.Open(t.Context(), path, opts...)
	if err != nil {
		t.Fatalf("Open() unexpected error: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("Close() unexpected error: %v", err)
		}
	})
	return s
}

func TestContract(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T) store.Store {
		return open(t, filepath.Join(t.TempDir(), "clavis.db"))
	})
}

func TestOpenRejectsInvalidPaths(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"", ":memory:", "file:clavis.db"} {
		if _, err := sqlite.Open(t.Context(), path); err == nil {
			t.Errorf("Open(%q) succeeded, want an error", path)
		}
	}
}

func TestMigrationsAreIdempotent(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "clavis.db")
	first := open(t, path)
	if err := first.Migrate(t.Context()); err != nil {
		t.Fatalf("second Migrate() unexpected error: %v", err)
	}
	open(t, path)
}

func TestWithoutMigrations(t *testing.T) {
	t.Parallel()
	s := open(t, filepath.Join(t.TempDir(), "clavis.db"), sqlite.WithoutMigrations())
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

func TestDatabaseFilesAreOwnerOnly(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions do not apply on Windows")
	}
	path := filepath.Join(t.TempDir(), "clavis.db")
	s := open(t, path)
	// Write something so SQLite creates its WAL and shared memory files.
	if err := s.Migrate(t.Context()); err != nil {
		t.Fatalf("Migrate() unexpected error: %v", err)
	}
	for _, name := range []string{path, path + "-wal", path + "-shm"} {
		info, err := os.Stat(name)
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			t.Errorf("%s has permissions %v, want no access for group or others", filepath.Base(name), perm)
		}
	}
}

func TestOpenKeepsExistingFilePermissions(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions do not apply on Windows")
	}
	path := filepath.Join(t.TempDir(), "clavis.db")
	if err := os.WriteFile(path, nil, 0o640); err != nil {
		t.Fatalf("creating file: %v", err)
	}
	open(t, path)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o640 {
		t.Errorf("Open() changed existing permissions to %v, want 0640", perm)
	}
}

// TestOpenUsesTheExactPath checks that characters with a meaning in SQLite
// URIs do not redirect the database to another file.
func TestOpenUsesTheExactPath(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"a%41.db", "query?mode=memory.db", "frag#x.db", "with space.db"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			path := filepath.Join(dir, name)
			s, err := sqlite.Open(t.Context(), path)
			if err != nil {
				t.Fatalf("Open(%q) unexpected error: %v", name, err)
			}
			if _, err := s.Tenants().List(t.Context(), [16]byte{}, 1); err != nil {
				t.Fatalf("List() unexpected error: %v", err)
			}
			if err := s.Close(); err != nil {
				t.Fatalf("Close() unexpected error: %v", err)
			}

			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatalf("reading directory: %v", err)
			}
			var names []string
			for _, e := range entries {
				names = append(names, e.Name())
			}
			for _, got := range names {
				if !strings.HasPrefix(got, name) {
					t.Errorf("Open(%q) created unexpected file %q (all files: %v)", name, got, names)
				}
			}
			if !slices.Contains(names, name) {
				t.Errorf("Open(%q) did not create the requested file (files: %v)", name, names)
			}
			reopened, err := sqlite.Open(t.Context(), path, sqlite.WithoutMigrations())
			if err != nil {
				t.Fatalf("reopening %q: %v", name, err)
			}
			defer reopened.Close()
			if _, err := reopened.Tenants().List(t.Context(), [16]byte{}, 1); err != nil {
				t.Errorf("schema missing after reopening %q: %v", name, err)
			}
		})
	}
}
