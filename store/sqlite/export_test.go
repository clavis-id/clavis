package sqlite

import "context"

// MigrateTo applies the migrations up to and including version, so tests can
// check what a later migration does to existing data.
func (s *Store) MigrateTo(ctx context.Context, version int64) error {
	return s.migrateTo(ctx, version)
}

// Exec runs a statement against the database, so tests can write rows as an
// earlier schema version expects them.
func (s *Store) Exec(ctx context.Context, query string, args ...any) error {
	_, err := s.db.ExecContext(ctx, query, args...)
	return err
}
