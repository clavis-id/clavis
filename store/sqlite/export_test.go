package sqlite

import "context"

// MigrateTo applies the migrations up to and including version, so tests can
// check what a later migration does to existing data.
func (s *Store) MigrateTo(ctx context.Context, version int64) error {
	return s.migrateTo(ctx, version)
}
