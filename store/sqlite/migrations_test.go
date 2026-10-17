package sqlite_test

import (
	"path/filepath"
	"testing"
	"time"
	"uuid"

	"clavisid.org/clavis/store"
	"clavisid.org/clavis/store/sqlite"
)

// TestMigrationGivesEarlierSessionsThePasswordACR checks migration 00009:
// sessions created before acr values existed (ADR 0019) all come from a
// password sign-in.
func TestMigrationGivesEarlierSessionsThePasswordACR(t *testing.T) {
	t.Parallel()
	s := open(t, filepath.Join(t.TempDir(), "clavis.db"), sqlite.WithoutMigrations())
	ctx := t.Context()
	if err := s.MigrateTo(ctx, 8); err != nil {
		t.Fatalf("MigrateTo(8) unexpected error: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	tn := store.Tenant{ID: uuid.NewV7(), Slug: "default", Name: "Default", CreatedAt: now, UpdatedAt: now}
	u := store.User{ID: uuid.NewV7(), TenantID: tn.ID, Email: "ada@example.com", Status: store.UserActive,
		CreatedAt: now, UpdatedAt: now}
	if err := s.Tenants().Create(ctx, tn); err != nil {
		t.Fatalf("creating the tenant: %v", err)
	}
	if err := s.Users().Create(ctx, u); err != nil {
		t.Fatalf("creating the user: %v", err)
	}
	sessions := map[string]store.Session{}
	for _, acr := range []string{"", "urn:example:acr:other"} {
		session := store.Session{ID: uuid.NewV7(), TenantID: tn.ID, TokenHash: []byte("session " + acr), UserID: u.ID,
			AuthTime: now, ACR: acr, CreatedAt: now, LastSeenAt: now, IdleExpiresAt: now.Add(time.Hour),
			ExpiresAt: now.Add(time.Hour)}
		if err := s.Sessions().Create(ctx, session); err != nil {
			t.Fatalf("creating a session: %v", err)
		}
		sessions[acr] = session
	}

	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate() unexpected error: %v", err)
	}
	for acr, want := range map[string]string{"": "https://clavisid.org/acr/password", "urn:example:acr:other": "urn:example:acr:other"} {
		got, err := s.Sessions().GetByTokenHash(ctx, tn.ID, sessions[acr].TokenHash)
		if err != nil || got.ACR != want {
			t.Errorf("acr of a session stored with %q = %q, %v; want %q", acr, got.ACR, err, want)
		}
	}
}
