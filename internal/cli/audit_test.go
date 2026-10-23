package cli

import (
	"bytes"
	"encoding/json/v2"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"uuid"

	"clavisid.org/clavis/internal/app"
	"clavisid.org/clavis/store"
	"clavisid.org/clavis/store/sqlite"
)

func TestAuditCommands(t *testing.T) {
	t.Parallel()

	dsn := filepath.Join(t.TempDir(), "clavis.db")
	environ := []string{"CLAVIS_DATABASE_DSN=" + dsn}
	run := func(args ...string) (stdout, stderr string, code int) {
		var out, errOut bytes.Buffer
		code = Execute(t.Context(), args, nil, &out, &errOut, environ)
		return out.String(), errOut.String(), code
	}
	for _, args := range [][]string{
		{"clients", "create", "--client-id", "partner", "--redirect-uri", "https://partner.example.com/callback"},
		{"users", "create", "ada@example.com"},
		{"users", "create", "grace@example.com"},
	} {
		if _, errOut, code := run(args...); code != 0 {
			t.Fatalf("%v = %d, %q", args, code, errOut)
		}
	}
	// The consent page creates grants; the test writes one directly, and
	// the CLI revokes it as an operator.
	st, err := sqlite.Open(t.Context(), dsn)
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	d := app.Deps{Store: st, Logger: slog.New(slog.DiscardHandler), Now: time.Now, NewID: uuid.NewV7}
	tn, err := app.FindTenant(t.Context(), d, app.DefaultTenantSlug)
	if err != nil {
		t.Fatalf("default tenant: %v", err)
	}
	ada, err := app.FindUser(t.Context(), d, tn.ID, "ada@example.com")
	if err != nil {
		t.Fatalf("FindUser() unexpected error: %v", err)
	}
	grace, err := app.FindUser(t.Context(), d, tn.ID, "grace@example.com")
	if err != nil {
		t.Fatalf("FindUser() unexpected error: %v", err)
	}
	c, err := app.GetClient(t.Context(), d, tn.ID, "partner")
	if err != nil {
		t.Fatalf("GetClient() unexpected error: %v", err)
	}
	now := time.Now()
	if err := st.Grants().Put(t.Context(), store.Grant{ID: uuid.NewV7(), TenantID: tn.ID, UserID: ada.ID,
		ClientID: c.ID, Scopes: []string{"openid"}, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatalf("Put() unexpected error: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("closing store: %v", err)
	}
	for _, args := range [][]string{
		{"grants", "revoke", "partner", "--user", "ada@example.com", "--yes"},
		{"users", "delete", "grace@example.com", "--yes"},
	} {
		if _, errOut, code := run(args...); code != 0 {
			t.Fatalf("%v = %d, %q", args, code, errOut)
		}
	}

	out, errOut, code := run("audit", "list")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if code != 0 || len(lines) != 6 || !strings.HasPrefix(lines[0], "TIME") {
		t.Fatalf("audit list = %d, %q, %q", code, out, errOut)
	}
	// Newest first; a deleted user is named by ID, every event here is an
	// operator's.
	for i, want := range []string{
		"user.deleted operator " + grace.ID.String() + " - - -",
		"grant.revoked operator ada@example.com partner - -",
		"user.created operator " + grace.ID.String() + " - - -",
		"user.created operator ada@example.com - - -",
		"client.created operator - partner - pkce_exempt=false skip_consent=false type=confidential",
	} {
		if got := strings.Join(strings.Fields(lines[i+1])[1:], " "); !strings.HasPrefix(got, want+" ") {
			t.Errorf("line %d = %q, want %q and an ID", i+1, got, want)
		}
	}
	if errOut != "" {
		t.Errorf("audit list wrote %q to stderr", errOut)
	}

	// Pages continue with --before.
	out, errOut, code = run("audit", "list", "--type", app.EventUserCreated, "--limit", "1")
	if code != 0 || !strings.Contains(out, grace.ID.String()) || !strings.Contains(errOut, "--before ") {
		t.Fatalf("first page = %d, %q, %q", code, out, errOut)
	}
	before := strings.TrimSpace(strings.TrimSuffix(strings.SplitAfter(errOut, "--before ")[1], ".\n"))
	out, errOut, code = run("audit", "list", "--type", app.EventUserCreated, "--limit", "1", "--before", before)
	if code != 0 || !strings.Contains(out, "ada@example.com") || strings.Contains(out, grace.ID.String()) {
		t.Errorf("second page = %d, %q, %q", code, out, errOut)
	}

	// A user is named by address, or by ID once deleted.
	if out, _, code = run("audit", "list", "--user", "ada@example.com"); code != 0 ||
		strings.Count(strings.TrimSpace(out), "\n") != 2 {
		t.Errorf("events of ada = %d, %q", code, out)
	}
	if out, _, code = run("audit", "list", "--user", grace.ID.String()); code != 0 ||
		strings.Count(strings.TrimSpace(out), "\n") != 2 {
		t.Errorf("events of grace = %d, %q", code, out)
	}
	if _, errOut, code = run("audit", "list", "--user", "grace@example.com"); code == 0 ||
		!strings.Contains(errOut, "pass the ID of a deleted user") {
		t.Errorf("events of a deleted address = %d, %q", code, errOut)
	}

	out, errOut, code = run("audit", "list", "--json", "--type", app.EventClientCreated)
	if code != 0 {
		t.Fatalf("audit list --json = %d, %q", code, errOut)
	}
	var e struct {
		ID       uuid.UUID         `json:"id"`
		Type     string            `json:"type"`
		Actor    string            `json:"actor"`
		ClientID string            `json:"client_id"`
		UserID   *string           `json:"user_id"`
		Details  map[string]string `json:"details"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &e); err != nil || e.Type != app.EventClientCreated ||
		e.Actor != "operator" || e.ClientID != "partner" || e.UserID != nil || e.Details["pkce_exempt"] != "false" ||
		e.ID == uuid.Nil() {
		t.Errorf("JSON event = %+v, %v from %q", e, err, out)
	}

	for _, args := range [][]string{
		{"audit", "list", "--limit", "0"},
		{"audit", "list", "--limit", "1001"},
		{"audit", "list", "--before", "yesterday"},
		{"audit", "list", "--tenant", "missing"},
	} {
		if _, _, code := run(args...); code == 0 {
			t.Errorf("%v succeeded", args)
		}
	}
}
