package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"
	"time"
	"uuid"

	"clavisid.org/clavis/internal/app"
	"clavisid.org/clavis/internal/authn/password"
	"clavisid.org/clavis/internal/oauth"
	"clavisid.org/clavis/kek"
	"clavisid.org/clavis/store"
	"clavisid.org/clavis/store/sqlite"
)

// testKey is a valid encryption key for tests (32 zero bytes, base64).
const testKey = "CLAVIS_KEYS_ENCRYPTION_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func TestVersion(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	code := Execute(t.Context(), []string{"version"}, nil, &stdout, &stderr, nil)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.HasPrefix(stdout.String(), "clavis ") || !strings.Contains(stdout.String(), "go: go1.") {
		t.Errorf("unexpected version output %q", stdout.String())
	}
}

func TestUnknownCommand(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	if code := Execute(t.Context(), []string{"launch"}, nil, &stdout, &stderr, nil); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "unknown command") {
		t.Errorf("stderr %q does not explain the error", stderr.String())
	}
}

func TestServeRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	environ := []string{"CLAVIS_ISSUER=http://auth.example.com", testKey}
	if code := Execute(t.Context(), []string{"serve"}, nil, &stdout, &stderr, environ); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "issuer") {
		t.Errorf("stderr %q does not mention the issuer", stderr.String())
	}
}

func TestServeReadsConfigFileFromEnvironment(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "clavis.yaml")
	if err := os.WriteFile(path, []byte("log:\n  level: loud\n"), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	var stdout, stderr bytes.Buffer
	environ := []string{"CLAVIS_CONFIG=" + path}
	if code := Execute(t.Context(), []string{"serve"}, nil, &stdout, &stderr, environ); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "log.level") {
		t.Errorf("stderr %q does not report the invalid level from the file", stderr.String())
	}
}

// TestServeLifecycle starts the server, waits for it to report its address,
// calls the health endpoint, then cancels the context and expects a clean
// exit.
func TestServeLifecycle(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	pr, pw := io.Pipe()
	environ := []string{
		"CLAVIS_SERVER_ADDRESS=127.0.0.1:0",
		"CLAVIS_DATABASE_DSN=" + filepath.Join(t.TempDir(), "clavis.db"),
		"CLAVIS_SERVICE_HOST=10.0.0.12",
		testKey,
	}

	exit := make(chan int, 1)
	go func() {
		exit <- Execute(ctx, []string{"serve"}, nil, io.Discard, pw, environ)
		_ = pw.Close()
	}()

	var address string
	var sawIgnoredWarning bool
	scanner := bufio.NewScanner(pr)
	for address == "" && scanner.Scan() {
		var record map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			t.Fatalf("log line is not JSON: %q", scanner.Text())
		}
		switch record["msg"] {
		case "ignoring environment variable that matches no configuration key":
			sawIgnoredWarning = record["name"] == "CLAVIS_SERVICE_HOST"
		case "http server listening":
			address, _ = record["address"].(string)
		}
	}
	if address == "" {
		t.Fatalf("server never reported its address (scanner error: %v)", scanner.Err())
	}
	go func() { _, _ = io.Copy(io.Discard, pr) }()

	if !sawIgnoredWarning {
		t.Error("no warning was logged for the unknown CLAVIS_SERVICE_HOST variable")
	}

	for _, path := range []string{"/healthz", "/readyz", "/oauth2/jwks"} {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+address+path, http.NoBody)
		if err != nil {
			t.Fatalf("building request: %v", err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s status = %d, want 200", path, resp.StatusCode)
		}
	}

	cancel()
	if code := <-exit; code != 0 {
		t.Errorf("exit code = %d, want 0 after cancellation", code)
	}
}

func TestMigrate(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "clavis.db")
	// No encryption key: migrations need only the database settings.
	environ := []string{"CLAVIS_DATABASE_DSN=" + path, "CLAVIS_DATABASE_AUTO_MIGRATE=false"}

	var stdout, stderr bytes.Buffer
	if code := Execute(t.Context(), []string{"migrate"}, nil, &stdout, &stderr, environ); code != 0 {
		t.Fatalf("migrate exit code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "database migrations applied") {
		t.Errorf("migrate did not log its result: %q", stderr.String())
	}

	s, err := sqlite.Open(t.Context(), path, sqlite.WithoutMigrations())
	if err != nil {
		t.Fatalf("opening migrated database: %v", err)
	}
	defer s.Close()
	if _, err := s.Tenants().List(t.Context(), [16]byte{}, 1); err != nil {
		t.Errorf("schema is missing after migrate: %v", err)
	}
}

func TestServeWithoutAutoMigrateNeedsMigratedDatabase(t *testing.T) {
	t.Parallel()

	environ := []string{
		"CLAVIS_SERVER_ADDRESS=127.0.0.1:0",
		"CLAVIS_DATABASE_DSN=" + filepath.Join(t.TempDir(), "clavis.db"),
		"CLAVIS_DATABASE_AUTO_MIGRATE=false",
		testKey,
	}
	var stdout, stderr bytes.Buffer
	if code := Execute(t.Context(), []string{"serve"}, nil, &stdout, &stderr, environ); code != 1 {
		t.Errorf("exit code = %d, want 1 on an unmigrated database", code)
	}
	if !strings.Contains(stderr.String(), "default tenant") {
		t.Errorf("stderr %q does not explain the failure", stderr.String())
	}
}

func TestNewEncryptionKey(t *testing.T) {
	t.Parallel()

	seen := make(map[string]bool)
	for range 2 {
		var stdout, stderr bytes.Buffer
		if code := Execute(t.Context(), []string{"keys", "new-encryption-key"}, nil, &stdout, &stderr, nil); code != 0 {
			t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
		}
		encoded := strings.TrimSpace(stdout.String())
		if _, err := kek.ParseSecret(encoded); err != nil {
			t.Errorf("output %q is not a valid encryption key: %v", encoded, err)
		}
		if seen[encoded] {
			t.Error("two invocations printed the same key")
		}
		seen[encoded] = true
	}
}

// TestServeExposesMetrics runs the server with metrics enabled and scrapes the
// separate metrics listener.
func TestServeExposesMetrics(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	pr, pw := io.Pipe()
	environ := []string{
		"CLAVIS_SERVER_ADDRESS=127.0.0.1:0",
		"CLAVIS_DATABASE_DSN=" + filepath.Join(t.TempDir(), "clavis.db"),
		"CLAVIS_TELEMETRY_METRICS_ENABLED=true",
		"CLAVIS_TELEMETRY_METRICS_ADDRESS=127.0.0.1:0",
		testKey,
	}
	exit := make(chan int, 1)
	go func() {
		exit <- Execute(ctx, []string{"serve"}, nil, io.Discard, pw, environ)
		_ = pw.Close()
	}()

	addresses := make(map[string]string)
	scanner := bufio.NewScanner(pr)
	for len(addresses) < 2 && scanner.Scan() {
		var record map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			t.Fatalf("log line is not JSON: %q", scanner.Text())
		}
		if record["msg"] == "http server listening" {
			name, _ := record["server"].(string)
			addresses[name], _ = record["address"].(string)
		}
	}
	go func() { _, _ = io.Copy(io.Discard, pr) }()
	if addresses["api"] == "" || addresses["metrics"] == "" {
		t.Fatalf("listening addresses = %v, want api and metrics", addresses)
	}

	get := func(url string) (int, string) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, http.NoBody)
		if err != nil {
			t.Fatalf("building request: %v", err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", url, err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}

	get("http://" + addresses["api"] + "/oauth2/jwks")
	code, body := get("http://" + addresses["metrics"] + "/metrics")
	if code != http.StatusOK {
		t.Fatalf("GET /metrics status = %d, want 200", code)
	}
	for _, want := range []string{"clavis_signing_keys_created_total", "http_server_request_duration_seconds", "go_goroutines"} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics output does not contain %q", want)
		}
	}
	if code, _ := get("http://" + addresses["api"] + "/metrics"); code != http.StatusNotFound {
		t.Errorf("GET /metrics on the API listener status = %d, want 404", code)
	}

	cancel()
	if code := <-exit; code != 0 {
		t.Errorf("exit code = %d, want 0 after cancellation", code)
	}
}

func TestTenantsCommands(t *testing.T) {
	t.Parallel()

	dsn := filepath.Join(t.TempDir(), "clavis.db")
	environ := []string{"CLAVIS_ISSUER=https://auth.example.com", "CLAVIS_DATABASE_DSN=" + dsn, testKey}
	run := func(args ...string) (stdout, stderr string, code int) {
		var out, errOut bytes.Buffer
		code = Execute(t.Context(), args, nil, &out, &errOut, environ)
		return out.String(), errOut.String(), code
	}

	out, errOut, code := run("tenants", "create", "acme", "--name", "Acme Corp")
	if code != 0 {
		t.Fatalf("tenants create: exit code %d, stderr %q", code, errOut)
	}
	if !strings.Contains(out, "Created tenant acme") || !strings.Contains(out, "Issuer: https://auth.example.com/t/acme") {
		t.Errorf("tenants create output %q lacks the slug or the issuer", out)
	}
	st, err := sqlite.Open(t.Context(), dsn)
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	acme, err := st.Tenants().GetBySlug(t.Context(), "acme")
	if err != nil {
		t.Fatalf("tenant not stored: %v", err)
	}
	if keys, err := st.SigningKeys().List(t.Context(), acme.ID); err != nil || len(keys) != 1 {
		t.Errorf("signing keys of the new tenant = %d, %v; want 1 key", len(keys), err)
	}
	_ = st.Close()

	if out, errOut, code = run("tenants", "list"); code != 0 || !strings.Contains(out, "acme") || !strings.Contains(out, "Acme Corp") {
		t.Errorf("tenants list: exit code %d, stdout %q, stderr %q", code, out, errOut)
	}
	if _, errOut, code = run("tenants", "create", "acme"); code != 1 || !strings.Contains(errOut, "already exists") {
		t.Errorf("duplicate create: exit code %d, stderr %q", code, errOut)
	}
	if _, errOut, code = run("tenants", "delete", "acme"); code != 1 || !strings.Contains(errOut, "--yes") {
		t.Errorf("delete without --yes: exit code %d, stderr %q", code, errOut)
	}
	if _, errOut, code = run("tenants", "delete", "default", "--yes"); code != 1 || !strings.Contains(errOut, "cannot be deleted") {
		t.Errorf("delete default: exit code %d, stderr %q", code, errOut)
	}
	if out, errOut, code = run("tenants", "delete", "acme", "--yes"); code != 0 || !strings.Contains(out, "Deleted tenant acme") {
		t.Errorf("delete: exit code %d, stdout %q, stderr %q", code, out, errOut)
	}
	if out, _, _ = run("tenants", "list"); strings.Contains(out, "acme") {
		t.Errorf("deleted tenant still listed: %q", out)
	}
}

func TestTenantsCreateNeedsEncryptionKey(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	environ := []string{
		"CLAVIS_ISSUER=https://auth.example.com",
		"CLAVIS_DATABASE_DSN=" + filepath.Join(t.TempDir(), "clavis.db"),
	}
	if code := Execute(t.Context(), []string{"tenants", "create", "acme"}, nil, &stdout, &stderr, environ); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "encryption_key") {
		t.Errorf("stderr %q does not mention the missing encryption key", stderr.String())
	}
}

func TestClientsCommands(t *testing.T) {
	t.Parallel()

	dsn := filepath.Join(t.TempDir(), "clavis.db")
	environ := []string{"CLAVIS_ISSUER=https://auth.example.com", "CLAVIS_DATABASE_DSN=" + dsn, testKey}
	run := func(args ...string) (stdout, stderr string, code int) {
		var out, errOut bytes.Buffer
		code = Execute(t.Context(), args, nil, &out, &errOut, environ)
		return out.String(), errOut.String(), code
	}
	if _, errOut, code := run("tenants", "create", "acme"); code != 0 {
		t.Fatalf("tenants create: exit code %d, stderr %q", code, errOut)
	}
	secretOf := func(out string) string {
		_, rest, ok := strings.Cut(out, "secret: ")
		if !ok {
			t.Fatalf("output %q has no client secret", out)
		}
		secret, _, _ := strings.Cut(rest, "\n")
		return secret
	}
	storedHash := func() []byte {
		st, err := sqlite.Open(t.Context(), dsn)
		if err != nil {
			t.Fatalf("opening store: %v", err)
		}
		defer st.Close()
		acme, err := st.Tenants().GetBySlug(t.Context(), "acme")
		if err != nil {
			t.Fatalf("tenant not stored: %v", err)
		}
		c, err := st.Clients().GetByClientID(t.Context(), acme.ID, "web-app")
		if err != nil {
			t.Fatalf("client not stored: %v", err)
		}
		return c.SecretHash
	}

	out, errOut, code := run("clients", "create", "--tenant", "acme", "--client-id", "web-app",
		"--name", "Web app", "--redirect-uri", "https://app.example.com/callback",
		"--redirect-uri", "http://127.0.0.1/callback", "--access-token-lifetime", "15m")
	if code != 0 {
		t.Fatalf("clients create: exit code %d, stderr %q", code, errOut)
	}
	if !strings.Contains(out, "Created client web-app in tenant acme") || !strings.Contains(out, "cannot be shown again") {
		t.Errorf("clients create output %q lacks the confirmation or the warning to store the secret", out)
	}
	secret := secretOf(out)
	if !oauth.ClientSecretMatches(storedHash(), secret) {
		t.Errorf("printed secret %q does not match the stored hash", secret)
	}

	out, errOut, code = run("clients", "show", "web-app", "--tenant", "acme")
	if code != 0 {
		t.Fatalf("clients show: exit code %d, stderr %q", code, errOut)
	}
	for _, want := range []string{"Web app", "confidential", "https://app.example.com/callback",
		"http://127.0.0.1/callback", "offline_access", "PKCE:", "required", "15m0s", "default"} {
		if !strings.Contains(out, want) {
			t.Errorf("clients show output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, secret) {
		t.Error("clients show printed the client secret")
	}

	// PKCE is required unless an operator turns it off, which warns.
	_, errOut, code = run("clients", "create", "--tenant", "acme", "--client-id", "conformance",
		"--redirect-uri", "https://app.example.com/callback", "--pkce-exempt")
	if code != 0 || !strings.Contains(errOut, "Warning: client conformance may send authorization requests without PKCE") {
		t.Errorf("clients create --pkce-exempt: exit code %d, stderr %q", code, errOut)
	}
	out, errOut, code = run("clients", "create", "--tenant", "acme", "--client-id", "spa", "--type", "public",
		"--redirect-uri", "https://spa.example.com/callback")
	if code != 0 || strings.Contains(out, "secret") {
		t.Errorf("public clients create: exit code %d, stdout %q, stderr %q", code, out, errOut)
	}
	if _, errOut, code = run("clients", "create", "--tenant", "acme", "--client-id", "native", "--type", "public",
		"--redirect-uri", "http://127.0.0.1/callback", "--pkce-exempt"); code != 1 || !strings.Contains(errOut, "always require PKCE") {
		t.Errorf("public client with --pkce-exempt: exit code %d, stderr %q", code, errOut)
	}
	if _, errOut, code = run("clients", "create", "--tenant", "acme", "--client-id", "bad",
		"--redirect-uri", "https://*.example.com/callback"); code != 1 || !strings.Contains(errOut, "wildcard") {
		t.Errorf("wildcard redirect URI: exit code %d, stderr %q", code, errOut)
	}

	out, errOut, code = run("clients", "list", "--tenant", "acme")
	if code != 0 {
		t.Fatalf("clients list: exit code %d, stderr %q", code, errOut)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 4 || !strings.Contains(lines[2], "conformance") || !strings.Contains(lines[2], "exempt") ||
		!strings.Contains(lines[1], "required") {
		t.Errorf("clients list output does not show each client and its PKCE setting:\n%s", out)
	}
	if out, _, _ = run("clients", "list"); strings.Contains(out, "web-app") {
		t.Errorf("clients list for the default tenant shows a client of acme:\n%s", out)
	}

	if _, errOut, code = run("clients", "rotate-secret", "web-app", "--tenant", "acme"); code != 1 || !strings.Contains(errOut, "--yes") {
		t.Errorf("rotate-secret without --yes: exit code %d, stderr %q", code, errOut)
	}
	out, errOut, code = run("clients", "rotate-secret", "web-app", "--tenant", "acme", "--yes")
	if code != 0 {
		t.Fatalf("rotate-secret: exit code %d, stderr %q", code, errOut)
	}
	rotated := secretOf(out)
	if hash := storedHash(); !oauth.ClientSecretMatches(hash, rotated) || oauth.ClientSecretMatches(hash, secret) {
		t.Error("after rotation the stored hash must match the new secret only")
	}
	if _, errOut, code = run("clients", "rotate-secret", "spa", "--tenant", "acme", "--yes"); code != 1 || !strings.Contains(errOut, "no secret") {
		t.Errorf("rotate-secret of a public client: exit code %d, stderr %q", code, errOut)
	}

	if _, errOut, code = run("clients", "delete", "web-app", "--tenant", "acme"); code != 1 || !strings.Contains(errOut, "--yes") {
		t.Errorf("delete without --yes: exit code %d, stderr %q", code, errOut)
	}
	if out, errOut, code = run("clients", "delete", "web-app", "--tenant", "acme", "--yes"); code != 0 || !strings.Contains(out, "Deleted client web-app") {
		t.Errorf("delete: exit code %d, stdout %q, stderr %q", code, out, errOut)
	}
	if _, errOut, code = run("clients", "show", "web-app", "--tenant", "acme"); code != 1 || !strings.Contains(errOut, "client not found") {
		t.Errorf("show after delete: exit code %d, stderr %q", code, errOut)
	}
	if _, errOut, code = run("clients", "list", "--tenant", "missing"); code != 1 || !strings.Contains(errOut, "tenant not found") {
		t.Errorf("unknown tenant: exit code %d, stderr %q", code, errOut)
	}
}

func TestClientsCreateInDefaultTenantOfNewDatabase(t *testing.T) {
	t.Parallel()

	// The server creates the default tenant when it first starts; registering
	// a client must not need a server start first.
	var stdout, stderr bytes.Buffer
	environ := []string{"CLAVIS_DATABASE_DSN=" + filepath.Join(t.TempDir(), "clavis.db")}
	args := []string{"clients", "create", "--client-id", "web-app", "--redirect-uri", "https://app.example.com/callback"}
	if code := Execute(t.Context(), args, nil, &stdout, &stderr, environ); code != 0 {
		t.Fatalf("exit code = %d, stderr %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Created client web-app in tenant default") {
		t.Errorf("stdout %q does not confirm the client in the default tenant", stdout.String())
	}
}

func TestClientsReadCommandsDoNotCreateTheDefaultTenant(t *testing.T) {
	t.Parallel()

	dsn := filepath.Join(t.TempDir(), "clavis.db")
	environ := []string{"CLAVIS_DATABASE_DSN=" + dsn}
	for _, args := range [][]string{
		{"clients", "list"},
		{"clients", "show", "web-app"},
		{"clients", "rotate-secret", "web-app", "--yes"},
		{"clients", "delete", "web-app", "--yes"},
	} {
		var stdout, stderr bytes.Buffer
		if code := Execute(t.Context(), args, nil, &stdout, &stderr, environ); code != 1 {
			t.Errorf("%v: exit code = %d, want 1", args, code)
		}
		if !strings.Contains(stderr.String(), `tenant not found: "default"; it is created when the server first starts or when the first record is created`) {
			t.Errorf("%v: stderr %q does not explain the missing default tenant", args, stderr.String())
		}
	}
	st, err := sqlite.Open(t.Context(), dsn)
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	defer st.Close()
	if tenants, err := st.Tenants().List(t.Context(), uuid.Nil(), 10); err != nil || len(tenants) != 0 {
		t.Errorf("tenants after read commands = %d, %v; want none", len(tenants), err)
	}
}

func TestUsersCommands(t *testing.T) {
	t.Parallel()

	dsn := filepath.Join(t.TempDir(), "clavis.db")
	environ := []string{"CLAVIS_DATABASE_DSN=" + dsn, "CLAVIS_PASSWORDS_MIN_LENGTH=12"}
	run := func(stdin string, args ...string) (stdout, stderr string, code int) {
		var out, errOut bytes.Buffer
		code = Execute(t.Context(), args, strings.NewReader(stdin), &out, &errOut, environ)
		return out.String(), errOut.String(), code
	}
	login := func(email, pw string) error {
		st, err := sqlite.Open(t.Context(), dsn)
		if err != nil {
			t.Fatalf("opening store: %v", err)
		}
		defer st.Close()
		d := app.Deps{Store: st, Logger: slog.New(slog.DiscardHandler), Now: time.Now, NewID: uuid.NewV7}
		tn, err := app.FindTenant(t.Context(), d, app.DefaultTenantSlug)
		if err != nil {
			t.Fatalf("default tenant: %v", err)
		}
		h, err := password.New(password.DefaultConfig())
		if err != nil {
			t.Fatalf("password.New() unexpected error: %v", err)
		}
		_, err = app.AuthenticatePassword(t.Context(), d, h, tn.ID, email, pw)
		return err
	}

	// A password that fails the policy leaves no user behind.
	if _, errOut, code := run("too short\n", "users", "create", "ada@example.com", "--with-password"); code != 1 ||
		!strings.Contains(errOut, "12 to 256 characters") {
		t.Errorf("create with a short password: exit code %d, stderr %q", code, errOut)
	}
	out, errOut, code := run("correct horse battery\n", "users", "create", "Ada@Example.com", "--with-password",
		"--name", "Ada Lovelace", "--email-verified")
	if code != 0 || !strings.Contains(out, "Created user ada@example.com in tenant default") || !strings.Contains(out, "Password set") {
		t.Fatalf("users create: exit code %d, stdout %q, stderr %q", code, out, errOut)
	}
	if strings.Contains(out+errOut, "correct horse battery") {
		t.Error("users create printed the password")
	}
	if err := login("ada@example.com", "correct horse battery"); err != nil {
		t.Errorf("login with the new password: %v", err)
	}
	if _, errOut, code = run("", "users", "create", "ada@example.com"); code != 1 || !strings.Contains(errOut, "already exists") {
		t.Errorf("duplicate create: exit code %d, stderr %q", code, errOut)
	}
	if out, errOut, code = run("", "users", "create", "grace@example.com"); code != 0 || strings.Contains(out, "Password set") {
		t.Errorf("create without a password: exit code %d, stdout %q, stderr %q", code, out, errOut)
	}

	if out, errOut, code = run("battery staple horse\r\n", "users", "set-password", "ADA@example.com"); code != 0 ||
		!strings.Contains(out, "Set the password of ada@example.com") {
		t.Errorf("set-password: exit code %d, stdout %q, stderr %q", code, out, errOut)
	}
	if err := login("ada@example.com", "battery staple horse"); err != nil {
		t.Errorf("login with the changed password: %v", err)
	}
	if err := login("ada@example.com", "correct horse battery"); !errors.Is(err, app.ErrInvalidCredentials) {
		t.Errorf("login with the old password = %v, want ErrInvalidCredentials", err)
	}
	if _, errOut, code = run("", "users", "set-password", "ada@example.com"); code != 1 || !strings.Contains(errOut, "no password on standard input") {
		t.Errorf("set-password without input: exit code %d, stderr %q", code, errOut)
	}
	if _, errOut, code = run("battery staple horse\n", "users", "set-password", "nobody@example.com"); code != 1 ||
		!strings.Contains(errOut, "user not found") {
		t.Errorf("set-password of an unknown user: exit code %d, stderr %q", code, errOut)
	}

	out, errOut, code = run("", "users", "list")
	if code != 0 {
		t.Fatalf("users list: exit code %d, stderr %q", code, errOut)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 || !strings.Contains(lines[1], "ada@example.com") || !strings.Contains(lines[1], "Ada Lovelace") ||
		!strings.Contains(lines[1], "true") || !strings.Contains(lines[2], "grace@example.com") {
		t.Errorf("users list output:\n%s", out)
	}

	if _, errOut, code = run("", "users", "delete", "ada@example.com"); code != 1 || !strings.Contains(errOut, "--yes") {
		t.Errorf("delete without --yes: exit code %d, stderr %q", code, errOut)
	}
	if out, errOut, code = run("", "users", "delete", "ada@example.com", "--yes"); code != 0 || !strings.Contains(out, "Deleted user") {
		t.Errorf("delete: exit code %d, stdout %q, stderr %q", code, out, errOut)
	}
	if err := login("ada@example.com", "battery staple horse"); !errors.Is(err, app.ErrInvalidCredentials) {
		t.Errorf("login after delete = %v, want ErrInvalidCredentials", err)
	}
	if _, errOut, code = run("", "users", "list", "--tenant", "missing"); code != 1 || !strings.Contains(errOut, "tenant not found") {
		t.Errorf("unknown tenant: exit code %d, stderr %q", code, errOut)
	}
}

func TestUsersReadCommandsDoNotCreateTheDefaultTenant(t *testing.T) {
	t.Parallel()

	environ := []string{"CLAVIS_DATABASE_DSN=" + filepath.Join(t.TempDir(), "clavis.db")}
	for _, args := range [][]string{
		{"users", "list"},
		{"users", "set-password", "ada@example.com"},
		{"users", "delete", "ada@example.com", "--yes"},
	} {
		var stdout, stderr bytes.Buffer
		if code := Execute(t.Context(), args, strings.NewReader("correct horse battery\n"), &stdout, &stderr, environ); code != 1 ||
			!strings.Contains(stderr.String(), `tenant not found: "default"`) {
			t.Errorf("%v: exit code %d, stderr %q", args, code, stderr.String())
		}
	}
}

func TestReadPasswordFromAPipe(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct{ in, want string }{
		{"secret\n", "secret"},
		{"secret\r\n", "secret"},
		{"secret", "secret"},
		{"first\nsecond\n", "first"},
		{" spaced secret \n", " spaced secret "},
	} {
		got, err := readPassword(strings.NewReader(tt.in), io.Discard)
		if err != nil || got != tt.want {
			t.Errorf("readPassword(%q) = %q, %v; want %q", tt.in, got, err, tt.want)
		}
	}
	for _, in := range []string{"", "\n", "\r\n"} {
		if _, err := readPassword(strings.NewReader(in), io.Discard); err == nil {
			t.Errorf("readPassword(%q) succeeded, want an error", in)
		}
	}
	if _, err := readPassword(iotest.ErrReader(errors.New("broken pipe")), io.Discard); err == nil ||
		!strings.Contains(err.Error(), "broken pipe") {
		t.Errorf("readPassword() of a failing reader = %v", err)
	}
}

func TestResourcesCommands(t *testing.T) {
	t.Parallel()

	environ := []string{"CLAVIS_DATABASE_DSN=" + filepath.Join(t.TempDir(), "clavis.db")}
	run := func(args ...string) (stdout, stderr string, code int) {
		var out, errOut bytes.Buffer
		code = Execute(t.Context(), args, nil, &out, &errOut, environ)
		return out.String(), errOut.String(), code
	}
	out, errOut, code := run("resources", "create", "https://api.example.com/orders", "--name", "Orders",
		"--scope", "orders:read", "--scope", "orders:write")
	if code != 0 || !strings.Contains(out, "Created API resource https://api.example.com/orders in tenant default "+
		"with scopes orders:read orders:write") {
		t.Fatalf("resources create = %d, %q, %q", code, out, errOut)
	}
	if _, errOut, code := run("resources", "create", "https://api.example.com/v2", "--scope", "orders:read"); code == 0 ||
		!strings.Contains(errOut, "belongs to https://api.example.com/orders") {
		t.Errorf("creating a resource with a taken scope = %d, %q", code, errOut)
	}
	out, _, code = run("resources", "list")
	if code != 0 || !strings.Contains(out, "IDENTIFIER") || !strings.Contains(out, "Orders") {
		t.Errorf("resources list = %d, %q", code, out)
	}
	// A client can be the server of a registered resource only.
	if _, errOut, code := run("clients", "create", "--client-id", "orders-api", "--grant-type", "client_credentials",
		"--resource-server", "https://api.example.com/orders"); code != 0 {
		t.Fatalf("clients create --resource-server = %d, %q", code, errOut)
	}
	if out, _, code := run("clients", "show", "orders-api"); code != 0 ||
		!strings.Contains(out, "Resource server for:") || !strings.Contains(out, "https://api.example.com/orders") {
		t.Errorf("clients show of a resource server = %d, %q", code, out)
	}
	if _, errOut, code := run("clients", "create", "--client-id", "other-api", "--grant-type", "client_credentials",
		"--resource-server", "https://api.example.com/unknown"); code == 0 ||
		!strings.Contains(errOut, "is not a registered API resource") {
		t.Errorf("clients create for an unknown resource = %d, %q", code, errOut)
	}
	if _, errOut, code := run("resources", "delete", "https://api.example.com/orders"); code == 0 ||
		!strings.Contains(errOut, "--yes") {
		t.Errorf("resources delete without --yes = %d, %q", code, errOut)
	}
	if out, errOut, code := run("resources", "delete", "https://api.example.com/orders", "--yes"); code != 0 ||
		!strings.Contains(out, "Deleted API resource") {
		t.Errorf("resources delete = %d, %q, %q", code, out, errOut)
	}
}

func TestGrantsCommands(t *testing.T) {
	t.Parallel()

	dsn := filepath.Join(t.TempDir(), "clavis.db")
	environ := []string{"CLAVIS_DATABASE_DSN=" + dsn}
	run := func(args ...string) (stdout, stderr string, code int) {
		var out, errOut bytes.Buffer
		code = Execute(t.Context(), args, nil, &out, &errOut, environ)
		return out.String(), errOut.String(), code
	}
	if _, errOut, code := run("clients", "create", "--client-id", "partner", "--redirect-uri",
		"https://partner.example.com/callback"); code != 0 {
		t.Fatalf("clients create = %d, %q", code, errOut)
	}
	if _, errOut, code := run("users", "create", "ada@example.com"); code != 0 {
		t.Fatalf("users create = %d, %q", code, errOut)
	}
	// The consent page creates grants; the test writes one directly.
	st, err := sqlite.Open(t.Context(), dsn)
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	d := app.Deps{Store: st, Logger: slog.New(slog.DiscardHandler), Now: time.Now, NewID: uuid.NewV7}
	tn, err := app.FindTenant(t.Context(), d, app.DefaultTenantSlug)
	if err != nil {
		t.Fatalf("default tenant: %v", err)
	}
	u, err := app.FindUser(t.Context(), d, tn.ID, "ada@example.com")
	if err != nil {
		t.Fatalf("FindUser() unexpected error: %v", err)
	}
	c, err := app.GetClient(t.Context(), d, tn.ID, "partner")
	if err != nil {
		t.Fatalf("GetClient() unexpected error: %v", err)
	}
	now := time.Now()
	if err := st.Grants().Put(t.Context(), store.Grant{ID: uuid.NewV7(), TenantID: tn.ID, UserID: u.ID, ClientID: c.ID,
		Scopes: []string{"openid", "email"}, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatalf("Put() unexpected error: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("closing store: %v", err)
	}

	if _, errOut, code := run("grants", "list"); code == 0 || !strings.Contains(errOut, "--user is required") {
		t.Errorf("grants list without --user = %d, %q", code, errOut)
	}
	out, errOut, code := run("grants", "list", "--user", "ada@example.com")
	if code != 0 || !strings.Contains(out, "CLIENT ID") || !strings.Contains(out, "partner") ||
		!strings.Contains(out, "openid email") {
		t.Errorf("grants list = %d, %q, %q", code, out, errOut)
	}
	if _, errOut, code := run("grants", "revoke", "partner", "--user", "ada@example.com"); code == 0 ||
		!strings.Contains(errOut, "--yes") {
		t.Errorf("grants revoke without --yes = %d, %q", code, errOut)
	}
	if out, errOut, code := run("grants", "revoke", "partner", "--user", "ada@example.com", "--yes"); code != 0 ||
		!strings.Contains(out, "Revoked the grant of ada@example.com for partner") {
		t.Errorf("grants revoke = %d, %q, %q", code, out, errOut)
	}
	if _, errOut, code := run("grants", "revoke", "partner", "--user", "ada@example.com", "--yes"); code == 0 ||
		!strings.Contains(errOut, "grant not found") {
		t.Errorf("revoking a revoked grant = %d, %q", code, errOut)
	}
	if out, _, code := run("grants", "list", "--user", "ada@example.com"); code != 0 || strings.Contains(out, "partner") {
		t.Errorf("grants list after revoke = %d, %q", code, out)
	}
}
