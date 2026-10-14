package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json/v2"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"clavisid.org/clavis/kek"
	"clavisid.org/clavis/store/sqlite"
)

// testKey is a valid encryption key for tests (32 zero bytes, base64).
const testKey = "CLAVIS_KEYS_ENCRYPTION_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func TestVersion(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	code := Execute(t.Context(), []string{"version"}, &stdout, &stderr, nil)
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
	if code := Execute(t.Context(), []string{"launch"}, &stdout, &stderr, nil); code != 1 {
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
	if code := Execute(t.Context(), []string{"serve"}, &stdout, &stderr, environ); code != 1 {
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
	if code := Execute(t.Context(), []string{"serve"}, &stdout, &stderr, environ); code != 1 {
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
		exit <- Execute(ctx, []string{"serve"}, io.Discard, pw, environ)
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
	if code := Execute(t.Context(), []string{"migrate"}, &stdout, &stderr, environ); code != 0 {
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
	if code := Execute(t.Context(), []string{"serve"}, &stdout, &stderr, environ); code != 1 {
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
		if code := Execute(t.Context(), []string{"keys", "new-encryption-key"}, &stdout, &stderr, nil); code != 0 {
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
		exit <- Execute(ctx, []string{"serve"}, io.Discard, pw, environ)
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
		code = Execute(t.Context(), args, &out, &errOut, environ)
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
	if code := Execute(t.Context(), []string{"tenants", "create", "acme"}, &stdout, &stderr, environ); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "encryption_key") {
		t.Errorf("stderr %q does not mention the missing encryption key", stderr.String())
	}
}
