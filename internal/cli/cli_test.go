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

	"github.com/clavis-id/clavis/kek"
	"github.com/clavis-id/clavis/store/sqlite"
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
	environ := []string{"CLAVIS_DATABASE_DSN=" + path, "CLAVIS_DATABASE_AUTO_MIGRATE=false", testKey}

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
