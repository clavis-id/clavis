package config

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func writeFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "clavis.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing config file: %v", err)
	}
	return path
}

// testKey is a valid encryption key for tests (32 zero bytes, base64).
const testKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func TestLoadDefaults(t *testing.T) {
	t.Parallel()

	res, err := Load("", []string{"CLAVIS_KEYS_ENCRYPTION_KEY=" + testKey})
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}
	want := Default()
	want.Keys.EncryptionKey = testKey
	if diff := cmp.Diff(want, res.Config); diff != "" {
		t.Errorf("Load() mismatch with Default() (-want +got):\n%s", diff)
	}
	if len(res.IgnoredEnv) != 0 {
		t.Errorf("IgnoredEnv = %v, want none", res.IgnoredEnv)
	}
}

func TestLoadRequiresEncryptionKey(t *testing.T) {
	t.Parallel()

	_, err := Load("", nil)
	if err == nil || !strings.Contains(err.Error(), "keys.encryption_key: required") {
		t.Errorf("Load() error = %v, want a missing encryption key error", err)
	}
}

func TestLoadNeverEchoesSecrets(t *testing.T) {
	t.Parallel()

	const bad = "c2VjcmV0LXRoYXQtaXMtdG9vLXNob3J0"
	_, err := Load("", []string{
		"CLAVIS_KEYS_ENCRYPTION_KEY=" + bad,
		"CLAVIS_KEYS_PREVIOUS_ENCRYPTION_KEYS=" + testKey + "," + bad,
	})
	if err == nil {
		t.Fatal("Load() accepted invalid encryption keys")
	}
	if strings.Contains(err.Error(), bad) {
		t.Errorf("Load() error %q contains the secret value", err)
	}
	if !strings.Contains(err.Error(), "previous_encryption_keys[1]") {
		t.Errorf("Load() error %q does not point at the invalid previous key", err)
	}
}

func TestLoadListsFromFileAndEnvironment(t *testing.T) {
	t.Parallel()

	path := writeFile(t, "keys:\n  algorithms: [RS256, ES256]\n")
	res, err := Load(path, []string{"CLAVIS_KEYS_ENCRYPTION_KEY=" + testKey})
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}
	if diff := cmp.Diff([]string{"RS256", "ES256"}, res.Config.Keys.Algorithms); diff != "" {
		t.Errorf("algorithms from file mismatch (-want +got):\n%s", diff)
	}

	res, err = Load(path, []string{
		"CLAVIS_KEYS_ENCRYPTION_KEY=" + testKey,
		"CLAVIS_KEYS_ALGORITHMS=RS256,EdDSA",
		"CLAVIS_KEYS_PREVIOUS_ENCRYPTION_KEYS=" + testKey + "," + testKey,
	})
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}
	if diff := cmp.Diff([]string{"RS256", "EdDSA"}, res.Config.Keys.Algorithms); diff != "" {
		t.Errorf("algorithms from environment mismatch (-want +got):\n%s", diff)
	}
	if got := len(res.Config.Keys.PreviousEncryptionKeys); got != 2 {
		t.Errorf("previous encryption keys = %d, want 2", got)
	}
}

func TestLoadFileAndEnvironment(t *testing.T) {
	t.Parallel()

	path := writeFile(t, `
issuer: https://auth.example.com
server:
  address: 127.0.0.1:9000
  read_header_timeout: 5s
log:
  level: debug
`)
	environ := []string{
		"HOME=/home/clavis",
		"CLAVIS_SERVER_ADDRESS=0.0.0.0:8443",
		"CLAVIS_SERVER_SHUTDOWN_TIMEOUT=1m",
		"CLAVIS_LOG_FORMAT=text",
		"CLAVIS_DATABASE_DRIVER=postgres",
		"CLAVIS_DATABASE_DSN=postgres://clavis@db.internal/clavis",
		"CLAVIS_DATABASE_AUTO_MIGRATE=false",
		"CLAVIS_KEYS_ENCRYPTION_KEY=" + testKey,
		"CLAVIS_CONFIG=/ignored/because/it/is/the/file/path",
		"CLAVIS_SERVICE_HOST=10.0.0.12",
		"CLAVIS_PORT=tcp://10.0.0.12:8080",
	}

	res, err := Load(path, environ)
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}

	want := Default()
	want.Issuer = "https://auth.example.com"
	want.Server.Address = "0.0.0.0:8443"
	want.Server.ReadHeaderTimeout = 5 * time.Second
	want.Server.ShutdownTimeout = time.Minute
	want.Log.Level = "debug"
	want.Log.Format = "text"
	want.Database = Database{Driver: "postgres", DSN: "postgres://clavis@db.internal/clavis", AutoMigrate: false}
	want.Keys.EncryptionKey = testKey
	if diff := cmp.Diff(want, res.Config); diff != "" {
		t.Errorf("Load() config mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]string{"CLAVIS_PORT", "CLAVIS_SERVICE_HOST"}, res.IgnoredEnv); diff != "" {
		t.Errorf("IgnoredEnv mismatch (-want +got):\n%s", diff)
	}
}

func TestLoadErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		file    string
		environ []string
		want    []string
	}{
		{
			name: "unknown key in file",
			file: "server:\n  port: 8080\n",
			want: []string{"port"},
		},
		{
			name: "malformed YAML",
			file: "server: [unclosed\n",
			want: []string{"parsing config file"},
		},
		{
			name:    "invalid duration from environment",
			environ: []string{"CLAVIS_SERVER_READ_TIMEOUT=soon"},
			want:    []string{"read_timeout"},
		},
		{
			name: "duration without a unit in the file",
			file: "keys:\n  check_interval: 3600\n",
			want: []string{"check_interval", "needs a unit"},
		},
		{
			name:    "duration without a unit in the environment",
			environ: []string{"CLAVIS_SERVER_READ_HEADER_TIMEOUT=10"},
			want:    []string{"read_header_timeout", "missing unit"},
		},
		{
			name: "every validation problem is reported",
			file: `
issuer: http://auth.example.com
server:
  address: "8080"
  write_timeout: 0s
database:
  driver: mysql
  dsn: ""
keys:
  algorithms: [ES256]
  check_interval: 48h
telemetry:
  tracing:
    endpoint: "collector:4318"
    sample_ratio: 1.5
  metrics:
    enabled: true
    address: "9464"
log:
  level: verbose
  format: xml
`,
			want: []string{
				"issuer:",
				"server.address:",
				"server.write_timeout: must be positive",
				"database.driver:",
				"database.dsn:",
				"keys.encryption_key: required",
				"algorithms must include RS256",
				"check_interval (48h0m0s) must be positive and no longer than publish_ahead",
				"telemetry.tracing.sample_ratio:",
				"telemetry.tracing.endpoint:",
				"telemetry.metrics.address:",
				"log.level:",
				"log.format:",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := ""
			if tt.file != "" {
				path = writeFile(t, tt.file)
			}
			_, err := Load(path, tt.environ)
			if err == nil {
				t.Fatal("Load() succeeded, want an error")
			}
			for _, s := range tt.want {
				if !strings.Contains(err.Error(), s) {
					t.Errorf("Load() error %q does not mention %q", err, s)
				}
			}
		})
	}
}

func TestLoadMissingFile(t *testing.T) {
	t.Parallel()

	_, err := Load(filepath.Join(t.TempDir(), "missing.yaml"), nil)
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Load() error = %v, want os.ErrNotExist", err)
	}
}

func TestEnvKeysCoverEveryField(t *testing.T) {
	t.Parallel()

	want := map[string]string{
		"CLAVIS_ISSUER":                         "issuer",
		"CLAVIS_SERVER_ADDRESS":                 "server.address",
		"CLAVIS_SERVER_READ_HEADER_TIMEOUT":     "server.read_header_timeout",
		"CLAVIS_SERVER_READ_TIMEOUT":            "server.read_timeout",
		"CLAVIS_SERVER_WRITE_TIMEOUT":           "server.write_timeout",
		"CLAVIS_SERVER_IDLE_TIMEOUT":            "server.idle_timeout",
		"CLAVIS_SERVER_SHUTDOWN_TIMEOUT":        "server.shutdown_timeout",
		"CLAVIS_DATABASE_DRIVER":                "database.driver",
		"CLAVIS_DATABASE_DSN":                   "database.dsn",
		"CLAVIS_DATABASE_AUTO_MIGRATE":          "database.auto_migrate",
		"CLAVIS_KEYS_ENCRYPTION_KEY":            "keys.encryption_key",
		"CLAVIS_KEYS_PREVIOUS_ENCRYPTION_KEYS":  "keys.previous_encryption_keys",
		"CLAVIS_KEYS_ALGORITHMS":                "keys.algorithms",
		"CLAVIS_KEYS_ROTATION_PERIOD":           "keys.rotation_period",
		"CLAVIS_KEYS_PUBLISH_AHEAD":             "keys.publish_ahead",
		"CLAVIS_KEYS_RETENTION":                 "keys.retention",
		"CLAVIS_KEYS_CHECK_INTERVAL":            "keys.check_interval",
		"CLAVIS_TELEMETRY_TRACING_ENABLED":      "telemetry.tracing.enabled",
		"CLAVIS_TELEMETRY_TRACING_ENDPOINT":     "telemetry.tracing.endpoint",
		"CLAVIS_TELEMETRY_TRACING_SAMPLE_RATIO": "telemetry.tracing.sample_ratio",
		"CLAVIS_TELEMETRY_METRICS_ENABLED":      "telemetry.metrics.enabled",
		"CLAVIS_TELEMETRY_METRICS_ADDRESS":      "telemetry.metrics.address",
		"CLAVIS_LOG_LEVEL":                      "log.level",
		"CLAVIS_LOG_FORMAT":                     "log.format",
	}
	if diff := cmp.Diff(want, envKeys(reflect.TypeFor[Config](), "")); diff != "" {
		t.Errorf("envKeys() mismatch (-want +got):\n%s", diff)
	}
}

// FuzzParse feeds arbitrary YAML to the configuration parser, which must
// return an error rather than panic on any input.
func FuzzParse(f *testing.F) {
	for _, seed := range []string{
		"",
		"issuer: https://auth.example.com\n",
		"server:\n  address: :8080\n  read_timeout: 5s\n",
		"keys:\n  algorithms: [RS256, ES256]\n  rotation_period: 720h\n",
		"telemetry:\n  tracing:\n    sample_ratio: 0.5\n",
		"server: [1, 2]\n",
		"log: {level: {nested: true}}\n",
	} {
		f.Add([]byte(seed))
	}
	environ := []string{"CLAVIS_KEYS_ENCRYPTION_KEY=" + testKey}
	f.Fuzz(func(t *testing.T, data []byte) {
		res, err := parse(data, environ)
		if err == nil {
			if verr := res.Config.Validate(); verr != nil {
				t.Fatalf("parse() returned a configuration that fails validation: %v", verr)
			}
		}
	})
}

func TestLoadDatabaseNeedsOnlyDatabaseSettings(t *testing.T) {
	t.Parallel()

	res, err := LoadDatabase("", []string{"CLAVIS_DATABASE_DSN=/var/lib/clavis/clavis.db"})
	if err != nil {
		t.Fatalf("LoadDatabase() unexpected error: %v", err)
	}
	if res.Config.Database.DSN != "/var/lib/clavis/clavis.db" {
		t.Errorf("DSN = %q, want the value from the environment", res.Config.Database.DSN)
	}
	if _, err := LoadDatabase("", []string{"CLAVIS_DATABASE_DRIVER=mysql"}); err == nil {
		t.Error("LoadDatabase() accepted an invalid driver")
	}
}
