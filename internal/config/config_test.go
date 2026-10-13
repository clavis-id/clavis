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

func TestLoadDefaults(t *testing.T) {
	t.Parallel()

	res, err := Load("", nil)
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}
	if diff := cmp.Diff(Default(), res.Config); diff != "" {
		t.Errorf("Load() mismatch with Default() (-want +got):\n%s", diff)
	}
	if len(res.IgnoredEnv) != 0 {
		t.Errorf("IgnoredEnv = %v, want none", res.IgnoredEnv)
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
			name: "every validation problem is reported",
			file: `
issuer: http://auth.example.com
server:
  address: "8080"
  write_timeout: 0s
database:
  driver: mysql
  dsn: ""
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
		"CLAVIS_ISSUER":                     "issuer",
		"CLAVIS_SERVER_ADDRESS":             "server.address",
		"CLAVIS_SERVER_READ_HEADER_TIMEOUT": "server.read_header_timeout",
		"CLAVIS_SERVER_READ_TIMEOUT":        "server.read_timeout",
		"CLAVIS_SERVER_WRITE_TIMEOUT":       "server.write_timeout",
		"CLAVIS_SERVER_IDLE_TIMEOUT":        "server.idle_timeout",
		"CLAVIS_SERVER_SHUTDOWN_TIMEOUT":    "server.shutdown_timeout",
		"CLAVIS_DATABASE_DRIVER":            "database.driver",
		"CLAVIS_DATABASE_DSN":               "database.dsn",
		"CLAVIS_DATABASE_AUTO_MIGRATE":      "database.auto_migrate",
		"CLAVIS_LOG_LEVEL":                  "log.level",
		"CLAVIS_LOG_FORMAT":                 "log.format",
	}
	if diff := cmp.Diff(want, envKeys(reflect.TypeFor[Config](), "")); diff != "" {
		t.Errorf("envKeys() mismatch (-want +got):\n%s", diff)
	}
}
