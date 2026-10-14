package clavis

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"clavisid.org/clavis/internal/app"
	"clavisid.org/clavis/store"
)

var update = flag.Bool("update", false, "rewrite golden files in testdata")

// createTenant creates a tenant and its signing keys through the use case
// the CLI calls.
func createTenant(t *testing.T, s *Server, slug string) store.Tenant {
	t.Helper()
	tenant, err := app.CreateTenant(t.Context(), s.deps, s.keys.Rotate, slug, "")
	if err != nil {
		t.Fatalf("creating tenant %q: %v", slug, err)
	}
	return tenant
}

// checkGolden compares body, indented, with testdata/name, or rewrites the
// file when the test runs with -update.
func checkGolden(t *testing.T, name string, body []byte) {
	t.Helper()
	v := jsontext.Value(append([]byte(nil), body...))
	if err := v.Indent(jsontext.WithIndent("  ")); err != nil {
		t.Fatalf("indenting %s: %v\n%s", name, err, body)
	}
	got := append([]byte(v), '\n')
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatalf("writing golden file: %v", err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading golden file (run go test -update to create it): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s does not match the golden file (run go test -update after checking the change)\ngot:\n%s\nwant:\n%s",
			name, got, want)
	}
}

func TestProviderMetadata(t *testing.T) {
	t.Parallel()

	s := newTestServer(t, openStore(t))
	createTenant(t, s, "acme")
	h := s.Handler()
	tests := []struct {
		path, golden string
	}{
		// OpenID Connect Discovery 1.0, section 4: appended to the issuer.
		{path: "/.well-known/openid-configuration", golden: "metadata-default.json"},
		{path: "/t/acme/.well-known/openid-configuration", golden: "metadata-acme.json"},
		// RFC 8414, section 3.1: inserted before the issuer path.
		{path: "/.well-known/oauth-authorization-server", golden: "metadata-default.json"},
		{path: "/.well-known/oauth-authorization-server/t/acme", golden: "metadata-acme.json"},
	}
	for _, tt := range tests {
		rec := serve(t, h, http.MethodGet, tt.path)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s status = %d, want 200", tt.path, rec.Code)
			continue
		}
		if got := rec.Header().Get("Content-Type"); got != "application/json" {
			t.Errorf("GET %s Content-Type = %q, want application/json", tt.path, got)
		}
		if got := rec.Header().Get("Cache-Control"); got != "public, max-age=300" {
			t.Errorf("GET %s Cache-Control = %q", tt.path, got)
		}
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
			t.Errorf("GET %s Access-Control-Allow-Origin = %q, want *", tt.path, got)
		}
		checkGolden(t, tt.golden, rec.Body.Bytes())
	}
}

func TestMetadataListsConfiguredAlgorithms(t *testing.T) {
	t.Parallel()

	cfg := testConfig(t, openStore(t))
	cfg.SigningKeys.Algorithms = []string{"RS256", "EdDSA"}
	rec := serve(t, mustNew(t, cfg).Handler(), http.MethodGet, "/.well-known/openid-configuration")
	var doc struct {
		Algs []string `json:"id_token_signing_alg_values_supported"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decoding metadata: %v", err)
	}
	if len(doc.Algs) != 2 || doc.Algs[0] != "RS256" || doc.Algs[1] != "EdDSA" {
		t.Errorf("id_token_signing_alg_values_supported = %v, want [RS256 EdDSA]", doc.Algs)
	}
}

func TestTenantsHaveSeparateKeys(t *testing.T) {
	t.Parallel()

	s := newTestServer(t, openStore(t))
	createTenant(t, s, "acme")
	createTenant(t, s, "beta")
	h := s.Handler()

	seen := map[string]string{}
	for _, path := range []string{"/oauth2/jwks", "/t/acme/oauth2/jwks", "/t/beta/oauth2/jwks"} {
		rec := serve(t, h, http.MethodGet, path)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s status = %d, want 200", path, rec.Code)
		}
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
			t.Errorf("GET %s Access-Control-Allow-Origin = %q, want *", path, got)
		}
		var set struct {
			Keys []struct {
				KeyID string `json:"kid"`
			} `json:"keys"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &set); err != nil {
			t.Fatalf("decoding %s: %v", path, err)
		}
		if len(set.Keys) != 1 {
			t.Fatalf("GET %s returned %d keys, want 1", path, len(set.Keys))
		}
		if other, ok := seen[set.Keys[0].KeyID]; ok {
			t.Errorf("%s and %s publish the same key", other, path)
		}
		seen[set.Keys[0].KeyID] = path
	}
}

func TestUnknownTenantsAreNotFound(t *testing.T) {
	t.Parallel()

	s := newTestServer(t, openStore(t))
	h := s.Handler()
	for _, path := range []string{
		"/t/missing/oauth2/jwks",
		"/t/missing/.well-known/openid-configuration",
		"/.well-known/oauth-authorization-server/t/missing",
		// The default tenant has exactly one issuer: the root.
		"/t/default/oauth2/jwks",
		"/.well-known/oauth-authorization-server/t/default",
		"/t/Not-A-Slug/oauth2/jwks",
		"/.well-known/oauth-authorization-server/t/",
		"/.well-known/oauth-authorization-server/t/acme/extra",
		"/.well-known/oauth-authorization-server/other",
	} {
		rec := serve(t, h, http.MethodGet, path)
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s status = %d, want 404", path, rec.Code)
		}
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("GET %s Cache-Control = %q, want no-store so the tenant can appear later", path, got)
		}
	}
}

func TestTenantLookupFailureIsInternalError(t *testing.T) {
	t.Parallel()

	var logs syncBuffer
	st := openStore(t)
	cfg := testConfig(t, st)
	cfg.Logger = slog.New(slog.NewJSONHandler(&logs, nil))
	s := mustNew(t, cfg)
	createTenant(t, s, "acme")
	if err := st.Close(); err != nil {
		t.Fatalf("closing store: %v", err)
	}

	rec := serve(t, s.Handler(), http.MethodGet, "/t/acme/oauth2/jwks")
	if rec.Code != http.StatusInternalServerError || rec.Body.String() != "internal error\n" {
		t.Errorf("status = %d, body = %q; want 500 with a generic message", rec.Code, rec.Body.String())
	}
	if !strings.Contains(logs.String(), `"route":"GET /t/{tenant}/oauth2/jwks"`) {
		t.Errorf("logs lack the route pattern:\n%s", logs.String())
	}
	if strings.Contains(logs.String(), "/t/acme") {
		t.Errorf("logs contain the request path:\n%s", logs.String())
	}
}

func TestNewCopiesSigningAlgorithms(t *testing.T) {
	t.Parallel()

	cfg := testConfig(t, openStore(t))
	cfg.SigningKeys.Algorithms = []string{"RS256", "ES256"}
	h := mustNew(t, cfg).Handler()
	cfg.SigningKeys.Algorithms[1] = "EdDSA"

	rec := serve(t, h, http.MethodGet, "/.well-known/openid-configuration")
	var doc struct {
		Algs []string `json:"id_token_signing_alg_values_supported"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decoding metadata: %v", err)
	}
	if !slices.Equal(doc.Algs, []string{"RS256", "ES256"}) {
		t.Errorf("algorithms = %v, want the values passed to New", doc.Algs)
	}
}

func TestDeletedTenantIsNotFound(t *testing.T) {
	t.Parallel()

	s := newTestServer(t, openStore(t))
	createTenant(t, s, "acme")
	if err := app.DeleteTenant(t.Context(), s.deps, "acme"); err != nil {
		t.Fatalf("deleting tenant: %v", err)
	}
	if rec := serve(t, s.Handler(), http.MethodGet, "/t/acme/.well-known/openid-configuration"); rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

// TestWellKnownHandlerWithIssuerPath mounts Clavis below /auth, where RFC
// 8414 metadata lives outside the mount point.
func TestWellKnownHandlerWithIssuerPath(t *testing.T) {
	t.Parallel()

	cfg := testConfig(t, openStore(t))
	cfg.Issuer = "http://localhost:8080/auth"
	s := mustNew(t, cfg)
	createTenant(t, s, "acme")

	mux := http.NewServeMux()
	mux.Handle("/auth/", http.StripPrefix("/auth", s.Handler()))
	mux.Handle("/.well-known/oauth-authorization-server/", s.WellKnownHandler())

	issuers := map[string]string{
		"/auth/.well-known/openid-configuration":              "http://localhost:8080/auth",
		"/auth/t/acme/.well-known/openid-configuration":       "http://localhost:8080/auth/t/acme",
		"/.well-known/oauth-authorization-server/auth":        "http://localhost:8080/auth",
		"/.well-known/oauth-authorization-server/auth/t/acme": "http://localhost:8080/auth/t/acme",
	}
	for path, want := range issuers {
		rec := serve(t, mux, http.MethodGet, path)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s status = %d, want 200", path, rec.Code)
			continue
		}
		var doc struct {
			Issuer string `json:"issuer"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
			t.Fatalf("decoding %s: %v", path, err)
		}
		if doc.Issuer != want {
			t.Errorf("GET %s issuer = %q, want %q", path, doc.Issuer, want)
		}
	}
	// The path-less form belongs to an issuer without a path, not this one.
	if rec := serve(t, mux, http.MethodGet, "/.well-known/oauth-authorization-server/"); rec.Code != http.StatusNotFound {
		t.Errorf("metadata for another issuer: status = %d, want 404", rec.Code)
	}
	// Handler does not serve RFC 8414 metadata below the mount point.
	if rec := serve(t, mux, http.MethodGet, "/auth/.well-known/oauth-authorization-server"); rec.Code != http.StatusNotFound {
		t.Errorf("RFC 8414 metadata below the issuer path: status = %d, want 404", rec.Code)
	}
}

func TestWellKnownHandlerRejectsOtherMethods(t *testing.T) {
	t.Parallel()

	h := newTestServer(t, openStore(t)).WellKnownHandler()
	rec := serve(t, h, http.MethodPost, "/.well-known/oauth-authorization-server")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rec.Code)
	}
	if got := rec.Header().Get("Allow"); got != "GET, HEAD" {
		t.Errorf("Allow = %q, want GET, HEAD", got)
	}
}
