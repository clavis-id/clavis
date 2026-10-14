package clavis

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"clavisid.org/clavis/internal/app"
	"clavisid.org/clavis/internal/issuer"
	"clavisid.org/clavis/internal/keys"
	"clavisid.org/clavis/kek"
	"clavisid.org/clavis/store"
	"clavisid.org/clavis/store/sqlite"
)

func openStore(t *testing.T) *sqlite.Store {
	t.Helper()
	s, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "clavis.db"))
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func testConfig(t *testing.T, st store.Store) Config {
	t.Helper()
	enc, err := kek.NewLocal(kek.GenerateSecret())
	if err != nil {
		t.Fatalf("kek.NewLocal() unexpected error: %v", err)
	}
	return Config{Issuer: "http://localhost:8080", Store: st, KeyEncrypter: enc}
}

func newTestServer(t *testing.T, st store.Store) *Server {
	t.Helper()
	return mustNew(t, testConfig(t, st))
}

// mustNew creates a Server that is closed when the test ends.
func mustNew(t *testing.T, cfg Config) *Server {
	t.Helper()
	s, err := New(t.Context(), cfg)
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func serve(t *testing.T, h http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), method, path, http.NoBody))
	return rec
}

func TestNewRejectsInvalidIssuer(t *testing.T) {
	t.Parallel()

	cfg := testConfig(t, openStore(t))
	cfg.Issuer = "http://auth.example.com"
	_, err := New(t.Context(), cfg)
	if !errors.Is(err, issuer.ErrInvalid) {
		t.Errorf("New() error = %v, want issuer.ErrInvalid", err)
	}
}

func TestNewRequiresStore(t *testing.T) {
	t.Parallel()

	cfg := testConfig(t, nil)
	if _, err := New(t.Context(), cfg); err == nil {
		t.Error("New() succeeded without a store")
	}
}

func TestNewRequiresKeyEncrypter(t *testing.T) {
	t.Parallel()

	cfg := testConfig(t, openStore(t))
	cfg.KeyEncrypter = nil
	if _, err := New(t.Context(), cfg); err == nil {
		t.Error("New() succeeded without a key encrypter")
	}
}

func TestNewRejectsInvalidSigningKeyPolicy(t *testing.T) {
	t.Parallel()

	tests := map[string]SigningKeyPolicy{
		"missing RS256":               {Algorithms: []string{"ES256"}},
		"unsupported algorithm":       {Algorithms: []string{"RS256", "HS256"}},
		"check interval too long":     {CheckInterval: 25 * time.Hour},
		"negative check interval":     {CheckInterval: -time.Minute},
		"publish ahead beyond period": {RotationPeriod: time.Hour, PublishAhead: 2 * time.Hour, CheckInterval: time.Minute},
		"negative retention":          {Retention: -time.Hour},
	}
	for name, policy := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg := testConfig(t, openStore(t))
			cfg.SigningKeys = policy
			if _, err := New(t.Context(), cfg); err == nil {
				t.Errorf("New() accepted a policy with %s", name)
			}
		})
	}
}

func TestNewRejectsCanceledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := New(ctx, testConfig(t, openStore(t)))
	if !errors.Is(err, context.Canceled) {
		t.Errorf("New() error = %v, want context.Canceled", err)
	}
}

func TestNewCreatesDefaultTenant(t *testing.T) {
	t.Parallel()

	st := openStore(t)
	newTestServer(t, st)
	if _, err := st.Tenants().GetBySlug(t.Context(), app.DefaultTenantSlug); err != nil {
		t.Errorf("default tenant was not created: %v", err)
	}
}

func TestIssuer(t *testing.T) {
	t.Parallel()

	if got, want := newTestServer(t, openStore(t)).Issuer(), "http://localhost:8080"; got != want {
		t.Errorf("Issuer() = %q, want %q", got, want)
	}
}

func TestProbes(t *testing.T) {
	t.Parallel()

	h := newTestServer(t, openStore(t)).Handler()

	tests := []struct {
		method string
		path   string
		want   int
	}{
		{method: http.MethodGet, path: "/healthz", want: http.StatusOK},
		{method: http.MethodHead, path: "/healthz", want: http.StatusOK},
		{method: http.MethodPost, path: "/healthz", want: http.StatusMethodNotAllowed},
		{method: http.MethodGet, path: "/readyz", want: http.StatusOK},
		{method: http.MethodGet, path: "/oauth2/jwks", want: http.StatusOK},
		{method: http.MethodPost, path: "/oauth2/jwks", want: http.StatusMethodNotAllowed},
		{method: http.MethodGet, path: "/unknown", want: http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			t.Parallel()
			if rec := serve(t, h, tt.method, tt.path); rec.Code != tt.want {
				t.Errorf("status = %d, want %d", rec.Code, tt.want)
			}
		})
	}
}

func TestProbeHeaders(t *testing.T) {
	t.Parallel()

	h := newTestServer(t, openStore(t)).Handler()
	for _, path := range []string{"/healthz", "/readyz"} {
		rec := serve(t, h, http.MethodGet, path)
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("%s Cache-Control = %q, want no-store", path, got)
		}
		if got := rec.Body.String(); got != "ok\n" {
			t.Errorf("%s body = %q, want %q", path, got, "ok\n")
		}
	}
}

func TestReadyReportsUnavailableStore(t *testing.T) {
	t.Parallel()

	st := openStore(t)
	h := newTestServer(t, st).Handler()
	if err := st.Close(); err != nil {
		t.Fatalf("closing store: %v", err)
	}
	if rec := serve(t, h, http.MethodGet, "/readyz"); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("GET /readyz status = %d, want 503 when the store is closed", rec.Code)
	}
	if rec := serve(t, h, http.MethodGet, "/healthz"); rec.Code != http.StatusOK {
		t.Errorf("GET /healthz status = %d, want 200 regardless of the store", rec.Code)
	}
}

func TestJWKS(t *testing.T) {
	t.Parallel()

	st := openStore(t)
	rec := serve(t, newTestServer(t, st).Handler(), http.MethodGet, "/oauth2/jwks")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/jwk-set+json" {
		t.Errorf("Content-Type = %q, want application/jwk-set+json", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=300" {
		t.Errorf("Cache-Control = %q, want public, max-age=300", got)
	}

	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &set); err != nil {
		t.Fatalf("body is not a JWK set: %v\n%s", err, rec.Body.String())
	}
	if len(set.Keys) != 1 {
		t.Fatalf("JWK set has %d keys, want 1", len(set.Keys))
	}
	key := set.Keys[0]
	if key["kty"] != "RSA" || key["alg"] != "RS256" || key["use"] != "sig" || key["kid"] == "" {
		t.Errorf("unexpected key parameters: %v", key)
	}
	for _, private := range []string{"d", "p", "q", "dp", "dq", "qi"} {
		if _, ok := key[private]; ok {
			t.Errorf("published key contains private parameter %q", private)
		}
	}

	tenant, err := st.Tenants().GetBySlug(t.Context(), app.DefaultTenantSlug)
	if err != nil {
		t.Fatalf("loading default tenant: %v", err)
	}
	stored, err := st.SigningKeys().List(t.Context(), tenant.ID)
	if err != nil {
		t.Fatalf("listing stored keys: %v", err)
	}
	if len(stored) != 1 || stored[0].KeyID != key["kid"] {
		t.Errorf("published kid %v does not match the stored key", key["kid"])
	}
}

func TestJWKSHidesStoreErrors(t *testing.T) {
	t.Parallel()

	st := openStore(t)
	h := newTestServer(t, st).Handler()
	if err := st.Close(); err != nil {
		t.Fatalf("closing store: %v", err)
	}
	rec := serve(t, h, http.MethodGet, "/oauth2/jwks")
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	if got := rec.Body.String(); got != "internal error\n" {
		t.Errorf("body = %q, want a generic message", got)
	}
}

// syncBuffer is a bytes.Buffer that is safe for concurrent writes, for loggers
// shared with the background goroutines of a Server.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestInternalErrorsLogTheRouteNotThePath(t *testing.T) {
	t.Parallel()

	var logs syncBuffer
	st := openStore(t)
	cfg := testConfig(t, st)
	cfg.Logger = slog.New(slog.NewJSONHandler(&logs, nil))
	h := mustNew(t, cfg).Handler()
	if err := st.Close(); err != nil {
		t.Fatalf("closing store: %v", err)
	}
	serve(t, h, http.MethodGet, "/oauth2/jwks")

	found := false
	for line := range strings.Lines(logs.String()) {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("decoding log line %q: %v", line, err)
		}
		if entry["msg"] != "request failed" {
			continue
		}
		found = true
		if got, want := entry["route"], "GET /oauth2/jwks"; got != want {
			t.Errorf("route = %v, want %q", got, want)
		}
		if _, ok := entry["path"]; ok {
			t.Errorf("log entry has a path attribute, which carries client input: %v", entry)
		}
	}
	if !found {
		t.Errorf("no %q entry in the logs:\n%s", "request failed", logs.String())
	}
}

func TestProtocolRoutesAreTraced(t *testing.T) {
	t.Parallel()

	recorder := tracetest.NewSpanRecorder()
	cfg := testConfig(t, openStore(t))
	cfg.TracerProvider = sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	h := mustNew(t, cfg).Handler()

	for _, path := range []string{"/healthz", "/readyz", "/oauth2/jwks"} {
		serve(t, h, http.MethodGet, path)
	}
	spans := recorder.Ended()
	if len(spans) != 1 {
		names := make([]string, 0, len(spans))
		for _, sp := range spans {
			names = append(names, sp.Name())
		}
		t.Fatalf("recorded spans %v, want only the JWKS request", names)
	}
	if got := spans[0].Name(); got != "GET /oauth2/jwks" {
		t.Errorf("span name = %q, want the route pattern", got)
	}
}

func TestCloseStopsBackgroundWork(t *testing.T) {
	t.Parallel()

	s, err := New(context.Background(), testConfig(t, openStore(t)))
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close() unexpected error: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("second Close() unexpected error: %v", err)
	}
	if rec := serve(t, s.Handler(), http.MethodGet, "/oauth2/jwks"); rec.Code != http.StatusOK {
		t.Errorf("GET /oauth2/jwks after Close() status = %d, want 200", rec.Code)
	}
}

func TestNewValidatesBeforeWriting(t *testing.T) {
	t.Parallel()

	st := openStore(t)
	cfg := testConfig(t, st)
	cfg.SigningKeys = SigningKeyPolicy{Algorithms: []string{"ES256"}}
	if _, err := New(t.Context(), cfg); err == nil {
		t.Fatal("New() accepted a policy without RS256")
	}
	if _, err := st.Tenants().GetBySlug(t.Context(), app.DefaultTenantSlug); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("New() with an invalid policy wrote the default tenant (lookup error: %v)", err)
	}
}

// TestJWKSCachingFitsPublishAhead guarantees that a key reaches every cached
// copy of the JWK set before it signs: the HTTP cache lifetime plus the
// Manager's cache lifetime must stay below the shortest publish-ahead.
func TestJWKSCachingFitsPublishAhead(t *testing.T) {
	t.Parallel()

	if jwksMaxAge+keys.JWKSCacheTTL >= keys.MinPublishAhead {
		t.Errorf("JWK set caching (%s + %s) is not shorter than keys.MinPublishAhead (%s)",
			jwksMaxAge, keys.JWKSCacheTTL, keys.MinPublishAhead)
	}
}
