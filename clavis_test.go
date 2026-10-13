package clavis

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/clavis-id/clavis/internal/app"
	"github.com/clavis-id/clavis/internal/issuer"
	"github.com/clavis-id/clavis/store"
	"github.com/clavis-id/clavis/store/sqlite"
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

func newTestServer(t *testing.T, st store.Store) *Server {
	t.Helper()
	s, err := New(t.Context(), Config{Issuer: "http://localhost:8080", Store: st})
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}
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

	_, err := New(t.Context(), Config{Issuer: "http://auth.example.com", Store: openStore(t)})
	if !errors.Is(err, issuer.ErrInvalid) {
		t.Errorf("New() error = %v, want issuer.ErrInvalid", err)
	}
}

func TestNewRequiresStore(t *testing.T) {
	t.Parallel()

	if _, err := New(t.Context(), Config{Issuer: "https://auth.example.com"}); err == nil {
		t.Error("New() succeeded without a store")
	}
}

func TestNewRejectsCanceledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := New(ctx, Config{Issuer: "https://auth.example.com", Store: openStore(t)})
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
