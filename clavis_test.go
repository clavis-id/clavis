package clavis

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/clavis-id/clavis/internal/issuer"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	s, err := New(t.Context(), Config{Issuer: "http://localhost:8080"})
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}
	return s
}

func TestNewRejectsInvalidIssuer(t *testing.T) {
	t.Parallel()

	_, err := New(t.Context(), Config{Issuer: "http://auth.example.com"})
	if !errors.Is(err, issuer.ErrInvalid) {
		t.Errorf("New() error = %v, want issuer.ErrInvalid", err)
	}
}

func TestNewRejectsCancelledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := New(ctx, Config{Issuer: "https://auth.example.com"})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("New() error = %v, want context.Canceled", err)
	}
}

func TestIssuer(t *testing.T) {
	t.Parallel()

	if got, want := newTestServer(t).Issuer(), "http://localhost:8080"; got != want {
		t.Errorf("Issuer() = %q, want %q", got, want)
	}
}

func TestHealth(t *testing.T) {
	t.Parallel()

	h := newTestServer(t).Handler()

	tests := []struct {
		method string
		path   string
		want   int
	}{
		{method: http.MethodGet, path: "/healthz", want: http.StatusOK},
		{method: http.MethodHead, path: "/healthz", want: http.StatusOK},
		{method: http.MethodPost, path: "/healthz", want: http.StatusMethodNotAllowed},
		{method: http.MethodGet, path: "/unknown", want: http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), tt.method, tt.path, nil))
			if rec.Code != tt.want {
				t.Errorf("status = %d, want %d", rec.Code, tt.want)
			}
		})
	}
}

func TestHealthHeaders(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	newTestServer(t).Handler().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", nil))
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if got := rec.Body.String(); got != "ok\n" {
		t.Errorf("body = %q, want %q", got, "ok\n")
	}
}
