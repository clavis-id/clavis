package clavis

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"
	"uuid"

	"github.com/clavis-id/clavis/internal/app"
	"github.com/clavis-id/clavis/internal/issuer"
	"github.com/clavis-id/clavis/store"
)

// readinessTimeout bounds the database check performed by GET /readyz.
const readinessTimeout = 2 * time.Second

// Config configures a Clavis server.
type Config struct {
	// Issuer is the base URL that identifies this Clavis instance, for
	// example "https://auth.example.com" or "https://example.com/auth". It
	// must use https, except for loopback hosts during development, and must
	// not contain a query, a fragment or a trailing slash.
	Issuer string

	// Store persists every Clavis record. It is required; use store/sqlite
	// for a single instance or store/postgres for several.
	Store store.Store

	// Logger receives structured logs. When nil, logs are discarded.
	Logger *slog.Logger
}

// Server is a Clavis instance. Mount the value returned by Handler on any
// router, or serve it directly with net/http.
//
// A Server is safe for concurrent use.
type Server struct {
	issuer  *url.URL
	store   store.Store
	logger  *slog.Logger
	handler http.Handler
}

// New validates cfg, prepares the store (creating the default tenant on
// first use) and returns a ready-to-use Server.
//
// Background work started by the Server stops when ctx is canceled, so ctx
// should live as long as the Server is in use.
func New(ctx context.Context, cfg Config) (*Server, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("clavis: %w", err)
	}
	iss, err := issuer.Parse(cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("clavis: %w", err)
	}
	if cfg.Store == nil {
		return nil, errors.New("clavis: Config.Store is required")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	deps := app.Deps{Store: cfg.Store, Logger: logger, Now: time.Now, NewID: uuid.NewV7}
	if _, err := app.EnsureDefaultTenant(ctx, deps); err != nil {
		return nil, fmt.Errorf("clavis: %w", err)
	}

	s := &Server{issuer: iss, store: cfg.Store, logger: logger}
	s.handler = s.routes()
	return s, nil
}

// Issuer returns the validated issuer URL as a string.
func (s *Server) Issuer() string {
	return s.issuer.String()
}

// Handler returns the HTTP handler that serves every Clavis endpoint.
func (s *Server) Handler() http.Handler {
	return s.handler
}

// routes builds the request multiplexer.
func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleReady)
	return mux
}

// handleHealth reports that the process is alive. It never touches
// dependencies, so orchestrators can use it as a liveness probe.
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte("ok\n"))
}

// handleReady reports whether Clavis can serve requests, which requires a
// reachable store. Orchestrators use it as a readiness probe.
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")

	ctx, cancel := context.WithTimeout(r.Context(), readinessTimeout)
	defer cancel()
	if err := s.store.Ping(ctx); err != nil {
		s.logger.LogAttrs(ctx, slog.LevelWarn, "readiness check failed", slog.String("error", err.Error()))
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("unavailable\n"))
		return
	}
	_, _ = w.Write([]byte("ok\n"))
}
