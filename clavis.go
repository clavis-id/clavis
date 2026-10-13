package clavis

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/clavis-id/clavis/internal/issuer"
)

// Config configures a Clavis server.
type Config struct {
	// Issuer is the base URL that identifies this Clavis instance, for
	// example "https://auth.example.com" or "https://example.com/auth". It
	// must use https, except for loopback hosts during development, and must
	// not contain a query, a fragment or a trailing slash.
	Issuer string

	// Logger receives structured logs. When nil, logs are discarded.
	Logger *slog.Logger
}

// Server is a Clavis instance. Mount the value returned by Handler on any
// router, or serve it directly with net/http.
//
// A Server is safe for concurrent use.
type Server struct {
	issuer  *url.URL
	logger  *slog.Logger
	handler http.Handler
}

// New validates cfg and returns a ready-to-use Server.
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
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	s := &Server{issuer: iss, logger: logger}
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
	return mux
}

// handleHealth reports that the process is alive. It never touches
// dependencies, so orchestrators can use it as a liveness probe.
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte("ok\n"))
}
