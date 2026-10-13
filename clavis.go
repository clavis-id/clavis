package clavis

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"
	"uuid"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"clavisid.org/clavis/internal/app"
	"clavisid.org/clavis/internal/issuer"
	"clavisid.org/clavis/internal/keys"
	"clavisid.org/clavis/kek"
	"clavisid.org/clavis/store"
)

// readinessTimeout bounds the database check performed by GET /readyz.
const readinessTimeout = 2 * time.Second

// jwksMaxAge is how long clients may cache the JWK set. It is far shorter
// than the default publish-ahead period, so cached sets always contain a
// successor key before it starts signing.
const jwksMaxAge = 5 * time.Minute

// defaultKeyCheckInterval is how often signing key rotation runs.
const defaultKeyCheckInterval = time.Hour

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

	// KeyEncrypter encrypts private signing keys before they reach the store.
	// It is required. kek.NewLocal suits most deployments; keep its secret
	// outside the database, for example in a secrets manager.
	KeyEncrypter kek.Encrypter

	// SigningKeys configures signing key algorithms and rotation. Zero fields
	// take their defaults.
	SigningKeys SigningKeyPolicy

	// Logger receives structured logs. When nil, logs are discarded.
	Logger *slog.Logger

	// TracerProvider creates the spans Clavis emits for protocol requests.
	// When nil, the global provider of go.opentelemetry.io/otel is used,
	// which discards spans unless the program installs one.
	TracerProvider trace.TracerProvider

	// MeterProvider creates the metrics Clavis records. When nil, the global
	// provider of go.opentelemetry.io/otel is used.
	MeterProvider metric.MeterProvider
}

// SigningKeyPolicy configures token signing keys. Zero fields take their
// defaults.
type SigningKeyPolicy struct {
	// Algorithms lists the JWS algorithms every tenant can sign with:
	// "RS256", "ES256" and "EdDSA" are supported. It must include RS256,
	// which OpenID Connect requires. Default: RS256 only.
	Algorithms []string
	// RotationPeriod is how long each key signs. Default: 30 days.
	RotationPeriod time.Duration
	// PublishAhead is how long a new key is published before it starts
	// signing, so clients that cache the JWK set learn it in time. Default:
	// 24 hours.
	PublishAhead time.Duration
	// Retention is how long a retired key stays published so tokens it
	// signed can still be verified. Default: 48 hours.
	Retention time.Duration
	// CheckInterval is how often rotation runs. It must be shorter than
	// PublishAhead. Default: 1 hour.
	CheckInterval time.Duration
}

// Server is a Clavis instance. Mount the value returned by Handler on any
// router, or serve it directly with net/http.
//
// A Server is safe for concurrent use.
type Server struct {
	issuer        *url.URL
	store         store.Store
	keys          *keys.Manager
	defaultTenant uuid.UUID
	logger        *slog.Logger
	tracer        trace.TracerProvider
	meter         metric.MeterProvider
	handler       http.Handler

	stop      context.CancelFunc
	done      chan struct{}
	closeOnce sync.Once
}

// New validates cfg, prepares the store (creating the default tenant and its
// signing keys on first use) and returns a ready-to-use Server.
//
// New starts signing key rotation in the background. Call Close to stop it
// when the Server is no longer needed; canceling ctx stops it too.
// Background work never outlives ctx, so ctx must live as long as the Server
// is in use.
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
	if cfg.KeyEncrypter == nil {
		return nil, errors.New("clavis: Config.KeyEncrypter is required")
	}
	policy, interval := cfg.SigningKeys.withDefaults()
	if interval <= 0 || interval >= policy.PublishAhead {
		return nil, fmt.Errorf("clavis: SigningKeys.CheckInterval (%s) must be positive and shorter than PublishAhead (%s)",
			interval, policy.PublishAhead)
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	tracer := cfg.TracerProvider
	if tracer == nil {
		tracer = otel.GetTracerProvider()
	}
	meter := cfg.MeterProvider
	if meter == nil {
		meter = otel.GetMeterProvider()
	}

	deps := app.Deps{Store: cfg.Store, Logger: logger, Now: time.Now, NewID: uuid.NewV7}
	tenant, err := app.EnsureDefaultTenant(ctx, deps)
	if err != nil {
		return nil, fmt.Errorf("clavis: %w", err)
	}

	manager, err := keys.NewManager(keys.Config{
		Store:         cfg.Store,
		Encrypter:     cfg.KeyEncrypter,
		Policy:        policy,
		Logger:        logger,
		Now:           deps.Now,
		NewID:         deps.NewID,
		MeterProvider: meter,
	})
	if err != nil {
		return nil, fmt.Errorf("clavis: %w", err)
	}
	if err := manager.RotateAll(ctx); err != nil {
		return nil, fmt.Errorf("clavis: preparing signing keys: %w", err)
	}
	bgCtx, stop := context.WithCancel(ctx) //nolint:gosec // stop is kept in the Server and called by Close.
	s := &Server{
		issuer:        iss,
		store:         cfg.Store,
		keys:          manager,
		defaultTenant: tenant.ID,
		logger:        logger,
		tracer:        tracer,
		meter:         meter,
		stop:          stop,
		done:          make(chan struct{}),
	}
	s.handler = s.routes()
	go func() {
		defer close(s.done)
		manager.Run(bgCtx, interval)
	}()
	return s, nil
}

// Close stops the background work started by New and waits for it to
// finish. It does not close the store, which the caller owns. Close is safe
// to call more than once; requests served after Close keep working, but keys
// are no longer rotated.
func (s *Server) Close() error {
	s.closeOnce.Do(s.stop)
	<-s.done
	return nil
}

// Issuer returns the validated issuer URL as a string.
func (s *Server) Issuer() string {
	return s.issuer.String()
}

// Handler returns the HTTP handler that serves every Clavis endpoint.
func (s *Server) Handler() http.Handler {
	return s.handler
}

// routes builds the request multiplexer. Probes are not instrumented, so
// frequent health checks do not flood traces and metrics.
func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleReady)
	s.handle(mux, "GET /oauth2/jwks", s.handleJWKS)
	return mux
}

// handle registers an instrumented route. Spans are named after the route
// pattern, which keeps their cardinality bounded.
func (s *Server) handle(mux *http.ServeMux, pattern string, h http.HandlerFunc) {
	mux.Handle(pattern, otelhttp.NewHandler(h, pattern,
		otelhttp.WithTracerProvider(s.tracer),
		otelhttp.WithMeterProvider(s.meter),
		otelhttp.WithSpanNameFormatter(func(operation string, _ *http.Request) string { return operation }),
	))
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

// handleJWKS serves the public signing keys of the default tenant as a JWK
// set (RFC 7517, section 5).
func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	set, err := s.keys.JWKS(r.Context(), s.defaultTenant)
	if err != nil {
		s.internalError(w, r, "loading the JWK set", err)
		return
	}
	body, err := json.Marshal(set)
	if err != nil {
		s.internalError(w, r, "encoding the JWK set", err)
		return
	}
	w.Header().Set("Content-Type", "application/jwk-set+json")
	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(jwksMaxAge.Seconds())))
	_, _ = w.Write(body)
}

// internalError logs err and answers with a generic 500 response that
// reveals nothing about the failure.
func (s *Server) internalError(w http.ResponseWriter, r *http.Request, action string, err error) {
	s.logger.LogAttrs(r.Context(), slog.LevelError, "request failed",
		slog.String("action", action),
		slog.String("path", r.URL.Path),
		slog.String("error", err.Error()))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = w.Write([]byte("internal error\n"))
}

// withDefaults returns the rotation policy and check interval with defaults
// applied to zero fields. Other values pass through and are validated later.
func (p SigningKeyPolicy) withDefaults() (keys.Policy, time.Duration) {
	policy := keys.DefaultPolicy()
	if len(p.Algorithms) > 0 {
		policy.Algorithms = p.Algorithms
	}
	if p.RotationPeriod != 0 {
		policy.RotationPeriod = p.RotationPeriod
	}
	if p.PublishAhead != 0 {
		policy.PublishAhead = p.PublishAhead
	}
	if p.Retention != 0 {
		policy.Retention = p.Retention
	}
	interval := defaultKeyCheckInterval
	if p.CheckInterval != 0 {
		interval = p.CheckInterval
	}
	return policy, interval
}
