package clavis

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
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
	"clavisid.org/clavis/internal/oidc"
	"clavisid.org/clavis/kek"
	"clavisid.org/clavis/store"
)

// readinessTimeout bounds the database check performed by GET /readyz.
const readinessTimeout = 2 * time.Second

// jwksMaxAge is how long clients may cache the JWK set. It is far shorter
// than the default publish-ahead period, so cached sets always contain a
// successor key before it starts signing.
const jwksMaxAge = 5 * time.Minute

// metadataMaxAge is how long clients may cache the provider metadata.
const metadataMaxAge = 5 * time.Minute

// tenantPathPrefix is the path below the issuer under which every tenant
// other than the default one is served (ADR 0009).
const tenantPathPrefix = "/t/"

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
	// PublishAhead is the minimum time a new key is published before it
	// starts signing, so clients that cache the JWK set learn it in time. At
	// least 15 minutes. Default: 24 hours.
	PublishAhead time.Duration
	// Retention is how long a retired key stays published so tokens it
	// signed can still be verified. Default: 48 hours.
	Retention time.Duration
	// CheckInterval is how often rotation runs. It must not exceed
	// PublishAhead, and successors are created PublishAhead plus
	// CheckInterval before they sign. Default: 1 hour.
	CheckInterval time.Duration
}

// Server is a Clavis instance. Mount the value returned by Handler on any
// router, or serve it directly with net/http.
//
// The default tenant is served at the issuer and every other tenant at
// <issuer>/t/<slug>, each with its own metadata and keys.
//
// A Server is safe for concurrent use.
type Server struct {
	issuer        *url.URL
	store         store.Store
	keys          *keys.Manager
	deps          app.Deps
	defaultTenant store.Tenant
	algorithms    []string
	logger        *slog.Logger
	tracer        trace.TracerProvider
	meter         metric.MeterProvider
	handler       http.Handler
	wellKnown     http.Handler

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
	policy := cfg.SigningKeys.withDefaults()
	if err := policy.Validate(); err != nil {
		return nil, fmt.Errorf("clavis: invalid SigningKeys: %w", err)
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

	// Everything is validated before the first write to the store.
	deps := app.Deps{Store: cfg.Store, Logger: logger, Now: time.Now, NewID: uuid.NewV7}
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
	tenant, err := app.EnsureDefaultTenant(ctx, deps)
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
		deps:          deps,
		defaultTenant: tenant,
		algorithms:    policy.Algorithms,
		logger:        logger,
		tracer:        tracer,
		meter:         meter,
		stop:          stop,
		done:          make(chan struct{}),
	}
	s.wellKnown = s.instrument(oidc.AuthorizationServerMetadataPath, http.HandlerFunc(s.handleWellKnown))
	s.handler = s.routes()
	go func() {
		defer close(s.done)
		manager.Run(bgCtx)
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

// Handler returns the HTTP handler that serves every Clavis endpoint. It
// expects request paths relative to the issuer: mount it where the issuer's
// path points, removing that path, as in the example of New.
func (s *Server) Handler() http.Handler {
	return s.handler
}

// WellKnownHandler serves the RFC 8414 authorization server metadata of
// every tenant. RFC 8414, section 3.1, places it at the root of the issuer's
// host, at /.well-known/oauth-authorization-server followed by the issuer's
// path, so Handler cannot receive it when the issuer has a path. In that
// case, mount WellKnownHandler at the root of the host's router:
//
//	mux.Handle("/.well-known/oauth-authorization-server/", auth.WellKnownHandler())
//
// When the issuer has no path, Handler already serves these URLs.
// OpenID Connect discovery (<issuer>/.well-known/openid-configuration) is
// always served by Handler.
func (s *Server) WellKnownHandler() http.Handler {
	return s.wellKnown
}

// routes builds the request multiplexer. Probes are not instrumented, so
// frequent health checks do not flood traces and metrics.
func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleReady)
	s.handleTenant(mux, http.MethodGet, oidc.DiscoveryPath, s.handleMetadata)
	s.handleTenant(mux, http.MethodGet, oidc.JWKSPath, s.handleJWKS)
	if s.issuer.Path == "" {
		mux.Handle(oidc.AuthorizationServerMetadataPath, s.wellKnown)
		mux.Handle(oidc.AuthorizationServerMetadataPath+"/", s.wellKnown)
	}
	return mux
}

// tenant is the tenant a request addresses, with its issuer identifier.
type tenant struct {
	store.Tenant
	issuer string
}

// tenantHandler serves a request addressed to one tenant.
type tenantHandler func(http.ResponseWriter, *http.Request, tenant)

// handleTenant registers h at path for the default tenant and at
// /t/{tenant}<path> for every other tenant.
func (s *Server) handleTenant(mux *http.ServeMux, method, path string, h tenantHandler) {
	root := method + " " + path
	mux.Handle(root, s.instrument(root, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.serveTenant(w, r, "", h)
	})))
	scoped := method + " " + tenantPathPrefix + "{tenant}" + path
	mux.Handle(scoped, s.instrument(scoped, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.serveTenant(w, r, r.PathValue("tenant"), h)
	})))
}

// serveTenant resolves the tenant with the given slug, or the default tenant
// when slug is empty, and passes the request to h. Unknown tenants get a 404
// response.
func (s *Server) serveTenant(w http.ResponseWriter, r *http.Request, slug string, h tenantHandler) {
	if slug == "" {
		h(w, r, tenant{Tenant: s.defaultTenant, issuer: s.issuer.String()})
		return
	}
	t, err := app.TenantBySlug(r.Context(), s.deps, slug)
	switch {
	case errors.Is(err, app.ErrTenantNotFound):
		s.notFound(w)
		return
	case err != nil:
		s.internalError(w, r, "resolving the tenant", err)
		return
	}
	h(w, r, tenant{Tenant: t, issuer: s.issuer.String() + tenantPathPrefix + t.Slug})
}

// instrument wraps h so that it records a span and HTTP metrics named after
// pattern, which keeps their cardinality bounded.
func (s *Server) instrument(pattern string, h http.Handler) http.Handler {
	return otelhttp.NewHandler(h, pattern,
		otelhttp.WithTracerProvider(s.tracer),
		otelhttp.WithMeterProvider(s.meter),
		otelhttp.WithSpanNameFormatter(func(operation string, _ *http.Request) string { return operation }),
	)
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

// handleJWKS serves the public signing keys of a tenant as a JWK set
// (RFC 7517, section 5).
func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request, t tenant) {
	set, err := s.keys.JWKS(r.Context(), t.ID)
	if err != nil {
		s.internalError(w, r, "loading the JWK set", err)
		return
	}
	s.writePublicJSON(w, r, "application/jwk-set+json", jwksMaxAge, set)
}

// handleMetadata serves the provider metadata of a tenant, for OpenID
// Connect Discovery 1.0, section 4, and RFC 8414, section 3.
func (s *Server) handleMetadata(w http.ResponseWriter, r *http.Request, t tenant) {
	s.writePublicJSON(w, r, "application/json", metadataMaxAge, oidc.NewMetadata(t.issuer, s.algorithms))
}

// handleWellKnown serves RFC 8414 metadata at
// /.well-known/oauth-authorization-server<issuer path>[/t/<slug>]. It parses
// the path itself because the issuer's path is configuration, not a route
// pattern.
func (s *Server) handleWellKnown(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rest, ok := strings.CutPrefix(r.URL.Path, oidc.AuthorizationServerMetadataPath+s.issuer.Path)
	switch {
	case !ok:
		s.notFound(w)
	case rest == "":
		s.serveTenant(w, r, "", s.handleMetadata)
	default:
		slug, ok := strings.CutPrefix(rest, tenantPathPrefix)
		if !ok || slug == "" || strings.Contains(slug, "/") {
			s.notFound(w)
			return
		}
		s.serveTenant(w, r, slug, s.handleMetadata)
	}
}

// writePublicJSON encodes v as the body of a response that any origin may
// read and cache for maxAge. It suits public documents such as metadata and
// key sets, which browser-based clients fetch across origins.
func (s *Server) writePublicJSON(w http.ResponseWriter, r *http.Request, contentType string,
	maxAge time.Duration, v any,
) {
	body, err := json.Marshal(v)
	if err != nil {
		s.internalError(w, r, "encoding the response", err)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(maxAge.Seconds())))
	w.Header().Set("Access-Control-Allow-Origin", "*")
	_, _ = w.Write(body)
}

// notFound answers with a plain 404 response.
func (s *Server) notFound(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte("not found\n"))
}

// internalError logs err and answers with a generic 500 response that
// reveals nothing about the failure. It logs the matched route pattern rather
// than the request path, so clients cannot write their own text into the logs.
func (s *Server) internalError(w http.ResponseWriter, r *http.Request, action string, err error) {
	s.logger.LogAttrs(r.Context(), slog.LevelError, "request failed",
		slog.String("action", action),
		slog.String("route", r.Pattern),
		slog.String("error", err.Error()))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = w.Write([]byte("internal error\n"))
}

// withDefaults returns the rotation policy with keys.DefaultPolicy applied to
// zero fields. Other values pass through and are validated by the caller.
func (p SigningKeyPolicy) withDefaults() keys.Policy {
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
	if p.CheckInterval != 0 {
		policy.CheckInterval = p.CheckInterval
	}
	return policy
}
