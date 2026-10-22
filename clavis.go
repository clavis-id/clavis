package clavis

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
	"uuid"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"clavisid.org/clavis/email"
	"clavisid.org/clavis/internal/app"
	"clavisid.org/clavis/internal/authn/password"
	"clavisid.org/clavis/internal/i18n"
	"clavisid.org/clavis/internal/issuer"
	"clavisid.org/clavis/internal/keys"
	"clavisid.org/clavis/internal/mailer"
	"clavisid.org/clavis/internal/oidc"
	"clavisid.org/clavis/internal/ui"
	"clavisid.org/clavis/kek"
	"clavisid.org/clavis/store"
)

// readinessTimeout bounds the database check performed by GET /readyz.
const readinessTimeout = 2 * time.Second

// jwksMaxAge is how long clients may cache the JWK set. It is far shorter
// than the default publish-ahead period, so cached sets always contain a
// successor key before it starts signing.
const jwksMaxAge = 5 * time.Minute

// cleanupInterval is how often expired authorization requests, sessions and
// codes are deleted. It matches the lifetime of an authorization request.
const cleanupInterval = 10 * time.Minute

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

	// Passwords configures password hashing. Zero fields take their
	// defaults.
	Passwords PasswordPolicy

	// Email delivers the messages Clavis sends to users, such as
	// verification codes (ADR 0024). Clavis queues each message and sends it
	// in the background, so responses do not wait for delivery. When nil,
	// the features that need email are unavailable. email.NewSMTP sends
	// through an SMTP server; email.NewConsole writes messages to the log
	// and is for development only.
	Email email.Sender
}

// PasswordPolicy configures password hashing (ADR 0015). Zero fields take
// their defaults, which follow the OWASP Password Storage Cheat Sheet.
type PasswordPolicy struct {
	// MinLength is the shortest password users may choose, in characters,
	// from 8 to 256. Default: 8.
	MinLength int
	// Argon2idMemoryKiB, Argon2idIterations and Argon2idParallelism set the
	// cost of new argon2id hashes. Defaults: 19456 KiB, 2 and 1, the
	// minimum.
	Argon2idMemoryKiB   uint32
	Argon2idIterations  uint32
	Argon2idParallelism uint8
	// PBKDF2Iterations sets the cost of new PBKDF2-HMAC-SHA-256 hashes, which
	// replace argon2id in FIPS 140-3 mode. Default: 600,000, the minimum.
	PBKDF2Iterations int
	// MaxConcurrentHashes bounds how many hashes are computed at once, and
	// so the memory they use. Default: the number of CPUs available.
	MaxConcurrentHashes int
	// RefuseArgon2idInFIPSMode stops FIPS 140-3 mode from verifying argon2id
	// hashes created before it was enabled; those users must reset their
	// passwords. By default, FIPS mode verifies each such hash once and
	// replaces it with a PBKDF2 hash.
	RefuseArgon2idInFIPSMode bool
}

// config returns the policy with password.DefaultConfig applied to zero
// fields.
func (p PasswordPolicy) config() password.Config {
	cfg := password.DefaultConfig()
	if p.MinLength != 0 {
		cfg.MinLength = p.MinLength
	}
	if p.Argon2idMemoryKiB != 0 {
		cfg.Argon2id.MemoryKiB = p.Argon2idMemoryKiB
	}
	if p.Argon2idIterations != 0 {
		cfg.Argon2id.Iterations = p.Argon2idIterations
	}
	if p.Argon2idParallelism != 0 {
		cfg.Argon2id.Parallelism = p.Argon2idParallelism
	}
	if p.PBKDF2Iterations != 0 {
		cfg.PBKDF2Iterations = p.PBKDF2Iterations
	}
	cfg.MaxConcurrent = p.MaxConcurrentHashes
	cfg.FIPSMigrateArgon2id = !p.RefuseArgon2idInFIPSMode
	return cfg
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
	// signed can still be verified, including ID tokens that relying parties
	// send back as id_token_hint. Default: 15 days.
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
	signer        tokenSigner
	passwords     *password.Hasher
	assets        *ui.Assets
	catalogs      *i18n.Catalogs
	crossOrigin   *http.CrossOriginProtection
	deps          app.Deps
	defaultTenant store.Tenant
	logger        *slog.Logger
	tracer        trace.TracerProvider
	meter         metric.MeterProvider
	mailer        *mailer.Mailer // nil without Config.Email
	handler       http.Handler
	wellKnown     http.Handler

	stop      context.CancelFunc
	work      sync.WaitGroup
	closeOnce sync.Once
}

// New validates cfg, prepares the store (creating the default tenant and its
// signing keys on first use) and returns a ready-to-use Server.
//
// New starts signing key rotation, the cleanup of expired records and, with
// Config.Email, email delivery in the background. Call Close to stop them
// when the Server is no longer needed; canceling ctx stops them too.
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
	passwords, err := password.New(cfg.Passwords.config())
	if err != nil {
		return nil, fmt.Errorf("clavis: invalid Passwords: %w", err)
	}
	assets, err := ui.NewAssets()
	if err != nil {
		return nil, fmt.Errorf("clavis: %w", err)
	}
	catalogs, err := i18n.Load()
	if err != nil {
		return nil, fmt.Errorf("clavis: %w", err)
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
	var mail *mailer.Mailer
	if cfg.Email != nil {
		if _, ok := cfg.Email.(*email.Console); ok {
			logger.LogAttrs(ctx, slog.LevelWarn, "the console email driver writes messages, including codes "+
				"and links that grant access, to the log; use it only for development")
		}
		mail = mailer.New(cfg.Email, logger)
		deps.Mail = mail
	}
	bgCtx, stop := context.WithCancel(ctx) //nolint:gosec // stop is kept in the Server and called by Close.
	s := &Server{
		issuer:        iss,
		store:         cfg.Store,
		keys:          manager,
		signer:        tokenSigner{manager},
		passwords:     passwords,
		assets:        assets,
		catalogs:      catalogs,
		crossOrigin:   http.NewCrossOriginProtection(),
		deps:          deps,
		defaultTenant: tenant,
		logger:        logger,
		tracer:        tracer,
		meter:         meter,
		mailer:        mail,
		stop:          stop,
	}
	s.wellKnown = allowGet(s.instrument(http.MethodGet+" "+oidc.AuthorizationServerMetadataPath,
		http.HandlerFunc(s.handleWellKnown)))
	s.handler = s.routes()
	s.work.Go(func() { manager.Run(bgCtx) })
	s.work.Go(func() { s.runCleanup(bgCtx) })
	if s.mailer != nil {
		s.work.Go(func() { s.mailer.Run(bgCtx) })
	}
	return s, nil
}

// runCleanup deletes expired authorization requests, sessions and codes
// every cleanupInterval until ctx is canceled. Instances that share a store
// may all run it; deleting an expired record twice is harmless.
func (s *Server) runCleanup(ctx context.Context) {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := app.PurgeExpired(ctx, s.deps); err != nil && ctx.Err() == nil {
				s.logger.LogAttrs(ctx, slog.LevelError, "deleting expired records failed",
					slog.String("error", err.Error()))
			}
		}
	}
}

// Close stops the background work started by New and waits for it to
// finish. It does not close the store, which the caller owns. Close is safe
// to call more than once; requests served after Close keep working, but keys
// are no longer rotated.
func (s *Server) Close() error {
	s.closeOnce.Do(s.stop)
	s.work.Wait()
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
	s.handleTenant(mux, http.MethodGet, oidc.AuthorizationPath, s.handleAuthorize)
	s.handleTenant(mux, http.MethodPost, oidc.AuthorizationPath, s.handleAuthorize)
	s.handleTenant(mux, http.MethodPost, oidc.TokenPath, s.handleToken)
	s.handleTenant(mux, http.MethodOptions, oidc.TokenPath, handlePreflight("POST"))
	s.handleTenant(mux, http.MethodPost, oidc.RevocationPath, s.handleRevocation)
	s.handleTenant(mux, http.MethodOptions, oidc.RevocationPath, handlePreflight("POST"))
	s.handleTenant(mux, http.MethodPost, oidc.IntrospectionPath, s.handleIntrospection)
	s.handleTenant(mux, http.MethodGet, oidc.UserinfoPath, s.handleUserInfo)
	s.handleTenant(mux, http.MethodPost, oidc.UserinfoPath, s.handleUserInfo)
	s.handleTenant(mux, http.MethodOptions, oidc.UserinfoPath, handlePreflight("GET, POST"))
	s.handleTenant(mux, http.MethodGet, loginPath, s.handleLoginPage)
	s.handleTenant(mux, http.MethodPost, loginPath, s.handleLogin)
	s.handleTenant(mux, http.MethodGet, consentPath, s.handleConsentPage)
	s.handleTenant(mux, http.MethodPost, consentPath, s.handleConsent)
	s.handleTenant(mux, http.MethodGet, signupPath, s.handleSignupPage)
	s.handleTenant(mux, http.MethodPost, signupPath, s.handleSignup)
	s.handleTenant(mux, http.MethodGet, signupVerifyPath, s.handleVerifyPage(signupFlow))
	s.handleTenant(mux, http.MethodPost, signupVerifyPath, s.handleVerify(signupFlow))
	s.handleTenant(mux, http.MethodGet, signupPasswordPath, s.handlePasswordPage(signupFlow))
	s.handleTenant(mux, http.MethodPost, signupPasswordPath, s.handleSignupPassword)
	s.handleTenant(mux, http.MethodGet, resetPath, s.handleResetPage)
	s.handleTenant(mux, http.MethodPost, resetPath, s.handleReset)
	s.handleTenant(mux, http.MethodGet, resetVerifyPath, s.handleVerifyPage(resetFlow))
	s.handleTenant(mux, http.MethodPost, resetVerifyPath, s.handleVerify(resetFlow))
	s.handleTenant(mux, http.MethodGet, resetPasswordPath, s.handlePasswordPage(resetFlow))
	s.handleTenant(mux, http.MethodPost, resetPasswordPath, s.handleResetPassword)
	s.handleTenant(mux, http.MethodGet, oidc.EndSessionPath, s.handleEndSession)
	s.handleTenant(mux, http.MethodPost, oidc.EndSessionPath, s.handleEndSession)
	s.handleTenant(mux, http.MethodPost, logoutPath, s.handleLogout)
	s.handleTenant(mux, http.MethodGet, brandingPath+"{name}", s.handleLogo)
	s.handleTenant(mux, http.MethodGet, "/{$}", s.handleRoot)
	s.handleTenant(mux, http.MethodGet, accountPath, s.handleAccountPage)
	s.handleTenant(mux, http.MethodPost, accountPath, s.handleAccount)
	s.handleTenant(mux, http.MethodGet, accountLoginPath, s.handleAccountLoginPage)
	s.handleTenant(mux, http.MethodPost, accountLoginPath, s.handleAccountLogin)
	s.handleTenant(mux, http.MethodPost, accountLogoutPath, s.handleAccountLogout)
	s.handleTenant(mux, http.MethodGet, accountPasswordPath, s.handleAccountPasswordPage)
	s.handleTenant(mux, http.MethodPost, accountPasswordPath, s.handleAccountPassword)
	s.handleTenant(mux, http.MethodGet, accountApplicationsPath, s.handleAccountApplicationsPage)
	s.handleTenant(mux, http.MethodPost, accountApplicationsPath, s.handleAccountApplications)
	// Assets are the same for every tenant and are not instrumented, like
	// the probes.
	mux.HandleFunc(http.MethodGet+" "+assetsPath+"{name}", s.handleAsset)
	if s.issuer.Path == "" {
		mux.Handle(oidc.AuthorizationServerMetadataPath, s.wellKnown)
		mux.Handle(oidc.AuthorizationServerMetadataPath+"/", s.wellKnown)
	}
	return mux
}

// tenant is the tenant a request addresses, with its issuer identifier and
// the path of that issuer on this host.
type tenant struct {
	store.Tenant
	issuer string
	path   string
	// signup tells whether people can sign up: the tenant allows it, it is
	// not the admin tenant, and email is enabled (ADR 0026).
	signup bool
	// reset tells whether users can reset their password, which needs email
	// (ADR 0027).
	reset bool
}

// authorizationTenant returns what the authorization use cases need to know
// about t.
func (t tenant) authorizationTenant() app.AuthorizationTenant {
	return app.AuthorizationTenant{ID: t.ID, Issuer: t.issuer, Signup: t.signup}
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
// response. Every request reads its tenant from the store, the default one
// too, so a change of its settings applies at once.
func (s *Server) serveTenant(w http.ResponseWriter, r *http.Request, slug string, h tenantHandler) {
	var t store.Tenant
	var err error
	if slug == "" {
		t, err = app.TenantByID(r.Context(), s.deps, s.defaultTenant.ID)
	} else {
		t, err = app.TenantBySlug(r.Context(), s.deps, slug)
	}
	switch {
	case errors.Is(err, app.ErrTenantNotFound) && slug != "":
		s.notFound(w)
		return
	case err != nil:
		s.internalError(w, r, "resolving the tenant", err)
		return
	}
	resolved := tenant{
		Tenant: t,
		issuer: s.issuer.String(),
		path:   s.issuer.Path,
		// UpdateTenant refuses signup for the admin tenant; a stored setting
		// that says otherwise is ignored.
		signup: t.SignupEnabled && t.Slug != app.AdminTenantSlug && s.deps.Mail != nil,
		reset:  s.deps.Mail != nil,
	}
	if slug != "" {
		resolved.issuer += tenantPathPrefix + t.Slug
		resolved.path += tenantPathPrefix + t.Slug
	}
	h(w, r, resolved)
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
	s.writePublicJSON(w, r, "application/json", metadataMaxAge, oidc.NewMetadata(t.issuer, t.signup))
}

// allowGet answers requests other than GET and HEAD with 405 before they
// reach h, as http.ServeMux does for "GET" route patterns.
func allowGet(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// handleWellKnown serves RFC 8414 metadata at
// /.well-known/oauth-authorization-server<issuer path>[/t/<slug>]. It parses
// the path itself because the issuer's path is configuration, not a route
// pattern.
func (s *Server) handleWellKnown(w http.ResponseWriter, r *http.Request) {
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

// notFound answers with a plain 404 response that caches must not store,
// so a tenant becomes reachable as soon as it is created.
func (s *Server) notFound(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
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
		// Copied, so later changes to the caller's Config cannot reach the
		// running Server.
		policy.Algorithms = slices.Clone(p.Algorithms)
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
