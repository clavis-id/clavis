# Architecture

This document describes the target architecture of Clavis. Phase 0 (foundations) is
implemented: the public embed API, storage ports with SQLite and PostgreSQL adapters, signing
key management, telemetry and the release pipeline. Everything else is design and will be
built phase by phase (see the [roadmap](roadmap.md)). Decisions with lasting consequences are
recorded as ADRs in [`adr/`](adr/).

## Principles

- **Standards over invention.** Every externally visible behavior maps to a published
  specification (RFC, OpenID specification, W3C recommendation). Proprietary extensions are
  avoided; when unavoidable they are namespaced and documented.
- **Stdlib first.** Prefer the Go standard library. A third-party dependency must justify its
  maintenance status, security history and transitive footprint (see ADR 0002).
- **Embeddable by construction.** Every component is reachable as an `http.Handler` or a plain
  Go API. Nothing requires a specific router, framework, global state or process layout.
- **Ports and adapters.** The domain and use cases never depend on transport, storage or
  vendors. Infrastructure plugs in through small interfaces.
- **Secure defaults.** The zero-configuration setup is the secure setup. Weakening a default
  requires an explicit, logged configuration change.

## Deployment modes

### Embedded library

```go
db, err := sqlite.Open(ctx, "auth.db")
if err != nil {
    return err
}
enc, err := kek.NewLocal(secretFromYourSecretsManager)
if err != nil {
    return err
}

auth, err := clavis.New(ctx, clavis.Config{
    Issuer:       "https://app.example.com/auth",
    Store:        db,
    KeyEncrypter: enc,
})
if err != nil {
    return err
}

mux.Handle("/auth/", http.StripPrefix("/auth", auth.Handler()))
// RFC 8414 metadata lives at the host root when the issuer has a path.
mux.Handle("/.well-known/oauth-authorization-server/", auth.WellKnownHandler())
mux.Handle("/api/", middleware.Require(auth.Verifier(), middleware.Scopes("orders:read"))(api))
```

The host application owns the process, the listener, TLS and the router. Clavis owns its
routes below the mount point, its storage schema and its background jobs (key rotation,
cleanup), which stop when the passed context is cancelled.

### Standalone server

```
clavis serve --config clavis.yaml
```

The binary wires the same public API with configuration loading, an HTTP server, the admin API,
the hosted UI, telemetry exporters and graceful shutdown. Container images are distroless and
multi-architecture.

## Repository layout

```
clavis/
  cmd/clavis/            CLI and server entry point (serve, migrate, tenants, clients, keys;
                         later plan, apply, import)
  clavis.go              Public embed API (New, Config, Server, Server.Handler, Server.Verifier)
                         and the HTTP handlers of the protocol endpoints
  middleware/            Public: resource-server token validation for net/http
  store/                 Public: storage ports and record types
    sqlite/              Public: SQLite adapter (modernc.org/sqlite, CGo-free)
      migrations/        SQL migrations, embedded in the adapter
      queries/           SQL queries compiled by sqlc
      internal/db/       Generated query code (do not edit)
    postgres/            Public: PostgreSQL adapter (pgx v5), same structure as sqlite/
    storetest/           Public: contract suite every adapter must pass
  kek/                   Public: key encryption (Encrypter interface, AES-256-GCM Local)
  hooks/                 Public: hook payload types and WebAssembly ABI
  client/                Public: generated Go client for the admin API
  internal/
    domain/              Entities and invariants: Tenant, User, Client, Session, Credential,
                         Grant, Consent, SigningKey, AuditEvent
    app/                 Use cases: signup, login, MFA, consent, token issuance, revocation
    oauth/               OAuth 2.1 rules: client identifiers and secrets, redirect URIs, scopes
    oidc/                OpenID Connect rules and messages: discovery metadata, ID tokens
    authn/               Authenticators: password, passkeys, TOTP, magic link, upstream IdPs
    keys/                Signing key lifecycle, rotation, envelope encryption at rest
    adminapi/            Admin REST handlers generated from api/openapi.yaml
    ui/                  templ components, static assets, i18n catalogs
    webhook/             Outbound event delivery (Standard Webhooks)
    wasmhooks/           wazero runtime for WebAssembly hooks
    ratelimit/           In-process and store-backed limiters
    importer/            Hash formats and migration connectors
    config/              Configuration schema, loading and validation
    telemetry/           slog setup, OpenTelemetry traces and metrics
  api/openapi.yaml       Admin API contract (source of truth)
  sqlc.yaml              Query code generation for both adapters
  conformance/           OpenID conformance suite plans and runner
  e2e/                   Playwright browser tests
  deploy/                dev/ local config, docker/ release image, cloudflare/go-import/ Worker
                         serving the clavisid.org/clavis import path; later Compose and Helm
  docs/                  Design documents and ADRs
```

## Dependency rules

1. `internal/domain` imports only the standard library.
2. `internal/app` imports `internal/domain` and the port interfaces it consumes.
3. Adapters (`store/sqlite`, `store/postgres`, `internal/webhook`, email senders, KMS clients)
   implement ports and may import `internal/domain`. They never import each other.
4. Protocol packages (`internal/oauth`, `internal/oidc`) hold the rules and message formats of
   the specifications. They import neither storage nor `internal/app`, so use cases can apply
   them.
5. HTTP handlers (the root package, later `internal/adminapi` and `internal/ui`) call use cases
   in `internal/app`; they never touch storage directly.
6. Public packages are thin: they construct and expose internal components. A type becomes
   public only when an embedder needs to name it.
7. No package-level mutable state. Time, randomness, ID generation and outbound HTTP clients are
   injected so tests can control them.

## Public API policy

- Before v1.0 the public API may change in any minor release, with notes in the changelog.
- From v1.0, public packages follow semantic import versioning; breaking changes require a new
  major version.
- The admin HTTP API is versioned in its path (`/admin/v1`). The OpenAPI document is the
  contract and is checked for breaking changes in CI.
- Protocol endpoints follow their specifications and are not versioned.

## Multi-tenancy model

- A tenant is an isolated user directory with its own issuer, signing keys, clients, users,
  branding, policies and hooks (equivalent to a Cognito user pool or a Keycloak realm).
- Issuer per tenant: `https://<host>/t/<tenant>` by default, or a custom domain mapped to the
  tenant.
- A `default` tenant is created automatically and mounted at the root issuer, so single-app
  deployments never see tenancy.
- A reserved `admin` tenant holds the clients that call the admin API (ADR 0016).
- Every storage query is scoped by tenant ID; the store ports make the tenant ID a required
  argument rather than an optional filter.
- Organizations (business customers inside a tenant, with their own SSO connections and SCIM
  endpoints) arrive in Phase 2 and live inside a tenant.

## Protocol surface (per tenant)

Paths are relative to the tenant's issuer: the issuer itself for the `default` tenant and
`<issuer>/t/<slug>` for the others. RFC 8414 metadata is the exception: section 3.1 of the RFC
places it at `/.well-known/oauth-authorization-server` followed by the issuer's path, at the root
of the host. `Server.Handler` serves it when the issuer has no path; otherwise the host mounts
`Server.WellKnownHandler` at its root. Unknown tenants get a 404 response, and the `default`
tenant is not reachable under `/t/default`.

| Endpoint | Specification | Phase |
|---|---|---|
| `/.well-known/openid-configuration` | OpenID Connect Discovery 1.0 | 1 (implemented) |
| `/.well-known/oauth-authorization-server` | RFC 8414 | 1 (implemented) |
| `/oauth2/authorize` | RFC 6749, OAuth 2.1, PKCE (RFC 7636) | 1 |
| `/oauth2/token` | RFC 6749, OAuth 2.1 | 1 |
| `/oauth2/jwks` | RFC 7517 | 0 (implemented) |
| `/oauth2/userinfo` | OpenID Connect Core 1.0 | 1 |
| `/oauth2/revoke` | RFC 7009 | 1 |
| `/oauth2/introspect` | RFC 7662 | 1 |
| `/oauth2/logout` | OpenID Connect RP-Initiated Logout 1.0 | 1 |
| `/oauth2/par` | RFC 9126 | 2 |
| `/oauth2/device_authorization` | RFC 8628 | 2 |
| `/oauth2/register` | RFC 7591 (fallback to CIMD) | 3 |
| `/oauth2/bc-authorize` | OpenID CIBA Core 1.0 | 3 |

## Security architecture

- **Passwords:** argon2id with at least the OWASP baseline (19 MiB memory, 2 iterations,
  1 lane), or PBKDF2-HMAC-SHA-256 with 600,000 iterations in FIPS mode; parameters stored with
  each hash and upgraded transparently on login. See ADR 0015.
- **Signing keys:** one sequence per tenant and algorithm (RS256 always; ES256 and EdDSA
  optional), encrypted at rest through `kek.Encrypter` (AES-256-GCM by default, bound to the
  record by additional data). Rotated every 30 days by default; a successor is published at
  least 24 hours before it signs (publish-ahead plus the one-hour check interval), keys of a
  newly enabled algorithm are published ahead the same way, and a retired key stays in the
  JWKS for 48 hours. The JWK set is cached in memory for one minute. See ADR 0011.
- **Tokens:** short-lived JWT access tokens whose audience is the API resource they grant
  access to; opaque, rotating refresh tokens with reuse detection that revokes the whole token
  family; client secrets generated by Clavis and stored hashed. See ADR 0014.
- **Clients:** confidential or public (RFC 6749, section 2.1). Redirect URIs are registered in
  full and compared as exact strings, except for the port of `http` URIs on 127.0.0.1 or [::1]
  (RFC 8252, section 7.3); wildcards, fragments and `http` outside loopback interfaces are
  rejected. PKCE is required unless an operator exempts a confidential client (ADR 0018).
- **Authorization requests:** stored server side and bound to the browser that started them,
  so the hosted UI and future custom interfaces share one flow. See ADR 0013.
- **Browser sessions:** `__Host-` prefixed, `Secure`, `HttpOnly`, `SameSite=Lax` cookies;
  cross-origin protection via `http.CrossOriginProtection`; strict Content Security Policy on
  the hosted UI.
- **Comparisons:** every secret comparison is constant time.
- **Logging:** secrets, tokens, passwords, codes and full authorization requests are never
  logged. Audit events record who, what, when and from where, without credential material.
- **FIPS mode:** builds with `GOFIPS140=certified` restrict algorithms to the validated module.

## Observability

- **Logs:** structured `log/slog` records on standard error, JSON in production. Secrets and
  tokens are never logged (see Security architecture).
- **Probes:** `GET /healthz` (liveness, never touches dependencies) and `GET /readyz`
  (readiness, pings the store). Probes are not traced or measured, so frequent health checks do
  not flood telemetry.
- **Traces:** every protocol route is wrapped with OpenTelemetry `otelhttp`; spans are named
  after the route pattern (for example `GET /oauth2/jwks`) to keep cardinality bounded.
  Embedders pass a `TracerProvider` in `clavis.Config` or rely on the global provider. The
  binary exports over OTLP/HTTP (`telemetry.tracing`), honoring the standard
  `OTEL_EXPORTER_OTLP_*` and `OTEL_RESOURCE_ATTRIBUTES` variables, with a parent-based ratio
  sampler. It installs no propagator, so trace context sent by untrusted clients to public
  endpoints is ignored and cannot force sampling.
- **Metrics:** `otelhttp` request metrics, `clavis.signing_keys.created` (by algorithm),
  `clavis.signing_keys.rotation_failures` and Go runtime metrics. The binary serves them in the
  Prometheus format on a separate listener (`telemetry.metrics.address`, default
  `127.0.0.1:9464`), never on the API port.

## Extension points

| Port | Default adapter | Purpose |
|---|---|---|
| `store.Store` | SQLite, PostgreSQL | Persistence |
| `Sender` | SMTP | Email delivery |
| `kek.Encrypter` | `kek.Local` (AES-256-GCM) | Signing key protection (KMS adapters later) |
| `Hook` | Webhook, WebAssembly | Lifecycle customization |
| `RateLimiter` | In-process, store-backed | Abuse protection |
| `UpstreamProvider` | Generic OIDC, Google, GitHub, Apple, Microsoft | Federation |
| `LegacyVerifier` | Cognito, generic HTTP | Lazy migration |
