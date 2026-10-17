# Architecture

This document describes the target architecture of Clavis. Phase 0 (foundations) is
implemented: the public embed API, storage ports with SQLite and PostgreSQL adapters, signing
key management, telemetry and the release pipeline. Phase 1 is in progress: tenants, clients,
users with passwords, and the authorization endpoint with the hosted login page work today.
Everything else is design and will be built phase by phase (see the [roadmap](roadmap.md)). Decisions with lasting consequences are
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
  cmd/clavis/            CLI and server entry point (serve, migrate, tenants, clients, users,
                         keys; later plan, apply, import)
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
| `/oauth2/authorize` | RFC 6749, OAuth 2.1, PKCE (RFC 7636), RFC 9207 | 1 (authorization code flow implemented) |
| `/oauth2/token` | RFC 6749, OAuth 2.1, PKCE (RFC 7636), RFC 9068 | 1 (authorization code and client credentials implemented) |
| `/oauth2/jwks` | RFC 7517 | 0 (implemented) |
| `/oauth2/userinfo` | OpenID Connect Core 1.0, RFC 6750 | 1 (implemented) |
| `/oauth2/revoke` | RFC 7009 | 1 |
| `/oauth2/introspect` | RFC 7662 | 1 |
| `/oauth2/logout` | OpenID Connect RP-Initiated Logout 1.0 | 1 |
| `/oauth2/par` | RFC 9126 | 2 |
| `/oauth2/device_authorization` | RFC 8628 | 2 |
| `/oauth2/register` | RFC 7591 (fallback to CIMD) | 3 |
| `/oauth2/bc-authorize` | OpenID CIBA Core 1.0 | 3 |

The hosted UI adds `/login` per tenant, the sign-in page of a stored authorization request,
and `/assets/` at the issuer of the default tenant, the stylesheet and other static files
shared by every tenant. Asset names include a hash of their content, so they are cached for a
year.

## Security architecture

- **Passwords:** argon2id with at least the OWASP baseline (19 MiB memory, 2 iterations,
  1 lane), or PBKDF2-HMAC-SHA-256 with 600,000 iterations in FIPS mode; parameters stored with
  each hash and upgraded transparently on login. See ADR 0015.
  - Passwords are normalized to Unicode NFKC before hashing (NIST SP 800-63B-4) and have 8 to
    256 characters; `passwords.min_length` raises the minimum.
  - A login for an unknown account, or for an account without a password, does the work of a
    verification with the current parameters, and a semaphore
    (`passwords.max_concurrent_hashes`) bounds the memory hashing can use.
  - Stored hashes are parsed with the same upper bounds as the configuration, so a hash cannot
    make a verification arbitrarily expensive.
  - FIPS exception: by default, FIPS mode verifies an argon2id hash made before FIPS mode was
    enabled, once, and replaces it with a PBKDF2 hash, logging the event. argon2id is not an
    approved algorithm; deployments that must not run it at all set
    `passwords.fips_migrate_argon2id: false`, and those users reset their passwords.
- **Signing keys:** one sequence per tenant and algorithm (RS256 always; ES256 and EdDSA
  optional), encrypted at rest through `kek.Encrypter` (AES-256-GCM by default, bound to the
  record by additional data). Rotated every 30 days by default; a successor is published at
  least 24 hours before it signs (publish-ahead plus the one-hour check interval), keys of a
  newly enabled algorithm are published ahead the same way, and a retired key stays in the
  JWKS for 48 hours. The JWK set is cached in memory for one minute. See ADR 0011.
- **Tokens:** see ADR 0014.
  - The token endpoint authenticates the client first (`client_secret_basic`,
    `client_secret_post`, or `none` for public clients; one method per request) and then
    serves the `authorization_code` and `client_credentials` grants.
  - Access tokens are RS256 JWTs per RFC 9068 (`typ` `at+jwt`), valid for 10 minutes by
    default. Their `aud` lists the API resources whose scopes they grant, plus the issuer when
    they grant OpenID Connect scopes, because the issuer serves userinfo. Each token is
    recorded by its `jti`, so it can be revoked before it expires.
  - ID tokens are RS256 JWTs with `auth_time`, `acr`, `amr`, `nonce` and `at_hash`; the profile
    claims come from userinfo (OpenID Connect Core 1.0, section 5.4).
  - The `claims` parameter adds individual claims about the user to the ID token or the
    userinfo response (section 5.5), only from scopes the client may request.
  - `acr` values are URIs under `https://clavisid.org/acr/`, with the EAP values `phr` and
    `phrh` for phishing-resistant methods (ADR 0019). A password sign-in has
    `https://clavisid.org/acr/password`. `acr_values` is a voluntary request; an essential
    `acr` that Clavis cannot produce fails with `access_denied`.
  - A code is redeemed once. Presenting it again fails and revokes the access tokens issued
    for it. The token request must name the code's redirect URI when the authorization request
    did, and must carry `code_verifier` exactly when the authorization request carried a
    challenge (RFC 9700, section 4.8.2).
  - API resources are registered per tenant with an absolute URI and the scopes they define;
    a scope belongs to one resource, and OpenID Connect scopes to none.
  - Userinfo accepts the access token in the `Authorization` header or a form body, never in
    the query, and rejects revoked tokens and tokens of disabled or deleted users.
  - Refresh tokens (opaque, rotated on every use, with reuse detection that revokes the whole
    family) arrive in Phase 1, milestone 2; until then `offline_access` is not granted. Client
    secrets are generated by Clavis and stored hashed.
  - The token and userinfo endpoints allow cross-origin requests without credentials, for
    browser-based clients.
- **Clients:** confidential or public (RFC 6749, section 2.1). A client ID is never a UUID,
  the form of user identifiers, so the sub of a token a client obtains for itself cannot match
  a user's (RFC 9068, section 5). Redirect URIs are registered in full; wildcards, fragments and `http` outside loopback interfaces are rejected. Authorization
  requests must send a registered redirect URI exactly, except that the port of `http` URIs on
  127.0.0.1 or [::1] may differ (RFC 8252, section 7.3). Post-logout redirect URIs match
  exactly, with no port exception (OpenID Connect RP-Initiated Logout 1.0, section 3). PKCE is
  required unless an operator exempts a confidential client (ADR 0018).
- **Authorization requests:** validated in full before any user interaction (OAuth 2.1 and
  OpenID Connect Core 1.0, section 3.1.2), then stored server side for 10 minutes under a
  random 128-bit identifier, so the hosted UI and future custom interfaces share one flow. See
  ADR 0013.
  - An unknown client or an unregistered redirect URI ends on an error page; every other
    error goes back to the redirect URI with `iss` (RFC 9207). OpenID Connect requests must
    name their redirect URI; OAuth requests may omit it when the client has only one.
  - A request is bound to the browser that sent it through the `__Host-clavis-binding`
    cookie, whose SHA-256 hash it stores, so a sign-in started in one browser cannot be
    finished in another. A request is single use.
  - Requests that use the request object, `request_uri`, dynamic registration or a response
    type other than `code` are rejected with the matching error.
  - `id_token_hint` must be an ID token that the tenant issued to the client; it may have
    expired. Only that user's session or sign-in answers the request, and the same holds for
    a `sub` claim that the `claims` parameter requests with a value (OpenID Connect Core 1.0,
    section 5.5.1). A `login_hint` that is an email address fills in the sign-in form.
- **Authorization codes:** 256 random bits, stored as a SHA-256 hash, valid for 60 seconds,
  bound to the client, the redirect URI, the PKCE challenge, the nonce, the scopes and the
  session (ADR 0014).
- **Cleanup:** every 10 minutes, each instance deletes expired authorization requests,
  sessions and access token records, and codes that expired more than an hour ago, so a
  replayed code is still recognized for a while. An authorization request, which needs no authentication, is gone
  within 20 minutes of its creation.
- **Browser sessions:** one server-side session per sign-in, stored as the SHA-256 hash of a
  256-bit cookie named `__Host-clavis-session-<tenant ID>`, so tenants on one host never share
  a session. Sessions end after 24 hours without use or 14 days in all, and a new sign-in
  replaces the browser's previous session. Every Clavis cookie is `Secure`, `HttpOnly` and
  `SameSite=Lax`, with `Path=/`.
  - Single sign-on: a session answers the authorization requests of every client of its
    tenant without the login page, while its user is active and the request needs no
    consent. Each use moves its idle expiry.
  - A new sign-in is needed for `prompt=login`, `max_age=0`, an authentication older than
    `max_age`, or an `id_token_hint` of another user. Until account selection exists,
    `prompt=select_account` shows the sign-in form too. With `prompt=none`, a request that
    needs a sign-in fails with `login_required`.
- **Consent:** see ADR 0020. A grant records the scopes a user allowed a client.
  - After the user authenticates, a request needs consent when it asks for a scope that the
    grant lacks (a claim requested individually counts as its scope) or carries
    `prompt=consent`. Clients that skip consent by policy, for first-party applications,
    need it only for `prompt=consent`. With `prompt=none`, a request that needs consent
    fails with `consent_required`.
  - The consent page names the client, the account and each scope. Allowing adds the
    request's scopes to the grant and issues the code; denying answers `access_denied`.
  - The decision must come from the browser that started the request, with the session that
    authenticated it; the form is protected like the sign-in form.
  - `clavis grants list|revoke` lists and revokes the grants of a user. Revoking a grant
    revokes the client's access tokens for the user, and the next request asks again.
- **Hosted pages:** rendered on the server with templ, without scripts. They send a Content
  Security Policy that allows only same-origin stylesheets and images, forbids framing, and
  lets forms submit only to Clavis and, on the login page, to the origin of the client's
  redirect URI, because browsers apply `form-action` to the redirect after a sign-in. The
  sign-in form is protected by `http.CrossOriginProtection`, and pages are never cached and
  send no referrer.
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
