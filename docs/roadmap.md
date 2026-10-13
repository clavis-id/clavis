# Roadmap

Each phase ends with explicit exit criteria. A phase is not complete until every criterion is
met in CI. Versions before v1.0 make no compatibility promises.

Current phase: **Design** (no code yet).

## Phase 0: Foundations

Scope:
- Go 1.27 toolchain, `go.mod` with module path `github.com/clavis-id/clavis`.
- Makefile, golangci-lint v2 configuration, GitHub Actions CI, Renovate, CodeQL, OSSF
  Scorecard, gitleaks.
- goreleaser v2 pipeline: multi-architecture binaries, distroless images, cosign keyless
  signatures, SBOM, artifact attestations.
- Storage ports with SQLite and PostgreSQL adapters, goose migrations, sqlc queries,
  `store/storetest` contract suite.
- Configuration loading and validation, slog logging, OpenTelemetry setup.
- Signing key management: generation, encryption at rest, rotation, JWKS rendering.
- Test harness: clock injection, `httptest` server helpers, testcontainers setup.
- CONTRIBUTING.md, SECURITY.md, code of conduct.

Exit criteria:
- `make test`, `make test-postgres`, `make lint` pass in CI on Linux and macOS, amd64 and arm64.
- Contract suite passes on both adapters.
- A tagged pre-release produces signed binaries and images.

## Phase 1: MVP v0.1 (Cognito user pool parity core)

Scope:
- Tenants with per-tenant issuer; `default` tenant.
- Users: email and password signup (argon2id), email verification, password reset, profile.
- Browser sessions and the hosted login UI (templ + htmx), English and Spanish.
- OpenID Connect provider: authorization code with PKCE, refresh token rotation with reuse
  detection, client credentials, discovery, JWKS, userinfo, revocation, introspection,
  RP-initiated logout.
- MFA with TOTP and recovery codes; passkeys (registration, login, conditional UI).
- Admin REST API (OpenAPI 3.1) and CLI for tenants, clients and users.
- Audit log, rate limiting, account lockout policy.
- Webhooks for user and session events (Standard Webhooks signatures).
- Embedded mode: `clavis.New`, `Server.Handler`, `middleware.Require`.

Exit criteria:
- OpenID conformance suite: Basic OP, Config OP, Form Post and RP-Initiated Logout plans pass.
- RFC 9700 threat tests pass.
- Playwright suite covers every hosted UI flow including passkeys.
- An example application embeds Clavis and another consumes it as a standalone server.
- Footprint targets met.

## Phase 2: v0.2 to v0.3

Scope:
- Upstream identity providers: generic OpenID Connect, Google, GitHub, Apple, Microsoft.
- Passwordless email: magic links and one-time codes.
- Organizations inside a tenant, with per-organization SSO connections and domain discovery.
- Roles and permissions, emitted as token claims.
- Hooks: pre-signup, post-confirmation, pre-token generation, post-authentication, as webhooks
  and as WebAssembly modules.
- Migration toolkit: Cognito lazy migration connector, generic HTTP legacy verifier, bulk
  import for Auth0, Firebase and Keycloak exports.
- Admin console (templ + htmx).
- Pushed Authorization Requests (RFC 9126), DPoP (RFC 9449), device authorization grant
  (RFC 8628).
- Config as code: `clavis plan` and `clavis apply`.

Exit criteria:
- Conformance: Dynamic OP plans relevant to supported features pass.
- A documented end-to-end migration from a Cognito user pool without password resets.

## Phase 3: v0.4 to v0.6

Scope:
- Agent-ready set: Client ID Metadata Documents, RFC 9728 helpers in `middleware`,
  resource indicators (RFC 8707), token exchange with `act` claims (RFC 8693), OpenID CIBA,
  Dynamic Client Registration fallback (RFC 7591), integration guides for MCP servers.
- SAML 2.0 identity provider and service provider for organization SSO.
- SCIM 2.0 provisioning endpoints.
- Key encryption adapters: AWS KMS, Google Cloud KMS, HashiCorp Vault Transit.
- Helm chart, Terraform provider, TypeScript browser SDK.
- Documentation site (Astro Starlight).

Exit criteria:
- An MCP server protected by Clavis passes the MCP authorization flow with at least two
  independent MCP clients.
- SCIM and SAML interoperability verified against at least one major enterprise IdP.

## v1.0

- Public Go API and admin API frozen under semantic versioning.
- External security audit completed and findings resolved.
- OpenID Foundation certification for the supported profiles.
- FIPS 140-3 mode documented and tested in CI.
- Upgrade path tests from every v0.x minor release.
