# Phase 1 implementation plan

- Status: Accepted
- Date: 2026-10-14
- Scope and exit criteria: [roadmap, Phase 1](../roadmap.md#phase-1-mvp-v01-cognito-user-pool-parity-core)

Phase 1 turns the Phase 0 foundations into a working OpenID Connect provider: users sign in
through hosted pages, clients obtain tokens through standard flows, and the result passes the
OpenID Foundation conformance suite. This plan orders the work into five milestones. Each
milestone ends with a pre-release, and `v0.1.0` ships when every exit criterion of the phase is
met.

Every work item below is one pull request into `develop`, unless the item notes a split. Items
are listed in dependency order within a milestone. Each milestone has a matching GitHub
milestone, and each work item has an issue that links back to this plan.

## Decisions

The design decisions this plan relies on are recorded as ADRs:

| ADR | Decision |
|---|---|
| [0013](../adr/0013-authorization-requests-and-browser-sessions.md) | Authorization requests are stored server side and bound to the browser; sessions are server side with one cookie per tenant |
| [0014](../adr/0014-tokens-api-resources-and-client-credentials.md) | Token formats and lifetimes, API resources as audiences, PKCE policy, hashed client secrets |
| [0015](../adr/0015-password-hashing-and-fips-mode.md) | argon2id by default, PBKDF2-HMAC-SHA256 in FIPS mode, PHC string format |
| [0016](../adr/0016-administration-and-the-admin-tenant.md) | Admin API authenticated with OAuth tokens from a reserved `admin` tenant; CLI bootstrap |
| [0017](../adr/0017-openid-conformance-suite-in-ci.md) | OpenID conformance suite in CI with committed expected failures |
| [0018](../adr/0018-pkce-exemption-is-a-client-setting.md) | The PKCE exemption for confidential clients is a client setting (supersedes the PKCE policy of 0014) |
| [0019](../adr/0019-authentication-context-class-references.md) | `acr` values are URIs under `https://clavisid.org/acr/` plus the EAP values `phr` and `phrh`; `acr_values` is voluntary |
| [0020](../adr/0020-consent-and-grants.md) | Grants per user and client; consent when a scope is new or `prompt=consent`; revoking a grant revokes its tokens |
| [0021](../adr/0021-refresh-token-rotation.md) | Refresh tokens with `offline_access` or for OAuth requests; one family per code exchange; concurrent refreshes count as reuse; tokens recorded before the step that validates them |
| [0022](../adr/0022-revocation-and-introspection.md) | Revoking a refresh token revokes its family; clients introspect their own tokens, and resource server clients the access tokens for their API resources |
| [0023](../adr/0023-logout-and-form-post.md) | Logout asks for confirmation and ends the session's online access; post-logout redirects need an `id_token_hint`; retired keys stay published 15 days; form post responses |
| [0024](../adr/0024-email-delivery.md) | A public `email.Sender` port with SMTP and console senders; messages queued in memory and sent in the background; TLS required except to a loopback host |
| [0025](../adr/0025-internationalization-and-theming.md) | Embedded JSON catalogs checked for missing keys; locale from the selector, `ui_locales`, then `Accept-Language`; per-tenant colors, radius and logo, applied without loosening the Content Security Policy |
| [0026](../adr/0026-signup-and-email-verification.md) | Signup per tenant, address first: a code or a link bound to the browser, then the password; the same responses and work for new and existing addresses; `prompt=create` |
| [0027](../adr/0027-password-reset.md) | Reset with the email verifications of 0026; only active accounts get the message; the user signs in again; a new password ends every session and token of the user |
| [0028](../adr/0028-account-pages.md) | Account pages at `<issuer>/account` on the session of single sign-on: profile of the standard claims, password change, connected applications; the issuer root leads there |
| [0029](../adr/0029-audit-log-and-client-addresses.md) | Audit events per tenant for sign-ins, accounts, consent, tokens and clients, without credential material, kept 90 days by default; client addresses from X-Forwarded-For only behind trusted proxies |
| [0030](../adr/0030-rate-limits-and-account-lockout.md) | Stored limits per email address (lockout after 10 wrong passwords in 15 minutes, wrong codes, messages) that reveal nothing about accounts; in-memory limits per client address on wrong guesses, messages and token endpoint errors; 429 with Retry-After |

## Rules for every work item

- Storage changes ship in both adapters with migrations, sqlc queries and contract tests in
  `store/storetest`, including tenant isolation tests.
- Protocol behavior cites the specification section it implements in a code comment, and the
  standards matrix in CLAUDE.md moves from Planned to In progress or Implemented.
- Parsers of untrusted input (authorization requests, redirect URIs, scopes, tokens, client
  credentials, form posts) get fuzz targets.
- New security-sensitive packages join the coverage floor (`COVER_FLOOR_PKGS`), starting with
  `internal/oauth`, `internal/oidc` and `internal/authn`.
- Configuration additions are validated at load time and documented in the example
  configuration.
- Once the conformance harness exists, each pull request that makes a conformance test pass
  removes it from the expected failures in the same change.
- Hosted UI changes keep the strict Content Security Policy and cross-origin protection, and,
  from milestone 4 on, update the Playwright suite.

## Milestone 1: Protocol core (`v0.1.0-alpha.3`)

Goal: a client can complete the authorization code flow against a hosted login page and call
userinfo, with the Basic OP and Config OP conformance plans running in CI.

1. **Tenant routing and discovery.**
   - Serve the `default` tenant at the issuer root and every other tenant under `/t/{slug}`.
     Unknown tenants answer 404.
   - Serve OpenID Connect Discovery 1.0 metadata per tenant.
   - Serve RFC 8414 metadata, including the path-inserted form for tenant issuers. When Clavis
     is embedded under a path, the host mounts a separate well-known handler at its root.
   - Create the signing keys of a new tenant when the tenant is created.
   - Add `clavis tenants create|list|delete`, working directly against the store.
   - Golden files cover the metadata documents.
2. **Conformance harness** (ADR 0017).
   - Add `conformance/` with the pinned suite, the TLS setup, the plan configuration and the
     expected failure and skip lists, plus a `make conformance` target and a CI workflow.
   - The first run covers the Config OP plan, with most tests listed as expected failures.
   - This item also confirms early how the suite handles PKCE and how it automates the login
     form.
3. **Clients.**
   - Add client records and store ports. A client has a type (confidential or public), a
     hashed secret, redirect and post-logout redirect URIs, allowed grant types and scopes,
     token lifetimes, a consent policy and a PKCE policy (ADR 0014).
   - Redirect URIs use exact matching, with the RFC 8252 loopback port exception, and are
     fuzzed.
   - Add `clavis clients create|list|show|delete|rotate-secret`. The secret is shown once.
4. **Users and password authentication.**
   - Add users (email unique per tenant, status, standard OpenID Connect claims) and
     credentials.
   - Add `internal/authn/password` (ADR 0015), with rehash on login, a dummy hash for unknown
     users and a concurrency limit on hashing.
   - Add `clavis users create|list|delete|set-password`. The password is read from the
     terminal or stdin, never from arguments.
5. **Authorization endpoint and hosted login** (ADR 0013).
   - Implement `GET` and `POST /oauth2/authorize` for `response_type=code`, with validation
     per OAuth 2.1 and OpenID Connect Core.
   - Errors in the client or redirect URI show an error page instead of redirecting. Error
     redirects carry `iss` (RFC 9207).
   - Store authorization requests server side, bound to the browser.
   - Add the hosted UI scaffolding: templ as a pinned tool with a generated-code check,
     embedded assets, CSP, `http.CrossOriginProtection` and minimal CSS.
   - Add password login, browser sessions, and authorization codes bound to the client, the
     redirect URI, PKCE and the nonce.
6. **Token endpoint, ID tokens, access tokens and userinfo** (ADR 0014).
   - Token endpoint grants: `authorization_code` and `client_credentials`.
   - Client authentication: `client_secret_basic`, `client_secret_post` and `none`.
   - Replaying an authorization code revokes the tokens issued from it.
   - Add API resources, ID tokens with `at_hash`, RFC 9068 access tokens and the userinfo
     endpoint.
   - Interoperability tests use `golang.org/x/oauth2` and `github.com/coreos/go-oidc/v3`.
   - Basic OP and Config OP pass, except the tests that depend on milestone 2 features, which
     stay listed as expected failures.

## Milestone 2: Sessions and token lifecycle (`v0.1.0-alpha.4`)

Goal: single sign-on, consent, refresh tokens, revocation, introspection and logout, with the
Basic OP, Config OP, Form Post and RP-Initiated Logout plans passing.

1. **Single sign-on and request parameters.**
   - Reuse the browser session across the clients of a tenant.
   - Support `prompt` (`none`, `login`, `consent`), `max_age` and `auth_time`, `login_hint`,
     `id_token_hint`, and the basic `acr_values`, `acr` and `amr`.
   - Support the `claims` request parameter to the extent the Basic OP plan requires.
2. **Consent.**
   - Add a consent page and stored grants per user, client and scope.
   - First-party clients can skip consent by policy.
   - Users can revoke a grant.
3. **Refresh tokens and cleanup.**
   - Add the `refresh_token` grant, available with `offline_access` or by client policy.
   - Refresh tokens are opaque, hashed and rotated on every use. They belong to token
     families, and reusing a rotated token revokes its whole family.
   - The background job that deletes expired codes, authorization requests and sessions,
     added with work item 1.5, also deletes expired refresh tokens.
4. **Revocation and introspection.**
   - Implement RFC 7009 and RFC 7662, authenticated with client credentials.
   - Introspection reveals nothing about tokens of other clients unless policy allows it.
5. **Logout and response modes.**
   - Implement OpenID Connect RP-Initiated Logout 1.0: `end_session_endpoint`,
     `id_token_hint`, post-logout redirect URIs with exact matching, `state`, a confirmation
     page and session termination.
   - Add the OAuth 2.0 Form Post Response Mode.
   - The Form Post and RP-Initiated Logout conformance plans pass.

## Milestone 3: Accounts (`v0.1.0-alpha.5`)

Goal: self-service accounts with email verification and password reset, in English and
Spanish, protected against abuse and enumeration.

1. **Email delivery.**
   - Add a `Sender` port with an SMTP adapter (`github.com/wneessen/go-mail`).
   - Add a console driver for development only. It works only when configured explicitly and
     logs a warning at startup, because it prints verification codes.
   - Text and HTML templates.
2. **Internationalization and theming.**
   - Embedded message catalogs for English and Spanish.
   - Locale selection from `ui_locales` and `Accept-Language` (`golang.org/x/text/language`).
   - Per-tenant branding through CSS custom properties.
   - Emails use the same catalogs.
3. **Signup and email verification.**
   - Self-service signup is enabled per tenant.
   - Verification codes and links are hashed and short lived.
   - Responses never reveal whether an account exists.
4. **Password reset and profile.**
   - Enumeration-safe password reset.
   - A profile page for the standard claims, and password change.
5. **Abuse protection and audit.**
   - In-process rate limits by IP address and account on login, token, reset, verification
     and MFA endpoints.
   - Account lockout stored in the database, so it holds across instances, without enabling
     enumeration.
   - An audit log of authentication, account and client events.
6. **RFC 9700 threat tests.** Open redirect, mix-up, PKCE downgrade, code replay, refresh token
   reuse, login CSRF and clickjacking are tested as attacks against the server.

## Milestone 4: MFA and passkeys (`v0.1.0-alpha.6`)

Goal: phishing-resistant and second-factor authentication, with every hosted UI flow covered
by browser tests.

1. **TOTP and recovery codes.**
   - Enrolment with a QR code.
   - Verification with protection against reusing a code (RFC 6238).
   - Hashed recovery codes.
   - `amr` values per RFC 8176, a per-tenant MFA policy, and step-up through `acr_values`.
2. **Passkeys.**
   - Registration and login with discoverable credentials and conditional UI
     (`github.com/go-webauthn/webauthn`).
   - The small TypeScript module is bundled at build time with the esbuild Go API, as a pinned
     tool with a generated-code check (ADR 0007).
3. **Playwright end-to-end suite.**
   - `e2e/` covers every hosted UI flow, including passkeys with a virtual authenticator.
   - axe-core accessibility checks.
   - A CI job runs the suite.

## Milestone 5: Administration and embedding (`v0.1.0`)

Goal: Clavis is managed through a documented API, embeds into Go applications with token
validation middleware, and meets every Phase 1 exit criterion.

1. **Admin tenant and admin API foundation** (ADR 0016).
   - Add the reserved `admin` tenant and `clavis admin bootstrap`.
   - The `/admin/v1` contract is OpenAPI 3.1 in `api/openapi.yaml`, served by an
     `oapi-codegen` strict server (pinned tool).
   - Bearer token authentication with admin scopes.
   - A CI check rejects breaking changes to the contract.
2. **Admin API resources.**
   - Tenants (including disabling a tenant, which then answers 404), clients, users, API
     resources and audit events, with cursor pagination.
   - A generated Go client in `client/`.
   - This item may split into one pull request per resource.
3. **Embedding and resource servers.**
   - Add `Server.Verifier()` and `Server.AdminHandler()`.
   - A public `middleware` package with `Require` and `Scopes`.
   - A verifier for standalone resource servers that fetches the JWK set remotely, with
     caching and the outbound HTTP rules (SSRF protection, timeouts and size limits).
4. **Webhooks.**
   - Endpoints per tenant, configured through the admin API.
   - User and session events, signed per Standard Webhooks.
   - A transactional outbox with retries and backoff, SSRF-safe delivery and a delivery log.
5. **Examples and release readiness.**
   - `examples/embedded` (a Go application that embeds Clavis and protects an API) and
     `examples/standalone` (a relying party that uses the binary).
   - CI checks the footprint targets: binary size, idle memory and cold start.
   - A getting-started guide and a configuration reference.
   - The standards matrix is updated, and `v0.1.0` is released.

## Conformance progression

| Milestone | Plans that must pass in CI |
|---|---|
| 1 | Config OP; Basic OP except the tests that need milestone 2 features |
| 2 | Config OP, Basic OP, Form Post, RP-Initiated Logout |
| 3 to 5 | All of the above, with no regressions |

## Risks

- **Conformance and PKCE.** Work item 1.2 confirmed that Basic OP tests omit PKCE, and that
  one test omits the nonce too. ADR 0018 makes the PKCE exemption a client setting, which the
  conformance clients use.
- **CI time.** The conformance suite and Playwright are slow. They run nightly and on pull
  requests that touch the relevant paths, not on every change.
- **Footprint.** templ, WebAuthn and the admin API grow the binary. Release-check already gates
  the size at 40 MiB; memory and cold start are measured from milestone 5.
- **Scope.** Phase 1 is the largest phase. If a milestone slips, webhooks (5.4) are the first
  candidate to move to Phase 2, after a decision by the maintainer.
