# Vision

Clavis is an open source identity and access management platform written in Go. It is an
OpenID Connect provider and OAuth 2.1 authorization server that any application can adopt with
minimal friction, either embedded as a Go library or deployed as a single binary.

This document records the market analysis (as of October 2026) that motivates the project and
the product pillars that guide every design decision.

## Problem

Teams that need authentication today usually choose among the following kinds of options.
Each is a valid choice for many teams; Clavis targets the combination none of them covers.

- **Managed services** (Amazon Cognito, Auth0, Clerk). Fast to start, with the user directory
  hosted by the vendor. Amazon Cognito does not provide a way to export password hashes, so a
  migration away from it typically relies on password resets or on lazy migration at sign-in.
  Pricing is usually based on monthly active users.
- **Self-hosted servers on other runtimes** (Keycloak). Mature and feature complete, running on
  the JVM, with extensions written in Java.
- **Go projects with copyleft or commercial tiers.** Zitadel moved to AGPL-3.0 with its v3
  release (2025) and Hanko's backend is AGPL-3.0; copyleft terms may not suit embedding in
  proprietary products. Ory Kratos and Hydra are Apache-2.0 and headless (no bundled UI), with
  SCIM, SAML, organization SSO and multi-tenancy primitives offered under the commercial Ory
  Enterprise License.
- **Projects with a different focus.** Authelia focuses on authentication for reverse proxies,
  Pocket ID on passkey-only sign-in, Dex on federating upstream identity providers, and session
  libraries such as limen on in-application session authentication rather than acting as an
  OAuth or OpenID Connect authorization server.

## Market analysis

Facts below were collected in October 2026 from each project's public documentation and may
change. Corrections are welcome through an issue or pull request. Product names are trademarks
of their respective owners; their mention does not imply affiliation or endorsement.

| Project | Language | License | Notes relevant to Clavis |
|---|---|---|---|
| Keycloak | Java | Apache-2.0 | JVM-based; extensions through Java service provider interfaces |
| Amazon Cognito | Managed service | Proprietary | Hosted only; no password hash export; priced per monthly active user |
| Zitadel | Go | AGPL-3.0 (since v3) | Event-sourced architecture; PostgreSQL as the standard database |
| Ory Kratos + Hydra | Go | Apache-2.0, plus commercial OEL | Separate services, headless; some B2B features in the commercial license |
| Authelia | Go | Apache-2.0 | Focused on reverse-proxy authentication |
| Casdoor | Go + React | Apache-2.0 | Standalone server with a web UI and a broad built-in feature set |
| Pocket ID | Go | BSD-2-Clause | Passkey-only OpenID Connect provider |
| Hanko | Go | AGPL-3.0 (backend) | Passkey-focused authentication and user management |
| Dex | Go | Apache-2.0 | Federation-focused OpenID Connect provider built around upstream connectors |
| limen | Go library | MIT | Session authentication library; not an authorization server |

Sources:
- Zitadel license change: https://zitadel.com/blog/apache-to-agpl
- Ory Enterprise License: https://www.ory.com/docs/oel/kratos/intro
- Hanko license: https://github.com/teamhanko/hanko
- Pocket ID: https://github.com/pocket-id
- limen: https://github.com/thecodearcher/limen
- Cognito user migration: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-migrate-user.html

**Gap:** in our research we did not find a permissively licensed Go project that is
simultaneously an embeddable library and a single-binary server, a conformance-tested OpenID
Connect and OAuth 2.1 authorization server, complete with business features in its open source
core, and aligned with AI agent authorization as defined by the Model Context Protocol
authorization specification (revision 2026-07-28).

## Product pillars

1. **Two modes, one codebase.** The same code runs embedded (`import` the module and mount
   `http.Handler`s) or standalone (`clavis serve`). It starts with embedded SQLite and no other
   dependency, and scales horizontally on PostgreSQL. Footprint targets: binary under 40 MB,
   idle resident memory under 50 MB, cold start under one second.
2. **Permissive license, no paid tier.** Apache-2.0. Organizations, enterprise SSO, SCIM and
   multi-tenancy belong to the open source core. There is no enterprise edition.
3. **Agent-ready authorization server.** OAuth 2.1 with authorization server metadata
   (RFC 8414), protected resource metadata helpers for resource servers (RFC 9728), resource
   indicators (RFC 8707), Client ID Metadata Documents with Dynamic Client Registration
   (RFC 7591) as a fallback, token exchange with `act` delegation claims (RFC 8693), OpenID
   Client Initiated Backchannel Authentication for human-in-the-loop approvals, and DPoP
   sender-constrained tokens (RFC 9449). AI agents are first-class identities.
4. **Leave-Cognito toolkit.** Lazy migration connectors verify a password once against Cognito
   or another legacy identity provider, then store a native hash, so users never reset their
   passwords. Bulk import understands bcrypt, Firebase scrypt, Keycloak PBKDF2 and argon2.
5. **Programmable flows in any language.** Lifecycle hooks (pre-signup, post-confirmation,
   pre-token generation, post-authentication) run as signed HTTP webhooks following the
   Standard Webhooks specification, or as sandboxed in-process WebAssembly modules executed by
   wazero without CGo.
6. **Passkeys first, standards rigor.** WebAuthn with conditional UI and passkey upgrade
   prompts, the OAuth 2.0 Security Best Current Practice (RFC 9700), Pushed Authorization
   Requests (RFC 9126), the OpenID Foundation conformance suite running in CI from the first
   protocol commit, and a FIPS 140-3 mode through the validated Go Cryptographic Module
   (`GOFIPS140=certified`).
7. **Config as code.** Tenants, clients, branding and policies can be declared in YAML and
   reconciled with `clavis plan` and `clavis apply`. Everything is also reachable through an
   OpenAPI 3.1 admin API, so SDKs can be generated for any language.

## Target users

- Application developers who want hosted login pages and standard OpenID Connect without
  writing authentication code.
- Go developers who want authentication inside their binary with no extra service to run.
- SaaS teams that need organizations, per-organization SSO and SCIM without an enterprise
  license.
- Teams migrating away from Cognito, Auth0, Firebase Authentication or Keycloak.
- Builders of AI agents and MCP servers that need a compliant authorization server.

## Concept map

| Amazon Cognito | Keycloak | Clavis |
|---|---|---|
| User pool | Realm | Tenant |
| App client | Client | Client |
| Group | Group / role | Group / role |
| Lambda trigger | SPI / event listener | Hook (webhook or WASM) |
| Managed login (hosted UI) | Login theme | Hosted UI with theming |
| Identity pool | (none) | Not built in; documented OIDC federation to AWS STS and GCP Workload Identity Federation |
| Custom attributes | User attributes | Tenant-scoped user metadata with a JSON Schema |

## Non-goals

- A fine-grained authorization engine. Clavis issues identity and coarse-grained roles and
  permissions; relationship-based or policy-based authorization should use OpenFGA or Cedar.
- An LDAP server.
- A password manager or secret vault.
- An API gateway.
- Issuing cloud provider credentials directly.
