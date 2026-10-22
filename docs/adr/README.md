# Architecture decision records

Each record captures one decision with lasting consequences: the context, the decision and its
trade-offs. Records are immutable once accepted; a later record supersedes an earlier one
instead of editing it.

Template: copy [`0000-template.md`](0000-template.md), take the next number, and open a pull
request. Status values: Proposed, Accepted, Superseded by NNNN, Deprecated.

| Number | Title | Status |
|---|---|---|
| [0001](0001-record-architecture-decisions.md) | Record architecture decisions | Accepted |
| [0002](0002-go-baseline-and-stdlib-first.md) | Go 1.27 baseline and stdlib-first dependency policy | Accepted |
| [0003](0003-apache-license-without-open-core.md) | Apache-2.0 without an open-core tier | Accepted |
| [0004](0004-dual-mode-library-and-binary.md) | Dual mode: embeddable library and single binary | Accepted |
| [0005](0005-own-oauth-oidc-implementation.md) | Own OAuth 2.1 and OpenID Connect implementation | Accepted |
| [0006](0006-storage-ports-sqlite-postgres.md) | Storage ports with SQLite and PostgreSQL adapters | Accepted |
| [0007](0007-hosted-ui-templ-htmx.md) | Hosted UI with templ and htmx | Accepted |
| [0008](0008-hooks-webhooks-and-wasm.md) | Hooks as webhooks and WebAssembly modules | Accepted |
| [0009](0009-per-tenant-issuer.md) | Multi-tenancy with a per-tenant issuer | Accepted |
| [0010](0010-module-path.md) | Module path github.com/clavis-id/clavis | Superseded by 0012 |
| [0011](0011-signing-key-lifecycle.md) | Signing key lifecycle and encryption at rest | Accepted; retention default superseded by 0023 |
| [0012](0012-vanity-import-path.md) | Vanity import path clavisid.org/clavis | Accepted |
| [0013](0013-authorization-requests-and-browser-sessions.md) | Authorization requests and browser sessions | Accepted |
| [0014](0014-tokens-api-resources-and-client-credentials.md) | Tokens, API resources and client credentials | Accepted; PKCE policy superseded by 0018 |
| [0015](0015-password-hashing-and-fips-mode.md) | Password hashing and FIPS mode | Accepted |
| [0016](0016-administration-and-the-admin-tenant.md) | Administration and the admin tenant | Accepted |
| [0017](0017-openid-conformance-suite-in-ci.md) | OpenID conformance suite in CI | Accepted |
| [0018](0018-pkce-exemption-is-a-client-setting.md) | PKCE exemption is a client setting | Accepted |
| [0019](0019-authentication-context-class-references.md) | Authentication context class references | Accepted |
| [0020](0020-consent-and-grants.md) | Consent and grants | Accepted |
| [0021](0021-refresh-token-rotation.md) | Refresh token rotation | Accepted |
| [0022](0022-revocation-and-introspection.md) | Revocation and introspection | Accepted |
| [0023](0023-logout-and-form-post.md) | Logout and the form post response mode | Accepted; ignoring ui_locales superseded by 0025 |
| [0024](0024-email-delivery.md) | Email delivery | Accepted |
| [0025](0025-internationalization-and-theming.md) | Internationalization and theming | Accepted |
| [0026](0026-signup-and-email-verification.md) | Signup and email verification | Accepted |
| [0027](0027-password-reset.md) | Password reset | Accepted |
