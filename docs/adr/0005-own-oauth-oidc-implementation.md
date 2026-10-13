# 0005. Own OAuth 2.1 and OpenID Connect implementation

- Status: Accepted
- Date: 2026-10-12

## Context

Options considered for the authorization server core:

- `ory/fosite`: flexible, security-focused framework; as of October 2026 it had no tagged
  release in the previous twelve months.
- `zitadel/oidc` (`op` package): Apache-2.0 and OpenID certified for the Basic and Config
  profiles. Its README feature table (October 2026) does not list PAR, DPoP, CIBA or Client ID
  Metadata Documents for the server side, it defines its own storage interface, and a new major
  version is in development.
- Own implementation on top of audited JOSE primitives.

The protocol layer is the core of the product, and the agent-ready pillar requires features
that, as far as their documentation shows, existing libraries do not provide today.

## Decision

Clavis implements its OAuth 2.1 and OpenID Connect endpoints in `internal/oauth` and
`internal/oidc`, using `github.com/go-jose/go-jose/v4` for JOSE and the standard library for
cryptographic primitives. No cryptographic primitive is implemented in Clavis.

## Consequences

- Full control over features, storage model and error handling.
- Higher correctness risk, mitigated by mandatory gates: the OpenID conformance suite in CI,
  interoperability tests with independent client libraries, RFC 9700 threat tests, fuzzing of
  every parser of untrusted input, and an external audit before v1.0.
- Protocol changes require more review than other changes.
