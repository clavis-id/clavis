# 0014. Tokens, API resources and client credentials

- Status: Accepted; the PKCE policy is superseded by [0018](0018-pkce-exemption-is-a-client-setting.md)
- Date: 2026-10-14

## Context

Phase 1 issues authorization codes, ID tokens, access tokens and refresh tokens, and
authenticates clients at the token endpoint.

- RFC 9068 requires an `aud` claim in JWT access tokens, but resource indicators (RFC 8707)
  only arrive in Phase 3.
- The security rules require PKCE. RFC 9700, section 2.1.1, lets a confidential client skip
  PKCE when it uses the OpenID Connect nonce correctly, and the OpenID conformance suite may
  rely on that.
- Client secrets must be stored so that a database copy does not reveal them.

## Decision

- **Authorization codes.**
  - 256 random bits, stored as a SHA-256 hash, single use, valid for 60 seconds.
  - Bound to the client, the redirect URI, the PKCE challenge, the nonce and the
    authorization request.
  - A second use revokes the tokens issued from the code (RFC 6749, section 4.1.2;
    RFC 9700, section 4.5).
- **PKCE.**
  - Only `S256` is accepted.
  - Public clients always require PKCE.
  - Confidential clients require it by default. A confidential client may be configured to
    accept OpenID Connect requests without PKCE only when they carry a nonce.
  - A request that sends `code_challenge` is always held to it, which prevents downgrade
    (RFC 9700, section 4.8).
- **API resources.** A tenant registers API resources, each with an identifier (a URI) and the
  scopes it defines.
- **Access tokens.**
  - JWTs per RFC 9068 (`typ: at+jwt`), signed with the tenant key.
  - Claims: `iss`, `sub`, `aud`, `exp`, `iat`, `jti`, `client_id` and `scope`, plus
    `auth_time`, `acr` and `amr` when a user is present.
  - `aud` lists the API resources whose scopes were granted. When only OpenID Connect scopes
    are granted (`openid`, `profile`, `email`, `address`, `phone`), `aud` is the tenant
    issuer, which serves userinfo. RFC 8707 `resource` support arrives in Phase 3.
  - Default lifetime: 10 minutes.
- **ID tokens.**
  - Follow OpenID Connect Core 1.0, including `at_hash`.
  - Signed with RS256 by default, or with another algorithm enabled for the tenant when the
    client asks for it.
  - Default lifetime: 10 minutes.
- **Refresh tokens.**
  - Issued with `offline_access`, or by client policy for OAuth-only clients.
  - Opaque 256-bit values, stored as SHA-256 hashes, rotated on every use.
  - Each token belongs to a family, one per grant. Reusing a rotated token revokes the whole
    family (RFC 9700, section 4.14.2). There is no grace period.
  - Defaults: 7 days idle, 30 days absolute.
- **Lifetimes** are configurable per client within bounds that the configuration validates.
- **Client secrets.**
  - Clavis generates them (256 random bits, base64url) and shows them once. It never accepts
    a secret chosen by the operator.
  - They are stored as SHA-256 hashes and compared in constant time. Their entropy makes a
    slow hash unnecessary, and SHA-256 is FIPS approved.
- **Client authentication in Phase 1:** `client_secret_basic`, `client_secret_post`, and
  `none` for public clients. `private_key_jwt` arrives with the FAPI-oriented work.

## Consequences

- Resource servers validate access tokens locally with the JWK set and check `aud` against
  their own identifier.
- Tokens cannot be listed or recovered from the database. Revocation works on hashes and
  token families.
- Short access token lifetimes make revocation of JWTs less pressing; introspection serves
  resource servers that need immediate revocation.
- The PKCE exception is opt-in per client, documented, and used only where the conformance
  suite requires it.
