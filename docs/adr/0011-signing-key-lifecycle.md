# 0011. Signing key lifecycle and encryption at rest

- Status: Accepted; the retention default is superseded by [0023](0023-logout-and-form-post.md)
- Date: 2026-10-13

## Context

Every token Clavis issues is signed with a tenant key. Keys must rotate without breaking
relying parties that cache the JWK set, several instances may share one database, and a copy
of the database must not expose private keys. Embedders need to choose where the key
encryption key lives, including a key management service later.

## Decision

- Each tenant has one key sequence per JWS algorithm. RS256 (RSA 2048) is always enabled
  because OpenID Connect requires it; ES256 (P-256) and EdDSA (Ed25519) are optional.
- A key's schedule is fixed at creation: it is published immediately, signs from
  `activates_at` to `retires_at`, and stays published until `expires_at`. Defaults: 30-day
  rotation period, successor published 24 hours ahead, retired keys kept for 48 hours.
- Rotation runs at startup and on an interval (default one hour, which must be shorter than the
  publish-ahead period). After an outage longer than a key's life, a replacement activates
  immediately.
- A `generation` number, unique per tenant and algorithm, makes concurrent rotations from
  several instances converge on one key: the losing insert gets a conflict and is ignored.
- The key ID (`kid`) is the RFC 7638 JWK thumbprint (SHA-256, base64url).
- Private keys are stored as PKCS #8 encrypted through the public `kek.Encrypter` interface.
  The built-in `kek.Local` uses AES-256-GCM with a random nonce. The additional data binds each
  ciphertext to its tenant, record ID and algorithm, so a ciphertext copied to another record
  fails to decrypt. Previous key encryption keys stay available for decryption, so the primary
  can rotate without re-encrypting stored keys first.
- The key encryption key is mandatory in both embedded and standalone modes; there is no
  insecure default. Its identifier is derived from a truncated SHA-256 of the secret.
- The JWK set is served at `/oauth2/jwks` as `application/jwk-set+json` with a five-minute
  cache lifetime, far below the publish-ahead period.

## Consequences

- Relying parties that refresh the JWK set at least every 24 hours never see an unknown `kid`.
- Losing the key encryption key makes stored keys unreadable; Clavis then needs new keys, and
  previously issued tokens can no longer be verified once their keys expire from caches. The
  operator documentation must say so.
- Decrypted private keys are cached in memory for the life of the process.
- A KMS-backed `kek.Encrypter` can be added without changing the storage format, since every
  ciphertext records the identifier of the key that produced it.
