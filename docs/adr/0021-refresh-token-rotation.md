# 0021. Refresh token rotation

- Status: Accepted
- Date: 2026-10-17

## Context

ADR 0014 sets the shape of refresh tokens: opaque 256-bit values stored as SHA-256 hashes,
rotated on every use, grouped in one family per grant, with reuse revoking the whole family and
no grace period; 7 days of inactivity and 30 days in all by default. Implementing them leaves
questions that ADR 0014 does not answer:

- When an OpenID Connect request gets a refresh token. OpenID Connect Core 1.0, section 11,
  ties refresh tokens to the `offline_access` scope and asks for `prompt=consent` unless other
  conditions permit offline access.
- What a refresh response contains. RFC 6749, section 6, lets the request narrow the scope, and
  OpenID Connect Core 1.0, section 12.2, sets rules for an ID token, which is optional.
- How rotation, reuse detection and revocation behave when requests race: two refreshes with
  the same token, a code replayed during its exchange, a refresh during a grant revocation.

## Decision

- **Issuance.** The code exchange issues a refresh token when the client may use the
  `refresh_token` grant and either the request is an OAuth request without `openid`, or it was
  granted `offline_access`. Consent (ADR 0020) lists `offline_access` exactly when the client
  gets a refresh token: also for an OAuth request, which gets one without asking, and never for
  a client that may not use the `refresh_token` grant. The page describes it as keeping access
  while the user is signed out, and the grant records it. A grant that includes it, or a client
  that skips consent by operator policy, is the condition that permits offline access, so
  `prompt=consent` is not required. Without a refresh token, `offline_access` is left out of
  the granted scope. The client credentials grant never issues refresh tokens (RFC 6749,
  section 4.4.3).
- **Families.** Each code exchange starts a family. The family keeps what the grant gave: the
  user, the client, the scopes, the authentication (`auth_time`, `acr`, `amr`), the claims the
  request named, the code and the session in which the user authenticated. A token keeps only
  its hash, its issue and expiry times, and when it was replaced.
- **Rotation.** A refresh replaces the current token in one transaction: it moves the idle
  expiry of the family, marks the old token as replaced and inserts the new one. A token
  expires after the idle lifetime, but never after the absolute expiry of its family.
- **Reuse.** Presenting a replaced token revokes its family and the access tokens that derive
  from its code (RFC 9700, section 4.14.2). Two refreshes with the same token at the same
  moment are reuse too: one rotation succeeds, the other revokes the family, and the tokens of
  the first response stop working. There is no grace period (ADR 0014).
- **Write order.** Tokens are recorded before the step that makes them valid: the access token
  and the family before the code is redeemed, and the access token before the refresh token is
  rotated. A concurrent replay can only find the code redeemed, or the token rotated, after
  the tokens exist, so its revocation reaches them. Revoking a grant revokes the families
  before the access tokens for the same reason.
- **Refresh response.** The request may narrow the scope of the new access token; the family
  keeps the scope it was granted, and a scope outside it fails with `invalid_scope`. When the
  new access token grants `openid`, the response has an ID token with the original `iss`,
  `sub`, `aud`, `auth_time`, `acr` and `amr`, a new `iat` and `exp`, and no `nonce` (OpenID
  Connect Core 1.0, section 12.2). Claims about the user come from the current profile.
- **Checks.** The token must have been issued to the authenticated client, its family must not
  be revoked or expired, the client must still allow the `refresh_token` grant, and the user
  must be active.
- **Lifecycle.** A replayed code, a revoked grant and a deleted user or client end families.
  Ending a browser session does not: offline access outlives the session. Families record the
  session so that RP-initiated logout (Phase 1, work item 2.5) can decide what ending a session
  revokes. The cleanup job deletes expired tokens and families.

## Consequences

- Clients must keep the refresh token of each response. A client that retries a refresh with a
  token it already used loses the family, and the user must sign in again.
- A stolen refresh token works only until the legitimate client refreshes again; whichever of
  the two comes second revokes the family.
- A replaced token stays stored until it would have expired, also in a revoked family, so
  presenting it again until then is recognized as reuse and logged. Afterwards it is unknown
  and refused like any invalid token.
- Revocation and introspection (work item 2.4) can act on a refresh token through its family.
