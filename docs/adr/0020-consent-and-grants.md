# 0020. Consent and grants

- Status: Accepted
- Date: 2026-10-17

## Context

ADR 0013 makes consent a step of the interaction that answers an authorization request, after
the user signs in. Until now Clavis had no consent step: any client of a tenant received a
code as soon as the user signed in, and with single sign-on even without a sign-in. OpenID
Connect Core 1.0 expects the provider to obtain the user's consent before it releases
information to a client (section 3.1.2.4). `prompt=consent` asks for it explicitly, and
`prompt=none` must fail with `consent_required` when consent is needed (section 3.1.2.6).

Clients already have a `SkipConsent` setting, for first-party applications whose operator
decides on behalf of the users. Users must also be able to withdraw consent.

## Decision

- **Grants.** A grant records the scopes that a user allowed a client, one grant per user and
  client within a tenant. Allowing a request adds its scopes to the grant. A claim requested
  individually through the `claims` parameter counts as the scope that carries it.
- **When to ask.** A request needs consent when the client does not skip consent and the
  request asks for a scope that the grant lacks. `prompt=consent` always asks, also for
  clients that skip consent, because the client requested it.
- **prompt=none.** A request that needs consent and forbids interaction fails with
  `consent_required`.
- **The page.** The consent page comes after the user authenticates, through the sign-in form
  or an existing session. It names the client, the account and each requested scope, and
  offers to allow or deny. Denying ends the request with `access_denied`.
- **Binding.** The stored request records the session that authenticated it. The decision
  must come from the browser that started the request (ADR 0013), while that session is
  still its session.
- **Revocation.** Revoking a grant deletes it and revokes the tokens issued to the client for
  the user: today the access token records, from work item 2.3 the refresh tokens too. The
  next request asks again. Operators revoke grants with the CLI now; users get a page for it
  with the account pages of milestone 3.
- **Lifecycle.** Deleting a user or a client deletes its grants.

## Consequences

- Single sign-on no longer releases information to a client the user never approved.
- First-party clients keep a sign-in without an extra page.
- A client that asks for more scopes later shows the page again, for the whole request.
- Each authorization request reads one grant; a cache can come later without changing the
  model.
