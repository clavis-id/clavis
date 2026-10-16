# 0013. Authorization requests and browser sessions

- Status: Accepted
- Date: 2026-10-14

## Context

Between the authorization request and the redirect back to the client, Clavis must
authenticate the user and may ask for consent. These steps run in the hosted UI today and in
custom interfaces later (ADR 0007). Several tenants can share one host, Clavis can be embedded
under a path, and several instances can share one database. Single sign-on needs a session
that outlives one authorization request.

## Decision

- **Validation.** `/oauth2/authorize` validates the whole request before any user
  interaction.
  - An invalid client or redirect URI shows an error page and never redirects (RFC 6749,
    section 4.1.2.1).
  - Other errors redirect to the client with `error`, `state` and `iss` (RFC 9207).
- **Stored authorization requests.** A valid request is stored server side. The record holds:
  - a random 128-bit identifier;
  - the tenant, the client and the validated parameters;
  - an expiry of 10 minutes;
  - the progress of the interaction: the authenticated user, `auth_time`, `amr` and the
    consent decision.

  The browser moves through the hosted pages carrying only the identifier.
- **Browser binding.** A stored request is bound to the browser that started it. A `__Host-`
  cookie carries a random value, and the request stores its hash. Pages reject the request
  from any other browser, so an attacker cannot make a victim complete an authorization the
  attacker started.
- **Interaction steps.** Login and consent are steps of the interaction. When the last step
  completes, Clavis issues the authorization code and redirects to the client. A later phase
  exposes the same steps through an API for custom interfaces.
- **Sessions.** Browser sessions are server-side records per tenant. A session holds the
  user, `auth_time`, `amr`, `acr`, the creation and last-seen times, and expiry.
- **Session cookie.**
  - There is one cookie per tenant. Its name is derived from the tenant ID, so tenants on one
    host never share a session.
  - The value is 256 random bits, stored as a SHA-256 hash.
  - The cookie is `__Host-` prefixed, `Secure`, `HttpOnly`, `SameSite=Lax` and `Path=/`.
- **Session lifetime.** The defaults are 24 hours idle and 14 days absolute, configurable per
  tenant.
- **Single sign-on.** A valid session satisfies login for any client of the same tenant,
  unless the request carries `prompt=login`, the `max_age` is exceeded, or the request needs
  a stronger authentication than the session has.
- **Logout.** RP-Initiated Logout ends the session. Back-channel logout arrives in Phase 2.
- **Browser protections.** State-changing pages use `http.CrossOriginProtection`, and every
  page sends a strict Content Security Policy with `frame-ancestors 'none'`.

## Consequences

- The flow works across instances because all state lives in the database, and it works
  embedded because cookies are scoped to the host, not to the mount path.
- `__Host-` cookies require HTTPS. Browsers treat `http://localhost` as secure, so local
  development keeps working.
- Each request with a session costs a database read. A cache can be added later without
  changing the model.
- Custom interfaces become an API over existing steps rather than a second implementation.
