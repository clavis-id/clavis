# 0019. Authentication context class references

- Status: Accepted
- Date: 2026-10-17

## Context

OpenID Connect describes how strongly a user authenticated with the `acr` claim, an
authentication context class reference (OpenID Connect Core 1.0, section 2). Clients ask for
a class with the `acr_values` parameter (section 3.1.2.1), or require one by requesting `acr`
as an essential claim through the `claims` parameter (section 5.5.1.1). Providers list the
values they support in `acr_values_supported` (OpenID Connect Discovery 1.0, section 3).

ADR 0013 already gives every session an `acr`, and makes single sign-on depend on it: a request
that needs a stronger authentication than the session has must authenticate the user again.
Today Clavis signs users in with a password only. TOTP and passkeys arrive in milestone 4 of
the Phase 1 plan.

The values are public: they appear in the provider metadata and in tokens, and clients compare
them as strings. Options considered:

- Numeric levels such as `1` and `2`, as in Keycloak's default configuration. They are short,
  but their meaning is a convention of each provider.
- URNs in an unregistered namespace. RFC 8141 requires namespaces to be registered.
- Absolute URIs under a domain the project controls. They are unique and describe themselves.
- `phr` and `phrh` from OpenID Extended Authentication Profile (EAP) ACR Values 1.0, which
  define phishing-resistant authentication. No registered value describes a password alone or
  a password with a second factor.

## Decision

- **Values.** Clavis uses absolute URIs under `https://clavisid.org/acr/`, plus the EAP values
  for phishing-resistant authentication:
  - `https://clavisid.org/acr/password`: a password alone. Available now.
  - `https://clavisid.org/acr/mfa`: a password and a second factor. Milestone 4.
  - `phr`: a phishing-resistant method, such as a passkey. Milestone 4.
  - `phrh`: phishing-resistant and protected by hardware. Milestone 4, once Clavis can tell
    such authenticators apart.

  The URIs identify classes; they need not resolve.
- **Metadata.** `acr_values_supported` lists only the values Clavis can produce.
- **Tokens.** A session records the `acr` of the sign-in that created it. ID tokens and JWT
  access tokens always carry it.
- **acr_values.** The parameter is a voluntary request (section 3.1.2.1): Clavis answers with
  the `acr` of the session. From milestone 4, when a requested value names a stronger class
  than the session has and the user can complete it, single sign-on yields to a new
  authentication, as ADR 0013 states.
- **Essential acr.** When the `claims` parameter requests `acr` as essential with values that
  Clavis cannot produce, the request fails with `access_denied` (section 5.5.1.1).
- **Changes.** Adding a value is compatible. Changing the meaning of a value needs a new ADR.

## Consequences

- Clients can recognize the values without a provider-specific table, and can require a class
  with the parameters the specifications define.
- The order of strength is a Clavis convention: password, then mfa, then phr, then phrh. A
  client that needs a minimum lists every value it accepts.
- Until milestone 4 there is one class, so `acr_values` cannot change the outcome of a
  request; it is accepted and the answer carries the password class.
- The project may later publish a page at each URI that describes its class.
