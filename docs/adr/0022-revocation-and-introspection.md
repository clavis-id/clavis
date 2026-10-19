# 0022. Revocation and introspection

- Status: Accepted
- Date: 2026-10-19

## Context

Clients need to end a grant before its tokens expire, for example when a user signs out of an
application: RFC 7009 defines the revocation endpoint. Resource servers validate access tokens
locally with the JWK set (ADR 0014), which cannot tell a revoked token from a valid one; RFC
7662 defines the introspection endpoint, through which a resource server asks whether a token
is active.

Both endpoints receive tokens from callers that authenticate as clients. Introspection serves
resource servers, which are rarely the client a token was issued to, but it must not let any
client learn about the tokens of other clients (RFC 7662, section 4). The Phase 1 plan asks that
introspection reveal nothing about tokens of other clients unless policy allows it. Options
considered for that policy:

- Each client introspects only its own tokens. Resource servers would get nothing.
- A client setting lets a client introspect any access token of its tenant, as Keycloak does.
  It is simple, but a resource server could ask about tokens meant for other APIs.
- A client is registered as the server of API resources and introspects the access tokens
  issued for them, as Zitadel ties introspection to the API that a token is for.

## Decision

- **Endpoints.** `POST /oauth2/revoke` and `POST /oauth2/introspect` under each issuer, with the
  client authentication of the token endpoint. The provider metadata announces them (RFC 8414,
  section 2). Token types are told apart by form, an access token being a compact JWS and a
  refresh token opaque base64url, so `token_type_hint` is ignored, as both specifications
  allow.
- **Revocation.**
  - Any client may revoke the tokens issued to it; public clients identify themselves with
    `client_id` (RFC 7009, section 2.1). Revocation allows cross-origin requests, like the
    token endpoint.
  - Revoking a refresh token, current or already replaced, revokes its family and the access
    tokens issued from it (section 2.1, and ADR 0021).
  - Revoking an access token revokes that token only. Its refresh token family stays, which
    section 2.1 allows.
  - A token that is invalid, unknown or of another tenant needs nothing, and the answer is
    200 with an empty body (section 2.2). A token issued to another client fails
    with `unauthorized_client`.
- **Who may introspect.**
  - Only confidential clients, because introspection must be authenticated (RFC 7662,
    section 2.1). A public client gets `invalid_client`.
  - A client may introspect the tokens issued to it.
  - A client may be registered as the server of API resources, by their identifiers
    (`clavis clients create --resource-server`). It may then introspect the access tokens
    whose audience includes one of those resources, and the response shows only those
    audiences and the scopes those resources define (RFC 7662, section 4). The issuer, the
    audience of tokens for userinfo, never counts as one of those resources, even when an API
    resource was registered under its identifier.
  - Refresh tokens can be introspected only by their client.
  - Every other token gets the response of an inactive token, so the response does not reveal
    whether it exists.
- **What is active.** An access token is active when its signature, type and issuer are
  valid, it has not expired or been revoked, and its user, if any, is active. A refresh token
  is active when it is the current token of its family, the family is neither revoked nor
  expired, and the user is active. Introspection has no side effects: a replaced refresh token
  is inactive, and introspecting it is not reuse.
- **Response.** An active access token reports `active`, `scope`, `client_id`, `token_type`
  (`Bearer`), `exp`, `iat`, `sub`, `aud`, `iss` and `jti`. An active refresh token reports
  `active`, `scope`, `client_id`, `exp`, `iat`, `sub` and `iss`. An inactive token reports
  only `"active": false`.
- **Registration.** Resource servers are registered by resource identifier, checked when the
  client is created. Deleting a resource leaves the identifier with the client; tokens issued
  for it until then remain introspectable by that client, and a resource registered again
  under the same identifier keeps its server.

## Consequences

- A resource server that needs immediate revocation introspects; others keep validating JWTs
  locally and accept tokens until they expire, 10 minutes by default.
- Clients can end offline access themselves, for example when a user signs out of an
  application, without the grant being revoked (ADR 0020).
- A resource server that holds a token can already read its JWT claims; introspection adds
  whether the token is still active and keeps other APIs' audiences and scopes out of the
  response.
- Changing which resources a client serves needs the admin API (work item 5.2); until then the
  client is registered again.
