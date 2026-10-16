# 0018. PKCE exemption is a client setting

- Status: Accepted
- Date: 2026-10-14
- Supersedes: the PKCE bullet of ADR 0014

## Context

ADR 0014 lets a confidential client skip PKCE only for OpenID Connect requests that carry a
nonce. Work item 1.2 checked the OpenID conformance suite (release v5.3.3) and found two facts
about the Basic OP plan:

- Its tests build authorization requests with `state` and `nonce` but without
  `code_challenge`. Only `oidcc-ensure-request-with-valid-pkce-succeeds` adds PKCE.
- It includes `oidcc-ensure-request-without-nonce-succeeds-for-code-flow`, which sends neither
  `nonce` nor PKCE and must succeed. OpenID Connect Core 1.0, section 3.1.2.1, makes `nonce`
  optional in the code flow.

Under ADR 0014 this test fails, so Clavis could not pass the plan. RFC 9700, section 2.1.1,
frames the exception as an assurance about the client: it is confidential, and it correctly
implements the nonce mechanism. It is not a property of each request.

## Decision

- **Method.** Only `S256` is accepted; `plain` is rejected.
- **Public clients** always require PKCE.
- **Confidential clients** require PKCE by default. An operator may turn this off for a
  confidential client that is known to validate the OpenID Connect nonce. Authorization code
  requests from that client are then accepted without `code_challenge`, whether or not they
  carry a nonce.
- **Downgrade protection.** A request that sends `code_challenge` is always held to it at the
  token endpoint, whatever the client setting (RFC 9700, section 4.8).
- **Visibility.** The setting is shown when clients are listed, recorded in the audit log when
  it changes, and the CLI warns when it is turned off.
- **Conformance.** The conformance suite clients turn it off.

## Consequences

- Clavis can pass the Basic OP plan as published.
- The secure behavior stays the default; weakening it is an explicit, visible, per-client
  decision, in line with the "secure defaults" principle.
- A client with PKCE turned off relies on its own nonce validation against authorization code
  injection.
