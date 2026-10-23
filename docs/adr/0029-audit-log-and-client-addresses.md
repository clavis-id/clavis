# 0029. Audit log and client addresses

- Status: Accepted
- Date: 2026-10-22

## Context

Work item 3.5 of the Phase 1 plan asks for an audit log of authentication, account and client
events. Reviews of earlier work items added what it must cover:

- failed sign-ins, without credential material;
- client creation, deletion and secret rotation, including the exemption from PKCE that ADR
  0018 requires to be audited;
- consent decisions and grant revocations (ADR 0020);
- refresh token reuse and replayed codes (ADR 0021);
- token revocations by clients (ADR 0022).

Until now these are log lines, which operators may not keep and cannot query per user. An
event should also say where its request came from, and behind a reverse proxy the address of
the connection is the proxy's. Three questions are open: what an event holds, how long events
stay, and which address a request has.

## Decision

- **Events.** Each event belongs to a tenant and records:
  - an ID (a UUIDv7, so IDs sort by time), the time and the type;
  - the actor;
  - the user the event is about, the client and the browser session, when there are any;
  - the IP address and user agent of the request;
  - details, as pairs of strings.

  Events are stored with the other records of the tenant and deleted with the tenant. They
  outlive the user, client and session they name, which they refer to without foreign keys.
- **Types.**

  | Type | Recorded when | Details |
  |---|---|---|
  | `user.signed_in` | A password sign-in for an authorization request, for the account pages, or right after a signup | `method` |
  | `user.sign_in_failed` | A wrong password, an unknown address, a disabled account, or a password changed during the sign-in (ADR 0027) | `method`, `reason`: `invalid_credentials` or `user_disabled` |
  | `user.signed_out` | RP-Initiated Logout, the account sign-out, or another user who signs in on the browser | `reason`: `another_user_signed_in` for the last |
  | `user.created`, `user.deleted` | An operator creates or deletes a user, or a signup creates one | |
  | `user.password_changed` | The account pages, a reset or an operator set a password | `how`: `account`, `reset` or `operator` |
  | `user.password_change_failed` | The account pages get a wrong current password | `reason` |
  | `user.profile_updated` | A user saves a changed profile | `claims`: the names of the changed claims |
  | `consent.allowed`, `consent.denied` | A user answers the consent page | `scopes` |
  | `grant.revoked` | A user or an operator revokes a grant | |
  | `token.revoked` | A client revokes a token | `token_type`, and `jti` or `refresh_token_family` |
  | `token.refresh_token_reused` | A replaced refresh token is presented | `refresh_token_family` |
  | `token.code_replayed` | A redeemed code is presented | |
  | `client.created` | An operator creates a client | `type`, `pkce_exempt`, `skip_consent` |
  | `client.deleted`, `client.secret_rotated` | An operator deletes a client or rotates its secret | |
  | `tenant.updated` | An operator changes the name or the signup setting of a tenant | the changed fields |

  Single sign-on with an existing session and the issuance of tokens are not events: the
  sign-in that started the session is. The log keeps recording both.
- **Actors.** An event names one of four actors:
  - `user`: the user, for example at sign-in or on the account pages;
  - `client`: a client at the token or revocation endpoint;
  - `operator`: the CLI now, and the admin API later;
  - `anonymous`: whoever failed to sign in, or signed the previous user out of a browser.

  The work of an operator is marked on its context, which wins over the actor that a use case
  names. A request never acts as an operator.
- **No credential material.** Events never hold passwords, codes, tokens or cookies. A failed
  sign-in names the user that the typed address belongs to, if any, but never the address
  itself: input that matches no account may be a password typed into the wrong field. A profile
  event names the changed claims, not their values. The user agent is kept without control
  characters and up to 256 bytes.
- **Best effort.** When the store refuses an event, the error is logged and the work stands:
  the event has happened, and failing the request would not undo it.
- **Retention.** The periodic cleanup also deletes events older than `audit.retention`, 90
  days by default; 0 keeps events forever. Embedders set `clavis.Config.AuditRetention`, where
  zero takes the default and a negative value keeps events forever.
- **Client address.** The address of a request is that of its connection, unless the
  connection comes from a trusted proxy (`server.trusted_proxies`, networks or addresses;
  `clavis.Config.TrustedProxies`).
  - From a trusted proxy, X-Forwarded-For names the client. Each proxy appends the address it
    received the request from, so the header is read from the right, over trusted proxies, and
    the first other address is the client. Addresses further left were sent by the client.
  - When every address is a trusted proxy, the leftmost one is the client. An entry that is not
    an address ends the search at the trusted proxy that forwarded it.
  - Without trusted proxies the header is ignored, so a client cannot choose its address.
    The `Forwarded` header of RFC 7239 is not read.

  The rate limits of work item 3.5 use the same address.
- **Reading.** `clavis audit list` shows the events of a tenant, newest first. It filters by
  user (address, or ID for a deleted user) and by type, pages with `--before`, and writes JSON
  Lines with `--json`. The admin API of milestone 5 adds access over HTTP.

## Consequences

- Operators can see who signed in, from where, and what changed, per user and per tenant.
- Every sign-in, successful or not, writes a row. The table grows with traffic, bounded by the
  retention; the rate limits of work item 3.5 bound failed attempts.
- An event can be missing when the store fails after the work it records; the log then has
  the error.
- A `trusted_proxies` setting that misses a proxy gives requests the proxy's address; one that
  includes networks of clients lets them choose their address. Operators list only their
  proxies.
- Deleting a tenant deletes its events. Changes to branding and API resources, and the creation
  and deletion of tenants, are not events yet: the admin API (milestone 5) audits
  administration as a whole.
