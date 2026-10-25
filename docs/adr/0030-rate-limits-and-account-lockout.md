# 0030. Rate limits and account lockout

- Status: Accepted
- Date: 2026-10-25

## Context

Work item 3.5 of the Phase 1 plan asks for in-process rate limits by IP address and account,
and for an account lockout stored in the database that does not enable enumeration. Reviews
of earlier work items added what the limits must cover:

- sign-in attempts: a stored authorization request accepts any number of passwords during its
  10 minutes, and anyone can start new requests (#50); the account sign-in and the password
  change of ADR 0028 verify passwords too (#84);
- messages per recipient address and per IP address, so that signup and reset cannot flood a
  mailbox, or the queue of ADR 0024 that every tenant shares (#74, #80);
- resets and wrong codes per account, counted across verifications and stored, because
  guessing the code of a reset takes the account (ADR 0027, #82);
- the token endpoint, and the revocation and introspection endpoints, which authenticate
  clients the same way; RFC 7662, section 4, warns against an introspection endpoint that is
  not throttled (#62, #64).

The maintainer chose a temporary lockout: ten wrong passwords for an account within 15
minutes, from any address, lock it for 15 minutes, answered like a wrong password. Addresses
without an account count too, and a reset unlocks. The client address of a request is the one
of ADR 0029. MFA endpoints come with milestone 4.

## Decision

- **Two kinds of limits.**
  - Limits per email address are stored in limit counters of the tenant, so they hold across
    the instances that share a store. They count the address that was typed, whether or not an
    account has it, so they reveal nothing about accounts. A counter is keyed by a SHA-256 hash
    of the normalized address and never holds the address itself.
  - Limits per client address are kept in the memory of each instance. They bound what one
    client address can do, across every account.
- **What counts.** The limits count what an attacker produces: wrong passwords, wrong codes,
  errors of the token endpoints, and messages, which cost whoever receives them. Right
  passwords and successful token requests do not count, so the people behind one address,
  such as an office, rarely meet a limit.
- **Limits per email address.**

  | Limit | Counts | Effect |
  |---|---|---|
  | 10 within 15 minutes | Wrong passwords: sign-ins for authorization requests and for the account pages, and the current password of a password change | The address is locked for 15 minutes after the tenth |
  | 10 within 24 hours | Wrong codes, across the email verifications of the address for signup and for reset | The codes of the address are refused for 24 hours after the tenth |
  | 5 within an hour | Messages of signup and reset | Messages are refused for an hour after the fifth |

  A counter starts with its first event and ends one window later; the event that reaches the
  limit moves the end to one window after it. Events during a lock do not extend it. A
  malformed address, which no account can have, is not counted.
- **Locked sign-ins.** A sign-in with a locked address does the work of a password
  verification and gets the answer of a wrong password, the right password too. A password change whose address is locked
  fails like a wrong current password. The audit log of ADR 0029 records
  `user.sign_in_locked` (with `until`) when wrong passwords lock the address of an account, and
  the reason `locked` for the sign-ins and password changes refused during the lock. Setting a
  password forgets the wrong passwords of the address: a reset, `clavis users set-password`
  or a password change.
- **Locked codes.** Links still work while the codes of an address are refused: they carry a
  256-bit token that cannot be guessed. The page of a refused code says so.
- **Limits per client address.**

  | Burst, then | Counts |
  |---|---|
  | 20, then one a minute | Wrong passwords, as above |
  | 10, then one a minute | Wrong codes |
  | 10, then one every two minutes | Messages of signup and reset |
  | 60, then one a second | Errors of the token, revocation and introspection endpoints, and inactive tokens that introspection reports |

  An IPv6 client counts by its /64 network, which one client usually holds whole. A client
  whose address is unknown is not limited. Links are not limited.
- **Algorithm.** The generic cell rate algorithm keeps one time per key: when the burst of the
  key is whole again. A key whose time has passed is forgotten. Each limit holds at most
  32,768 keys; beyond them, new addresses are not limited, because so many addresses are a
  distributed attack, which the limits per email address still bound. It needs no dependency:
  `golang.org/x/time/rate`, which the technology stack listed, keeps a limiter per key and
  would need the same eviction.
- **Responses.**
  - A hosted page whose client must wait answers 429 (RFC 6585, section 4) with `Retry-After`
    and a page that asks to wait a few minutes.
  - The token, revocation and introspection endpoints answer 429 with `Retry-After` and the
    JSON error `temporarily_unavailable`. OAuth 2.0 defines no error for this case; RFC 6749
    defines this code for the authorization endpoint, and clients treat it as any error.
  - Too many messages to an address, and the refused codes of an address, answer 429 with a
    page that says so, the same for every address.
- **Fixed values.** The limits are constants in this release. Tenant settings for them can
  come with the admin API (milestone 5), and MFA endpoints (milestone 4) use the same
  counters.

## Consequences

- Guessing the password of one account allows 10 tries per 15 minutes, about 1,000 a day,
  from any number of addresses. One client address gets 20 wrong passwords, then 60 an hour,
  across every account.
- Anyone who knows an address can lock its account for 15 minutes, and keep it locked with ten
  tries every 15 minutes. The user ends the lock with a reset, and an operator with
  `clavis users set-password`.
- Guessing a code allows 10 tries per address and day, about 3,650 a year out of a million
  codes. ADR 0027 recorded that about 140,000 resets gave an even chance of taking an account;
  the limits close that gap. The same limit keeps signup from proving an address by guessing.
- Anyone can refuse the codes of an address for a day, and use up its messages for an hour.
  The link of a message still works in the browser that started.
- Behind a reverse proxy that `server.trusted_proxies` does not list, every client has the
  address of the proxy and shares its limits. Operators must list their proxies.
- Limits per client address are per instance: with several instances, one address gets the
  burst of each, and a restart forgets them. Limits per email address hold across instances.
- Every failed sign-in for an address writes a counter, which the cleanup deletes once it
  ends.
- Tenant lookups for unknown slugs (#43) are bounded by the per-tenant cache of the third part
  of work item 3.5, not by these limits.
