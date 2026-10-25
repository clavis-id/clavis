# 0031. Per-tenant cache

- Status: Accepted
- Date: 2026-10-25

## Context

Work item 3.5 closes with the reviews that asked to bound what each request reads from the
store:

- every request under `/t/{slug}` looks up its tenant, unauthenticated, for any well-formed
  slug (#43);
- the default tenant is read on every request, so that a change of its settings applies at
  once (ADR 0026, #80);
- each token issuance lists the tenant's signing keys twice, one for the ID token and one for
  the access token, and its API resources once; each authorization request lists the API
  resources too (#52);
- each hosted page reads the tenant's branding, and the logo route reads a logo of up to
  128 KiB, although browsers cache it (ADR 0025, #78).

Clavis has no channel between processes: the command line changes tenants, resources and
branding in the database while servers run, and several instances may share a store. A cache
therefore trades freshness for reads. The key manager already keeps each tenant's JWK set for a
minute.

## Decision

- **What is cached.** Each server keeps, for 30 seconds:
  - tenants, by ID and by slug;
  - slugs that name no tenant;
  - the API resources of each tenant;
  - the branding of each tenant;
  - the logo of each tenant, or that it has none.

  Failed reads are not kept.
- **Signing keys.** The key manager keeps the list of each tenant's keys for one minute, like
  the JWK set, and picks the signing key from it by time. A successor is stored at least 15
  minutes before it signs, 24 hours by default (ADR 0011), so the kept list has it. Only a key
  that signs at once, for a new tenant or after an outage, can be missing, and then the manager
  reads the store again.
- **Freshness.**
  - A use case that changes a tenant, its API resources or its branding forgets what it
    changed at once in the cache of its process.
  - A change made by another process, such as the command line or another instance, applies
    within 30 seconds.
  - The command line has no cache, so its reads always reach the store.
  - A new API resource checks its scopes against the store, not the cache, so scopes stay
    unique.
- **Not cached.** Clients, users, sessions, grants, codes and tokens are read on every
  request. A deleted client, a rotated secret or a disabled user takes effect at once.
- **Bounds.** Each kind holds at most 10,000 entries, and logos at most 64, about 8 MiB. When
  a kind is full, its expired entries are removed, at most once per period; while it stays
  full, reads reach the store without being kept.

## Consequences

- Requests that repeat for a tenant read it, its keys, its resources and its branding once per
  period instead of every time. A flood of requests for one unknown slug reads the store once
  per period.
- Requests for many different unknown slugs still read the store once each, an indexed lookup,
  like requests with unknown client IDs. The limits of ADR 0030 do not count them.
- After an operator changes a tenant's settings, branding or API resources with the command
  line, servers apply the change within 30 seconds. A deleted API resource can still be
  granted for that long, and a deleted tenant still answers until its entry expires; its
  requests then fail on the missing records.
- Embedders that change tenants in the same process see changes at once.
