# 0009. Multi-tenancy with a per-tenant issuer

- Status: Accepted
- Date: 2026-10-12

## Context

Cognito isolates directories in user pools and Keycloak in realms, each with its own issuer and
keys. Adding multi-tenancy after the data model exists is costly and error prone.

## Decision

- A tenant is an isolated directory with its own issuer, signing keys, clients, users,
  branding, policies and hooks.
- The default issuer for a tenant is `https://<host>/t/<tenant>`; custom domains can map to a
  tenant.
- A `default` tenant is created automatically and served at the root issuer, so single-tenant
  deployments do not see tenancy.
- Tenant ID is a required argument on every tenant-scoped storage method.
- Organizations (business customers with their own SSO and SCIM) live inside a tenant.

## Consequences

- Tokens from one tenant can never validate in another, because issuer and keys differ.
- Every query and test must consider tenant isolation; the contract suite includes isolation
  tests.
- Per-tenant keys increase the number of keys to rotate and store.
