# 0016. Administration and the admin tenant

- Status: Accepted
- Date: 2026-10-14

## Context

Phase 1 adds an admin REST API for tenants, clients and users. The API needs authentication
that suits automation, scopes permissions and rotates credentials. Static API keys are
long-lived secrets without scopes. Keycloak administers realms from a dedicated `master` realm,
and Clavis already issues OAuth tokens. An operator also needs a way to create the first
credential, and to recover access when no credential works.

## Decision

- **Admin tenant.** A reserved tenant with the slug `admin` holds the clients, and later the
  users, that administer Clavis.
  - Standalone servers create it on first start; embedded servers create it when the host
    enables the admin API.
  - It cannot be deleted.
  - Its issuer is `<issuer>/t/admin`.
- **Admin API.**
  - Served under `/admin/v1` and described in OpenAPI 3.1 (`api/openapi.yaml`).
  - Every request needs an access token issued by the admin tenant, whose `aud` is the admin
    API resource.
  - Coarse scopes grant access: `tenants:read`, `tenants:write`, `clients:read`,
    `clients:write`, `users:read`, `users:write` and `audit:read`.
  - In Phase 1 an admin client acts on every tenant; per-tenant delegation comes later.
- **Bootstrap.** `clavis admin bootstrap` creates the first admin client with the
  `client_credentials` grant and prints its secret once.
- **CLI.** The CLI uses the server configuration and works directly against the database for
  tenants, clients and users. That makes setup possible before the API exists and gives a
  recovery path when access is lost. Remote administration goes through the API or the
  generated Go client.
- **Embedded mode.** Embedders get the admin API as a separate handler,
  `Server.AdminHandler()`, and mount it only if they want it.

## Consequences

- No static admin secrets exist. Admin credentials rotate like any client secret and are
  audited like any client.
- Clavis uses its own `client_credentials` flow, so the admin API exercises the protocol code
  every day.
- Database access is equivalent to full administrative access. The documentation states this
  explicitly.
- The reserved slug `admin` is unavailable to ordinary tenants.
