# 0006. Storage ports with SQLite and PostgreSQL adapters

- Status: Accepted
- Date: 2026-10-12

## Context

Clavis must start with zero external dependencies, which points to an embedded database, and
must scale horizontally, which points to PostgreSQL. Embedders may want their own database.

## Decision

- Storage is defined by public port interfaces in `store`, with the tenant ID as a required
  argument on every tenant-scoped method.
- Two first-party adapters: SQLite through `modernc.org/sqlite` (pure Go, no CGo) and
  PostgreSQL through `github.com/jackc/pgx/v5`.
- Queries are written in SQL and compiled with `sqlc`, one query set per engine.
- Migrations are SQL files per engine, embedded with `embed.FS` and applied with
  `github.com/pressly/goose/v3`, either automatically at startup or through `clavis migrate`.
- A public contract suite in `store/storetest` defines correct behavior for any adapter.

## Consequences

- Queries are duplicated per engine; the contract suite keeps them behaviorally identical.
- No ORM: schema and queries stay explicit and reviewable.
- Community adapters (for example MySQL) are possible without changes to Clavis.
