# 0004. Dual mode: embeddable library and single binary

- Status: Accepted
- Date: 2026-10-12

## Context

The Go identity providers surveyed in October 2026 run as standalone services. Go developers
who want authentication inside their own binary must either run another service or use a
session library that is not an OAuth or OpenID Connect authorization server. Polyglot teams
need a standalone server that any OIDC client library can talk to.

## Decision

Clavis is built as a library first. The public package `clavis` exposes `New(ctx, Config)`
returning a `Server` with `Handler()` and `Verifier()`. The `clavis` binary is a thin
composition of the same public API with configuration loading, an HTTP server, telemetry
exporters and graceful shutdown. Both modes are tested in CI.

## Consequences

- Public API design gets more scrutiny, since embedders depend on it directly.
- Clavis cannot assume it owns the process: no global state, no `os.Exit`, no signal handling
  in library code, and every background job stops when its context is cancelled.
- The binary never gains capabilities that the library lacks.
