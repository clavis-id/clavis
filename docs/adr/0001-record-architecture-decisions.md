# 0001. Record architecture decisions

- Status: Accepted
- Date: 2026-10-12

## Context

Clavis is a security-sensitive, long-lived open source project. Contributors need to understand
why the system is shaped the way it is, especially where a simpler-looking alternative was
rejected on purpose.

## Decision

Significant decisions are recorded as short architecture decision records in `docs/adr/`,
numbered sequentially, using the template in `0000-template.md`. Accepted records are not
edited; they are superseded by new records.

## Consequences

- Design discussions end with a written outcome that can be linked from code and reviews.
- Changing a recorded decision requires a new record, which makes reversals deliberate.
