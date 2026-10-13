# 0010. Module path github.com/clavis-id/clavis

- Status: Superseded by 0012
- Date: 2026-10-12

## Context

A Go module path is part of every import statement written by embedders. Changing it later
breaks all of them. Hosting under a personal account makes future transfer painful; a vanity
domain requires running infrastructure for `go-import` metadata.

## Decision

The module path is `github.com/clavis-id/clavis`, hosted in a dedicated GitHub organization
named `clavis-id`. Related repositories (SDKs, Helm chart, Terraform provider, documentation
site) live in the same organization.

## Consequences

- Maintainers can be added at the organization level without ownership transfers.
- The organization must be created before the first push; if the name becomes unavailable,
  this record is superseded before any code is published.
