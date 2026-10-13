# 0012. Vanity import path clavisid.org/clavis

- Status: Accepted
- Date: 2026-10-13
- Supersedes: 0010

## Context

ADR 0010 set the module path to `github.com/clavis-id/clavis`. The project now owns the
`clavisid.org` domain. A module path that names the hosting provider ties every embedder's
import statements to that provider: moving the repository would break all of them. No external
code imports Clavis yet, so changing the path now costs nothing for users.

## Decision

- The module path is `clavisid.org/clavis`. Tool modules follow the same prefix
  (`clavisid.org/clavis/tools/<name>`).
- The repository stays at `github.com/clavis-id/clavis`.
- A Cloudflare Worker on `clavisid.org` (source in `deploy/cloudflare/go-import`) answers
  `?go-get=1` requests for `clavisid.org/clavis` and every path below it with the `go-import`
  and `go-source` meta tags pointing at the repository, and redirects browsers to GitHub.
- Repository URLs in documentation, licenses and image labels keep pointing at GitHub.

## Consequences

- The repository can move to another host by changing the Worker, without breaking imports.
- The domain and the Worker become part of the supply chain: losing the domain would break
  `go get` for anyone not using the module proxy. Domain renewal and Cloudflare account access
  must be protected accordingly (registrar lock, two-factor authentication).
- Once the module is public, proxy.golang.org caches every version, so existing versions keep
  resolving even if the Worker is briefly unavailable.
