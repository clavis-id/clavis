# Contributing to Clavis

Thank you for your interest in Clavis. This guide explains how to set up a development
environment and what a change needs before it can be merged.

Clavis is in an early stage. Before starting significant work, open an issue to discuss it, so
that the change fits the [roadmap](docs/roadmap.md) and the
[architecture decisions](docs/adr/).

## Prerequisites

- Go 1.27 or later.
- GNU Make.
- Docker, for PostgreSQL tests and for code generation (sqlc runs in a container).

Every other tool (golangci-lint, govulncheck, gitleaks, actionlint) is pinned in its own module
under `tools/` and runs through `go tool`; nothing else needs to be installed. Clavis does not
use CGo, so no C toolchain is required either.

## Common tasks

```
make help              List every target
make build             Compile every package and build bin/clavis
make run               Run the server locally with deploy/dev/clavis.yaml
make test              Run tests with the race detector in random order
make test-postgres     Run the store tests against a throwaway PostgreSQL container
make generate          Regenerate code after changing SQL migrations or queries
make release-snapshot  Build release archives and images locally without publishing
make lint              Run golangci-lint and actionlint
make fmt               Format Go code
make vuln              Report known vulnerabilities
make check             Run everything CI runs on pull requests
```

## Branches

- `master` holds released code. Every release is a tag on `master`.
- `develop` is the integration branch. Branch from `develop` and open pull requests against
  `develop`.
- Name branches `type/short-description`, for example `feat/pkce-validation` or
  `fix/refresh-token-reuse`.

## Commits

Commits follow [Conventional Commits](https://www.conventionalcommits.org/): `feat`, `fix`,
`docs`, `test`, `refactor`, `perf`, `build`, `ci`, `chore` or `security`, followed by a short
imperative summary under 72 characters, for example:

```
feat(oauth): reject authorization codes that were already redeemed
```

Keep one logical change per commit, and commit generated code together with its source.

## Pull requests

A pull request is ready for review when:

- It includes the tests described in [docs/testing.md](docs/testing.md) for the kind of change.
- `make check` passes.
- Documentation is updated, and any decision with lasting consequences is recorded as a new ADR
  in `docs/adr/`.
- All text (code, comments, documentation, commit messages) is written in English and contains
  no emojis.

Changes to protocol behavior, cryptography, sessions or token handling receive extra review and
must reference the specification section they implement.

## Releases

See [docs/releasing.md](docs/releasing.md).

## Reporting security issues

Do not open public issues for vulnerabilities. Follow [SECURITY.md](SECURITY.md).

## License

Clavis is licensed under the [Apache License, Version 2.0](LICENSE). By submitting a
contribution, you agree that it is licensed under the same terms, as described in section 5 of
the license.
