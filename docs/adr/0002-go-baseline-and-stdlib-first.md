# 0002. Go 1.27 baseline and stdlib-first dependency policy

- Status: Accepted
- Date: 2026-10-12

## Context

Go 1.27 (August 2026) adds generic methods, `encoding/json/v2`, a standard `uuid` package with
UUIDv7, `crypto/mldsa`, and testing improvements (`testing/synctest.Sleep`,
`httptest.NewTestServer`, `testing/cryptotest.SetGlobalRandom`). Earlier releases added
`http.CrossOriginProtection`, `crypto/pbkdf2`, `crypto/hkdf` and the FIPS 140-3 Go
Cryptographic Module. An identity provider has a large attack surface; every dependency is
part of it.

## Decision

- The module declares `go 1.27` and CI tests the latest Go release.
- The standard library is the default choice. A third-party dependency is accepted only when
  it is actively maintained, has a reasonable security track record, keeps a small transitive
  footprint and provides substantial value over the standard library.
- Accepted core dependencies: go-jose v4, go-webauthn, pquerna/otp, golang.org/x/crypto,
  golang.org/x/oauth2, coreos/go-oidc v3, modernc.org/sqlite, pgx v5, goose v3, koanf v2,
  cobra, templ, wazero, go-mail, OpenTelemetry, and testcontainers-go for tests.
- No CGo in the default build.

## Consequences

- Users on older Go releases cannot embed Clavis until they upgrade; this is acceptable for a
  new project because Go supports only the two latest releases.
- New dependencies require justification in the pull request.
- Static, cross-compiled binaries remain possible on every supported platform.
