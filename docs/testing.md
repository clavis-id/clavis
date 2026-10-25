# Testing strategy

An identity provider fails in ways that are expensive and silent: a lenient redirect URI check
or a replayable code is a vulnerability, not a bug report. Clavis therefore treats tests as part
of the product. No change merges without the tests described here.

## Layers

### Unit tests

- Standard library `testing`, table-driven, with `github.com/google/go-cmp` for comparisons.
  No assertion framework.
- Time and identifiers are injected as functions (`Now func() time.Time`,
  `NewID func() uuid.UUID`). Expiry, rotation and lockout logic is tested with
  `testing/synctest` so tests never sleep.
- Cryptographic randomness is made deterministic with `testing/cryptotest.SetGlobalRandom`
  (Go 1.27) where golden outputs are needed.
- Every exported function and every error path in `internal/oauth`, `internal/oidc`,
  `internal/keys` and `internal/authn` has a test.

### Store contract tests

- `store/storetest` is a public suite that exercises every storage port: CRUD, tenant isolation,
  uniqueness constraints, concurrency (conditional updates, refresh token family revocation),
  pagination and expiry cleanup.
- It runs against SQLite (a temporary database file per test) on every test run, and against
  PostgreSQL when `CLAVIS_TEST_POSTGRES_DSN` points at a server: `make test-postgres` starts a
  throwaway container locally, and CI uses a service container. Each test creates and drops its
  own database, so subtests run in parallel.
- No container library is used: a plain Docker container keeps test-only dependencies out of
  the module graph that embedders inherit.
- Third-party adapters (for example MySQL) prove compatibility by passing the same suite.

### Integration tests

- The full server is started in process with `net/http/httptest`.
- Every grant and flow is driven by independent client libraries (`golang.org/x/oauth2`,
  `github.com/coreos/go-oidc/v3`) rather than by Clavis code, to prove interoperability and
  avoid testing the implementation against itself.
- Golden files cover the discovery document, JWKS shape and token claims. Regenerate with
  `go test ./... -update` and review the diff.

### Protocol conformance

- The OpenID Foundation conformance suite runs in Docker against the current commit of Clavis
  (`make conformance`; see [`conformance/README.md`](../conformance/README.md) and ADR 0017).
- The Conformance workflow runs nightly on `develop`, on pull requests that change protocol
  code or `conformance/`, and on demand.
- `conformance/expected-failures.json` and `expected-skips.json` list the known gaps, each with
  its reason. Any other failure, and any listed entry that no longer happens, fails the run.
- Profiles grow with the roadmap: Config OP (from work item 1.2), Basic OP (from work item
  1.6), Form Post and RP-Initiated Logout (Phase 1); Dynamic OP and PAR (Phase 2); FAPI 2.0 Security Profile
  (later).
- A failing conformance run is fixed before merging. It is not a required status check, because
  it only runs for the pull requests that change protocol code.

### Security tests

- The threats in RFC 9700 (OAuth 2.0 Security Best Current Practice) are encoded as named
  tests: open redirectors, authorization code injection and replay, PKCE downgrade, mix-up,
  refresh token replay, token leakage through referrers, clickjacking headers, CSRF.
- Native Go fuzzing. Current targets: issuer parsing (`internal/issuer`), configuration parsing
  (`internal/config`), ciphertext decryption (`kek`), tenant slugs and email addresses
  (`internal/app`), redirect URI validation and matching and authorization request parsing
  (`internal/oauth`), client credentials at the token endpoint (`internal/oauth`), stored
  password hashes (`internal/authn/password`), and the authorization endpoint as a whole,
  which must answer any query with the login page, an error page or a redirect to a
  registered redirect URI (root package). Planned: client metadata documents (Phase 2) and
  SCIM filters (Phase 3). JWS parsing is left to go-jose, which has its own fuzz targets.
  Short runs on every pull request; long nightly runs are planned.
- Interoperability: `golang.org/x/oauth2` and `github.com/coreos/go-oidc/v3` drive the
  authorization code flow (confidential and public clients), userinfo and the client
  credentials grant against a TLS server (`interop_test.go`).
- Static and supply chain analysis: `govulncheck`, `gosec` through golangci-lint, CodeQL,
  gitleaks, OSSF Scorecard, dependency review on pull requests.

### Migration tests

- Hash compatibility vectors for bcrypt, Firebase scrypt, Keycloak PBKDF2 and argon2, taken
  from upstream documentation and real exports.
- A fake Cognito API built on `httptest` validates the lazy migration connector, including
  wrong passwords, disabled users, throttling and network failures.

### End-to-end browser tests

- Playwright tests in `e2e/` cover the hosted UI: signup, login, verification, password reset,
  MFA enrollment, consent and logout.
- Passkey registration and login use the Chrome DevTools Protocol WebAuthn virtual
  authenticator.
- axe-core accessibility checks run on every hosted UI page.
- This is the only non-Go code in the test suite; it exists because browser behavior cannot be
  verified otherwise.

### Performance

- Go benchmarks for token issuance, token validation, JWKS serving and session lookup, compared
  with `benchstat` against `develop`; regressions above an agreed threshold fail CI.
- k6 scenarios for login and token endpoints run before releases.
- CI checks the footprint targets: release binary (stripped, as built by goreleaser) under
  40 MB, idle resident memory under 50 MB, cold start under one second.

## Always-on rules

- Tests run with `-race` and `-shuffle=on`.
- Every package with tests has a `TestMain` that calls `goleak.VerifyTestMain`
  (`go.uber.org/goleak`, test-only), so a goroutine that outlives the tests fails the run.
- Security-critical packages keep at least 80 percent statement coverage, enforced in CI by
  `make cover-check`. The list in the Makefile (`COVER_FLOOR_PKGS`) currently holds
  `email`, `internal/authn/password`, `internal/i18n`, `internal/issuer`, `internal/keys`,
  `internal/oauth`, `internal/oidc`, `internal/ratelimit` and `kek`; every new package under
  `internal/authn` joins it.
- Every fuzz target runs for 15 seconds in CI on each pull request (`make fuzz`).
- No test depends on the network outside servers or containers it starts itself.
- No test depends on test execution order. Time-dependent behavior uses an injected clock or
  `testing/synctest` rather than sleeping on the wall clock.

## What each change must include

| Change | Required tests |
|---|---|
| New or changed protocol behavior | Unit, integration with an independent client, conformance run, RFC 9700 review |
| New storage method | Contract test in `store/storetest`, passing on SQLite and PostgreSQL |
| New parser of untrusted input | Unit tests and a fuzz target |
| Hosted UI change | Playwright test and accessibility check |
| Bug fix | A regression test that fails before the fix |
| Performance-sensitive path | Benchmark |

## Commands

Available:

| Command | Purpose |
|---|---|
| `make test` | Unit and integration tests (`-race -shuffle=on`); PostgreSQL tests skip without a DSN |
| `make test-postgres` | Store tests against a throwaway PostgreSQL container |
| `make test-store` | Store tests, including PostgreSQL when `CLAVIS_TEST_POSTGRES_DSN` is set |
| `make test-go-import` | Tests of the Cloudflare Worker that serves the import path (Node.js) |
| `make cover` | Coverage profile and total for every package |
| `make cover-check` | Coverage floor for security-critical packages |
| `make fuzz` | Every fuzz target for `FUZZTIME` each (default 30s) |
| `make lint` | golangci-lint and actionlint |
| `make vuln` | govulncheck |

Planned:

| Command | Purpose | Phase |
|---|---|---|
| `make conformance` | Start Clavis and run the OpenID conformance plans | 1 |
| `make e2e` | Playwright browser tests | 1 |
| `make bench` | Benchmarks with `benchstat` comparison | 1 |
