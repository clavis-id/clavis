# Testing strategy

An identity provider fails in ways that are expensive and silent: a lenient redirect URI check
or a replayable code is a vulnerability, not a bug report. Clavis therefore treats tests as part
of the product. No change merges without the tests described here.

## Layers

### Unit tests

- Standard library `testing`, table-driven, with `github.com/google/go-cmp` for comparisons.
  No assertion framework.
- Time is injected through a clock interface. Expiry, rotation and lockout logic is tested with
  `testing/synctest` so tests never sleep.
- Cryptographic randomness is made deterministic with `testing/cryptotest.SetGlobalRandom`
  (Go 1.27) where golden outputs are needed.
- Every exported function and every error path in `internal/oauth`, `internal/oidc`,
  `internal/keys` and `internal/authn` has a test.

### Store contract tests

- `store/storetest` is a public suite that exercises every storage port: CRUD, tenant isolation,
  uniqueness constraints, concurrency (conditional updates, refresh token family revocation),
  pagination and expiry cleanup.
- It runs against SQLite in memory on every test run and against PostgreSQL through
  `testcontainers-go` in CI and on demand locally.
- Third-party adapters (for example MySQL) prove compatibility by passing the same suite.

### Integration tests

- The full server is started in process with `net/http/httptest`.
- Every grant and flow is driven by independent client libraries (`golang.org/x/oauth2`,
  `github.com/coreos/go-oidc/v3`) rather than by Clavis code, to prove interoperability and
  avoid testing the implementation against itself.
- Golden files cover the discovery document, JWKS shape and token claims. Regenerate with
  `go test ./... -update` and review the diff.

### Protocol conformance

- The OpenID Foundation conformance suite runs in Docker against a Clavis instance.
- Triggered on every change under `internal/oauth`, `internal/oidc` or `internal/keys`, and
  nightly on `develop`.
- Profiles grow with the roadmap: Basic OP, Config OP, Form Post, RP-Initiated Logout
  (Phase 1); Dynamic OP and PAR (Phase 2); FAPI 2.0 Security Profile (later).
- A failing conformance module blocks the merge.

### Security tests

- The threats in RFC 9700 (OAuth 2.0 Security Best Current Practice) are encoded as named
  tests: open redirectors, authorization code injection and replay, PKCE downgrade, mix-up,
  refresh token replay, token leakage through referrers, clickjacking headers, CSRF.
- Native Go fuzzing targets: redirect URI matching, scope parsing, JWS and JWT parsing, client
  metadata documents, authorization request parsing, configuration parsing, SCIM filters
  (Phase 3). Short fuzz runs in CI on every pull request; long runs nightly.
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
- CI checks the footprint targets: binary size under 40 MB, idle resident memory under 50 MB,
  cold start under one second.

## Always-on rules

- Tests run with `-race` and `-shuffle=on`.
- Goroutine leaks are checked at the end of every package test run.
- Coverage floor of 80 percent for `internal/oauth`, `internal/oidc`, `internal/keys` and
  `internal/authn`; coverage is reported for every package.
- No test depends on the network outside containers it starts itself.
- No test depends on wall-clock time or on test execution order.

## What each change must include

| Change | Required tests |
|---|---|
| New or changed protocol behavior | Unit, integration with an independent client, conformance run, RFC 9700 review |
| New storage method | Contract test in `store/storetest`, passing on SQLite and PostgreSQL |
| New parser of untrusted input | Unit tests and a fuzz target |
| Hosted UI change | Playwright test and accessibility check |
| Bug fix | A regression test that fails before the fix |
| Performance-sensitive path | Benchmark |

## Planned commands

| Command | Purpose |
|---|---|
| `make test` | Unit and integration tests with SQLite (`-race -shuffle=on`) |
| `make test-postgres` | Same suite plus store contract tests on PostgreSQL |
| `make fuzz` | Short fuzz run for every target |
| `make conformance` | Start Clavis and run the OpenID conformance plans |
| `make e2e` | Playwright browser tests |
| `make bench` | Benchmarks with `benchstat` comparison |
| `make lint` | golangci-lint, govulncheck |
| `make cover` | Coverage report and floor check |
