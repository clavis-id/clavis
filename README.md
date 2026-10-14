# Clavis

Open source identity and access management written in Go. Clavis is an OpenID Connect and
OAuth 2.1 authorization server that you can embed in a Go application as a library or run as a
single static binary in front of any stack.

Clavis is Latin for "key".

> Status: pre-alpha. Phase 0 (foundations) is complete: the embeddable server, SQLite and
> PostgreSQL storage, signing key rotation with a published JWK set, telemetry and the release
> pipeline. The OpenID Connect and OAuth flows arrive in Phase 1. Interfaces may change in any
> release before v1.0; see the [roadmap](docs/roadmap.md).

## Why Clavis

Clavis aims to be a permissively licensed, standards-first identity platform that is easy to
adopt and easy to leave: one codebase that embeds in a Go program or runs as a single binary,
with every feature in the open source core. See [Vision](docs/vision.md) for the full
rationale and how Clavis relates to existing projects.

## Pillars

1. **Two modes, one codebase.** Import Clavis and mount its `http.Handler`s, or run the
   single binary. Starts with embedded SQLite and zero external dependencies; scales out on
   PostgreSQL.
2. **Apache-2.0, no paid tier.** Organizations, enterprise SSO, SCIM and multi-tenancy are part
   of the open source core.
3. **Agent ready.** OAuth 2.1 authorization server aligned with the MCP authorization
   specification: protected resource metadata (RFC 9728), resource indicators (RFC 8707),
   Client ID Metadata Documents, token exchange with delegation (RFC 8693), CIBA for
   human-in-the-loop approvals and DPoP (RFC 9449).
4. **Leave Cognito without password resets.** Lazy migration connectors and native import of
   bcrypt, Firebase scrypt, Keycloak PBKDF2 and argon2 hashes.
5. **Programmable flows in any language.** Lifecycle hooks as signed webhooks or sandboxed
   WebAssembly modules, the self-hosted equivalent of Cognito Lambda triggers.
6. **Passkeys first, standards rigor.** WebAuthn with conditional UI, OAuth 2.0 Security Best
   Current Practice (RFC 9700), the OpenID conformance suite running in CI, and a FIPS 140-3
   mode through the Go Cryptographic Module.
7. **Config as code.** Declarative YAML with `plan` and `apply`, plus an OpenAPI 3.1 admin API
   for generating clients in any language.

## Target developer experience

Embedded in a Go application:

```go
db, err := sqlite.Open(ctx, "auth.db")
if err != nil {
    return err
}
enc, err := kek.NewLocal(secretFromYourSecretsManager)
if err != nil {
    return err
}

auth, err := clavis.New(ctx, clavis.Config{
    Issuer:       "https://app.example.com/auth",
    Store:        db,
    KeyEncrypter: enc,
})
if err != nil {
    return err
}

mux.Handle("/auth/", http.StripPrefix("/auth", auth.Handler()))
mux.Handle("/api/", middleware.Require(auth.Verifier(), middleware.Scopes("orders:read"))(api))
```

As a standalone server, any OpenID Connect client library in any language integrates with
Clavis through standard discovery:

```
clavis keys new-encryption-key   # store the output in your secrets manager
clavis serve --config clavis.yaml
```

## Documentation

- [Vision and market analysis](docs/vision.md)
- [Architecture](docs/architecture.md)
- [Testing strategy](docs/testing.md)
- [Roadmap](docs/roadmap.md) and the [Phase 1 plan](docs/plans/phase-1.md)
- [Releasing](docs/releasing.md)
- [Architecture decision records](docs/adr/)

## Contributing

Contributions are welcome; start with [CONTRIBUTING.md](CONTRIBUTING.md). Everyone taking part
in the project follows the [code of conduct](CODE_OF_CONDUCT.md). Report vulnerabilities
privately as described in [SECURITY.md](SECURITY.md).

## License

Clavis is licensed under the [Apache License, Version 2.0](LICENSE).
