# 0015. Password hashing and FIPS mode

- Status: Accepted
- Date: 2026-10-14

## Context

OWASP recommends argon2id for password storage. Clavis also offers a FIPS 140-3 mode through
the Go Cryptographic Module, and the security rules forbid hard-requiring a non-approved
algorithm in that mode. argon2 (`golang.org/x/crypto/argon2`, built on BLAKE2b) is not FIPS
approved; PBKDF2 with HMAC-SHA-256 is, and `crypto/pbkdf2` is part of the module. Memory-hard
hashing also limits how many logins a process can verify at once.

## Decision

- **Format.** Hashes are stored as PHC strings that carry the algorithm and its parameters,
  for example `$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>`.
- **Default.** New hashes use argon2id with at least the OWASP baseline: 19 MiB of memory,
  2 iterations, 1 lane and a 128-bit salt. Stronger parameters are configurable.
- **FIPS mode.** When `crypto/fips140.Enabled()` reports FIPS mode, new hashes use
  PBKDF2-HMAC-SHA-256 with 600,000 iterations (the OWASP recommendation) and a 128-bit salt.
  An argon2id hash found in FIPS mode is verified once and replaced with a PBKDF2 hash on the
  same login, and the event is logged.
- **Rehash on login.** A successful login rehashes the password when the stored algorithm or
  parameters are below the current policy.
- **Unknown users.** A login for an unknown user verifies against a dummy hash with the
  current parameters, so response time does not reveal whether the account exists.
- **Concurrency.** A semaphore bounds concurrent hash computations, and excess requests wait,
  which caps the memory argon2id can use.
- **Imported hashes.** bcrypt, Firebase scrypt and Keycloak PBKDF2 belong to the Phase 2
  migration toolkit; the PHC format leaves room for them.

## Consequences

- One code path serves both modes, and switching a deployment to FIPS mode migrates hashes
  gradually without forcing password resets.
- PBKDF2 is weaker against GPU attacks than argon2id. FIPS deployments accept that trade-off
  for compliance.
- Login latency and memory use depend on the parameters. The semaphore protects the process
  under load, so the limit has to be sized for the expected login rate.
