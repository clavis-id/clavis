# 0008. Hooks as webhooks and WebAssembly modules

- Status: Accepted
- Date: 2026-10-12

## Context

Cognito customizes flows with Lambda triggers and Keycloak with Java service provider
interfaces. Both tie extensions to one platform or language. Clavis needs customization
points (pre-signup, post-confirmation, pre-token generation, post-authentication) that work in
any language and in embedded mode.

## Decision

- Hooks are defined as typed payloads in the public `hooks` package.
- A hook can be delivered as a signed HTTP request following the Standard Webhooks
  specification, or executed in process as a WebAssembly module with
  `github.com/tetratelabs/wazero` (pure Go, no CGo).
- WebAssembly hooks run with no filesystem or network access by default, with memory and time
  limits per invocation.
- In embedded mode, Go code can register hooks as plain functions.
- Asynchronous events use a transactional outbox so delivery survives restarts.

## Consequences

- Hook authors can use any language that compiles to WebAssembly, or any HTTP stack.
- The WebAssembly ABI becomes a public contract and must be versioned.
- Synchronous hooks add latency to authentication flows; timeouts and failure policies
  (fail open or fail closed) are explicit per hook.
