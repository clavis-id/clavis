# 0007. Hosted UI with templ and htmx

- Status: Accepted
- Date: 2026-10-12

## Context

Integrating without frontend work requires hosted login pages. A single-page application would
add a Node.js toolchain to the build, a larger attack surface in the browser and a separate
release artifact. Passkeys require a small amount of JavaScript for the WebAuthn API.

## Decision

- Hosted UI and admin console are server-rendered with `github.com/a-h/templ`, with htmx for
  partial updates.
- A small vanilla TypeScript module handles WebAuthn and is bundled at build time with the
  esbuild Go API, so the build needs no Node.js.
- All assets are embedded in the binary with `embed.FS` and served with a strict Content
  Security Policy.
- Theming uses CSS custom properties per tenant; text is translated through message catalogs
  (English and Spanish first).
- Teams that want a fully custom UI use the same flows through the API.

## Consequences

- One binary contains everything; no separate frontend deployment.
- Rich client-side interactions are limited by design.
- Browser behavior is verified with Playwright, the only non-Go test tooling.
