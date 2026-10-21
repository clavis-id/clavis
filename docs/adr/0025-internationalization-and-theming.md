# 0025. Internationalization and theming

- Status: Accepted
- Date: 2026-10-20
- Supersedes: ignoring `ui_locales` at the end session endpoint, in ADR 0023

## Context

ADR 0007 says that the hosted pages are translated through message catalogs, English and
Spanish first, and that tenants theme them through CSS custom properties. Work item 3.2 of the
Phase 1 plan makes that concrete before signup and password reset add more pages and emails.
Four questions are open:

- How catalogs are stored and checked, so that a missing translation fails a test instead of
  showing a key to a user.
- How a page picks its language. OpenID Connect lets a relying party send `ui_locales` with
  authorization and logout requests; browsers send `Accept-Language`; a user may want another
  language than either.
- What a tenant can change, given that every page sends a strict Content Security Policy
  without inline styles.
- Where a tenant's logo comes from, without loading anything from another origin.

## Decision

- **Catalogs.** `internal/i18n` embeds one JSON file per locale, a flat object from keys to
  messages. Keys are typed constants in Go. Messages name their placeholders, such as
  `{client}`, so each language orders them as its grammar needs; pages can render a
  placeholder with markup, such as a name in bold. Loading fails when a locale lacks a message
  of the English catalog, has one that English lacks, or uses other placeholders, and a test
  checks that the English catalog defines exactly the declared keys. The same catalogs hold the
  text of the email messages (ADR 0024). The JSON format suits translation tools and leaves
  room for tenants to override messages by key later. Fixed English details about a rejected
  request, such as a parameter name, stay in English inside the translated sentence: they are
  meant for the application's developers.
- **Locale selection.** A page's language is, in order: the locale the user picked with the
  language selector on the page, which a `__Host-clavis-locale` cookie then remembers for a
  year; the request's `ui_locales`, stored with the authorization request and carried through
  the logout confirmation; the `Accept-Language` header; English. Unsupported or malformed
  values are ignored, since every source only expresses a preference. Discovery announces
  `ui_locales_supported`.
- **Language selector.** The interactive pages (sign-in, consent, logout confirmation) end
  with one button per locale. A button sends the page's own request again with the
  `clavis_locale` parameter: a GET for the sign-in and consent pages, which only read the
  stored request, and a POST of the logout request to the end session endpoint. The parameter
  has a vendor prefix so it cannot collide with a protocol parameter. It needs no script.
  Informational pages, such as errors, have no selector, because their requests cannot be
  repeated safely.
- **Theme.** A tenant sets colors for the light and dark color schemes (accent, accent text,
  background, surface, text, muted, border, error) as `#rrggbb`, and a corner radius from 0 to
  32 pixels. Values left unset keep the defaults; light colors apply only outside the dark
  scheme. The theme is written into a `style` element, allowed by its hash in `style-src`, so
  the page still loads no other inline style. Only validated values reach the element, and the
  renderer checks them again.
- **Logo.** A tenant can upload a PNG, JPEG or WebP image of at most 128 KiB and 1024 by 1024
  pixels. It is decoded fully before it is stored, stored in the database with the theme, and
  served by Clavis under a name that includes its content hash, with long-lived caching,
  `nosniff` and a sandboxing policy. SVG is refused, because an SVG image is a document that can
  hold scripts. WebP needs `golang.org/x/image/webp`, maintained by the Go project.
- **Administration.** `clavis tenants theme show|set|logo|reset` manages branding until the
  admin API (milestone 5) adds it.

## Consequences

- Adding a locale means adding a catalog that passes the same checks, and its name to the list
  of supported locales.
- Every page renders once per locale in tests, which fail on a key or placeholder left in the
  output.
- Each page reads the tenant's branding from the store; the cache planned for tenant lookups
  in work item 3.5 can hold it too.
- A tenant cannot inject arbitrary CSS or load assets from other origins, which keeps the
  Content Security Policy strict; richer customization is left to a later decision.
- The locale cookie applies to every tenant on the host, like the browser's own language.
