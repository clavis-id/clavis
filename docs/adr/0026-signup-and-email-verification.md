# 0026. Signup and email verification

- Status: Accepted
- Date: 2026-10-21

## Context

Work item 3.3 of the Phase 1 plan lets people create their own accounts. The plan asks for:

- signup that each tenant enables;
- verification codes and links that are hashed and short lived;
- responses that never reveal whether an account exists.

ADR 0024 already hides how long an SMTP server takes, by queuing messages. The review of the
email work (#74) added a requirement: signup must do the same work for a new address and for
an address with an account, and must answer the same way when a message cannot be queued.

Five questions are open:

- In what order the user gives the address, proves it and chooses a password.
- How the address is proved.
- Where the setting lives.
- How a client asks for the signup page.
- What happens when email is disabled.

## Decision

- **Setting.** Each tenant has a `signup_enabled` setting, off by default, which
  `clavis tenants update SLUG --signup` changes. The admin tenant of ADR 0016 never allows
  signup. Signup also needs email: without an email driver no tenant offers it, which reveals
  nothing about any address. The default tenant is now read from the store on every request,
  like the others, so a change applies without a restart. The tenant cache of work item 3.5
  will cover both.
- **Flow: the address first.**
  1. The sign-in page links to `/signup` for its authorization request.
  2. The user types an address. Clavis looks it up, stores an email verification and queues a
     message, whatever it finds:
     - an address without an account gets a code and a link;
     - an address with an account gets a notice that it has one.

     The browser goes to the code page in both cases. A message that cannot be queued is only
     logged.
  3. The user types the code, or follows the link, in the same browser.
  4. The user chooses a password under the policy of ADR 0015.
  5. Clavis creates the account with the address verified and signs the user in as after a
     password sign-in (`amr` `pwd`, the password `acr` of ADR 0019). Then it answers the
     authorization request: consent or a code. If the request has expired meanwhile, a page
     says that the account is ready, and the user goes back to the application, where single
     sign-on finds the session.

  The password is hashed only after the address is proved. No account exists until then, so
  nobody can claim someone else's address with an unverified account.
- **Email verifications.** A verification is a stored record:
  - It has a random 128-bit identifier, a six-digit code and a 256-bit link token. Only the
    SHA-256 hashes of the code and the token are stored; the code is hashed with the
    identifier.
  - It is bound to the browser binding cookie of ADR 0013, like an authorization request, so
    the code and the link work only in the browser that started the signup. A stolen hash of
    the code is useless elsewhere.
  - It lives 15 minutes and allows five code submissions. Each submission is counted
    atomically before the comparison, so concurrent guesses cannot exceed the limit.
  - It is deleted when the account is created and purged once it expires.
  - It has a purpose (`signup`), so password reset in work item 3.4 can reuse it.

  The link opens a page with a confirmation button, so mail scanners that fetch links do not
  use it. In another browser, the link page asks for the code instead.
- **prompt=create.** Clavis implements Initiating User Registration via OpenID Connect 1.0
  (Final). A tenant that offers signup sends `prompt=create` requests to the signup page, even
  for a browser with a session. Discovery lists every supported value in
  `prompt_values_supported`, with `create` only for such tenants. Elsewhere `create` is an
  unsupported value and the request fails with `invalid_request` (section 4.1). Combining
  `create` with `none` is an error, as for any other value.
- **Enumeration.** For a new address and an address with an account, Clavis gives the same
  responses: the same status, redirects, pages and headers. It also does the same store
  operations and renders and queues one message for each. Tests compare the responses,
  including with a full queue. A malformed address gets an error, which says nothing about
  accounts. Messages per address and per IP address are limited in work item 3.5.

## Consequences

- Signup works only with email. Operators see a note when they enable it on a server whose
  configuration has no email driver.
- Accounts created by signup always have a verified address.
- Someone who signs up with an existing address can guess its code with five tries in a
  million, and then learns only that the account exists.
- A user who reads the message on another device types the code; the link works only in the
  browser that started.
- Every signup queues a message. Until the rate limits of work item 3.5 exist, anyone can
  make Clavis send the fixed signup messages to any address, at the pace of the queue.
- Each request now reads the default tenant from the store.
