# 0027. Password reset

- Status: Accepted
- Date: 2026-10-22

## Context

Work item 3.4 of the Phase 1 plan asks for a password reset that never reveals whether an
account exists, with tests for expiry, single use and enumeration safety. ADR 0026 built
email verifications for signup: a code and a link, hashed, short lived and bound to the
browser. Reviews added three requirements to the work item:

- a password change or reset ends the user's other sessions and revokes the user's tokens;
- `clavis users set-password`, the operator's reset, does the same;
- the signup notice for an address with an account points to the reset.

Two questions are open: what an address without an account receives, and whether the user is
signed in after the reset.

## Decision

- **Flow.**
  1. When email is enabled, the sign-in page links to "Forgot your password?" (`/reset`) for
     its authorization request.
  2. The user types the address of the account. The browser goes to the code page whatever
     the address.
  3. The user types the code, or follows the link, in the same browser.
  4. The user chooses a new password under the policy of ADR 0015.
  5. The user returns to the sign-in form of the same authorization request, with the address
     filled in and a notice, and signs in with the new password. If the request has expired
     meanwhile, a page says that the password changed.
- **Verifications.** A reset uses the email verifications of ADR 0026 with the purpose
  `reset`: the same code, link, binding, lifetime, attempt limit and single use. A signup
  verification cannot complete a reset, nor the other way round.
- **Enumeration.** For every address, Clavis looks up the user, stores a verification and
  renders the message, and the browser sees the same responses. Clavis queues the message only
  when the address has an active account. An unknown address or a disabled account gets
  nothing, so Clavis does not write to addresses that never signed up. The queue already
  delivers in the background (ADR 0024), so the remaining difference in time is one send to a
  channel. Tests compare the responses for an active account, an unknown address and a disabled
  account, also with a full queue.
- **Effects of the reset.**
  - The address of the account becomes verified, since the user proved it.
  - Every session of the user ends.
  - The user's codes not redeemed yet are deleted.
  - The user's access tokens and refresh token families are revoked.
  - The browser's session cookie is removed.

  The same happens when an operator sets a password with `clavis users set-password`.
- **No sign-in.** A reset proves only that the user reads the account's mail. It never replaces
  a sign-in, so the user signs in with the new password. Milestone 4 adds a second factor,
  which a reset must not skip.
- **Signup notice.** The message that signup sends to an address with an account now names
  "Forgot your password?" on the sign-in page.

## Consequences

- A user who forgot the password signs in once more after the reset, which password managers
  fill in.
- Someone who knows a user's password loses access when the user resets it or an operator sets
  a new one: browser sessions, refresh tokens and access tokens all end.
- A reset for an unknown address leaves a verification that nobody can complete, which expires
  with the others.
- Without email, users cannot reset their password; operators use `clavis users set-password`.
- Like signup, reset queues messages for anyone who types an address, so it needs the limits
  per address and IP of work item 3.5.
