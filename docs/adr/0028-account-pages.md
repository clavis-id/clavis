# 0028. Account pages

- Status: Accepted
- Date: 2026-10-22

## Context

Work item 3.4 of the Phase 1 plan asks for a profile page for the standard claims and a password
change. Notes on the work item add three requests:

- a page where users see the applications they allowed and remove their access (ADR 0020), which
  operators do with `clavis grants revoke` until then;
- validation of every profile claim the page can edit;
- the root of an issuer, which answers 404, should lead to a main page.

The hosted pages so far always belong to an authorization request of a client. A user who comes
to Clavis directly has no request to sign in for. Three questions are open: how these pages sign
the user in, what the profile edits, and how a password change affects the user's other
sessions.

## Decision

- **Pages.** Each tenant serves its account pages under its issuer:
  - `/account`: the profile;
  - `/account/password`: a password change;
  - `/account/applications`: the applications the user allowed;
  - `/account/login` and `/account/logout`: sign-in and sign-out.

  The root of the issuer redirects to `/account`.
- **Sign-in.** The account pages use the browser session of single sign-on (ADR 0013).
  - Without an active session, `/account/login` signs the user in with a password. It needs no
    client and no authorization request.
  - The new session replaces the browser's previous one, like any sign-in, and also serves the
    tenant's applications.
  - Every form is protected by `http.CrossOriginProtection`, which also blocks login cross-site
    request forgery, since no request binds the sign-in to the browser.
  - A sign-in that races a password change ends, as in ADR 0027.
  - Sign-out ends the session like RP-Initiated Logout (ADR 0023) and stays at Clavis.
- **Profile.** The profile edits every standard claim of OpenID Connect Core 1.0, section 5.1,
  except the email address. Each claim is checked and stored normalized:
  - names, gender and the parts of the address are one line of text without control characters;
  - the street address may take several lines;
  - `profile`, `picture` and `website` are absolute https or http URLs;
  - `birthdate` is `YYYY-MM-DD` (the year may be `0000`) or `YYYY`;
  - `zoneinfo` has the form of a time zone name;
  - `locale` is a BCP 47 language tag in canonical form;
  - `phone_number` is an E.164 number with an optional extension.

  Every value is bounded, which also keeps U+0000 out of the store. A changed phone number is no
  longer verified. The formatted address, which the form does not show, stays only while the
  other parts of the address do not change and it passes the same rules. Otherwise saving the
  profile drops it, so it never contradicts the parts nor blocks the form with a problem the
  user cannot see.
  Changing the email address needs a proof of the new address that reveals nothing about other
  accounts, and comes later.
- **Password change.** The user gives the current password and a new one under the policy of
  ADR 0015. Like a reset (ADR 0027), the change ends every other session of the user and revokes
  the user's codes not redeemed yet, access tokens and refresh token families. The session that
  made the change stays.
- **Applications.** The page lists the grants of the user, with the client's name and what each
  scope allows. Removing one revokes the grant as ADR 0020 describes. Clients that skip consent
  keep no grant and do not appear.
- **Password reset.** The account sign-in page links to the reset of ADR 0027 without an
  authorization request. The reset binds to the browser by its own binding cookie, its message
  names no application, and it ends on the account sign-in page.

## Consequences

- Users have pages of their own, which operators can link to at the issuer.
- A user who signs in to the account pages is signed in to the tenant's applications as well.
- The account sign-in has no second factor until milestone 4, which applies the tenant's policy
  to it like to any sign-in.
- Changing the email address, managing second factors, listing sessions and deleting the account
  come later.
- The account sign-in needs the rate limits of work item 3.5, like the sign-in of an
  authorization request.
