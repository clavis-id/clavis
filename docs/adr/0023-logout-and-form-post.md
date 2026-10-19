# 0023. Logout and the form post response mode

- Status: Accepted
- Date: 2026-10-19
- Supersedes: the retention default of ADR 0011

## Context

The last work item of the session milestone adds OpenID Connect RP-Initiated Logout 1.0 and the
OAuth 2.0 Form Post Response Mode. ADR 0013 says that RP-initiated logout ends the browser
session, but leaves open:

- When the user must confirm. The specification says the OP SHOULD ask whether to sign out,
  and MUST ask when the request has no `id_token_hint` or names another session.
- When the browser may go back to the client. Section 3 forbids the redirect to a
  post-logout redirect URI that is not registered exactly, and without an `id_token_hint`
  unless the OP has other means of trusting the target.
- What ending a session revokes. ADR 0021 keeps refresh token families past the session,
  because offline access outlives it, and records each family's session so that this decision
  could be made with logout. The notes of earlier reviews ask that a session's pending codes
  end with it.
- How long an `id_token_hint` can be verified. Relying parties keep the ID token of a sign-in
  for logout, sessions last up to 14 days, and ADR 0011 deletes a retired key 48 hours after a
  rotation. A logout after a rotation would carry a hint signed by a key that is gone.

The form post response mode returns the authorization response as an HTML form that the
browser posts to the redirect URI. The hosted pages run no scripts under their Content Security
Policy, and the form must submit itself.

## Decision

- **Endpoint.** `GET` and `POST /oauth2/logout` under each issuer, announced as
  `end_session_endpoint`. Clavis reads `id_token_hint`, `client_id`,
  `post_logout_redirect_uri` and `state`, and ignores `logout_hint` and `ui_locales`.
- **Redirect after logout.** The browser goes back to the client only when:
  - the request has an `id_token_hint` that the tenant issued, which may have expired
    (section 2), and whose `aud` names a client of the tenant;
  - `client_id`, when present, names that client;
  - `post_logout_redirect_uri` is registered for that client, compared exactly (section 3).

  The redirect carries `state`. `client_id` alone is not enough to trust the target. A request
  that fails a check still lets the user sign out; the browser then stays at Clavis.
- **Confirmation.** A browser with an active session gets a page that names the account and,
  with a valid hint, the client, and asks the user to sign out. When the request fails a
  check, the page says why the browser will stay at Clavis. The form posts to `/logout`, which
  accepts only same-origin submissions, like the sign-in form. To stay signed in, the user
  closes the page. A browser without an active session has nothing to confirm: it goes to the
  post-logout redirect URI or to a page that says the user is signed out. A `POST` without the
  session cookie gets the confirmation page too: browsers do not send `SameSite=Lax` cookies
  with a cross-site `POST`, which is how a relying party posts the request, so the browser may
  still be signed in. The confirmation, submitted from Clavis itself, carries the cookie.
- **What logout ends.**
  - The session and its cookie.
  - The session's codes that were not exchanged yet.
  - The access tokens issued from the session's codes that started no refresh token family:
    the session's online access.
  - Refresh token families stay, with their access tokens. Every family is offline access:
    OpenID Connect requests get one only with `offline_access`, and the consent page describes
    the refresh token of an OAuth request as access while the user is signed out (ADR 0021).
  - Codes are kept 25 hours after they expire, the longest access token lifetime plus an hour,
    so that the access tokens issued from them are found.
  - Clavis deletes the session first, so no new code comes from it, then its pending codes, so
    that an exchange in progress fails when it redeems its code, and then revokes the access
    tokens. A single sign-on request that read the session just before it ended may still
    issue a code.
  - A new sign-in replaces the browser's session. When the same user signs in again, for
    example after `prompt=login`, the new session takes over the codes of the old one, and
    with them its online access, which a later logout ends. When another user signs in, the
    previous user is signed out of the browser, and the online access of the old session
    ends as at logout.
- **Key retention.** A retired key stays published for 15 days instead of 48 hours: the
  longest session, 14 days, plus the longest ID token lifetime, a day. An `id_token_hint` from
  any live session verifies, at the end session endpoint and at the authorization endpoint.
  `keys.retention` still configures it.
- **Form post.** An authorization request may send `response_mode=form_post`. The request
  keeps its response mode, so the response goes back the same way whether it comes at once,
  after the sign-in or after consent, with a code or an error.
  - The page holds a form with the response parameters that posts to the redirect URI. One
    inline script submits it, and the page's policy allows that script by its hash; a Continue
    button serves browsers that run no scripts. `form-action` allows only the client's origin.
  - An error in the `state` or the `response_mode` parameter itself goes back as a query, the
    default. Clavis does not support request objects, so a response mode given only inside one
    is not seen.
  - Discovery announces the `query` and `form_post` response modes.

## Consequences

- Logout ends single sign-on for every client of the tenant in that browser. Applications keep
  their own sessions; front-channel and back-channel logout (Phase 2) can end them.
- Resource servers that introspect tokens see a session's online access end at once; those that
  validate JWTs locally accept those tokens until they expire, 10 minutes by default.
- The JWK set publishes two keys for about half of each rotation period. Deployments that
  shorten the retention lose the post-logout redirect for hints signed by keys that are gone.
  Each key stores its expiry when it is created, so keys created before the new retention
  keep 48 hours: for one rotation period after an upgrade, hints signed by the retiring key
  stop verifying 48 hours after it retires.
- Authorization code records stay a day longer than before.
- The conformance run adds the Form Post Basic and RP-Initiated Logout plans. The logout tests
  that expect a screenshot end in review, with screenshots of the confirmation page or of the
  signed-out page.
