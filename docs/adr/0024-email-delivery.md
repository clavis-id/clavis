# 0024. Email delivery

- Status: Accepted
- Date: 2026-10-19

## Context

Milestone 3 adds signup with email verification and password reset, so Clavis starts sending
email to users. The Phase 1 plan names a `Sender` port with an SMTP adapter on
`github.com/wneessen/go-mail`, a console driver for development, and text and HTML templates.
Three questions remain open:

- When a message goes out relative to the request that causes it. Sending during the request
  makes the response wait for the mail server, and the difference in time tells an attacker
  whether a message was sent, which reveals whether an account exists. A store-backed outbox
  survives restarts but keeps codes at rest and needs coordination between instances.
- How embedders use a provider of their own, such as an HTTP email API, instead of SMTP.
- How the SMTP connection is protected. Credentials and one-time codes must not travel in
  plain text, but local development often uses a test server, such as Mailpit, without TLS.

## Decision

- **Port.** The public package `email` defines `Message` (one recipient, a subject, a plain
  text body and an optional HTML body) and `Sender`, which delivers one message.
  `clavis.Config.Email` takes any `Sender`, like `Config.KeyEncrypter` takes any
  `kek.Encrypter`. A `Sender` wraps `email.ErrRejected` around permanent refusals, which are
  not retried.
- **Adapters.** `email.NewSMTP` sends through an SMTP server with go-mail, one connection per
  message, and authenticates with the strongest mechanism the server offers. `email.NewConsole`
  writes each message to the log at the warning level instead, for development only.
- **TLS.** STARTTLS is required by default (port 587), and implicit TLS (RFC 8314, port 465)
  is available. Certificates are verified, with TLS 1.2 or later. Plain text is accepted only
  for a loopback host and without credentials. A server that does not offer STARTTLS ends the
  connection before anything is sent.
- **Delivery.** A use case queues a message and returns at once. Background workers, two per
  instance, deliver queued messages and retry a failure twice, after 5 and 30 seconds, with a
  one-minute limit on each attempt. The queue holds 256 messages in memory; a full queue drops
  the message and logs an error. Messages are never stored, so codes never reach the database,
  and a restart loses the messages not sent yet: the user asks for another. Logs never show the
  content or the recipient of a message: an SMTP failure is described by its step and the
  server's reply codes, not by the reply text, which often quotes the address.
- **Configuration.** The `email` section chooses the driver: `smtp`, `console`, or none, the
  default, which disables email and the features that need it. The console driver is never
  chosen implicitly, and the server logs a warning when it starts with it.
  `clavis email test --to ADDRESS` sends a test message with the configured driver and waits
  for the result.
- **Templates.** `internal/emailtmpl` renders a message from its content (a subject,
  paragraphs, an optional one-time code, an optional link and a footer) as plain text with an
  HTML alternative. The HTML has inline styles, no images and no scripts, and links must be
  absolute `https` or `http` URLs. Milestone 3 translates the content (work item 3.2).

## Consequences

- Responses that send email take the same time whether or not a message goes out, which the
  enumeration-safe flows of work items 3.3 and 3.4 need.
- A message can be lost on restart or when the queue is full. Users recover by asking again;
  a store-backed outbox can replace the queue later without changing the `Sender` port.
- Sender authentication (SPF, DKIM, DMARC) is the job of the mail provider or relay.
- go-mail is a new dependency: MIT licensed, maintained (v0.8.1, July 2026), and it only
  requires `golang.org/x/crypto` and `golang.org/x/text`, which Clavis already uses. The
  standard library's `net/smtp` is frozen and offers no TLS policy, context support or MIME
  building. Clavis dials the connections itself, so a canceled context or a failed upgrade
  always closes them.
