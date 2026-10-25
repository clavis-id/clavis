package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
	"uuid"

	"clavisid.org/clavis/store"
)

// Types of audit events (ADR 0029). A failed password change is a change
// with a wrong current password, and a locked sign-in an address that wrong
// passwords locked (ADR 0030); the details of an event say more.
const (
	EventSignedIn             = "user.signed_in"
	EventSignInFailed         = "user.sign_in_failed"
	EventSignInLocked         = "user.sign_in_locked"
	EventSignedOut            = "user.signed_out"
	EventUserCreated          = "user.created"
	EventUserDeleted          = "user.deleted"
	EventPasswordChanged      = "user.password_changed"
	EventPasswordChangeFailed = "user.password_change_failed"
	EventProfileUpdated       = "user.profile_updated"
	EventConsentAllowed       = "consent.allowed"
	EventConsentDenied        = "consent.denied"
	EventGrantRevoked         = "grant.revoked"
	EventTokenRevoked         = "token.revoked"
	EventRefreshTokenReused   = "token.refresh_token_reused"
	EventCodeReplayed         = "token.code_replayed"
	EventClientCreated        = "client.created"
	EventClientDeleted        = "client.deleted"
	EventClientSecretRotated  = "client.secret_rotated"
	EventTenantUpdated        = "tenant.updated"
)

// DefaultAuditRetention is how long `clavis serve` keeps audit events unless
// configured otherwise.
const DefaultAuditRetention = 90 * 24 * time.Hour

// maxUserAgentLength bounds the User-Agent header that an audit event keeps.
const maxUserAgentLength = 256

// origin is where the work of a context comes from: an operator, or a
// request with the client's address and user agent.
type origin struct {
	operator  bool
	ip        string
	userAgent string
}

type originKey struct{}

// RequestInfo is what an audit event records about the request that caused
// it.
type RequestInfo struct {
	// IP is the address of the client, as the server determined it.
	IP string
	// UserAgent is the User-Agent header.
	UserAgent string
}

// WithRequest returns ctx for the work of an HTTP request: the audit events
// of that work record info. It replaces what AsOperator set, so a request
// never acts as an operator.
func WithRequest(ctx context.Context, info RequestInfo) context.Context {
	return context.WithValue(ctx, originKey{}, origin{ip: info.IP, userAgent: info.UserAgent})
}

// AsOperator returns ctx for the work of an operator, such as a command of
// the CLI: its audit events name the operator as their actor.
func AsOperator(ctx context.Context) context.Context {
	return context.WithValue(ctx, originKey{}, origin{operator: true})
}

func originOf(ctx context.Context) origin {
	o, _ := ctx.Value(originKey{}).(origin)
	return o
}

// audit records event e of a tenant, with its ID, time and origin, as ADR
// 0029 describes. The work of an operator always names the operator as the
// actor. A failure is logged rather than returned: the event happened
// already, and failing the work it records would not undo it.
func audit(ctx context.Context, d Deps, e store.AuditEvent) {
	o := originOf(ctx)
	e.ID, e.OccurredAt = d.NewID(), d.Now()
	e.IP, e.UserAgent = o.ip, cleanUserAgent(o.userAgent)
	if o.operator {
		e.Actor = store.ActorOperator
	}
	if e.Details == nil {
		e.Details = map[string]string{}
	}
	if err := d.Store.AuditEvents().Create(ctx, e); err != nil {
		d.Logger.LogAttrs(ctx, slog.LevelError, "audit event not recorded",
			slog.String("tenant_id", e.TenantID.String()), slog.String("type", e.Type),
			slog.String("error", err.Error()))
	}
}

// auditSignIn records the password sign-in of the user with the ID userID,
// which started the session with the ID sessionID, for the client with the
// client ID clientID, or for the account pages when clientID is empty.
func auditSignIn(ctx context.Context, d Deps, tenantID, userID uuid.UUID, clientID string, sessionID uuid.UUID) {
	audit(ctx, d, store.AuditEvent{TenantID: tenantID, Type: EventSignedIn, Actor: store.ActorUser,
		UserID: userID, ClientID: clientID, SessionID: sessionID, Details: map[string]string{"method": "password"}})
}

// auditSignInFailure records a password sign-in that failed with err, when
// err is a wrong password or a disabled account; other errors are not the
// user's. u is the user that the typed address names, or the zero user. The
// address itself is not recorded: it is input that no account confirms, and
// people sometimes type their password into it.
func auditSignInFailure(ctx context.Context, d Deps, tenantID uuid.UUID, u store.User, clientID string, err error) {
	reason := failureReason(err)
	if reason == "" {
		return
	}
	audit(ctx, d, store.AuditEvent{TenantID: tenantID, Type: EventSignInFailed, Actor: store.ActorAnonymous,
		UserID: u.ID, ClientID: clientID, Details: map[string]string{"method": "password", "reason": reason}})
}

// failureReason names the failure err of a password check in an audit
// event, or returns "" when err is not a failure of the credentials.
func failureReason(err error) string {
	switch {
	case errors.Is(err, errLocked):
		return "locked"
	case errors.Is(err, ErrInvalidCredentials):
		return "invalid_credentials"
	case errors.Is(err, ErrUserDisabled):
		return "user_disabled"
	}
	return ""
}

// cleanUserAgent returns a User-Agent header as an audit event keeps it:
// valid UTF-8 without control characters, and bounded.
func cleanUserAgent(ua string) string {
	ua = strings.Map(func(r rune) rune {
		if unicode.In(r, unicode.Cc, unicode.Bidi_Control, unicode.Zl, unicode.Zp) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(ua, ""))
	for len(ua) > maxUserAgentLength {
		_, size := utf8.DecodeLastRuneInString(ua)
		ua = ua[:len(ua)-size]
	}
	return ua
}

// changedClaims returns the names of the profile claims that differ between
// before and after, separated by spaces, for an audit event that must not
// hold their values.
func changedClaims(before, after store.Profile) string {
	var names []string
	a, b := profileClaims(&before), profileClaims(&after)
	for i := range a {
		if *a[i].value != *b[i].value {
			names = append(names, a[i].name)
		}
	}
	if before.PhoneNumberVerified != after.PhoneNumberVerified {
		names = append(names, "phone_number_verified")
	}
	return strings.Join(names, " ")
}

// PurgeAuditEvents deletes the audit events of every tenant that are older
// than retention, unless retention is zero, which keeps them for good.
func PurgeAuditEvents(ctx context.Context, d Deps, retention time.Duration) error {
	if retention <= 0 {
		return nil
	}
	n, err := d.Store.AuditEvents().DeleteBefore(ctx, d.Now().Add(-retention))
	if err != nil {
		return fmt.Errorf("deleting old audit events: %w", err)
	}
	if n > 0 {
		d.Logger.LogAttrs(ctx, slog.LevelInfo, "deleted old audit events", slog.Int64("audit_events", n))
	}
	return nil
}

// AuditEventPage is a page of audit events, newest first, with the user
// each one is about when it still exists.
type AuditEventPage struct {
	Events []store.AuditEvent
	// Emails maps the IDs of the users of the events to their addresses.
	Emails map[uuid.UUID]string
}

// ListAuditEvents returns the audit events of a tenant that q selects, with
// the addresses of the users they are about.
func ListAuditEvents(ctx context.Context, d Deps, tenantID uuid.UUID, q store.AuditQuery) (AuditEventPage, error) {
	events, err := d.Store.AuditEvents().List(ctx, tenantID, q)
	if err != nil {
		return AuditEventPage{}, fmt.Errorf("listing audit events: %w", err)
	}
	page := AuditEventPage{Events: events, Emails: make(map[uuid.UUID]string)}
	for _, e := range events {
		if e.UserID == uuid.Nil() {
			continue
		}
		if _, ok := page.Emails[e.UserID]; ok {
			continue
		}
		if u, err := d.Store.Users().Get(ctx, tenantID, e.UserID); err == nil {
			page.Emails[e.UserID] = u.Email
		}
	}
	return page, nil
}
