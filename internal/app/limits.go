package app

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"time"
	"uuid"

	"clavisid.org/clavis/store"
)

// Limits per email address (ADR 0030). They are stored, so they hold across
// the instances that share a store. They count the address that was typed
// whether or not an account has it, so they reveal nothing about accounts.
// A password or a code counts before it is checked, so that attempts that
// arrive together cannot exceed a limit, and a right one forgets the count.
const (
	// MaxSignInFailures wrong passwords for an address within SignInLockout
	// lock it for SignInLockout after the last of them. Until then every
	// password fails like a wrong one, the right one too.
	MaxSignInFailures = 10
	SignInLockout     = 15 * time.Minute
	// MaxCodeFailures wrong codes for an address within CodeLockout, across
	// its email verifications, refuse its codes for CodeLockout after the
	// last of them. Links still work: they cannot be guessed.
	MaxCodeFailures = 10
	CodeLockout     = 24 * time.Hour
	// MaxMessages messages to an address within MessageWindow refuse more
	// messages for MessageWindow after the last of them.
	MaxMessages   = 5
	MessageWindow = time.Hour
)

// Kinds of the limit counters of an address.
const (
	limitSignIn  = "sign_in"
	limitCode    = "code"
	limitMessage = "message"
)

var (
	// ErrTooManyMessages reports an address that received MaxMessages
	// messages within MessageWindow; the user tries again later.
	ErrTooManyMessages = errors.New("too many messages to the address")
	// ErrCodesLocked reports an address that received MaxCodeFailures wrong
	// codes within CodeLockout. The link of the message still works.
	ErrCodesLocked = errors.New("too many wrong codes for the address")
	// errLocked is the ErrInvalidCredentials of an address locked by wrong
	// passwords, which callers cannot tell from a wrong password.
	errLocked = fmt.Errorf("%w: the address is locked", ErrInvalidCredentials)
)

// addressKey returns the key of the counter of kind for email, a normalized
// address of a tenant. The key is a hash, so counters keep no addresses.
func addressKey(tenantID uuid.UUID, kind, email string) store.LimitKey {
	sum := sha256.Sum256([]byte(email))
	return store.LimitKey{TenantID: tenantID, Kind: kind, Key: sum[:]}
}

// attempt is a password or a code for an address, which a limit counter
// counted before it was checked (ADR 0030). A right one forgets the
// counter; any other outcome leaves it counted, as a failure.
type attempt struct {
	key     store.LimitKey
	counted bool
	count   store.LimitCount
}

// countAttempt counts an attempt for k, which locks k for window when it is
// the limit-th.
func countAttempt(ctx context.Context, d Deps, k store.LimitKey, window time.Duration, limit int,
) (attempt, error) {
	c, err := d.Store.LimitCounters().Add(ctx, k, d.Now(), window, limit)
	if err != nil {
		return attempt{}, fmt.Errorf("counting an attempt: %w", err)
	}
	return attempt{key: k, counted: true, count: c}, nil
}

// beyond reports whether a comes after limit attempts within the window of
// its counter, which hold its key.
func (a attempt) beyond(limit int) bool {
	return a.counted && a.count.Count > limit
}

// locks reports whether a, which failed, is the limit-th attempt within the
// window of its counter, which locks its key.
func (a attempt) locks(limit int) bool {
	return a.counted && a.count.Count == limit
}

// forgetCounter deletes the counter of k. A failure is logged with msg and
// attrs: the work that it follows is done anyway.
func forgetCounter(ctx context.Context, d Deps, k store.LimitKey, msg string, attrs ...slog.Attr) {
	err := d.Store.LimitCounters().Delete(ctx, k)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		attrs = append(attrs, slog.String("tenant_id", k.TenantID.String()), slog.String("kind", k.Kind),
			slog.String("error", err.Error()))
		d.Logger.LogAttrs(ctx, slog.LevelError, msg, attrs...)
	}
}

// countSignIn counts a sign-in attempt with email, as typed for a sign-in to
// a tenant, before its password is checked. A malformed address, which no
// account has, is not counted.
func countSignIn(ctx context.Context, d Deps, tenantID uuid.UUID, email string) (attempt, error) {
	k, ok := signInKey(tenantID, email)
	if !ok {
		return attempt{}, nil
	}
	return countAttempt(ctx, d, k, SignInLockout, MaxSignInFailures)
}

// signInKey returns the key of the sign-ins with email, as typed for a
// tenant, or false for a malformed address.
func signInKey(tenantID uuid.UUID, email string) (store.LimitKey, bool) {
	normalized, err := NormalizeEmail(email)
	return addressKey(tenantID, limitSignIn, normalized), err == nil
}

// signInFailed records that the password of a was wrong. u is the user that
// the address names, or the zero user. The failure that locks the address
// is logged, and audited when it names a user.
func signInFailed(ctx context.Context, d Deps, a attempt, u store.User) {
	if !a.locks(MaxSignInFailures) {
		return
	}
	tenantID, until := a.key.TenantID, a.count.EndsAt
	attrs := []slog.Attr{slog.String("tenant_id", tenantID.String()), slog.Time("until", until)}
	if u.ID != uuid.Nil() {
		attrs = append(attrs, slog.String("user_id", u.ID.String()))
	}
	d.Logger.LogAttrs(ctx, slog.LevelWarn, "locked an address after wrong passwords", attrs...)
	if u.ID != uuid.Nil() {
		audit(ctx, d, store.AuditEvent{TenantID: tenantID, Type: EventSignInLocked, Actor: store.ActorAnonymous,
			UserID: u.ID, Details: map[string]string{"until": until.Format(time.RFC3339)}})
	}
}

// signInSucceeded forgets the attempts of the address of a, whose password
// was right.
func signInSucceeded(ctx context.Context, d Deps, a attempt) {
	if a.counted {
		forgetCounter(ctx, d, a.key, "wrong passwords not forgotten after a right one")
	}
}

// unlockSignIn forgets the wrong passwords of the address of u, whose
// password has just been set. Setting a password ends the lock (ADR 0030).
func unlockSignIn(ctx context.Context, d Deps, u store.User) {
	forgetCounter(ctx, d, addressKey(u.TenantID, limitSignIn, u.Email),
		"wrong passwords not forgotten after a password change", slog.String("user_id", u.ID.String()))
}

// countMessage counts a message to email, a normalized address of a tenant,
// and returns ErrTooManyMessages when the address has received
// MaxMessages within MessageWindow.
func countMessage(ctx context.Context, d Deps, tenantID uuid.UUID, email string) error {
	c, err := d.Store.LimitCounters().Add(ctx, addressKey(tenantID, limitMessage, email), d.Now(), MessageWindow,
		MaxMessages)
	switch {
	case err != nil:
		return fmt.Errorf("counting a message: %w", err)
	case c.Count > MaxMessages:
		d.Logger.LogAttrs(ctx, slog.LevelInfo, "refused a message: too many messages to the address",
			slog.String("tenant_id", tenantID.String()))
		return ErrTooManyMessages
	}
	return nil
}

// countCode counts a code typed for the address of v before it is
// compared.
func countCode(ctx context.Context, d Deps, v store.EmailVerification) (attempt, error) {
	return countAttempt(ctx, d, addressKey(v.TenantID, limitCode, v.Email), CodeLockout, MaxCodeFailures)
}

// codeFailed records that the code of a, typed for the address of v, was
// wrong. The failure that locks the codes of the address is logged.
func codeFailed(ctx context.Context, d Deps, a attempt, v store.EmailVerification) {
	if a.locks(MaxCodeFailures) {
		d.Logger.LogAttrs(ctx, slog.LevelWarn, "locked the codes of an address after wrong codes",
			slog.String("tenant_id", v.TenantID.String()), slog.String("verification_id", v.ID),
			slog.Time("until", a.count.EndsAt))
	}
}
