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

// held reports whether the counter of k holds its key: it reached limit and
// has not ended.
func held(ctx context.Context, d Deps, k store.LimitKey, limit int) (bool, error) {
	c, err := d.Store.LimitCounters().Get(ctx, k)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("reading a limit counter: %w", err)
	}
	return c.Count >= limit && d.Now().Before(c.EndsAt), nil
}

// countFailure counts a failure for k, which locks its key for window when
// it is the limit-th, and returns the counter. A failure that cannot be
// counted is logged: the request fails anyway.
func countFailure(ctx context.Context, d Deps, k store.LimitKey, window time.Duration, limit int,
) (store.LimitCount, bool) {
	c, err := d.Store.LimitCounters().Add(ctx, k, d.Now(), window, limit)
	if err != nil {
		d.Logger.LogAttrs(ctx, slog.LevelError, "failure not counted", slog.String("tenant_id", k.TenantID.String()),
			slog.String("kind", k.Kind), slog.String("error", err.Error()))
		return store.LimitCount{}, false
	}
	return c, true
}

// signInKey returns the key of the wrong passwords for email, as typed for
// a sign-in to a tenant, or false for a malformed address, which no account
// has and which is not counted.
func signInKey(tenantID uuid.UUID, email string) (store.LimitKey, bool) {
	normalized, err := NormalizeEmail(email)
	return addressKey(tenantID, limitSignIn, normalized), err == nil
}

// signInLocked reports whether email, as typed for a sign-in to a tenant,
// is locked by wrong passwords.
func signInLocked(ctx context.Context, d Deps, tenantID uuid.UUID, email string) (bool, error) {
	k, ok := signInKey(tenantID, email)
	if !ok {
		return false, nil
	}
	return held(ctx, d, k, MaxSignInFailures)
}

// countSignInFailure counts a wrong password for email, as typed for a
// sign-in to a tenant. u is the user that the address names, or the zero
// user. The failure that locks the address is logged, and audited when it
// names a user.
func countSignInFailure(ctx context.Context, d Deps, tenantID uuid.UUID, email string, u store.User) {
	k, ok := signInKey(tenantID, email)
	if !ok {
		return
	}
	c, ok := countFailure(ctx, d, k, SignInLockout, MaxSignInFailures)
	if !ok || c.Count != MaxSignInFailures {
		return
	}
	attrs := []slog.Attr{slog.String("tenant_id", tenantID.String()), slog.Time("until", c.EndsAt)}
	if u.ID != uuid.Nil() {
		attrs = append(attrs, slog.String("user_id", u.ID.String()))
	}
	d.Logger.LogAttrs(ctx, slog.LevelWarn, "locked an address after wrong passwords", attrs...)
	if u.ID != uuid.Nil() {
		audit(ctx, d, store.AuditEvent{TenantID: tenantID, Type: EventSignInLocked, Actor: store.ActorAnonymous,
			UserID: u.ID, Details: map[string]string{"until": c.EndsAt.Format(time.RFC3339)}})
	}
}

// unlockSignIn forgets the wrong passwords of the address of u, whose
// password has just been set. Setting a password ends the lock (ADR 0030).
// A failure is logged: the password is set anyway.
func unlockSignIn(ctx context.Context, d Deps, u store.User) {
	err := d.Store.LimitCounters().Delete(ctx, addressKey(u.TenantID, limitSignIn, u.Email))
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		d.Logger.LogAttrs(ctx, slog.LevelError, "wrong passwords not forgotten after a password change",
			slog.String("tenant_id", u.TenantID.String()), slog.String("user_id", u.ID.String()),
			slog.String("error", err.Error()))
	}
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

// codesLocked reports whether the address of v has received
// MaxCodeFailures wrong codes within CodeLockout.
func codesLocked(ctx context.Context, d Deps, v store.EmailVerification) (bool, error) {
	return held(ctx, d, addressKey(v.TenantID, limitCode, v.Email), MaxCodeFailures)
}

// countCodeFailure counts a wrong code for the address of v. The failure
// that locks the codes of the address is logged.
func countCodeFailure(ctx context.Context, d Deps, v store.EmailVerification) {
	c, ok := countFailure(ctx, d, addressKey(v.TenantID, limitCode, v.Email), CodeLockout, MaxCodeFailures)
	if ok && c.Count == MaxCodeFailures {
		d.Logger.LogAttrs(ctx, slog.LevelWarn, "locked the codes of an address after wrong codes",
			slog.String("tenant_id", v.TenantID.String()), slog.String("verification_id", v.ID),
			slog.Time("until", c.EndsAt))
	}
}
