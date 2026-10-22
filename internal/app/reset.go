package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"
	"uuid"

	"clavisid.org/clavis/internal/emailtmpl"
	"clavisid.org/clavis/internal/i18n"
	"clavisid.org/clavis/store"
)

// ErrResetUnavailable reports a server without email, which cannot reset
// passwords (ADR 0027).
var ErrResetUnavailable = errors.New("password reset is not available")

// StartPasswordReset begins the reset of the password of the account of the
// address that the user typed, for the authorization request p, or for the
// account pages when p is nil (ADR 0027, ADR 0028).
// It stores an email verification bound to the browser whose binding cookie
// hashes to bindingHash and renders a message with a code and a link to
// verifyURL, in the locale of text, whatever the address. It queues the
// message only when the address has an active account. Both cases do the
// same work otherwise and return a verification ID, so nothing that reaches
// the browser tells them apart. A malformed address returns an error that
// wraps ErrInvalidEmail.
func StartPasswordReset(ctx context.Context, d Deps, t AuthorizationTenant, p *PendingAuthorization, address string,
	bindingHash []byte, text i18n.Printer, verifyURL string,
) (string, error) {
	switch {
	case d.Mail == nil:
		return "", ErrResetUnavailable
	case p != nil && p.Request.SessionID != uuid.Nil():
		// A user signed in for the request already; it waits for consent.
		return "", ErrAuthorizationRequestNotFound
	}
	var requestID, client string
	if p != nil {
		requestID, client = p.Request.ID, p.Client.Name
	}
	email, err := NormalizeEmail(address)
	if err != nil {
		return "", err
	}
	u, err := d.Store.Users().GetByEmail(ctx, t.ID, email)
	active := err == nil && u.Status == store.UserActive
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return "", fmt.Errorf("looking up user: %w", err)
	}
	v, code, link, err := startVerification(ctx, d, t.ID, store.VerifyPasswordReset, email, bindingHash, requestID,
		verifyURL)
	if err != nil {
		return "", err
	}
	msg, err := emailtmpl.Render(ctx, email, resetMessage(text, client, code, link))
	if err != nil {
		return "", fmt.Errorf("rendering the password reset message: %w", err)
	}
	attrs := []slog.Attr{slog.String("tenant_id", t.ID.String()), slog.String("verification_id", v.ID)}
	if active {
		if err := d.Mail.Enqueue(ctx, msg); err != nil {
			// The page stays the same; the user can start again.
			d.Logger.LogAttrs(ctx, slog.LevelError, "password reset message not queued",
				append(attrs, slog.String("error", err.Error()))...)
		}
	}
	d.Logger.LogAttrs(ctx, slog.LevelInfo, "password reset started", append(attrs, slog.Bool("active_account", active))...)
	return v.ID, nil
}

// resetMessage returns the message that StartPasswordReset sends, which
// names the application that the user signs in to, unless client is empty.
func resetMessage(text i18n.Printer, client, code, link string) emailtmpl.Content {
	minutes := strconv.Itoa(int(EmailVerificationLifetime / time.Minute))
	body := text.T(i18n.EmailResetBody, "client", client, "minutes", minutes)
	if client == "" {
		body = text.T(i18n.EmailResetAccountBody, "minutes", minutes)
	}
	return emailtmpl.Content{
		Locale:     text.Locale(),
		Subject:    text.T(i18n.EmailResetSubject),
		Paragraphs: []string{body},
		Code:       code,
		LinkURL:    link,
		LinkText:   text.T(i18n.EmailResetLink),
		Footer:     text.T(i18n.EmailResetFooter),
	}
}

// CompletePasswordReset makes pw the password of the account of v, a
// verified password reset verification, and returns the user. The address is
// proved, so the account's address becomes verified. Like any password
// change, it ends every session of the user and revokes the user's tokens.
// A password outside the policy returns an error that wraps
// password.ErrPolicy, and the verification stays for another attempt. The
// verification is used once; an account that is gone or disabled meanwhile,
// or that never existed, returns ErrVerificationNotFound.
func CompletePasswordReset(ctx context.Context, d Deps, h PasswordHasher, v store.EmailVerification, pw string,
) (store.User, error) {
	if v.VerifiedAt.IsZero() || v.Purpose != store.VerifyPasswordReset {
		return store.User{}, ErrVerificationNotFound
	}
	if err := h.CheckNew(pw); err != nil {
		return store.User{}, err
	}
	hash, err := h.Hash(ctx, pw)
	if err != nil {
		return store.User{}, fmt.Errorf("hashing password: %w", err)
	}
	// Deleting the verification first makes it single use.
	switch err := d.Store.EmailVerifications().Delete(ctx, v.TenantID, v.ID); {
	case errors.Is(err, store.ErrNotFound):
		return store.User{}, ErrVerificationNotFound
	case err != nil:
		return store.User{}, fmt.Errorf("completing the email verification: %w", err)
	}
	u, err := d.Store.Users().GetByEmail(ctx, v.TenantID, v.Email)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return store.User{}, ErrVerificationNotFound
	case err != nil:
		return store.User{}, fmt.Errorf("looking up user: %w", err)
	case u.Status != store.UserActive:
		return store.User{}, ErrVerificationNotFound
	}
	now := d.Now()
	switch err := d.Store.Passwords().Set(ctx, store.Password{TenantID: u.TenantID, UserID: u.ID, Hash: hash,
		SetAt: now}); {
	case errors.Is(err, store.ErrNotFound):
		return store.User{}, ErrVerificationNotFound
	case err != nil:
		return store.User{}, fmt.Errorf("storing password: %w", err)
	}
	audit(ctx, d, store.AuditEvent{TenantID: u.TenantID, Type: EventPasswordChanged, Actor: store.ActorUser,
		UserID: u.ID, Details: map[string]string{"how": "reset"}})
	if !u.EmailVerified {
		u.EmailVerified, u.UpdatedAt = true, now
		if err := d.Store.Users().Update(ctx, u); err != nil {
			return store.User{}, fmt.Errorf("marking the address verified: %w", err)
		}
	}
	d.Logger.LogAttrs(ctx, slog.LevelInfo, "password reset",
		slog.String("tenant_id", u.TenantID.String()), slog.String("user_id", u.ID.String()))
	if err := endUserAccess(ctx, d, u, uuid.Nil()); err != nil {
		return store.User{}, err
	}
	return u, nil
}
