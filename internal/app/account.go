package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"uuid"

	"clavisid.org/clavis/store"
)

// ErrNoAccountSession reports a browser without an active session of a
// user who may sign in, which the account pages need (ADR 0028).
var ErrNoAccountSession = errors.New("no active session")

// Account is the user of the account pages, with the browser session that
// signed the user in.
type Account struct {
	User    store.User
	Session store.Session
}

// FindAccount returns the user of the session of a tenant whose cookie
// hashes to sessionHash, provided that the session has not expired and the
// user may still sign in, and records the use of the session as single
// sign-on does. Any other case returns ErrNoAccountSession.
func FindAccount(ctx context.Context, d Deps, tenantID uuid.UUID, sessionHash []byte) (Account, error) {
	s, ok, err := activeSession(ctx, d, tenantID, sessionHash)
	switch {
	case err != nil:
		return Account{}, err
	case !ok:
		return Account{}, ErrNoAccountSession
	}
	u, err := d.Store.Users().Get(ctx, tenantID, s.UserID)
	switch {
	case errors.Is(err, store.ErrNotFound) || err == nil && u.Status != store.UserActive:
		return Account{}, ErrNoAccountSession
	case err != nil:
		return Account{}, fmt.Errorf("looking up the user of the session: %w", err)
	}
	s, ok, err = touchSession(ctx, d, s)
	switch {
	case err != nil:
		return Account{}, err
	case !ok:
		return Account{}, ErrNoAccountSession
	}
	return Account{User: u, Session: s}, nil
}

// SignInToAccount signs a user in with a password for the account pages,
// which need no authorization request, and returns the new session. It
// replaces the session whose token hashes to previousSession, if any, and
// fails like a sign-in for an authorization request: wrong credentials
// return ErrInvalidCredentials, and a password that changed during the
// sign-in ends the new session.
func SignInToAccount(ctx context.Context, d Deps, h PasswordHasher, tenantID uuid.UUID, email, pw string,
	previousSession []byte,
) (Login, error) {
	u, setAt, err := authenticatePassword(ctx, d, h, tenantID, email, pw)
	if err != nil {
		auditSignInFailure(ctx, d, tenantID, u, "", err)
		return Login{}, err
	}
	session, token, err := startSession(ctx, d, tenantID, d.NewID(), u.ID, previousSession)
	if err != nil {
		return Login{}, err
	}
	login := Login{SessionToken: token, SessionExpiresAt: session.ExpiresAt, sessionID: session.ID}
	if err := confirmPassword(ctx, d, tenantID, u, setAt, login); err != nil {
		auditSignInFailure(ctx, d, tenantID, u, "", err)
		return Login{}, err
	}
	d.Logger.LogAttrs(ctx, slog.LevelInfo, "user signed in to the account pages",
		slog.String("tenant_id", tenantID.String()),
		slog.String("user_id", u.ID.String()),
		slog.String("session_id", session.ID.String()))
	auditSignIn(ctx, d, tenantID, u.ID, "", session.ID)
	return login, nil
}

// SignOutOfAccount ends the session of a, with the online access issued in
// it, as RP-Initiated Logout does (ADR 0023).
func SignOutOfAccount(ctx context.Context, d Deps, a Account) error {
	codes, tokens, err := endSession(ctx, d, a.Session.TenantID, a.Session)
	if err != nil {
		return err
	}
	d.Logger.LogAttrs(ctx, slog.LevelInfo, "user signed out of the account pages",
		slog.String("tenant_id", a.Session.TenantID.String()),
		slog.String("user_id", a.User.ID.String()),
		slog.String("session_id", a.Session.ID.String()),
		slog.Int64("deleted_authorization_codes", codes),
		slog.Int64("revoked_access_tokens", tokens))
	audit(ctx, d, store.AuditEvent{TenantID: a.Session.TenantID, Type: EventSignedOut, Actor: store.ActorUser,
		UserID: a.User.ID, SessionID: a.Session.ID})
	return nil
}

// ChangePassword replaces the password of the user of a, who must give the
// current one, with next. Like any password change, it ends every other
// session of the user and revokes the user's tokens; the session of a
// stays. A wrong current password returns ErrInvalidCredentials, and a new
// one outside the policy an error that wraps password.ErrPolicy.
func ChangePassword(ctx context.Context, d Deps, h PasswordHasher, a Account, current, next string) error {
	if _, _, err := authenticatePassword(ctx, d, h, a.User.TenantID, a.User.Email, current); err != nil {
		if reason := failureReason(err); reason != "" {
			audit(ctx, d, store.AuditEvent{TenantID: a.User.TenantID, Type: EventPasswordChangeFailed,
				Actor: store.ActorUser, UserID: a.User.ID, SessionID: a.Session.ID,
				Details: map[string]string{"reason": reason}})
		}
		return err
	}
	if err := h.CheckNew(next); err != nil {
		return err
	}
	hash, err := h.Hash(ctx, next)
	if err != nil {
		return fmt.Errorf("hashing password: %w", err)
	}
	u := a.User
	switch err := d.Store.Passwords().Set(ctx, store.Password{TenantID: u.TenantID, UserID: u.ID, Hash: hash,
		SetAt: d.Now()}); {
	case errors.Is(err, store.ErrNotFound):
		return fmt.Errorf("%w: %s", ErrUserNotFound, u.Email)
	case err != nil:
		return fmt.Errorf("storing password: %w", err)
	}
	d.Logger.LogAttrs(ctx, slog.LevelInfo, "user changed the password",
		slog.String("tenant_id", u.TenantID.String()), slog.String("user_id", u.ID.String()))
	audit(ctx, d, store.AuditEvent{TenantID: u.TenantID, Type: EventPasswordChanged, Actor: store.ActorUser,
		UserID: u.ID, SessionID: a.Session.ID, Details: map[string]string{"how": "account"}})
	unlockSignIn(ctx, d, u)
	return endUserAccess(ctx, d, u, a.Session.ID)
}
