package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"time"
	"uuid"

	"clavisid.org/clavis/internal/emailtmpl"
	"clavisid.org/clavis/internal/i18n"
	"clavisid.org/clavis/internal/oauth"
	"clavisid.org/clavis/store"
)

// Bounds of email verifications (ADR 0026).
const (
	// EmailVerificationLifetime is how long a code and a link work.
	EmailVerificationLifetime = 15 * time.Minute
	// MaxCodeAttempts bounds the codes submitted for one verification.
	MaxCodeAttempts = 5
	// CodeLength is the number of digits of a code.
	CodeLength = 6
)

// Errors returned by the signup use cases.
var (
	// ErrSignupUnavailable reports a tenant that does not offer signup, or a
	// server without email, which cannot verify addresses.
	ErrSignupUnavailable = errors.New("signup is not available")
	// ErrVerificationNotFound reports an email verification that does not
	// exist, has expired, was completed already, or belongs to another
	// browser. The cases are not told apart, like those of
	// ErrAuthorizationRequestNotFound.
	ErrVerificationNotFound = errors.New("the email verification has expired, was completed already, " +
		"or was started in another browser")
	// ErrWrongCode reports a code that does not match; the user can try
	// again while attempts remain.
	ErrWrongCode = errors.New("wrong code")
	// ErrTooManyAttempts reports a verification that received
	// MaxCodeAttempts codes, none of them right; the user starts again.
	ErrTooManyAttempts = errors.New("too many wrong codes")
)

// StartSignup begins the signup of the address that the user typed, for the
// authorization request p (ADR 0026). It stores an email verification bound
// to the browser whose binding cookie hashes to bindingHash and queues a
// message to the address in the locale of text: a code and a link to
// verifyURL when the address has no account, and a notice that it has one
// otherwise. Both cases do the same work and return a verification ID, and
// a message that cannot be queued is only logged, so nothing that reaches
// the browser tells them apart. A malformed address returns an error that
// wraps ErrInvalidEmail, and an address that received MaxMessages messages
// within MessageWindow, whether or not it has an account,
// ErrTooManyMessages (ADR 0030).
func StartSignup(ctx context.Context, d Deps, t AuthorizationTenant, p PendingAuthorization, address string,
	bindingHash []byte, text i18n.Printer, verifyURL string,
) (string, error) {
	switch {
	case !t.Signup || d.Mail == nil:
		return "", ErrSignupUnavailable
	case p.Request.SessionID != uuid.Nil():
		// A user signed in for the request already; it waits for consent.
		return "", ErrAuthorizationRequestNotFound
	}
	email, err := NormalizeEmail(address)
	if err != nil {
		return "", err
	}
	if err := countMessage(ctx, d, t.ID, email); err != nil {
		return "", err
	}
	_, err = d.Store.Users().GetByEmail(ctx, t.ID, email)
	exists := err == nil
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return "", fmt.Errorf("looking up user: %w", err)
	}

	v, code, link, err := startVerification(ctx, d, t.ID, store.VerifySignup, email, bindingHash, p.Request.ID,
		verifyURL)
	if err != nil {
		return "", err
	}
	msg, err := emailtmpl.Render(ctx, email, signupMessage(text, p.Client.Name, code, link, exists))
	if err != nil {
		return "", fmt.Errorf("rendering the signup message: %w", err)
	}
	attrs := []slog.Attr{slog.String("tenant_id", t.ID.String()), slog.String("verification_id", v.ID)}
	if err := d.Mail.Enqueue(ctx, msg); err != nil {
		// The page stays the same; the user can start again.
		d.Logger.LogAttrs(ctx, slog.LevelError, "signup message not queued",
			append(attrs, slog.String("error", err.Error()))...)
	}
	d.Logger.LogAttrs(ctx, slog.LevelInfo, "signup started", append(attrs, slog.Bool("existing_account", exists))...)
	return v.ID, nil
}

// startVerification stores a new email verification of a tenant for
// purpose and email, bound to the browser whose binding cookie hashes to
// bindingHash, for the authorization request with the ID requestID. It
// returns the verification with its code and the link to verifyURL that
// carries its token.
func startVerification(ctx context.Context, d Deps, tenantID uuid.UUID, purpose store.EmailVerificationPurpose,
	email string, bindingHash []byte, requestID, verifyURL string,
) (v store.EmailVerification, code, link string, err error) {
	now := d.Now()
	code, token := newCode(), oauth.NewToken()
	v = store.EmailVerification{
		ID:                     oauth.NewRequestID(),
		TenantID:               tenantID,
		Purpose:                purpose,
		Email:                  email,
		LinkHash:               oauth.HashToken(token),
		BindingHash:            bindingHash,
		AuthorizationRequestID: requestID,
		CreatedAt:              now,
		ExpiresAt:              now.Add(EmailVerificationLifetime),
	}
	v.CodeHash = codeHash(v.ID, code)
	if err := d.Store.EmailVerifications().Create(ctx, v); err != nil {
		return store.EmailVerification{}, "", "", fmt.Errorf("storing the email verification: %w", err)
	}
	link = verifyURL + "?" + url.Values{"verification": {v.ID}, "token": {token}}.Encode()
	return v, code, link, nil
}

// signupMessage returns the message that StartSignup sends: the code and
// the link for a new account, or a notice when the address has an account.
func signupMessage(text i18n.Printer, client, code, link string, exists bool) emailtmpl.Content {
	if exists {
		return emailtmpl.Content{
			Locale:     text.Locale(),
			Subject:    text.T(i18n.EmailSignupExistsSubject),
			Paragraphs: []string{text.T(i18n.EmailSignupExistsBody, "client", client)},
			Footer:     text.T(i18n.EmailSignupExistsFooter),
		}
	}
	minutes := strconv.Itoa(int(EmailVerificationLifetime / time.Minute))
	return emailtmpl.Content{
		Locale:     text.Locale(),
		Subject:    text.T(i18n.EmailSignupSubject),
		Paragraphs: []string{text.T(i18n.EmailSignupBody, "client", client, "minutes", minutes)},
		Code:       code,
		LinkURL:    link,
		LinkText:   text.T(i18n.EmailSignupLink),
		Footer:     text.T(i18n.EmailSignupFooter),
	}
}

// newCode returns a random code of CodeLength decimal digits. The modulo
// bias of a 64-bit random number is below one in 10^13.
func newCode() string {
	var b [8]byte
	_, _ = rand.Read(b[:]) // Never fails; see crypto/rand.Read.
	n := binary.BigEndian.Uint64(b[:]) % 1_000_000
	return fmt.Sprintf("%0*d", CodeLength, n)
}

// codeHash returns the hash under which the code of the verification with
// the given ID is stored. A code has few digits, so its hash alone protects
// it little; the binding to the browser keeps a stolen hash useless.
func codeHash(id, code string) []byte {
	sum := sha256.Sum256([]byte(id + ":" + code))
	return sum[:]
}

// NormalizeCode returns the code that the user typed without the spaces
// and hyphens that people add to group digits, and whether it has the form
// of a code.
func NormalizeCode(typed string) (string, bool) {
	if len(typed) > 4*CodeLength {
		return "", false
	}
	code := strings.Map(func(r rune) rune {
		if r == ' ' || r == '-' {
			return -1
		}
		return r
	}, typed)
	return code, len(code) == CodeLength && strings.Trim(code, "0123456789") == ""
}

// FindEmailVerification returns an email verification of a tenant for
// purpose, provided that it has not expired, that bindingHash is the binding
// hash it was stored with, and that it has attempts left or is verified.
// Every failure other than a store error returns ErrVerificationNotFound,
// except a verification without attempts left, which returns
// ErrTooManyAttempts.
func FindEmailVerification(ctx context.Context, d Deps, tenantID uuid.UUID, id string, bindingHash []byte,
	purpose store.EmailVerificationPurpose,
) (store.EmailVerification, error) {
	if !oauth.ValidRequestID(id) {
		return store.EmailVerification{}, ErrVerificationNotFound
	}
	v, err := d.Store.EmailVerifications().Get(ctx, tenantID, id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return store.EmailVerification{}, ErrVerificationNotFound
	case err != nil:
		return store.EmailVerification{}, fmt.Errorf("looking up the email verification: %w", err)
	case !d.Now().Before(v.ExpiresAt), v.Purpose != purpose,
		subtle.ConstantTimeCompare(v.BindingHash, bindingHash) != 1:
		return store.EmailVerification{}, ErrVerificationNotFound
	case v.VerifiedAt.IsZero() && v.Attempts >= MaxCodeAttempts:
		return store.EmailVerification{}, ErrTooManyAttempts
	}
	return v, nil
}

// VerifyCode checks the code that the user typed for v, which
// FindEmailVerification returned, and marks v verified when it matches.
// Every submission counts as an attempt, before the comparison, so
// concurrent guesses cannot exceed MaxCodeAttempts. A code that does not
// match returns ErrWrongCode, or ErrTooManyAttempts when it used the last
// attempt. Wrong codes also count against the address, across its
// verifications: after MaxCodeFailures of them, its codes return
// ErrCodesLocked until CodeLockout has passed (ADR 0030).
func VerifyCode(ctx context.Context, d Deps, v store.EmailVerification, typed string) error {
	if !v.VerifiedAt.IsZero() {
		return nil
	}
	switch locked, err := codesLocked(ctx, d, v); {
	case err != nil:
		return err
	case locked:
		return ErrCodesLocked
	}
	n, err := d.Store.EmailVerifications().AddAttempt(ctx, v.TenantID, v.ID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		// Deleted, or verified by a concurrent submission.
		return ErrVerificationNotFound
	case err != nil:
		return fmt.Errorf("counting the attempt: %w", err)
	case n > MaxCodeAttempts:
		return ErrTooManyAttempts
	}
	code, ok := NormalizeCode(typed)
	if !ok || subtle.ConstantTimeCompare(codeHash(v.ID, code), v.CodeHash) != 1 {
		countCodeFailure(ctx, d, v)
		if n == MaxCodeAttempts {
			return ErrTooManyAttempts
		}
		return ErrWrongCode
	}
	return markVerified(ctx, d, v)
}

// VerifyLink checks the token of the link for v, which
// FindEmailVerification returned, and marks v verified when it matches. A
// token that does not match returns ErrVerificationNotFound: a token cannot
// be guessed, so it was copied wrong.
func VerifyLink(ctx context.Context, d Deps, v store.EmailVerification, token string) error {
	if subtle.ConstantTimeCompare(oauth.HashToken(token), v.LinkHash) != 1 {
		return ErrVerificationNotFound
	}
	if !v.VerifiedAt.IsZero() {
		return nil
	}
	return markVerified(ctx, d, v)
}

func markVerified(ctx context.Context, d Deps, v store.EmailVerification) error {
	switch err := d.Store.EmailVerifications().MarkVerified(ctx, v.TenantID, v.ID, d.Now()); {
	case errors.Is(err, store.ErrNotFound):
		// Verified by a concurrent submission, or deleted.
		return ErrVerificationNotFound
	case err != nil:
		return fmt.Errorf("marking the email verification verified: %w", err)
	}
	d.Logger.LogAttrs(ctx, slog.LevelInfo, "email address verified",
		slog.String("tenant_id", v.TenantID.String()), slog.String("verification_id", v.ID))
	return nil
}

// Signup is a completed signup: the new user is signed in. When Request is
// true, Login answers the authorization request of the signup, as a
// password sign-in does. Otherwise that request was gone, and only
// Login.SessionToken and Login.SessionExpiresAt are set.
type Signup struct {
	Login
	Request bool
}

// CompleteSignup creates the account of v, a verified signup verification,
// with the password pw, signs the new user in, and answers p, the
// authorization request of the signup, when it is still pending; pass nil
// when FindAuthorizationRequest did not find it. It replaces the session
// whose token hashes to previousSession, if any. A password outside the
// policy returns an error that wraps password.ErrPolicy, and the
// verification stays for another attempt; an address that got an account
// meanwhile returns ErrUserExists. The verification is used once.
func CompleteSignup(ctx context.Context, d Deps, h PasswordHasher, t AuthorizationTenant,
	v store.EmailVerification, pw string, p *PendingAuthorization, previousSession []byte,
) (Signup, error) {
	if v.VerifiedAt.IsZero() || v.Purpose != store.VerifySignup {
		return Signup{}, ErrVerificationNotFound
	}
	if err := h.CheckNew(pw); err != nil {
		return Signup{}, err
	}
	hash, err := h.Hash(ctx, pw)
	if err != nil {
		return Signup{}, fmt.Errorf("hashing password: %w", err)
	}
	// Deleting the verification first makes it single use.
	switch err := d.Store.EmailVerifications().Delete(ctx, v.TenantID, v.ID); {
	case errors.Is(err, store.ErrNotFound):
		return Signup{}, ErrVerificationNotFound
	case err != nil:
		return Signup{}, fmt.Errorf("completing the email verification: %w", err)
	}
	u, err := createUser(ctx, d, t.ID, UserSpec{Email: v.Email, EmailVerified: true}, store.ActorUser)
	if err != nil {
		return Signup{}, err
	}
	if err := d.Store.Passwords().Set(ctx, store.Password{TenantID: t.ID, UserID: u.ID, Hash: hash,
		SetAt: d.Now()}); err != nil {
		return Signup{}, fmt.Errorf("storing password: %w", err)
	}
	d.Logger.LogAttrs(ctx, slog.LevelInfo, "user signed up",
		slog.String("tenant_id", t.ID.String()), slog.String("user_id", u.ID.String()))

	if p != nil && p.Request.SessionID == uuid.Nil() {
		login, err := signIn(ctx, d, t, *p, u, previousSession)
		switch {
		case err == nil:
			auditSignIn(ctx, d, t.ID, u.ID, p.Client.ClientID, login.sessionID)
			return Signup{Login: login, Request: true}, nil
		case !errors.Is(err, ErrAuthorizationRequestNotFound):
			return Signup{}, err
		}
	}
	// The authorization request is gone: the user returns to the
	// application, where single sign-on finds the new session.
	session, token, err := startSession(ctx, d, t.ID, d.NewID(), u.ID, previousSession)
	if err != nil {
		return Signup{}, err
	}
	d.Logger.LogAttrs(ctx, slog.LevelInfo, "user signed in",
		slog.String("tenant_id", t.ID.String()),
		slog.String("user_id", u.ID.String()),
		slog.String("session_id", session.ID.String()))
	auditSignIn(ctx, d, t.ID, u.ID, "", session.ID)
	return Signup{Login: Login{SessionToken: token, SessionExpiresAt: session.ExpiresAt}}, nil
}
