package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/mail"
	"strings"
	"time"
	"uuid"

	"clavisid.org/clavis/internal/authn/password"
	"clavisid.org/clavis/store"
)

// Length limits of email addresses (RFC 5321, section 4.5.3.1).
const (
	maxEmailLength      = 254
	maxEmailLocalLength = 64
)

// Errors returned by the user use cases.
var (
	ErrInvalidEmail = errors.New("invalid email address")
	ErrInvalidUser  = errors.New("invalid user")
	ErrUserExists   = errors.New("user already exists")
	ErrUserNotFound = errors.New("user not found")
	// ErrInvalidCredentials reports a failed login without saying whether
	// the account exists.
	ErrInvalidCredentials = errors.New("invalid email or password")
	// ErrUserDisabled reports a correct password for a disabled user.
	ErrUserDisabled = errors.New("user is disabled")
)

// PasswordHasher hashes and verifies passwords; *password.Hasher implements
// it.
type PasswordHasher interface {
	CheckNew(pw string) error
	Hash(ctx context.Context, pw string) (string, error)
	Verify(ctx context.Context, encoded, pw string) (password.Verification, error)
	VerifyDummy(ctx context.Context, pw string) error
	FIPS() bool
}

// NormalizeEmail validates an email address and returns it in lowercase,
// which is how users are stored and looked up. Addresses are limited to
// printable ASCII in the dot-atom form, without quoted local parts, comments
// or IP literals, and the domain needs at least two labels. Lowercasing the
// local part departs from RFC 5321, which leaves its case to the receiving
// server, but no common provider distinguishes it, and treating case
// variants as one account prevents duplicates.
func NormalizeEmail(email string) (string, error) {
	if email == "" || len(email) > maxEmailLength {
		return "", fmt.Errorf("%w: must have 1 to %d characters", ErrInvalidEmail, maxEmailLength)
	}
	for _, c := range []byte(email) {
		if c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
			return "", fmt.Errorf("%w: must contain only ASCII letters, digits and symbols, "+
				"without spaces, quotes or backslashes", ErrInvalidEmail)
		}
	}
	local, domain, ok := strings.Cut(email, "@")
	switch {
	case !ok || strings.Contains(domain, "@"):
		return "", fmt.Errorf("%w: must contain exactly one @", ErrInvalidEmail)
	case local == "" || len(local) > maxEmailLocalLength:
		return "", fmt.Errorf("%w: the part before @ must have 1 to %d characters", ErrInvalidEmail, maxEmailLocalLength)
	case !validEmailDomain(domain):
		return "", fmt.Errorf("%w: the domain must be a host name such as example.com", ErrInvalidEmail)
	}
	if addr, err := mail.ParseAddress(email); err != nil || addr.Address != email || addr.Name != "" {
		return "", fmt.Errorf("%w: not a valid address", ErrInvalidEmail)
	}
	return strings.ToLower(email), nil
}

// validEmailDomain reports whether domain is a DNS host name with at least
// two labels whose last label is not numeric.
func validEmailDomain(domain string) bool {
	labels := strings.Split(domain, ".")
	if len(domain) > 253 || len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range []byte(label) {
			if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return strings.Trim(labels[len(labels)-1], "0123456789") != ""
}

// UserSpec describes a user to create.
type UserSpec struct {
	Email         string
	EmailVerified bool
	// Name, GivenName and FamilyName are optional standard claims.
	Name       string
	GivenName  string
	FamilyName string
}

// CreateUser creates an active user without credentials.
func CreateUser(ctx context.Context, d Deps, tenantID uuid.UUID, spec UserSpec) (store.User, error) {
	email, err := NormalizeEmail(spec.Email)
	if err != nil {
		return store.User{}, err
	}
	for _, f := range []struct{ claim, value string }{
		{"name", spec.Name}, {"given_name", spec.GivenName}, {"family_name", spec.FamilyName},
	} {
		if f.value == "" {
			continue
		}
		if err := validateDisplayName(f.value); err != nil {
			return store.User{}, fmt.Errorf("%w: %s: %w", ErrInvalidUser, f.claim, err)
		}
	}
	now := d.Now()
	u := store.User{
		ID:            d.NewID(),
		TenantID:      tenantID,
		Email:         email,
		EmailVerified: spec.EmailVerified,
		Status:        store.UserActive,
		Profile:       store.Profile{Name: spec.Name, GivenName: spec.GivenName, FamilyName: spec.FamilyName},
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	switch err := d.Store.Users().Create(ctx, u); {
	case errors.Is(err, store.ErrConflict):
		return store.User{}, fmt.Errorf("%w: %s", ErrUserExists, email)
	case errors.Is(err, store.ErrNotFound):
		return store.User{}, ErrTenantNotFound
	case err != nil:
		return store.User{}, fmt.Errorf("creating user: %w", err)
	}
	d.Logger.LogAttrs(ctx, slog.LevelInfo, "created user",
		slog.String("tenant_id", tenantID.String()), slog.String("user_id", u.ID.String()))
	return u, nil
}

// FindUser returns the user of a tenant with the given email.
func FindUser(ctx context.Context, d Deps, tenantID uuid.UUID, email string) (store.User, error) {
	normalized, err := NormalizeEmail(email)
	if err != nil {
		return store.User{}, fmt.Errorf("%w: %w", ErrUserNotFound, err)
	}
	u, err := d.Store.Users().GetByEmail(ctx, tenantID, normalized)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return store.User{}, fmt.Errorf("%w: %s", ErrUserNotFound, normalized)
	case err != nil:
		return store.User{}, fmt.Errorf("looking up user: %w", err)
	}
	return u, nil
}

// ListUsers returns every user of a tenant in ID order, which follows
// creation time.
func ListUsers(ctx context.Context, d Deps, tenantID uuid.UUID) ([]store.User, error) {
	var all []store.User
	after := uuid.Nil()
	for {
		page, err := d.Store.Users().List(ctx, tenantID, after, store.MaxPageSize)
		if err != nil {
			return nil, fmt.Errorf("listing users: %w", err)
		}
		all = append(all, page...)
		if len(page) < store.MaxPageSize {
			return all, nil
		}
		after = page[len(page)-1].ID
	}
}

// DeleteUser deletes the user of a tenant with the given email, together
// with the user's credentials.
func DeleteUser(ctx context.Context, d Deps, tenantID uuid.UUID, email string) error {
	u, err := FindUser(ctx, d, tenantID, email)
	if err != nil {
		return err
	}
	switch err := d.Store.Users().Delete(ctx, tenantID, u.ID); {
	case errors.Is(err, store.ErrNotFound):
		return fmt.Errorf("%w: %s", ErrUserNotFound, u.Email)
	case err != nil:
		return fmt.Errorf("deleting user: %w", err)
	}
	d.Logger.LogAttrs(ctx, slog.LevelInfo, "deleted user",
		slog.String("tenant_id", tenantID.String()), slog.String("user_id", u.ID.String()))
	return nil
}

// SetPassword checks pw against the password policy and makes it the
// password of a user, replacing any previous one. Like any password change,
// it ends every session of the user and revokes the user's tokens, so an
// operator's reset also locks out whoever held the account.
func SetPassword(ctx context.Context, d Deps, h PasswordHasher, u store.User, pw string) error {
	if err := h.CheckNew(pw); err != nil {
		return err
	}
	encoded, err := h.Hash(ctx, pw)
	if err != nil {
		return fmt.Errorf("hashing password: %w", err)
	}
	p := store.Password{TenantID: u.TenantID, UserID: u.ID, Hash: encoded, SetAt: d.Now()}
	switch err := d.Store.Passwords().Set(ctx, p); {
	case errors.Is(err, store.ErrNotFound):
		return fmt.Errorf("%w: %s", ErrUserNotFound, u.Email)
	case err != nil:
		return fmt.Errorf("storing password: %w", err)
	}
	d.Logger.LogAttrs(ctx, slog.LevelInfo, "set password",
		slog.String("tenant_id", u.TenantID.String()), slog.String("user_id", u.ID.String()))
	return endUserAccess(ctx, d, u, uuid.Nil())
}

// endUserAccess ends what a user holds after a password change: every
// session but the one with the ID keep, the codes not redeemed yet, and
// every access token and refresh token family. Pass the zero UUID to keep
// no session.
func endUserAccess(ctx context.Context, d Deps, u store.User, keep uuid.UUID) error {
	now := d.Now()
	sessions, err := d.Store.Sessions().DeleteByUser(ctx, u.TenantID, u.ID, keep)
	if err != nil {
		return fmt.Errorf("ending the sessions of the user: %w", err)
	}
	// The sessions go first, so no new code comes from them.
	codes, err := d.Store.AuthorizationCodes().DeleteByUser(ctx, u.TenantID, u.ID)
	if err != nil {
		return fmt.Errorf("deleting the codes of the user: %w", err)
	}
	// Refresh token families come before access tokens, as when a grant is
	// revoked: a refresh records its access token before it rotates the
	// refresh token, so it either fails on the revoked family or its access
	// token is revoked below (ADR 0021).
	families, err := d.Store.RefreshTokens().RevokeByUser(ctx, u.TenantID, u.ID, now)
	if err != nil {
		return fmt.Errorf("revoking the refresh tokens of the user: %w", err)
	}
	tokens, err := d.Store.AccessTokens().RevokeByUser(ctx, u.TenantID, u.ID, now)
	if err != nil {
		return fmt.Errorf("revoking the access tokens of the user: %w", err)
	}
	if sessions+codes+tokens+families > 0 {
		d.Logger.LogAttrs(ctx, slog.LevelInfo, "ended the access of the user after a password change",
			slog.String("tenant_id", u.TenantID.String()), slog.String("user_id", u.ID.String()),
			slog.Int64("sessions", sessions), slog.Int64("authorization_codes", codes),
			slog.Int64("access_tokens", tokens), slog.Int64("refresh_token_families", families))
	}
	return nil
}

// AuthenticatePassword returns the user of a tenant whose email and password
// match. Every failure that could reveal whether the account exists returns
// ErrInvalidCredentials after the work of a password verification (ADR
// 0015). ErrUserDisabled is returned only for a correct password. A hash
// below the current policy is replaced with a new one.
func AuthenticatePassword(ctx context.Context, d Deps, h PasswordHasher, tenantID uuid.UUID,
	email, pw string,
) (store.User, error) {
	u, _, err := authenticatePassword(ctx, d, h, tenantID, email, pw)
	return u, err
}

// authenticatePassword is AuthenticatePassword, and also returns when the
// password that matched was set.
func authenticatePassword(ctx context.Context, d Deps, h PasswordHasher, tenantID uuid.UUID,
	email, pw string,
) (store.User, time.Time, error) {
	u, err := FindUser(ctx, d, tenantID, email)
	if errors.Is(err, ErrUserNotFound) {
		// Look up a password that cannot exist, so an unknown account makes
		// as many queries as a known one and the time of a round trip to the
		// database does not reveal which accounts exist.
		if _, err := d.Store.Passwords().Get(ctx, tenantID, uuid.Nil()); err != nil && !errors.Is(err, store.ErrNotFound) {
			return store.User{}, time.Time{}, fmt.Errorf("looking up password: %w", err)
		}
		return store.User{}, time.Time{}, failLogin(ctx, h, pw)
	}
	if err != nil {
		return store.User{}, time.Time{}, err
	}
	stored, err := d.Store.Passwords().Get(ctx, tenantID, u.ID)
	if errors.Is(err, store.ErrNotFound) {
		return store.User{}, time.Time{}, failLogin(ctx, h, pw)
	}
	if err != nil {
		return store.User{}, time.Time{}, fmt.Errorf("looking up password: %w", err)
	}

	v, err := h.Verify(ctx, stored.Hash, pw)
	switch {
	case errors.Is(err, password.ErrMalformedHash), errors.Is(err, password.ErrUnsupportedHash):
		// Verify did the work of a verification already.
		d.Logger.LogAttrs(ctx, slog.LevelWarn, "cannot verify the password hash of a user; the user must reset "+
			"the password", slog.String("tenant_id", tenantID.String()), slog.String("user_id", u.ID.String()),
			slog.String("error", err.Error()))
		return store.User{}, time.Time{}, ErrInvalidCredentials
	case err != nil:
		return store.User{}, time.Time{}, fmt.Errorf("verifying password: %w", err)
	case !v.Match:
		return store.User{}, time.Time{}, ErrInvalidCredentials
	case u.Status != store.UserActive:
		return store.User{}, time.Time{}, ErrUserDisabled
	}
	if v.Rehash {
		rehash(ctx, d, h, u, stored.Hash, pw, v.Algorithm)
	}
	return u, stored.SetAt, nil
}

// failLogin spends the time of a password verification and returns
// ErrInvalidCredentials, so a missing account or password answers like a
// wrong password.
func failLogin(ctx context.Context, h PasswordHasher, pw string) error {
	if err := h.VerifyDummy(ctx, pw); err != nil {
		return fmt.Errorf("verifying password: %w", err)
	}
	return ErrInvalidCredentials
}

// rehash replaces the stored hash of a correct password with a hash under the
// current policy. Failures are logged: the login itself has succeeded.
func rehash(ctx context.Context, d Deps, h PasswordHasher, u store.User, oldHash, pw, algorithm string) {
	attrs := []slog.Attr{slog.String("tenant_id", u.TenantID.String()), slog.String("user_id", u.ID.String())}
	newHash, err := h.Hash(ctx, pw)
	if err != nil {
		d.Logger.LogAttrs(ctx, slog.LevelError, "rehashing password", append(attrs, slog.String("error", err.Error()))...)
		return
	}
	switch err := d.Store.Passwords().Rehash(ctx, u.TenantID, u.ID, oldHash, newHash); {
	case errors.Is(err, store.ErrConflict), errors.Is(err, store.ErrNotFound):
		// The password changed or was removed during the login.
	case err != nil:
		d.Logger.LogAttrs(ctx, slog.LevelError, "storing rehashed password", append(attrs, slog.String("error", err.Error()))...)
	case h.FIPS() && algorithm == password.Argon2id:
		// ADR 0015: verifying argon2id in FIPS mode is an exception that is
		// logged.
		d.Logger.LogAttrs(ctx, slog.LevelWarn, "replaced an argon2id password hash in FIPS mode", attrs...)
	default:
		d.Logger.LogAttrs(ctx, slog.LevelInfo, "rehashed password", append(attrs, slog.String("from", algorithm))...)
	}
}
