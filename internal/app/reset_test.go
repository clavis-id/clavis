package app

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
	"uuid"

	"clavisid.org/clavis/internal/authn/password"
	"clavisid.org/clavis/internal/emailtmpl"
	"clavisid.org/clavis/internal/i18n"
	"clavisid.org/clavis/internal/oauth"
	"clavisid.org/clavis/store"
)

// startReset starts the password reset of address for a new authorization
// request and returns the verification.
func (f signupFixture) startReset(t *testing.T, address string) store.EmailVerification {
	t.Helper()
	p := f.start(t, webRequest())
	id, err := StartPasswordReset(t.Context(), f.d, f.tenant, &p, address, testBinding, f.text, testVerifyURL)
	if err != nil {
		t.Fatalf("StartPasswordReset(%q) unexpected error: %v", address, err)
	}
	v, err := FindEmailVerification(t.Context(), f.d, f.tenant.ID, id, testBinding, store.VerifyPasswordReset)
	if err != nil {
		t.Fatalf("FindEmailVerification() unexpected error: %v", err)
	}
	return v
}

// verifiedReset returns a verified password reset verification of ada.
func (f signupFixture) verifiedReset(t *testing.T) store.EmailVerification {
	t.Helper()
	v := f.startReset(t, "ada@example.com")
	if err := VerifyCode(t.Context(), f.d, v, codeOf(t, f.mail.last(t))); err != nil {
		t.Fatalf("VerifyCode() unexpected error: %v", err)
	}
	v, err := FindEmailVerification(t.Context(), f.d, f.tenant.ID, v.ID, testBinding, store.VerifyPasswordReset)
	if err != nil {
		t.Fatalf("FindEmailVerification() unexpected error: %v", err)
	}
	return v
}

// ADR 0027: an address with an active account, an unknown address and a
// disabled account get the same treatment, except that only the first gets
// the message.
func TestStartPasswordResetTreatsEveryAddressAlike(t *testing.T) {
	t.Parallel()
	f := newSignupFixture(t)
	var logs bytes.Buffer
	f.d.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	hopper, err := CreateUser(t.Context(), f.d, f.tenant.ID, UserSpec{Email: "hopper@example.com"})
	if err != nil {
		t.Fatalf("CreateUser() unexpected error: %v", err)
	}
	hopper.Status = store.UserDisabled
	if err := f.d.Store.Users().Update(t.Context(), hopper); err != nil {
		t.Fatalf("disabling the user: %v", err)
	}

	for address, normalized := range map[string]string{
		"Ada@Example.com":    "ada@example.com",
		"grace@example.com":  "grace@example.com",
		"hopper@example.com": "hopper@example.com",
	} {
		v := f.startReset(t, address)
		if v.Purpose != store.VerifyPasswordReset || v.Email != normalized || v.Attempts != 0 ||
			!v.VerifiedAt.IsZero() || v.AuthorizationRequestID == "" ||
			!v.ExpiresAt.Equal(f.d.Now().Add(EmailVerificationLifetime)) {
			t.Errorf("%s: verification = %+v", address, v)
		}
	}
	if len(f.mail.sent) != 1 {
		t.Fatalf("queued %d messages, want one, to the active account", len(f.mail.sent))
	}
	msg := f.mail.last(t)
	if msg.To != "ada@example.com" || msg.Subject != "Reset your password" || !strings.Contains(msg.Text, "Web app") ||
		!linkLine.MatchString(msg.Text) {
		t.Errorf("message = %+v", msg)
	}
	codeOf(t, msg)
	if strings.Count(logs.String(), "active_account=true") != 1 || strings.Count(logs.String(), "active_account=false") != 2 ||
		strings.Contains(logs.String(), "@example.com") {
		t.Errorf("logs = %s; want one active and two other accounts, without addresses", logs.String())
	}
}

func TestStartPasswordResetRefuses(t *testing.T) {
	t.Parallel()
	f := newSignupFixture(t)
	start := func(f signupFixture, p PendingAuthorization, address string) error {
		_, err := StartPasswordReset(t.Context(), f.d, f.tenant, &p, address, testBinding, f.text, testVerifyURL)
		return err
	}
	if err := start(f, f.start(t, webRequest()), "not an address"); !errors.Is(err, ErrInvalidEmail) {
		t.Errorf("StartPasswordReset() with a malformed address = %v, want ErrInvalidEmail", err)
	}
	mute := f
	mute.d.Mail = nil
	if err := start(mute, f.start(t, webRequest()), "ada@example.com"); !errors.Is(err, ErrResetUnavailable) {
		t.Errorf("StartPasswordReset() without email = %v, want ErrResetUnavailable", err)
	}
	waiting := f.start(t, webRequest())
	waiting.Request.SessionID = uuid.NewV7()
	if err := start(f, waiting, "ada@example.com"); !errors.Is(err, ErrAuthorizationRequestNotFound) {
		t.Errorf("StartPasswordReset() for a request that waits for consent = %v, want ErrAuthorizationRequestNotFound", err)
	}
	// A signup verification cannot reset a password, and the other way round.
	signup, _ := f.startSignup(t, "grace@example.com")
	if _, err := FindEmailVerification(t.Context(), f.d, f.tenant.ID, signup.ID, testBinding,
		store.VerifyPasswordReset); !errors.Is(err, ErrVerificationNotFound) {
		t.Errorf("a signup verification found for a reset: %v", err)
	}
}

func TestCompletePasswordReset(t *testing.T) {
	t.Parallel()
	f := newSignupFixture(t)
	f.h.minimumChars = 8
	sessionHash, _ := f.signIn(t, webRequest())
	v := f.verifiedReset(t)

	// A password outside the policy leaves the verification for another try.
	if _, err := CompletePasswordReset(t.Context(), f.d, f.h, v, "short"); !errors.Is(err, password.ErrPolicy) {
		t.Fatalf("CompletePasswordReset() with a short password = %v, want ErrPolicy", err)
	}
	u, err := CompletePasswordReset(t.Context(), f.d, f.h, v, "new horse battery")
	if err != nil || u.ID != f.user.ID || !u.EmailVerified {
		t.Fatalf("CompletePasswordReset() = %+v, %v; want ada with a verified address", u, err)
	}
	if stored, err := FindUser(t.Context(), f.d, f.tenant.ID, "ada@example.com"); err != nil || !stored.EmailVerified {
		t.Errorf("stored user = %+v, %v; want the address verified", stored, err)
	}
	if _, err := AuthenticatePassword(t.Context(), f.d, f.h, f.tenant.ID, "ada@example.com", "correct horse"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("the old password = %v, want ErrInvalidCredentials", err)
	}
	if _, err := AuthenticatePassword(t.Context(), f.d, f.h, f.tenant.ID, "ada@example.com", "new horse battery"); err != nil {
		t.Errorf("the new password = %v, want nil", err)
	}
	if _, err := f.d.Store.Sessions().GetByTokenHash(t.Context(), f.tenant.ID, sessionHash); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("the session from before the reset = %v, want ErrNotFound", err)
	}
	// The verification is used once.
	if _, err := CompletePasswordReset(t.Context(), f.d, f.h, v, "new horse battery"); !errors.Is(err, ErrVerificationNotFound) {
		t.Errorf("a second CompletePasswordReset() = %v, want ErrVerificationNotFound", err)
	}
}

func TestCompletePasswordResetRefuses(t *testing.T) {
	t.Parallel()
	f := newSignupFixture(t)
	unverified := f.startReset(t, "ada@example.com")
	if _, err := CompletePasswordReset(t.Context(), f.d, f.h, unverified, "new horse battery"); !errors.Is(err, ErrVerificationNotFound) {
		t.Errorf("CompletePasswordReset() before the verification = %v, want ErrVerificationNotFound", err)
	}
	signup, _ := f.startSignup(t, "grace@example.com")
	signup.VerifiedAt = f.d.Now()
	if _, err := CompletePasswordReset(t.Context(), f.d, f.h, signup, "new horse battery"); !errors.Is(err, ErrVerificationNotFound) {
		t.Errorf("CompletePasswordReset() with a signup verification = %v, want ErrVerificationNotFound", err)
	}
	// The account was disabled after the verification.
	v := f.verifiedReset(t)
	disabled := f.user
	disabled.Status = store.UserDisabled
	if err := f.d.Store.Users().Update(t.Context(), disabled); err != nil {
		t.Fatalf("disabling the user: %v", err)
	}
	if _, err := CompletePasswordReset(t.Context(), f.d, f.h, v, "new horse battery"); !errors.Is(err, ErrVerificationNotFound) {
		t.Errorf("CompletePasswordReset() of a disabled account = %v, want ErrVerificationNotFound", err)
	}
}

// From the review of #48 and #62: a new password, set by the user or by an
// operator, ends every session of the user and revokes the user's tokens.
func TestSetPasswordEndsTheUsersAccess(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	sessionHash, _ := f.signIn(t, webRequest())
	resp, client := f.refreshTokenFor(t, with(webRequest(), "scope", "openid offline_access"))
	pending, _ := f.codeFor(t, webRequest())

	if err := SetPassword(t.Context(), f.d, f.h, f.user, "new horse battery"); err != nil {
		t.Fatalf("SetPassword() unexpected error: %v", err)
	}
	if _, err := f.d.Store.Sessions().GetByTokenHash(t.Context(), f.tenant.ID, sessionHash); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("the session = %v, want ErrNotFound", err)
	}
	if _, err := f.d.Store.AuthorizationCodes().Get(t.Context(), f.tenant.ID,
		oauth.HashToken(pending)); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("the code not exchanged yet = %v, want ErrNotFound", err)
	}
	if _, err := f.refresh(t, client, resp.RefreshToken); err == nil {
		t.Error("the refresh token still works")
	}
	f.wantRevoked(t, "after the password change", resp.AccessToken)
}

// Every password reset message exists in every locale, without a key or a
// placeholder left in it.
func TestResetMessageInEveryLocale(t *testing.T) {
	t.Parallel()
	catalogs, err := i18n.Load()
	if err != nil {
		t.Fatalf("loading the catalogs: %v", err)
	}
	for _, locale := range i18n.Supported() {
		msg, err := emailtmpl.Render(t.Context(), "ada@example.com",
			resetMessage(catalogs.Printer(locale), "Shop", "123456", testVerifyURL+"?verification=v"))
		if err != nil {
			t.Fatalf("%s: Render() unexpected error: %v", locale, err)
		}
		for _, part := range []string{msg.Subject, msg.Text, msg.HTML} {
			if strings.ContainsAny(part, "{}") || strings.Contains(part, "email.reset") {
				t.Errorf("%s: a key or placeholder is left:\n%s", locale, part)
			}
		}
		if !strings.Contains(msg.HTML, `<html lang="`+string(locale)+`">`) || !strings.Contains(msg.Text, "123456") {
			t.Errorf("%s: message = %+v", locale, msg)
		}
	}
}

// pausingHasher pauses every verification until the test lets it go.
type pausingHasher struct {
	*fakeHasher
	verified, resume chan struct{}
}

func (h pausingHasher) Verify(ctx context.Context, encoded, pw string) (password.Verification, error) {
	v, err := h.fakeHasher.Verify(ctx, encoded, pw)
	h.verified <- struct{}{}
	<-h.resume
	return v, err
}

// ADR 0027: a sign-in that verified the old password before a password
// change ends without a session or a code, even though it stores them after
// the change ended every other session.
func TestSignInDuringAPasswordChange(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	p := f.start(t, webRequest())
	h := pausingHasher{fakeHasher: f.h, verified: make(chan struct{}), resume: make(chan struct{})}
	done := make(chan error)
	go func() {
		_, err := CompletePasswordLogin(t.Context(), f.d, h, f.tenant, p, "ada@example.com", "correct horse", nil)
		done <- err
	}()
	<-h.verified
	*f.now = f.now.Add(time.Minute)
	if err := SetPassword(t.Context(), f.d, f.h, f.user, "new horse battery"); err != nil {
		t.Fatalf("SetPassword() unexpected error: %v", err)
	}
	close(h.resume)
	if err := <-done; !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("a sign-in with the old password across the change = %v, want ErrInvalidCredentials", err)
	}
	if n, err := f.d.Store.Sessions().DeleteByUser(t.Context(), f.tenant.ID, f.user.ID, uuid.Nil()); err != nil || n != 0 {
		t.Errorf("sessions of the user after the change = %d, %v; want none", n, err)
	}
	if n, err := f.d.Store.AuthorizationCodes().DeleteByUser(t.Context(), f.tenant.ID, f.user.ID); err != nil || n != 0 {
		t.Errorf("codes of the user after the change = %d, %v; want none", n, err)
	}

	// A rehash on sign-in replaces the hash but not the password: the
	// session stays.
	f.h.rehash = true
	if _, err := CompletePasswordLogin(t.Context(), f.d, f.h, f.tenant, f.start(t, webRequest()), "ada@example.com",
		"new horse battery", nil); err != nil {
		t.Errorf("a sign-in that rehashes the password = %v, want nil", err)
	}
}

// pausingStore pauses a password change after it revoked the access tokens
// of the user.
type pausingStore struct {
	store.Store
	revoked, resume chan struct{}
}

func (s pausingStore) AccessTokens() store.AccessTokens {
	return pausingAccessTokens{s.Store.AccessTokens(), s.revoked, s.resume}
}

type pausingAccessTokens struct {
	store.AccessTokens
	revoked, resume chan struct{}
}

func (p pausingAccessTokens) RevokeByUser(ctx context.Context, tenantID, userID uuid.UUID, at time.Time) (int64, error) {
	n, err := p.AccessTokens.RevokeByUser(ctx, tenantID, userID, at)
	p.revoked <- struct{}{}
	<-p.resume
	return n, err
}

// A refresh during a password change gets no access token that outlives the
// change: its refresh token family is revoked before the access tokens.
func TestRefreshDuringAPasswordChange(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	resp, client := f.refreshTokenFor(t, with(webRequest(), "scope", "openid offline_access"))
	paused := f.d
	ps := pausingStore{Store: f.d.Store, revoked: make(chan struct{}), resume: make(chan struct{})}
	paused.Store = ps
	done := make(chan error)
	go func() { done <- SetPassword(t.Context(), paused, f.h, f.user, "new horse battery") }()
	<-ps.revoked
	refreshed, err := f.refresh(t, client, resp.RefreshToken)
	close(ps.resume)
	if err := <-done; err != nil {
		t.Fatalf("SetPassword() unexpected error: %v", err)
	}
	if err == nil {
		f.wantRevoked(t, "a refresh during the change", refreshed.AccessToken)
	}
	f.wantRevoked(t, "after the change", resp.AccessToken)
}
