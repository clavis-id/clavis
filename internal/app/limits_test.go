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

	"clavisid.org/clavis/email"
	"clavisid.org/clavis/internal/oauth"
	"clavisid.org/clavis/store"
)

// signInToAccount signs in to the account pages of f's tenant.
func (f authzFixture) signInToAccount(t *testing.T, address, pw string) error {
	t.Helper()
	_, err := SignInToAccount(t.Context(), f.d, f.h, f.tenant.ID, address, pw, nil)
	return err
}

// wrongPasswords signs in n times with a wrong password for address, each
// of which must fail like a wrong password without a lock.
func (f authzFixture) wrongPasswords(t *testing.T, address string, n int) {
	t.Helper()
	for i := range n {
		if err := f.signInToAccount(t, address, "wrong horse"); !errors.Is(err, ErrInvalidCredentials) ||
			errors.Is(err, errLocked) {
			t.Fatalf("wrong password %d for %s = %v, want ErrInvalidCredentials without a lock", i+1, address, err)
		}
	}
}

// ADR 0030: MaxSignInFailures wrong passwords lock the address for
// SignInLockout, during which the right password fails like a wrong one.
func TestWrongPasswordsLockTheAddress(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	f.wrongPasswords(t, "ada@example.com", MaxSignInFailures-1)
	// The address counts as normalized.
	f.wrongPasswords(t, "Ada@Example.COM", 1)
	until := f.now.Add(SignInLockout)
	wantEvent(t, lastEvent(t, f.d, f.tenant.ID, EventSignInLocked), store.AuditEvent{TenantID: f.tenant.ID,
		Type: EventSignInLocked, Actor: store.ActorAnonymous, UserID: f.user.ID,
		Details: map[string]string{"until": until.Format(time.RFC3339)}})

	*f.now = until.Add(-time.Second)
	if err := f.signInToAccount(t, "ada@example.com", "correct horse"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("the right password for a locked address = %v, want ErrInvalidCredentials", err)
	}
	wantEvent(t, lastEvent(t, f.d, f.tenant.ID, EventSignInFailed), store.AuditEvent{TenantID: f.tenant.ID,
		Type: EventSignInFailed, Actor: store.ActorAnonymous, UserID: f.user.ID,
		Details: map[string]string{"method": "password", "reason": "locked"}})
	// Attempts during the lock do not extend it, nor lock it again.
	if err := f.signInToAccount(t, "ada@example.com", "wrong horse"); !errors.Is(err, errLocked) {
		t.Fatalf("a wrong password for a locked address = %v, want the lock", err)
	}
	if n := len(eventsOf(t, f.d, f.tenant.ID, EventSignInLocked)); n != 1 {
		t.Errorf("%d %s events, want 1", n, EventSignInLocked)
	}
	// Other addresses are not locked.
	if _, err := CreateUser(t.Context(), f.d, f.tenant.ID, UserSpec{Email: "grace@example.com"}); err != nil {
		t.Fatalf("CreateUser() unexpected error: %v", err)
	}
	f.wrongPasswords(t, "grace@example.com", 1)

	*f.now = until
	if err := f.signInToAccount(t, "ada@example.com", "correct horse"); err != nil {
		t.Fatalf("the right password after the lock = %v, want a sign-in", err)
	}
	// The count starts again.
	f.wrongPasswords(t, "ada@example.com", MaxSignInFailures)
}

// ADR 0030: wrong passwords that arrive together lock the address after
// MaxSignInFailures, as they do one by one: each counts before its password
// is checked, so the attempts beyond the limit end at once, while the others
// wait in the verification.
func TestConcurrentWrongPasswordsLockTheAddress(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	const n = 3 * MaxSignInFailures
	h := pausingHasher{fakeHasher: f.h, verified: make(chan struct{}, n), resume: make(chan struct{})}
	results := make(chan error, n)
	for range n {
		go func() {
			_, err := SignInToAccount(t.Context(), f.d, h, f.tenant.ID, "ada@example.com", "wrong horse", nil)
			results <- err
		}()
	}
	ended := 0
	timeout := time.After(10 * time.Second)
wait:
	for ended < n-MaxSignInFailures {
		select {
		case err := <-results:
			ended++
			if !errors.Is(err, errLocked) {
				t.Errorf("an attempt ended with %v while others wait in the verification, want the lock", err)
			}
		case <-timeout:
			t.Errorf("%d attempts ended without a verification, want %d", ended, n-MaxSignInFailures)
			break wait
		}
	}
	close(h.resume)
	for ; ended < n; ended++ {
		<-results
	}
	if len(h.verified) != MaxSignInFailures {
		t.Errorf("%d passwords verified, want %d", len(h.verified), MaxSignInFailures)
	}
	if events := eventsOf(t, f.d, f.tenant.ID, EventSignInLocked); len(events) != 1 {
		t.Errorf("%d %s events, want 1", len(events), EventSignInLocked)
	}
}

// ADR 0030: a right password forgets the wrong passwords of the address.
func TestARightPasswordForgetsWrongOnes(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	f.wrongPasswords(t, "ada@example.com", MaxSignInFailures-1)
	if err := f.signInToAccount(t, "ada@example.com", "correct horse"); err != nil {
		t.Fatalf("the right password = %v, want a sign-in", err)
	}
	f.wrongPasswords(t, "ada@example.com", MaxSignInFailures)
	if err := f.signInToAccount(t, "ada@example.com", "correct horse"); !errors.Is(err, errLocked) {
		t.Errorf("the right password after %d more wrong ones = %v, want the lock", MaxSignInFailures, err)
	}
}

// ADR 0030: an address without an account locks like one with an account,
// so the lock reveals nothing; a malformed address cannot have an account
// and is not counted.
func TestUnknownAddressesLockToo(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	f.wrongPasswords(t, "nobody@example.com", MaxSignInFailures)
	if err := f.signInToAccount(t, "nobody@example.com", "wrong horse"); !errors.Is(err, errLocked) {
		t.Errorf("an unknown address after %d wrong passwords = %v, want the lock", MaxSignInFailures, err)
	}
	wantEvent(t, lastEvent(t, f.d, f.tenant.ID, EventSignInFailed), store.AuditEvent{TenantID: f.tenant.ID,
		Type: EventSignInFailed, Actor: store.ActorAnonymous,
		Details: map[string]string{"method": "password", "reason": "locked"}})
	if events := eventsOf(t, f.d, f.tenant.ID, EventSignInLocked); len(events) != 0 {
		t.Errorf("%s events = %+v, want none for an address without an account", EventSignInLocked, events)
	}

	f.wrongPasswords(t, "not an address", MaxSignInFailures+1)
}

// A disabled account answers ErrUserDisabled only to the right password,
// which is not a failure to count.
func TestDisabledAccountsAreNotCounted(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	disabled := f.user
	disabled.ID, disabled.Email, disabled.Status = f.d.NewID(), "grace@example.com", store.UserDisabled
	if err := f.d.Store.Users().Create(t.Context(), disabled); err != nil {
		t.Fatalf("creating a disabled user: %v", err)
	}
	if err := SetPassword(t.Context(), f.d, f.h, disabled, "correct horse"); err != nil {
		t.Fatalf("SetPassword() unexpected error: %v", err)
	}
	for range MaxSignInFailures + 1 {
		if err := f.signInToAccount(t, "grace@example.com", "correct horse"); !errors.Is(err, ErrUserDisabled) {
			t.Fatalf("the right password of a disabled account = %v, want ErrUserDisabled", err)
		}
	}
}

// ADR 0030: the current password of a password change counts like a
// sign-in, so a stolen session cannot guess it without limit.
func TestPasswordChangesCountAgainstTheAddress(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	login, err := SignInToAccount(t.Context(), f.d, f.h, f.tenant.ID, "ada@example.com", "correct horse", nil)
	if err != nil {
		t.Fatalf("SignInToAccount() unexpected error: %v", err)
	}
	a, err := FindAccount(t.Context(), f.d, f.tenant.ID, oauth.HashToken(login.SessionToken))
	if err != nil {
		t.Fatalf("FindAccount() unexpected error: %v", err)
	}
	for range MaxSignInFailures {
		if err := ChangePassword(t.Context(), f.d, f.h, a, "wrong horse", "new horse battery"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("ChangePassword() with a wrong current password = %v, want ErrInvalidCredentials", err)
		}
	}
	if err := ChangePassword(t.Context(), f.d, f.h, a, "correct horse", "new horse battery"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("ChangePassword() for a locked address = %v, want ErrInvalidCredentials", err)
	}
	wantEvent(t, lastEvent(t, f.d, f.tenant.ID, EventPasswordChangeFailed), store.AuditEvent{TenantID: f.tenant.ID,
		Type: EventPasswordChangeFailed, Actor: store.ActorUser, UserID: f.user.ID, SessionID: a.Session.ID,
		Details: map[string]string{"reason": "locked"}})
	if err := f.signInToAccount(t, "ada@example.com", "correct horse"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("a sign-in after the password change locked the address = %v, want ErrInvalidCredentials", err)
	}
}

// ADR 0030: setting a password, by an operator, a reset or a password
// change, forgets the wrong passwords of the address.
func TestSettingAPasswordUnlocksTheAddress(t *testing.T) {
	t.Parallel()
	t.Run("Operator", func(t *testing.T) {
		t.Parallel()
		f := newAuthzFixture(t)
		f.wrongPasswords(t, "ada@example.com", MaxSignInFailures)
		if err := SetPassword(t.Context(), f.d, f.h, f.user, "new horse battery"); err != nil {
			t.Fatalf("SetPassword() unexpected error: %v", err)
		}
		if err := f.signInToAccount(t, "ada@example.com", "new horse battery"); err != nil {
			t.Errorf("a sign-in after the operator set the password = %v, want it to succeed", err)
		}
	})
	t.Run("Reset", func(t *testing.T) {
		t.Parallel()
		f := newSignupFixture(t)
		f.wrongPasswords(t, "ada@example.com", MaxSignInFailures)
		if _, err := CompletePasswordReset(t.Context(), f.d, f.h, f.verifiedReset(t), "new horse battery"); err != nil {
			t.Fatalf("CompletePasswordReset() unexpected error: %v", err)
		}
		if err := f.signInToAccount(t, "ada@example.com", "new horse battery"); err != nil {
			t.Errorf("a sign-in after a reset = %v, want it to succeed", err)
		}
	})
	t.Run("Change", func(t *testing.T) {
		t.Parallel()
		f := newAuthzFixture(t)
		login, err := SignInToAccount(t.Context(), f.d, f.h, f.tenant.ID, "ada@example.com", "correct horse", nil)
		if err != nil {
			t.Fatalf("SignInToAccount() unexpected error: %v", err)
		}
		a, err := FindAccount(t.Context(), f.d, f.tenant.ID, oauth.HashToken(login.SessionToken))
		if err != nil {
			t.Fatalf("FindAccount() unexpected error: %v", err)
		}
		f.wrongPasswords(t, "ada@example.com", MaxSignInFailures-1)
		if err := ChangePassword(t.Context(), f.d, f.h, a, "correct horse", "new horse battery"); err != nil {
			t.Fatalf("ChangePassword() unexpected error: %v", err)
		}
		f.wrongPasswords(t, "ada@example.com", MaxSignInFailures)
	})
}

// ADR 0030: MaxMessages messages to an address within MessageWindow, from
// signup and reset together, refuse more until the window passes, whether
// or not the address has an account.
func TestMessagesPerAddress(t *testing.T) {
	t.Parallel()
	f := newSignupFixture(t)
	signup := func(address string) error {
		_, err := StartSignup(t.Context(), f.d, f.tenant, f.start(t, webRequest()), address, testBinding, f.text,
			testVerifyURL)
		return err
	}
	reset := func(address string) error {
		p := f.start(t, webRequest())
		_, err := StartPasswordReset(t.Context(), f.d, f.tenant, &p, address, testBinding, f.text, testVerifyURL)
		return err
	}
	for _, address := range []string{"ada@example.com", "nobody@example.com"} {
		for i := range MaxMessages {
			start := signup
			if i%2 == 1 {
				start = reset
			}
			if err := start(address); err != nil {
				t.Fatalf("message %d to %s = %v, want it sent", i+1, address, err)
			}
		}
		sent := len(f.mail.sent)
		if err := signup(strings.ToUpper(address)); !errors.Is(err, ErrTooManyMessages) {
			t.Errorf("a signup after %d messages to %s = %v, want ErrTooManyMessages", MaxMessages, address, err)
		}
		if err := reset(address); !errors.Is(err, ErrTooManyMessages) {
			t.Errorf("a reset after %d messages to %s = %v, want ErrTooManyMessages", MaxMessages, address, err)
		}
		if len(f.mail.sent) != sent {
			t.Errorf("%d messages queued after the limit, want none", len(f.mail.sent)-sent)
		}
	}
	if err := signup("grace@example.com"); err != nil {
		t.Errorf("a signup of another address = %v, want it sent", err)
	}
	*f.now = f.now.Add(MessageWindow)
	if err := reset("ada@example.com"); err != nil {
		t.Errorf("a reset after the window = %v, want it sent", err)
	}
}

// wrongCode returns a code that is not the code of msg.
func wrongCode(t *testing.T, msg email.Message) string {
	t.Helper()
	code := []byte(codeOf(t, msg))
	code[0] = '0' + (code[0]-'0'+1)%10
	return string(code)
}

// wrongCodes submits n codes for v that are not the code of msg, each of
// which must fail as a wrong code.
func (f signupFixture) wrongCodes(t *testing.T, v store.EmailVerification, msg email.Message, n int) {
	t.Helper()
	for range n {
		if err := VerifyCode(t.Context(), f.d, v, wrongCode(t, msg)); !errors.Is(err, ErrWrongCode) &&
			!errors.Is(err, ErrTooManyAttempts) {
			t.Fatalf("VerifyCode() with a wrong code = %v, want ErrWrongCode or ErrTooManyAttempts", err)
		}
	}
}

// ADR 0030: MaxCodeFailures wrong codes for an address, across its
// verifications of either purpose, refuse its codes for CodeLockout. The
// link still works.
func TestWrongCodesLockTheCodesOfAnAddress(t *testing.T) {
	t.Parallel()
	f := newSignupFixture(t)
	signup, signupMsg := f.startSignup(t, "grace@example.com")
	f.wrongCodes(t, signup, signupMsg, MaxCodeAttempts)
	if _, err := CreateUser(t.Context(), f.d, f.tenant.ID, UserSpec{Email: "grace@example.com"}); err != nil {
		t.Fatalf("CreateUser() unexpected error: %v", err)
	}
	f.wrongCodes(t, f.startReset(t, "grace@example.com"), f.mail.last(t), MaxCodeFailures-MaxCodeAttempts)

	v := f.startReset(t, "grace@example.com")
	msg := f.mail.last(t)
	if err := VerifyCode(t.Context(), f.d, v, codeOf(t, msg)); !errors.Is(err, ErrCodesLocked) {
		t.Fatalf("the right code for a locked address = %v, want ErrCodesLocked", err)
	}
	if err := VerifyCode(t.Context(), f.d, f.startReset(t, "ada@example.com"), codeOf(t, f.mail.last(t))); err != nil {
		t.Errorf("the right code for another address = %v, want it verified", err)
	}
	if err := VerifyLink(t.Context(), f.d, v, tokenOf(t, msg)); err != nil {
		t.Errorf("the link for a locked address = %v, want it verified", err)
	}

	*f.now = f.now.Add(CodeLockout)
	v = f.startReset(t, "grace@example.com")
	if err := VerifyCode(t.Context(), f.d, v, codeOf(t, f.mail.last(t))); err != nil {
		t.Errorf("the right code after the lock = %v, want it verified", err)
	}
}

// ADR 0030: a right code forgets the wrong codes of the address.
func TestARightCodeForgetsWrongOnes(t *testing.T) {
	t.Parallel()
	f := newSignupFixture(t)
	f.wrongCodes(t, f.startReset(t, "ada@example.com"), f.mail.last(t), MaxCodeAttempts)
	f.wrongCodes(t, f.startReset(t, "ada@example.com"), f.mail.last(t), MaxCodeFailures-MaxCodeAttempts-1)
	if err := VerifyCode(t.Context(), f.d, f.startReset(t, "ada@example.com"), codeOf(t, f.mail.last(t))); err != nil {
		t.Fatalf("the right code = %v, want it verified", err)
	}
	*f.now = f.now.Add(MessageWindow)
	f.wrongCodes(t, f.startReset(t, "ada@example.com"), f.mail.last(t), MaxCodeAttempts)
	f.wrongCodes(t, f.startReset(t, "ada@example.com"), f.mail.last(t), MaxCodeFailures-MaxCodeAttempts)
	if err := VerifyCode(t.Context(), f.d, f.startReset(t, "ada@example.com"), codeOf(t, f.mail.last(t))); !errors.Is(err, ErrCodesLocked) {
		t.Errorf("the right code after %d more wrong codes = %v, want ErrCodesLocked", MaxCodeFailures, err)
	}
}

// ADR 0030: wrong codes that arrive together, for several verifications of
// an address, lock its codes after MaxCodeFailures, as they do one by one:
// each counts before it is compared.
func TestConcurrentWrongCodesLockTheCodesOfAnAddress(t *testing.T) {
	t.Parallel()
	f := newSignupFixture(t)
	const verifications = 3
	n := verifications * MaxCodeAttempts
	results := make(chan error, n)
	for range verifications {
		v := f.startReset(t, "ada@example.com")
		code := wrongCode(t, f.mail.last(t))
		for range MaxCodeAttempts {
			go func() { results <- VerifyCode(t.Context(), f.d, v, code) }()
		}
	}
	wrong, locked := 0, 0
	for range n {
		switch err := <-results; {
		case errors.Is(err, ErrWrongCode), errors.Is(err, ErrTooManyAttempts):
			wrong++
		case errors.Is(err, ErrCodesLocked):
			locked++
		default:
			t.Errorf("VerifyCode() with a wrong code = %v", err)
		}
	}
	if wrong != MaxCodeFailures || locked != n-MaxCodeFailures {
		t.Errorf("%d wrong codes compared and %d refused, want %d and %d", wrong, locked, MaxCodeFailures,
			n-MaxCodeFailures)
	}
}

func TestPurgeExpiredRemovesLimitCounters(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	f.wrongPasswords(t, "ada@example.com", 1)
	k := addressKey(f.tenant.ID, limitSignIn, "ada@example.com")
	*f.now = f.now.Add(SignInLockout - time.Second)
	if err := PurgeExpired(t.Context(), f.d); err != nil {
		t.Fatalf("PurgeExpired() unexpected error: %v", err)
	}
	if _, err := f.d.Store.LimitCounters().Get(t.Context(), k); err != nil {
		t.Fatalf("a counter that has not ended = %v, want it kept", err)
	}
	*f.now = f.now.Add(time.Second)
	if err := PurgeExpired(t.Context(), f.d); err != nil {
		t.Fatalf("PurgeExpired() unexpected error: %v", err)
	}
	if _, err := f.d.Store.LimitCounters().Get(t.Context(), k); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("a counter that ended = %v, want it deleted", err)
	}
}

// failingLimitCounters fails the methods that its fields name.
type failingLimitCounters struct {
	store.LimitCounters
	add, del bool
}

func (c failingLimitCounters) Add(ctx context.Context, k store.LimitKey, now time.Time, window time.Duration,
	lockAt int,
) (store.LimitCount, error) {
	if c.add {
		return store.LimitCount{}, errUnavailable
	}
	return c.LimitCounters.Add(ctx, k, now, window, lockAt)
}

func (c failingLimitCounters) Delete(ctx context.Context, k store.LimitKey) error {
	if c.del {
		return errUnavailable
	}
	return c.LimitCounters.Delete(ctx, k)
}

// limitStore is a store whose limit counters fail as counters says.
type limitStore struct {
	store.Store
	counters failingLimitCounters
}

func (s limitStore) LimitCounters() store.LimitCounters { return s.counters }

// An attempt or a message that cannot be counted fails the request: it is
// counted before the work it limits. A count that cannot be forgotten is
// logged, and the request answers as it would.
func TestLimitCounterFailures(t *testing.T) {
	t.Parallel()
	f := newSignupFixture(t)
	var logs bytes.Buffer
	f.d.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	withCounters := func(c failingLimitCounters) signupFixture {
		g := f
		c.LimitCounters = f.d.Store.LimitCounters()
		g.d.Store = limitStore{Store: f.d.Store, counters: c}
		return g
	}

	g := withCounters(failingLimitCounters{add: true})
	for _, pw := range []string{"correct horse", "wrong horse"} {
		if err := g.signInToAccount(t, "ada@example.com", pw); !errors.Is(err, errUnavailable) {
			t.Errorf("a sign-in with %q that cannot be counted = %v, want the store error", pw, err)
		}
	}
	v := f.startReset(t, "ada@example.com")
	code := codeOf(t, f.mail.last(t))
	if err := VerifyCode(t.Context(), g.d, v, code); !errors.Is(err, errUnavailable) {
		t.Errorf("a code that cannot be counted = %v, want the store error", err)
	}
	if _, err := StartSignup(t.Context(), g.d, g.tenant, g.start(t, webRequest()), "grace@example.com", testBinding,
		g.text, testVerifyURL); !errors.Is(err, errUnavailable) {
		t.Errorf("a signup whose message cannot be counted = %v, want the store error", err)
	}

	g = withCounters(failingLimitCounters{del: true})
	if err := g.signInToAccount(t, "ada@example.com", "correct horse"); err != nil {
		t.Errorf("a right password whose count cannot be forgotten = %v, want a sign-in", err)
	}
	if err := VerifyCode(t.Context(), g.d, v, code); err != nil {
		t.Errorf("a right code whose count cannot be forgotten = %v, want it verified", err)
	}
	if err := SetPassword(t.Context(), g.d, g.h, g.user, "new horse battery"); err != nil {
		t.Errorf("SetPassword() whose unlock fails = %v, want the password set", err)
	}
	for _, msg := range []string{
		"wrong passwords not forgotten after a right one",
		"wrong codes not forgotten after a right one",
		"wrong passwords not forgotten after a password change",
	} {
		if !strings.Contains(logs.String(), `msg="`+msg+`"`) {
			t.Errorf("logs lack %q:\n%s", msg, logs.String())
		}
	}
}

// The key of an address is a hash: the counters keep no addresses.
func TestAddressKeysKeepNoAddresses(t *testing.T) {
	t.Parallel()
	tenantID := uuid.NewV7()
	k := addressKey(tenantID, limitSignIn, "ada@example.com")
	if k.TenantID != tenantID || k.Kind != limitSignIn || len(k.Key) != 32 ||
		bytes.Contains(k.Key, []byte("ada")) {
		t.Errorf("addressKey() = %+v", k)
	}
	if other := addressKey(tenantID, limitSignIn, "grace@example.com"); bytes.Equal(other.Key, k.Key) {
		t.Error("two addresses have the same key")
	}
}
