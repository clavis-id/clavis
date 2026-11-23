package app

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
	"uuid"

	"clavisid.org/clavis/email"
	"clavisid.org/clavis/internal/authn/password"
	"clavisid.org/clavis/internal/emailtmpl"
	"clavisid.org/clavis/internal/i18n"
	"clavisid.org/clavis/internal/mailer"
	"clavisid.org/clavis/internal/oauth"
	"clavisid.org/clavis/store"
)

const testVerifyURL = testIssuer + "/signup/verify"

// fakeMail records the messages it queues, or fails with err.
type fakeMail struct {
	mu   sync.Mutex
	sent []email.Message
	err  error
}

func (m *fakeMail) Enqueue(_ context.Context, msg email.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.sent = append(m.sent, msg)
	return nil
}

func (m *fakeMail) last(t *testing.T) email.Message {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.sent) == 0 {
		t.Fatal("no message was queued")
	}
	return m.sent[len(m.sent)-1]
}

var (
	codeLine = regexp.MustCompile(`(?m)^ {4}(\d{6})$`)
	linkLine = regexp.MustCompile(regexp.QuoteMeta(testVerifyURL) + `\?\S+`)
)

// signupFixture is an authzFixture whose tenant offers signup, with a fake
// mailer and an English printer.
type signupFixture struct {
	authzFixture
	mail *fakeMail
	text i18n.Printer
}

func newSignupFixture(t *testing.T) signupFixture {
	t.Helper()
	f := signupFixture{authzFixture: newAuthzFixture(t), mail: &fakeMail{}}
	f.d.Mail = f.mail
	f.tenant.Signup = true
	catalogs, err := i18n.Load()
	if err != nil {
		t.Fatalf("loading the catalogs: %v", err)
	}
	f.text = catalogs.Printer(i18n.English)
	return f
}

// startSignup starts the signup of address for a new authorization request
// and returns the verification with the queued message.
func (f signupFixture) startSignup(t *testing.T, address string) (store.EmailVerification, email.Message) {
	t.Helper()
	id, err := StartSignup(t.Context(), f.d, f.tenant, f.start(t, webRequest()), address, testBinding, f.text,
		testVerifyURL)
	if err != nil {
		t.Fatalf("StartSignup(%q) unexpected error: %v", address, err)
	}
	v, err := FindEmailVerification(t.Context(), f.d, f.tenant.ID, id, testBinding, store.VerifySignup)
	if err != nil {
		t.Fatalf("FindEmailVerification() unexpected error: %v", err)
	}
	return v, f.mail.last(t)
}

// verified returns a verified signup verification of address.
func (f signupFixture) verified(t *testing.T, address string) store.EmailVerification {
	t.Helper()
	v, msg := f.startSignup(t, address)
	if err := VerifyCode(t.Context(), f.d, v, codeOf(t, msg)); err != nil {
		t.Fatalf("VerifyCode() unexpected error: %v", err)
	}
	v, err := FindEmailVerification(t.Context(), f.d, f.tenant.ID, v.ID, testBinding, store.VerifySignup)
	if err != nil {
		t.Fatalf("FindEmailVerification() unexpected error: %v", err)
	}
	return v
}

func codeOf(t *testing.T, msg email.Message) string {
	t.Helper()
	m := codeLine.FindStringSubmatch(msg.Text)
	if m == nil {
		t.Fatalf("the message has no code:\n%s", msg.Text)
	}
	return m[1]
}

func tokenOf(t *testing.T, msg email.Message) string {
	t.Helper()
	u, err := url.Parse(linkLine.FindString(msg.Text))
	if err != nil || u.Query().Get("token") == "" {
		t.Fatalf("the message has no link:\n%s", msg.Text)
	}
	return u.Query().Get("token")
}

// ADR 0026: a new address and an address with an account get the same
// treatment, except for the message that the address receives.
func TestStartSignupTreatsEveryAddressAlike(t *testing.T) {
	t.Parallel()
	f := newSignupFixture(t)
	fresh, freshMsg := f.startSignup(t, "grace@example.com")
	existing, existingMsg := f.startSignup(t, "Ada@Example.com")

	for name, v := range map[string]store.EmailVerification{"new": fresh, "existing": existing} {
		if v.Purpose != store.VerifySignup || v.Attempts != 0 || !v.VerifiedAt.IsZero() ||
			!bytes.Equal(v.BindingHash, testBinding) || v.AuthorizationRequestID == "" ||
			!v.ExpiresAt.Equal(f.d.Now().Add(EmailVerificationLifetime)) || len(v.CodeHash) != 32 || len(v.LinkHash) != 32 {
			t.Errorf("%s address: verification = %+v", name, v)
		}
	}
	if fresh.Email != "grace@example.com" || existing.Email != "ada@example.com" {
		t.Errorf("addresses = %q and %q, want them normalized", fresh.Email, existing.Email)
	}

	if freshMsg.To != "grace@example.com" || freshMsg.Subject != "Confirm your email address" ||
		!strings.Contains(freshMsg.Text, "account for Web app") || !strings.Contains(freshMsg.Text, "15 minutes") {
		t.Errorf("message to a new address = %+v", freshMsg)
	}
	code, token := codeOf(t, freshMsg), tokenOf(t, freshMsg)
	if !bytes.Equal(codeHash(fresh.ID, code), fresh.CodeHash) || !bytes.Equal(oauth.HashToken(token), fresh.LinkHash) {
		t.Errorf("the message's code and link do not match the stored hashes")
	}
	if existingMsg.To != "ada@example.com" || existingMsg.Subject != "You already have an account" ||
		codeLine.MatchString(existingMsg.Text) || strings.Contains(existingMsg.Text, testVerifyURL) {
		t.Errorf("message to an address with an account = %+v", existingMsg)
	}
}

func TestStartSignupHidesQueueFailures(t *testing.T) {
	t.Parallel()
	f := newSignupFixture(t)
	var logs bytes.Buffer
	f.d.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	f.mail.err = mailer.ErrQueueFull
	for _, address := range []string{"grace@example.com", "ada@example.com"} {
		id, err := StartSignup(t.Context(), f.d, f.tenant, f.start(t, webRequest()), address, testBinding, f.text,
			testVerifyURL)
		if err != nil || !oauth.ValidRequestID(id) {
			t.Errorf("StartSignup(%q) with a full queue = %q, %v; want a verification", address, id, err)
		}
	}
	if strings.Count(logs.String(), "signup message not queued") != 2 || strings.Contains(logs.String(), "@example.com") {
		t.Errorf("logs = %s; want two failures without addresses", logs.String())
	}
}

func TestStartSignupRefuses(t *testing.T) {
	t.Parallel()
	f := newSignupFixture(t)
	start := func(f signupFixture, p PendingAuthorization, address string) error {
		_, err := StartSignup(t.Context(), f.d, f.tenant, p, address, testBinding, f.text, testVerifyURL)
		return err
	}
	if err := start(f, f.start(t, webRequest()), "not an address"); !errors.Is(err, ErrInvalidEmail) {
		t.Errorf("StartSignup() with a malformed address = %v, want ErrInvalidEmail", err)
	}
	closed := f
	closed.tenant.Signup = false
	if err := start(closed, f.start(t, webRequest()), "grace@example.com"); !errors.Is(err, ErrSignupUnavailable) {
		t.Errorf("StartSignup() on a tenant without signup = %v, want ErrSignupUnavailable", err)
	}
	mute := f
	mute.d.Mail = nil
	if err := start(mute, f.start(t, webRequest()), "grace@example.com"); !errors.Is(err, ErrSignupUnavailable) {
		t.Errorf("StartSignup() without email = %v, want ErrSignupUnavailable", err)
	}
	waiting := f.start(t, webRequest())
	waiting.Request.SessionID = uuid.NewV7()
	if err := start(f, waiting, "grace@example.com"); !errors.Is(err, ErrAuthorizationRequestNotFound) {
		t.Errorf("StartSignup() for a request that waits for consent = %v, want ErrAuthorizationRequestNotFound", err)
	}
}

func TestVerifyCode(t *testing.T) {
	t.Parallel()
	f := newSignupFixture(t)
	v, msg := f.startSignup(t, "grace@example.com")
	code := codeOf(t, msg)
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	for range MaxCodeAttempts - 1 {
		if err := VerifyCode(t.Context(), f.d, v, wrong); !errors.Is(err, ErrWrongCode) {
			t.Fatalf("VerifyCode() with a wrong code = %v, want ErrWrongCode", err)
		}
	}
	// The last attempt may still be right, typed with a space.
	if err := VerifyCode(t.Context(), f.d, v, code[:3]+" "+code[3:]); err != nil {
		t.Fatalf("VerifyCode() with the right code = %v, want nil", err)
	}
	v, err := FindEmailVerification(t.Context(), f.d, f.tenant.ID, v.ID, testBinding, store.VerifySignup)
	if err != nil || !v.VerifiedAt.Equal(f.d.Now()) {
		t.Fatalf("the verification after the right code = %+v, %v; want it verified", v, err)
	}
	if err := VerifyCode(t.Context(), f.d, v, wrong); err != nil {
		t.Errorf("VerifyCode() of a verified verification = %v, want nil", err)
	}
}

func TestVerifyCodeEndsAfterTooManyAttempts(t *testing.T) {
	t.Parallel()
	f := newSignupFixture(t)
	v, msg := f.startSignup(t, "grace@example.com")
	code := codeOf(t, msg)
	for i := range MaxCodeAttempts {
		want := ErrWrongCode
		if i == MaxCodeAttempts-1 {
			want = ErrTooManyAttempts
		}
		if err := VerifyCode(t.Context(), f.d, v, "12345"); !errors.Is(err, want) {
			t.Fatalf("attempt %d with a malformed code = %v, want %v", i+1, err, want)
		}
	}
	if _, err := FindEmailVerification(t.Context(), f.d, f.tenant.ID, v.ID, testBinding,
		store.VerifySignup); !errors.Is(err, ErrTooManyAttempts) {
		t.Errorf("FindEmailVerification() after the last attempt = %v, want ErrTooManyAttempts", err)
	}
	// A submission that found the verification before the last attempt
	// counts too.
	if err := VerifyCode(t.Context(), f.d, v, code); !errors.Is(err, ErrTooManyAttempts) {
		t.Errorf("VerifyCode() with the right code after the last attempt = %v, want ErrTooManyAttempts", err)
	}
}

func TestVerifyLink(t *testing.T) {
	t.Parallel()
	f := newSignupFixture(t)
	v, msg := f.startSignup(t, "grace@example.com")
	if err := VerifyLink(t.Context(), f.d, v, oauth.NewToken()); !errors.Is(err, ErrVerificationNotFound) {
		t.Errorf("VerifyLink() with another token = %v, want ErrVerificationNotFound", err)
	}
	token := tokenOf(t, msg)
	if err := VerifyLink(t.Context(), f.d, v, token); err != nil {
		t.Fatalf("VerifyLink() unexpected error: %v", err)
	}
	v, err := FindEmailVerification(t.Context(), f.d, f.tenant.ID, v.ID, testBinding, store.VerifySignup)
	if err != nil || v.VerifiedAt.IsZero() || v.Attempts != 0 {
		t.Fatalf("the verification after the link = %+v, %v; want it verified without attempts", v, err)
	}
	// Following the link again goes on.
	if err := VerifyLink(t.Context(), f.d, v, token); err != nil {
		t.Errorf("VerifyLink() again = %v, want nil", err)
	}
}

func TestFindEmailVerificationRefuses(t *testing.T) {
	t.Parallel()
	f := newSignupFixture(t)
	v, _ := f.startSignup(t, "grace@example.com")
	find := func(id string, binding []byte, purpose store.EmailVerificationPurpose) error {
		_, err := FindEmailVerification(t.Context(), f.d, f.tenant.ID, id, binding, purpose)
		return err
	}
	for name, err := range map[string]error{
		"malformed ID":  find("not an ID", testBinding, store.VerifySignup),
		"unknown ID":    find(oauth.NewRequestID(), testBinding, store.VerifySignup),
		"other browser": find(v.ID, oauth.HashToken("other browser"), store.VerifySignup),
		"no browser":    find(v.ID, nil, store.VerifySignup),
		"other purpose": find(v.ID, testBinding, "reset"),
	} {
		if !errors.Is(err, ErrVerificationNotFound) {
			t.Errorf("%s: FindEmailVerification() = %v, want ErrVerificationNotFound", name, err)
		}
	}
	*f.now = f.now.Add(EmailVerificationLifetime)
	if err := find(v.ID, testBinding, store.VerifySignup); !errors.Is(err, ErrVerificationNotFound) {
		t.Errorf("FindEmailVerification() of an expired verification = %v, want ErrVerificationNotFound", err)
	}
}

func TestCompleteSignup(t *testing.T) {
	t.Parallel()
	f := newSignupFixture(t)
	f.h.minimumChars = 8
	v := f.verified(t, "grace@example.com")
	p, err := FindAuthorizationRequest(t.Context(), f.d, f.tenant.ID, v.AuthorizationRequestID, testBinding)
	if err != nil {
		t.Fatalf("FindAuthorizationRequest() unexpected error: %v", err)
	}

	// A password outside the policy leaves the verification for another try.
	if _, err := CompleteSignup(t.Context(), f.d, f.h, f.tenant, v, "short", &p, nil); !errors.Is(err, password.ErrPolicy) {
		t.Fatalf("CompleteSignup() with a short password = %v, want ErrPolicy", err)
	}
	signup, err := CompleteSignup(t.Context(), f.d, f.h, f.tenant, v, "long enough", &p, nil)
	if err != nil {
		t.Fatalf("CompleteSignup() unexpected error: %v", err)
	}
	u, err := FindUser(t.Context(), f.d, f.tenant.ID, "grace@example.com")
	if err != nil || !u.EmailVerified || u.Status != store.UserActive {
		t.Fatalf("the new user = %+v, %v; want an active user with a verified address", u, err)
	}
	if _, err := AuthenticatePassword(t.Context(), f.d, f.h, f.tenant.ID, "grace@example.com", "long enough"); err != nil {
		t.Errorf("signing in with the new password = %v, want nil", err)
	}
	resp, err := url.Parse(signup.Response.URI())
	if !signup.Request || signup.Consent || err != nil || resp.Query().Get("code") == "" {
		t.Fatalf("CompleteSignup() = %+v; want a code for the request", signup)
	}
	session, err := f.d.Store.Sessions().GetByTokenHash(t.Context(), f.tenant.ID, oauth.HashToken(signup.SessionToken))
	if err != nil || session.UserID != u.ID {
		t.Errorf("the session = %+v, %v; want one of the new user", session, err)
	}
	// The verification is used once.
	if _, err := CompleteSignup(t.Context(), f.d, f.h, f.tenant, v, "long enough", nil, nil); !errors.Is(err, ErrVerificationNotFound) {
		t.Errorf("a second CompleteSignup() = %v, want ErrVerificationNotFound", err)
	}
}

func TestCompleteSignupWithoutTheRequest(t *testing.T) {
	t.Parallel()
	f := newSignupFixture(t)
	v := f.verified(t, "grace@example.com")
	signup, err := CompleteSignup(t.Context(), f.d, f.h, f.tenant, v, "long enough", nil, nil)
	if err != nil || signup.Request || signup.Response.RedirectURI != "" || signup.SessionToken == "" {
		t.Fatalf("CompleteSignup() without the request = %+v, %v; want only a session", signup, err)
	}
	if _, err := f.d.Store.Sessions().GetByTokenHash(t.Context(), f.tenant.ID,
		oauth.HashToken(signup.SessionToken)); err != nil {
		t.Errorf("the session of the new user = %v, want it stored", err)
	}
}

func TestCompleteSignupRefuses(t *testing.T) {
	t.Parallel()
	f := newSignupFixture(t)
	unverified, _ := f.startSignup(t, "grace@example.com")
	if _, err := CompleteSignup(t.Context(), f.d, f.h, f.tenant, unverified, "long enough", nil,
		nil); !errors.Is(err, ErrVerificationNotFound) {
		t.Errorf("CompleteSignup() before the verification = %v, want ErrVerificationNotFound", err)
	}
	// The address got an account between the verification and the password.
	v := f.verified(t, "hopper@example.com")
	if _, err := CreateUser(t.Context(), f.d, f.tenant.ID, UserSpec{Email: "hopper@example.com"}); err != nil {
		t.Fatalf("CreateUser() unexpected error: %v", err)
	}
	if _, err := CompleteSignup(t.Context(), f.d, f.h, f.tenant, v, "long enough", nil, nil); !errors.Is(err, ErrUserExists) {
		t.Errorf("CompleteSignup() for an address with an account = %v, want ErrUserExists", err)
	}
}

// Initiating User Registration via OpenID Connect 1.0, section 4.
func TestStartAuthorizationWithPromptCreate(t *testing.T) {
	t.Parallel()
	f := newSignupFixture(t)
	params := webRequest()
	params.Set("prompt", "create")

	closed := f.tenant
	closed.Signup = false
	_, err := StartAuthorization(t.Context(), f.d, fakeSigner{}, closed, params, testBinding, nil)
	var redirect *RedirectError
	if !errors.As(err, &redirect) || redirect.Err.Code != oauth.ErrorInvalidRequest {
		t.Errorf("prompt=create on a tenant without signup = %v, want invalid_request", err)
	}

	// The signup page comes even with a session.
	sessionHash, _ := f.signIn(t, webRequest())
	a, err := StartAuthorization(t.Context(), f.d, fakeSigner{}, f.tenant, params, testBinding, sessionHash)
	if err != nil || !a.Signup || a.RequestID == "" || a.Response.RedirectURI != "" {
		t.Errorf("prompt=create = %+v, %v; want a stored request for the signup page", a, err)
	}
}

func TestPurgeExpiredRemovesEmailVerifications(t *testing.T) {
	t.Parallel()
	f := newSignupFixture(t)
	v, _ := f.startSignup(t, "grace@example.com")
	*f.now = f.now.Add(EmailVerificationLifetime - time.Second)
	if err := PurgeExpired(t.Context(), f.d); err != nil {
		t.Fatalf("PurgeExpired() unexpected error: %v", err)
	}
	if _, err := f.d.Store.EmailVerifications().Get(t.Context(), f.tenant.ID, v.ID); err != nil {
		t.Fatalf("a verification that has not expired = %v, want it kept", err)
	}
	*f.now = f.now.Add(time.Second)
	if err := PurgeExpired(t.Context(), f.d); err != nil {
		t.Fatalf("PurgeExpired() unexpected error: %v", err)
	}
	if _, err := f.d.Store.EmailVerifications().Get(t.Context(), f.tenant.ID, v.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("an expired verification = %v, want it deleted", err)
	}
}

func TestNormalizeCode(t *testing.T) {
	t.Parallel()
	for typed, want := range map[string]string{
		"123456":                           "123456",
		"123 456":                          "123456",
		" 12-34-56":                        "123456",
		"12345":                            "",
		"1234567":                          "",
		"12345a":                           "",
		"１２３４５６":                           "",
		"":                                 "",
		strings.Repeat(" ", 30) + "123456": "",
	} {
		got, ok := NormalizeCode(typed)
		if ok != (want != "") || ok && got != want {
			t.Errorf("NormalizeCode(%q) = %q, %v; want %q", typed, got, ok, want)
		}
	}
}

func FuzzNormalizeCode(f *testing.F) {
	for _, seed := range []string{"123456", "123 456", "12-34-56", "abc", "１２３"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, typed string) {
		code, ok := NormalizeCode(typed)
		if !ok {
			return
		}
		if len(code) != CodeLength || strings.Trim(code, "0123456789") != "" {
			t.Errorf("NormalizeCode(%q) accepted %q", typed, code)
		}
		if again, ok := NormalizeCode(code); !ok || again != code {
			t.Errorf("NormalizeCode(%q) = %q, %v; want the code unchanged", code, again, ok)
		}
	})
}

// Every signup message exists in every locale, without a key or a
// placeholder left in it.
func TestSignupMessagesInEveryLocale(t *testing.T) {
	t.Parallel()
	catalogs, err := i18n.Load()
	if err != nil {
		t.Fatalf("loading the catalogs: %v", err)
	}
	for _, locale := range i18n.Supported() {
		for _, exists := range []bool{false, true} {
			content := signupMessage(catalogs.Printer(locale), "Shop", "123456", testVerifyURL+"?verification=v", exists)
			msg, err := emailtmpl.Render(t.Context(), "grace@example.com", content)
			if err != nil {
				t.Fatalf("%s, existing %v: Render() unexpected error: %v", locale, exists, err)
			}
			for _, part := range []string{msg.Subject, msg.Text, msg.HTML} {
				if strings.ContainsAny(part, "{}") || strings.Contains(part, "email.signup") {
					t.Errorf("%s, existing %v: a key or placeholder is left:\n%s", locale, exists, part)
				}
			}
			if !strings.Contains(msg.HTML, `<html lang="`+string(locale)+`">`) || !strings.Contains(msg.Text, "Shop") {
				t.Errorf("%s, existing %v: message = %+v", locale, exists, msg)
			}
		}
	}
}
