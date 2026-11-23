package clavis

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"clavisid.org/clavis/internal/app"
	"clavisid.org/clavis/internal/mailer"
	"clavisid.org/clavis/store"
)

var resetLink = regexp.MustCompile(`https://\S+/reset/verify\?\S+`)

// newResetServer returns a login server with a mailer that records
// messages; its tenant does not offer signup.
func newResetServer(t *testing.T) (*Server, store.Tenant, *testMail) {
	t.Helper()
	s, tn := newLoginServer(t, signupIssuer, "")
	mail := &testMail{}
	s.deps.Mail = mail
	return s, tn, mail
}

// startReset follows a new authorization request to the password reset
// page, posts address, and returns the authorization request ID and the
// verification ID of the page it leads to.
func (b *browser) startReset(query url.Values, address string) (request, verification string) {
	b.t.Helper()
	request = b.startLogin(signupIssuer, query)
	res, _ := b.post(signupIssuer+"/reset", url.Values{"request": {request}, "email": {address}}, "same-origin")
	loc, err := url.Parse(res.Header.Get("Location"))
	if res.StatusCode != http.StatusSeeOther || err != nil || loc.Path != "/reset/verify" {
		b.t.Fatalf("reset = %d to %q, want the code page", res.StatusCode, res.Header.Get("Location"))
	}
	return request, loc.Query().Get("verification")
}

func TestPasswordResetWithTheCode(t *testing.T) {
	t.Parallel()
	const issuer = signupIssuer
	s, tn, mail := newResetServer(t)
	// Another browser holds a session from before the reset.
	other := newBrowser(t, s.Handler())
	id := other.startLogin(issuer, authorizeQuery())
	if res, _ := other.post(issuer+"/login", loginForm(id, testPassword), "same-origin"); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("sign-in of the other browser = %d", res.StatusCode)
	}
	b := newBrowser(t, s.Handler())
	id = b.startLogin(issuer, authorizeQuery())
	if res, _ := b.post(issuer+"/login", loginForm(id, testPassword), "same-origin"); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("sign-in = %d", res.StatusCode)
	}

	query := authorizeQuery()
	query.Set("prompt", "login")
	id = b.startLogin(issuer, query)
	if _, page := b.get(issuer + "/login?request=" + id); !strings.Contains(page,
		`<a id="reset" href="`+issuer+`/reset?request=`+id+`">Forgot your password?</a>`) ||
		strings.Contains(page, `id="signup"`) {
		t.Fatalf("the login page does not link to the reset only:\n%s", page)
	}
	if res, page := b.get(issuer + "/reset?request=" + id); res.StatusCode != http.StatusOK ||
		!strings.Contains(page, "<title>Reset your password</title>") {
		t.Fatalf("reset page = %d:\n%s", res.StatusCode, page)
	}
	res, _ := b.post(issuer+"/reset", url.Values{"request": {id}, "email": {"Ada@Example.com"}}, "same-origin")
	loc, err := url.Parse(res.Header.Get("Location"))
	if res.StatusCode != http.StatusSeeOther || err != nil || loc.Path != "/reset/verify" {
		t.Fatalf("reset = %d to %q, want the code page", res.StatusCode, res.Header.Get("Location"))
	}
	verification := loc.Query().Get("verification")
	msg := mail.last(t, "ada@example.com")
	code := signupCode.FindStringSubmatch(msg.Text)
	if code == nil || msg.Subject != "Reset your password" || !strings.Contains(msg.Text, issuer+"/reset/verify?") {
		t.Fatalf("message = %+v", msg)
	}
	if _, page := b.get(loc.String()); !strings.Contains(page, "If <strong>ada@example.com</strong> has an account") {
		t.Errorf("code page:\n%s", page)
	}
	res, _ = b.post(issuer+"/reset/verify", url.Values{"verification": {verification}, "code": {code[1]}}, "same-origin")
	passwordPage := issuer + "/reset/password?verification=" + verification
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != passwordPage {
		t.Fatalf("code = %d to %q, want the password page", res.StatusCode, res.Header.Get("Location"))
	}
	if _, page := b.get(passwordPage); !strings.Contains(page, "<title>Choose a new password</title>") ||
		!strings.Contains(page, ">Change password</button>") {
		t.Errorf("password page:\n%s", page)
	}
	choose := func(pw string) (response, string) {
		t.Helper()
		return b.post(issuer+"/reset/password", url.Values{"verification": {verification}, "password": {pw}}, "same-origin")
	}
	if res, page := choose("short"); res.StatusCode != http.StatusOK ||
		!strings.Contains(page, "The password must have 8 to 256 characters.") {
		t.Errorf("a short password = %d:\n%s", res.StatusCode, page)
	}

	// The browser returns to the sign-in form of its request, signed out.
	res, page := choose("battery staple horse")
	if res.StatusCode != http.StatusOK || !strings.Contains(page, "Your password has been changed. Sign in with the new one.") ||
		!strings.Contains(page, `value="ada@example.com"`) || !strings.Contains(page, `<input type="hidden" name="request" value="`+id+`">`) {
		t.Fatalf("after the new password = %d:\n%s", res.StatusCode, page)
	}
	if c := checkCookie(t, res, sessionCookieName(tn.ID)); c == nil || c.MaxAge >= 0 {
		t.Errorf("session cookie = %+v, want it removed", c)
	}
	if _, page = b.post(issuer+"/login", loginForm(id, testPassword), "same-origin"); !strings.Contains(page,
		"The email or password is incorrect.") {
		t.Errorf("the old password still signs in:\n%s", page)
	}
	res, _ = b.post(issuer+"/login", loginForm(id, "battery staple horse"), "same-origin")
	if !strings.HasPrefix(res.Header.Get("Location"), "https://app.example.com/callback?code=") {
		t.Errorf("sign-in with the new password = %d to %q", res.StatusCode, res.Header.Get("Location"))
	}
	// The reset ended the other browser's session.
	if res, _ = other.get(issuer + "/oauth2/authorize?" + authorizeQuery().Encode()); !strings.HasPrefix(
		res.Header.Get("Location"), issuer+"/login?") {
		t.Errorf("authorize in the other browser = %d to %q, want the login page", res.StatusCode, res.Header.Get("Location"))
	}
	// The verification is used.
	if res, _ = b.get(passwordPage); res.StatusCode != http.StatusBadRequest {
		t.Errorf("password page after the reset = %d, want 400", res.StatusCode)
	}
}

func TestPasswordResetWithTheLink(t *testing.T) {
	t.Parallel()
	s, _, mail := newResetServer(t)
	b := newBrowser(t, s.Handler())
	_, verification := b.startReset(authorizeQuery(), "ada@example.com")
	link := resetLink.FindString(mail.last(t, "ada@example.com").Text)
	if res, page := newBrowser(t, s.Handler()).get(link); res.StatusCode != http.StatusBadRequest ||
		!strings.Contains(page, "<title>Password reset no longer valid</title>") ||
		!strings.Contains(page, "In the browser where you started, open the link or type the code") {
		t.Errorf("link in another browser = %d:\n%s", res.StatusCode, page)
	}
	if res, page := b.get(link); res.StatusCode != http.StatusOK ||
		!strings.Contains(page, "to go on resetting your password") {
		t.Fatalf("link page = %d:\n%s", res.StatusCode, page)
	}
	u, _ := url.Parse(link)
	res, _ := b.post(signupIssuer+"/reset/verify", url.Values{"verification": {verification},
		"token": {u.Query().Get("token")}}, "same-origin")
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != signupIssuer+"/reset/password?verification="+verification {
		t.Errorf("confirmation = %d to %q, want the password page", res.StatusCode, res.Header.Get("Location"))
	}
}

// ADR 0027: the responses to a password reset do not tell whether the
// address has an active account, even when the message cannot be queued.
// Only an active account gets the message.
func TestPasswordResetDoesNotRevealAccounts(t *testing.T) {
	t.Parallel()
	ids := regexp.MustCompile(`[A-Za-z0-9_-]{22}`)
	for _, queueErr := range []error{nil, mailer.ErrQueueFull} {
		s, tn, mail := newResetServer(t)
		mail.err = queueErr
		hopper, err := app.CreateUser(t.Context(), s.deps, tn.ID, app.UserSpec{Email: "hopper@example.com"})
		if err != nil {
			t.Fatalf("CreateUser() unexpected error: %v", err)
		}
		hopper.Status = store.UserDisabled
		if err := s.deps.Store.Users().Update(t.Context(), hopper); err != nil {
			t.Fatalf("disabling the user: %v", err)
		}
		var pages []string
		for _, address := range []string{"ada@example.com", "grace@example.com", "hopper@example.com"} {
			b := newBrowser(t, s.Handler())
			id := b.startLogin(signupIssuer, authorizeQuery())
			res, body := b.post(signupIssuer+"/reset", url.Values{"request": {id}, "email": {address}}, "same-origin")
			location := res.Header.Get("Location")
			_, verifyPage := b.get(location)
			normalize := func(s string) string {
				return ids.ReplaceAllString(strings.ReplaceAll(s, address, "ADDRESS"), "ID")
			}
			pages = append(pages, strings.Join([]string{
				res.Header.Get("Cache-Control"), res.Header.Get("Referrer-Policy"),
				http.StatusText(res.StatusCode), normalize(location), body, normalize(verifyPage),
				strings.Join(res.Header.Values("Set-Cookie"), "\n"),
			}, "\n---\n"))
		}
		for i, address := range []string{"an unknown address", "a disabled account"} {
			if pages[i+1] != pages[0] {
				t.Errorf("queue error %v: responses differ for an active account and %s:\n%s\n=====\n%s",
					queueErr, address, pages[0], pages[i+1])
			}
		}
		if queueErr == nil {
			if len(mail.sent) != 1 || mail.sent[0].To != "ada@example.com" {
				t.Errorf("queued %+v, want one message, to the active account", mail.sent)
			}
		}
	}
}

func TestPasswordResetUnavailable(t *testing.T) {
	t.Parallel()
	s, _ := newLoginServer(t, signupIssuer, "")
	b := newBrowser(t, s.Handler())
	id := b.startLogin(signupIssuer, authorizeQuery())
	if _, page := b.get(signupIssuer + "/login?request=" + id); strings.Contains(page, `id="reset"`) {
		t.Errorf("the login page of a server without email links to the reset:\n%s", page)
	}
	if res, page := b.get(signupIssuer + "/reset?request=" + id); res.StatusCode != http.StatusNotFound ||
		!strings.Contains(page, "<title>Password reset not available</title>") {
		t.Errorf("reset page without email = %d:\n%s", res.StatusCode, page)
	}
	for _, path := range []string{"/reset", "/reset/verify", "/reset/password"} {
		if res, _ := b.post(signupIssuer+path, url.Values{"request": {id}, "email": {"ada@example.com"}},
			"same-origin"); res.StatusCode != http.StatusNotFound {
			t.Errorf("POST %s without email = %d, want 404", path, res.StatusCode)
		}
	}
}

func TestPasswordResetRejectsCrossOriginPosts(t *testing.T) {
	t.Parallel()
	s, _, mail := newResetServer(t)
	b := newBrowser(t, s.Handler())
	id := b.startLogin(signupIssuer, authorizeQuery())
	for _, path := range []string{"/reset", "/reset/verify", "/reset/password"} {
		if res, _ := b.post(signupIssuer+path, url.Values{"request": {id}, "email": {"ada@example.com"}},
			"cross-site"); res.StatusCode != http.StatusForbidden {
			t.Errorf("cross-site POST %s = %d, want 403", path, res.StatusCode)
		}
	}
	if len(mail.sent) != 0 {
		t.Errorf("a cross-site reset queued %d messages", len(mail.sent))
	}
}

// A reset whose authorization request expired still changes the password.
func TestPasswordResetAfterTheRequestExpired(t *testing.T) {
	t.Parallel()
	s, tn, mail := newResetServer(t)
	b := newBrowser(t, s.Handler())
	id, verification := b.startReset(authorizeQuery(), "ada@example.com")
	code := signupCode.FindStringSubmatch(mail.last(t, "ada@example.com").Text)
	if res, _ := b.post(signupIssuer+"/reset/verify", url.Values{"verification": {verification}, "code": {code[1]}},
		"same-origin"); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("code = %d, want a redirect", res.StatusCode)
	}
	if err := s.deps.Store.AuthorizationRequests().Delete(t.Context(), tn.ID, id); err != nil {
		t.Fatalf("deleting the authorization request: %v", err)
	}
	res, page := b.post(signupIssuer+"/reset/password", url.Values{"verification": {verification},
		"password": {"battery staple horse"}}, "same-origin")
	if res.StatusCode != http.StatusOK || !strings.Contains(page, "<title>Your password has been changed</title>") {
		t.Fatalf("password after the request expired = %d:\n%s", res.StatusCode, page)
	}
	if _, err := app.AuthenticatePassword(t.Context(), s.deps, s.passwords, tn.ID, "ada@example.com",
		"battery staple horse"); err != nil {
		t.Errorf("signing in with the new password = %v", err)
	}
}
