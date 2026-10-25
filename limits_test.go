package clavis

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"clavisid.org/clavis/internal/app"
)

// ADR 0030: the lock of an address is stored, so the instances that share a
// store all honor it.
func TestLockoutHoldsAcrossInstances(t *testing.T) {
	t.Parallel()
	const issuer = signupIssuer
	cfg := testConfig(t, openStore(t))
	cfg.Issuer = issuer
	first, second := mustNew(t, cfg), mustNew(t, cfg)
	u, err := app.CreateUser(t.Context(), first.deps, first.defaultTenant.ID, app.UserSpec{Email: "ada@example.com"})
	if err != nil {
		t.Fatalf("CreateUser() unexpected error: %v", err)
	}
	if err := app.SetPassword(t.Context(), first.deps, first.passwords, u, testPassword); err != nil {
		t.Fatalf("SetPassword() unexpected error: %v", err)
	}
	signIn := func(s *Server, pw string) (response, string) {
		return newBrowser(t, s.Handler()).post(issuer+"/account/login",
			url.Values{"email": {"ada@example.com"}, "password": {pw}}, "same-origin")
	}
	for i := range app.MaxSignInFailures {
		if res, page := signIn(first, "wrong"); res.StatusCode != http.StatusOK ||
			!strings.Contains(page, "The email or password is incorrect.") {
			t.Fatalf("wrong password %d = %d:\n%s", i+1, res.StatusCode, page)
		}
	}
	res, page := signIn(second, testPassword)
	if res.StatusCode != http.StatusOK || !strings.Contains(page, "The email or password is incorrect.") {
		t.Errorf("the right password on another instance = %d, want the page of a wrong password:\n%s",
			res.StatusCode, page)
	}
}

// ADR 0030: an address that received too many messages gets a page that
// says so, the same whether or not it has an account.
func TestTooManyMessagesToAnAddress(t *testing.T) {
	t.Parallel()
	const issuer = signupIssuer
	s, _, mail := newSignupServer(t)
	b := newBrowser(t, s.Handler())
	var pages []string
	for _, address := range []string{"ada@example.com", "grace@example.com"} {
		for range app.MaxMessages {
			b.startSignup(address)
		}
		sent := len(mail.sent)
		id := b.startLogin(issuer, authorizeQuery())
		res, page := b.post(issuer+"/signup", url.Values{"request": {id}, "email": {address}}, "same-origin")
		if res.StatusCode != http.StatusTooManyRequests || !strings.Contains(page, "<title>Too many messages</title>") ||
			!strings.Contains(page, "Too many messages were sent to this address.") {
			t.Errorf("signup of %s after %d messages = %d:\n%s", address, app.MaxMessages, res.StatusCode, page)
		}
		res, reset := b.post(issuer+"/reset", url.Values{"email": {address}}, "same-origin")
		if res.StatusCode != http.StatusTooManyRequests || !strings.Contains(reset, "<title>Too many messages</title>") {
			t.Errorf("reset of %s after %d messages = %d:\n%s", address, app.MaxMessages, res.StatusCode, reset)
		}
		if len(mail.sent) != sent {
			t.Errorf("%d messages to %s after the limit, want none", len(mail.sent)-sent, address)
		}
		pages = append(pages, page)
	}
	if pages[0] != pages[1] {
		t.Errorf("the pages for an address with an account and one without differ:\n%s\n%s", pages[0], pages[1])
	}
}

// ADR 0030: wrong codes across the verifications of an address lock its
// codes; the page says that the link still works, and it does.
func TestWrongCodesLockTheCodesOfAnAddressPage(t *testing.T) {
	t.Parallel()
	const issuer = signupIssuer
	s, _, mail := newSignupServer(t)
	b := newBrowser(t, s.Handler())
	verify := func(verification, code string) (response, string) {
		return b.post(issuer+"/signup/verify", url.Values{"verification": {verification}, "code": {code}}, "same-origin")
	}
	for range app.MaxCodeFailures / app.MaxCodeAttempts {
		verification := b.startSignup("grace@example.com")
		wrong := []byte(signupCode.FindStringSubmatch(mail.last(t, "grace@example.com").Text)[1])
		wrong[0] = '0' + (wrong[0]-'0'+1)%10
		for range app.MaxCodeAttempts {
			verify(verification, string(wrong))
		}
	}
	verification := b.startSignup("grace@example.com")
	msg := mail.last(t, "grace@example.com")
	res, page := verify(verification, signupCode.FindStringSubmatch(msg.Text)[1])
	if res.StatusCode != http.StatusTooManyRequests || !strings.Contains(page, "<title>Too many attempts</title>") ||
		!strings.Contains(page, "Open the link in the message in this browser") {
		t.Fatalf("the right code for a locked address = %d:\n%s", res.StatusCode, page)
	}
	link, err := url.Parse(signupLink.FindString(msg.Text))
	if err != nil {
		t.Fatalf("parsing the link: %v", err)
	}
	res, _ = b.post(issuer+"/signup/verify", url.Values{"verification": {verification},
		"token": {link.Query().Get("token")}}, "same-origin")
	if loc := res.Header.Get("Location"); res.StatusCode != http.StatusSeeOther ||
		!strings.HasPrefix(loc, issuer+"/signup/password?") {
		t.Errorf("the link for a locked address = %d to %q, want the password page", res.StatusCode, loc)
	}
}
