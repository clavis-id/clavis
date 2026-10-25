package clavis

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

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
	// Each message comes from another client address, so that the limit
	// per address meets them first.
	client := 0
	for _, address := range []string{"ada@example.com", "grace@example.com"} {
		for range app.MaxMessages {
			client++
			b.addr = fmt.Sprintf("198.51.100.%d:1234", client)
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
	// Each code comes from another client address, so that the limit per
	// address meets them first.
	client := 0
	for range app.MaxCodeFailures / app.MaxCodeAttempts {
		verification := b.startSignup("grace@example.com")
		wrong := otherCode(t, mail.last(t, "grace@example.com").Text)
		for range app.MaxCodeAttempts {
			client++
			b.addr = fmt.Sprintf("198.51.100.%d:1234", client)
			verify(verification, wrong)
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

// otherCode returns a code that is not the code of the message text.
func otherCode(t *testing.T, text string) string {
	t.Helper()
	m := signupCode.FindStringSubmatch(text)
	if m == nil {
		t.Fatalf("the message has no code:\n%s", text)
	}
	code := []byte(m[1])
	code[0] = '0' + (code[0]-'0'+1)%10
	return string(code)
}

// fixClock makes the clock of s stand still at the returned time, which
// the test moves.
func fixClock(s *Server) *time.Time {
	now := time.Now()
	s.deps.Now = func() time.Time { return now }
	return &now
}

// wantTooManyRequests checks the page of a client that must wait, and that
// it is told to retry after retry.
func wantTooManyRequests(t *testing.T, what string, res response, page, retry string) {
	t.Helper()
	if res.StatusCode != http.StatusTooManyRequests || res.Header.Get("Retry-After") != retry ||
		!strings.Contains(page, "<title>Too many requests</title>") ||
		!strings.Contains(page, "Too many requests came from your network.") {
		t.Errorf("%s = %d, Retry-After %q, want 429 after %s:\n%s", what, res.StatusCode,
			res.Header.Get("Retry-After"), retry, page)
	}
}

// ADR 0030: wrong passwords from one client address, at the sign-in forms
// and the password change, wait after a burst; right ones do not count.
func TestWrongPasswordsPerClient(t *testing.T) {
	t.Parallel()
	const issuer = signupIssuer
	s, _ := newLoginServer(t, issuer, "")
	now := fixClock(s)
	b := newBrowser(t, s.Handler())
	signIn := func(email, pw string) (response, string) {
		return b.post(issuer+"/account/login", url.Values{"email": {email}, "password": {pw}}, "same-origin")
	}
	for range passwordLimit.burst + 1 {
		if res, _ := signIn("ada@example.com", testPassword); res.StatusCode != http.StatusSeeOther {
			t.Fatalf("a right password = %d, want a sign-in", res.StatusCode)
		}
	}
	// Wrong passwords for other addresses each, so that no address locks.
	for i := range passwordLimit.burst - 1 {
		if res, page := signIn(fmt.Sprintf("user%d@example.com", i), "wrong"); res.StatusCode != http.StatusOK ||
			!strings.Contains(page, "The email or password is incorrect.") {
			t.Fatalf("wrong password %d = %d:\n%s", i+1, res.StatusCode, page)
		}
	}
	changePassword := func() (response, string) {
		return b.post(issuer+"/account/password", url.Values{"current_password": {"wrong"},
			"new_password": {"new horse battery"}}, "same-origin")
	}
	if res, page := changePassword(); res.StatusCode != http.StatusOK ||
		!strings.Contains(page, "The current password is incorrect.") {
		t.Fatalf("a password change with a wrong password = %d:\n%s", res.StatusCode, page)
	}

	retry := strconv.Itoa(int(passwordLimit.interval / time.Second))
	res, page := signIn("ada@example.com", testPassword)
	wantTooManyRequests(t, "an account sign-in after the burst", res, page, retry)
	// A browser without a session, from the same address.
	fresh := newBrowser(t, s.Handler())
	id := fresh.startLogin(issuer, authorizeQuery())
	res, page = fresh.post(issuer+"/login", loginForm(id, testPassword), "same-origin")
	wantTooManyRequests(t, "a sign-in for an authorization request after the burst", res, page, retry)
	res, page = changePassword()
	wantTooManyRequests(t, "a password change after the burst", res, page, retry)

	other := newBrowser(t, s.Handler())
	other.addr = "198.51.100.7:1234"
	if res, _ := other.post(issuer+"/account/login", url.Values{"email": {"ada@example.com"},
		"password": {testPassword}}, "same-origin"); res.StatusCode != http.StatusSeeOther {
		t.Errorf("a sign-in from another client address = %d, want it to succeed", res.StatusCode)
	}

	*now = now.Add(passwordLimit.interval)
	if res, _ := signIn("someone@example.com", "wrong"); res.StatusCode != http.StatusOK {
		t.Errorf("a wrong password an interval later = %d, want it checked", res.StatusCode)
	}
	res, page = signIn("ada@example.com", testPassword)
	wantTooManyRequests(t, "a second sign-in an interval later", res, page, retry)
}

// ADR 0030: wrong codes from one client address wait after a burst; links
// do not.
func TestWrongCodesPerClient(t *testing.T) {
	t.Parallel()
	const issuer = signupIssuer
	s, _, mail := newSignupServer(t)
	fixClock(s)
	b := newBrowser(t, s.Handler())
	verify := func(form url.Values) (response, string) {
		return b.post(issuer+"/signup/verify", form, "same-origin")
	}
	// Wrong codes for several addresses, so that no address locks.
	for sent, i := 0, 0; sent < codeLimit.burst; i++ {
		address := fmt.Sprintf("user%d@example.com", i)
		verification := b.startSignup(address)
		wrong := otherCode(t, mail.last(t, address).Text)
		for j := 0; j < app.MaxCodeAttempts && sent < codeLimit.burst; j++ {
			verify(url.Values{"verification": {verification}, "code": {wrong}})
			sent++
		}
	}
	verification := b.startSignup("grace@example.com")
	msg := mail.last(t, "grace@example.com")
	res, page := verify(url.Values{"verification": {verification}, "code": {signupCode.FindStringSubmatch(msg.Text)[1]}})
	wantTooManyRequests(t, "a code after the burst", res, page, strconv.Itoa(int(codeLimit.interval/time.Second)))
	link, err := url.Parse(signupLink.FindString(msg.Text))
	if err != nil {
		t.Fatalf("parsing the link: %v", err)
	}
	res, _ = verify(url.Values{"verification": {verification}, "token": {link.Query().Get("token")}})
	if loc := res.Header.Get("Location"); res.StatusCode != http.StatusSeeOther ||
		!strings.HasPrefix(loc, issuer+"/signup/password?") {
		t.Errorf("a link after the burst = %d to %q, want the password page", res.StatusCode, loc)
	}
}

// ADR 0030: the messages of signup and reset from one client address wait
// after a burst, whether or not the addresses have accounts.
func TestMessagesPerClient(t *testing.T) {
	t.Parallel()
	const issuer = signupIssuer
	s, _, mail := newSignupServer(t)
	fixClock(s)
	b := newBrowser(t, s.Handler())
	reset := func(address string) (response, string) {
		return b.post(issuer+"/reset", url.Values{"email": {address}}, "same-origin")
	}
	for i := range messageLimit.burst {
		address := fmt.Sprintf("user%d@example.com", i)
		if i%2 == 0 {
			b.startSignup(address)
		} else if res, _ := reset(address); res.StatusCode != http.StatusSeeOther {
			t.Fatalf("reset %d = %d, want the code page", i+1, res.StatusCode)
		}
	}
	sent := len(mail.sent)
	retry := strconv.Itoa(int(messageLimit.interval / time.Second))
	id := b.startLogin(issuer, authorizeQuery())
	res, page := b.post(issuer+"/signup", url.Values{"request": {id}, "email": {"grace@example.com"}}, "same-origin")
	wantTooManyRequests(t, "a signup after the burst", res, page, retry)
	res, page = reset("ada@example.com")
	wantTooManyRequests(t, "a reset after the burst", res, page, retry)
	if len(mail.sent) != sent {
		t.Errorf("%d messages queued after the burst, want none", len(mail.sent)-sent)
	}
}

// ADR 0030: errors of the token, revocation and introspection endpoints,
// and inactive tokens of introspection, from one client address wait after
// a burst; successful requests do not count.
func TestFailedTokenRequestsPerClient(t *testing.T) {
	t.Parallel()
	s, secret := tokenServer(t)
	now := fixClock(s)
	h := s.Handler()
	basic := http.Header{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte("web:"+secret))}}
	wrong := http.Header{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte("web:wrong"))}}
	for range tokenLimit.burst + 1 {
		if rec := post(t, h, "/oauth2/revoke", formContentType, "token=unknown", basic); rec.Code != http.StatusOK {
			t.Fatalf("a revocation = %d %s, want 200", rec.Code, rec.Body.String())
		}
	}
	for range tokenLimit.burst - 1 {
		if rec := post(t, h, "/oauth2/token", formContentType, "grant_type=client_credentials", wrong); rec.Code != http.StatusUnauthorized {
			t.Fatalf("a wrong secret = %d %s, want 401", rec.Code, rec.Body.String())
		}
	}
	if rec := post(t, h, "/oauth2/introspect", formContentType, "token=unknown", basic); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), `"active":false`) {
		t.Fatalf("an introspection = %d %s, want an inactive token", rec.Code, rec.Body.String())
	}

	for _, path := range []string{"/oauth2/token", "/oauth2/revoke", "/oauth2/introspect"} {
		rec := post(t, h, path, formContentType, "grant_type=client_credentials&token=unknown", basic)
		if rec.Code != http.StatusTooManyRequests || errorCode(t, rec) != "temporarily_unavailable" ||
			rec.Header().Get("Retry-After") != "1" || rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s after the burst = %d %v %s", path, rec.Code, rec.Header(), rec.Body.String())
		}
	}
	rec := post(t, h, "/oauth2/token", formContentType, "grant_type=client_credentials", basic)
	if rec.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("a refused token request lacks CORS headers, which browsers need to read it: %v", rec.Header())
	}

	*now = now.Add(tokenLimit.interval)
	if rec := post(t, h, "/oauth2/revoke", formContentType, "token=unknown", basic); rec.Code != http.StatusOK {
		t.Errorf("a revocation an interval later = %d %s, want 200", rec.Code, rec.Body.String())
	}
}

// Clients count by address, IPv6 clients by their /64 network, and behind
// trusted proxies by the address that X-Forwarded-For names. A client
// whose address is unknown is not limited.
func TestLimitKey(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t, openStore(t))
	cfg.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	s := mustNew(t, cfg)
	key := func(remote, forwarded string) (clientKey, bool) {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/account/login", http.NoBody)
		r.RemoteAddr = remote
		if forwarded != "" {
			r.Header.Set("X-Forwarded-For", forwarded)
		}
		return s.limitKey(r)
	}
	same := [][2][2]string{
		{{"192.0.2.1:1234", ""}, {"192.0.2.1:5678", ""}},
		{{"192.0.2.1:1234", ""}, {"[::ffff:192.0.2.1]:1234", ""}},
		{{"192.0.2.1:1234", ""}, {"10.1.2.3:1234", "192.0.2.1"}},
		{{"[2001:db8:1:2::1]:443", ""}, {"[2001:db8:1:2:ffff:ffff:ffff:ffff]:443", ""}},
	}
	for _, pair := range same {
		a, okA := key(pair[0][0], pair[0][1])
		b, okB := key(pair[1][0], pair[1][1])
		if !okA || !okB || a != b {
			t.Errorf("keys of %v and %v differ, want the same", pair[0], pair[1])
		}
	}
	different := [][2][2]string{
		{{"192.0.2.1:1234", ""}, {"192.0.2.2:1234", ""}},
		{{"[2001:db8:1:2::1]:443", ""}, {"[2001:db8:1:3::1]:443", ""}},
		{{"10.1.2.3:1234", "192.0.2.1"}, {"10.1.2.3:1234", "192.0.2.2"}},
		{{"192.0.2.1:1234", "192.0.2.2"}, {"192.0.2.2:1234", ""}},
	}
	for _, pair := range different {
		a, _ := key(pair[0][0], pair[0][1])
		b, _ := key(pair[1][0], pair[1][1])
		if a == b {
			t.Errorf("keys of %v and %v are the same, want them to differ", pair[0], pair[1])
		}
	}
	if _, ok := key("@", ""); ok {
		t.Error("an unknown address has a key, want none")
	}
}
