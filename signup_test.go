package clavis

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
	"uuid"

	"clavisid.org/clavis/email"
	"clavisid.org/clavis/internal/app"
	"clavisid.org/clavis/internal/mailer"
	"clavisid.org/clavis/store"
)

// testMail records the messages that the server queues, or fails with err.
type testMail struct {
	mu   sync.Mutex
	sent []email.Message
	err  error
}

func (m *testMail) Enqueue(_ context.Context, msg email.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.sent = append(m.sent, msg)
	return nil
}

// last returns the last message queued to address.
func (m *testMail) last(t *testing.T, address string) email.Message {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.sent) - 1; i >= 0; i-- {
		if m.sent[i].To == address {
			return m.sent[i]
		}
	}
	t.Fatalf("no message was queued to %s", address)
	return email.Message{}
}

var (
	signupCode = regexp.MustCompile(`(?m)^ {4}(\d{6})$`)
	signupLink = regexp.MustCompile(`https://\S+/signup/verify\?\S+`)
)

// signupIssuer is the issuer of the servers that newSignupServer returns.
const signupIssuer = "https://auth.example.com"

// newSignupServer returns a login server whose default tenant offers
// signup, with a mailer that records messages.
func newSignupServer(t *testing.T) (*Server, store.Tenant, *testMail) {
	t.Helper()
	s, tn := newLoginServer(t, signupIssuer, "")
	mail := &testMail{}
	s.deps.Mail = mail
	on := true
	if _, err := app.UpdateTenant(t.Context(), s.deps, tn.Slug, app.TenantChanges{SignupEnabled: &on}); err != nil {
		t.Fatalf("UpdateTenant() unexpected error: %v", err)
	}
	return s, tn, mail
}

// startSignup follows a new authorization request to the signup page,
// posts address, and returns the verification ID of the page it leads to.
func (b *browser) startSignup(issuer, address string) string {
	b.t.Helper()
	id := b.startLogin(issuer, authorizeQuery())
	res, _ := b.post(issuer+"/signup", url.Values{"request": {id}, "email": {address}}, "same-origin")
	loc, err := url.Parse(res.Header.Get("Location"))
	if res.StatusCode != http.StatusSeeOther || err != nil || loc.Path != "/signup/verify" {
		b.t.Fatalf("signup = %d to %q, want the code page", res.StatusCode, res.Header.Get("Location"))
	}
	return loc.Query().Get("verification")
}

func TestSignupWithTheCode(t *testing.T) {
	t.Parallel()
	const issuer = signupIssuer
	s, _, mail := newSignupServer(t)
	b := newBrowser(t, s.Handler())

	id := b.startLogin(issuer, authorizeQuery())
	_, page := b.get(issuer + "/login?request=" + id)
	if !strings.Contains(page, `<a id="signup" href="`+issuer+`/signup?request=`+id+`">Create one</a>`) {
		t.Fatalf("the login page does not link to signup:\n%s", page)
	}
	res, page := b.get(issuer + "/signup?request=" + id)
	if res.StatusCode != http.StatusOK || !strings.Contains(page, "<title>Create an account</title>") ||
		!strings.Contains(page, `<form method="post" action="/signup">`) {
		t.Fatalf("signup page = %d:\n%s", res.StatusCode, page)
	}
	if res, page = b.post(issuer+"/signup", url.Values{"request": {id}, "email": {"not an address"}},
		"same-origin"); res.StatusCode != http.StatusOK || !strings.Contains(page, "Enter a valid email address") {
		t.Errorf("signup with a malformed address = %d:\n%s", res.StatusCode, page)
	}
	res, _ = b.post(issuer+"/signup", url.Values{"request": {id}, "email": {"Grace@Example.com"}}, "same-origin")
	loc, err := url.Parse(res.Header.Get("Location"))
	if res.StatusCode != http.StatusSeeOther || err != nil || loc.Path != "/signup/verify" {
		t.Fatalf("signup = %d to %q, want the code page", res.StatusCode, res.Header.Get("Location"))
	}
	verifyPage := loc.String()
	verification := loc.Query().Get("verification")
	msg := mail.last(t, "grace@example.com")
	code := signupCode.FindStringSubmatch(msg.Text)
	if code == nil || msg.Subject != "Confirm your email address" || !strings.Contains(msg.Text, "Web App") {
		t.Fatalf("message = %+v", msg)
	}

	res, page = b.get(verifyPage)
	if res.StatusCode != http.StatusOK || !strings.Contains(page, "<strong>grace@example.com</strong>") ||
		!strings.Contains(page, `autocomplete="one-time-code"`) {
		t.Fatalf("code page = %d:\n%s", res.StatusCode, page)
	}
	wrong := "000000"
	if code[1] == wrong {
		wrong = "111111"
	}
	verify := func(code string) (response, string) {
		t.Helper()
		return b.post(issuer+"/signup/verify", url.Values{"verification": {verification}, "code": {code}}, "same-origin")
	}
	if res, page = verify(wrong); res.StatusCode != http.StatusOK || !strings.Contains(page, "The code is incorrect.") {
		t.Errorf("a wrong code = %d:\n%s", res.StatusCode, page)
	}
	res, _ = verify(code[1])
	passwordPage := res.Header.Get("Location")
	if res.StatusCode != http.StatusSeeOther || passwordPage != issuer+"/signup/password?verification="+verification {
		t.Fatalf("the right code = %d to %q, want the password page", res.StatusCode, passwordPage)
	}
	// The code page of a verified address moves on.
	if res, _ = b.get(verifyPage); res.Header.Get("Location") != passwordPage {
		t.Errorf("code page after the code = %d to %q", res.StatusCode, res.Header.Get("Location"))
	}

	res, page = b.get(passwordPage)
	if res.StatusCode != http.StatusOK || !strings.Contains(page, `autocomplete="new-password"`) ||
		!strings.Contains(page, `minlength="8"`) || !strings.Contains(page, "Use 8 to 256 characters.") {
		t.Fatalf("password page = %d:\n%s", res.StatusCode, page)
	}
	if csp := res.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self' https://app.example.com;") {
		t.Errorf("Content-Security-Policy = %q, want the client as a form target", csp)
	}
	choose := func(pw string) (response, string) {
		t.Helper()
		return b.post(issuer+"/signup/password", url.Values{"verification": {verification}, "password": {pw}}, "same-origin")
	}
	if res, page = choose("short"); res.StatusCode != http.StatusOK ||
		!strings.Contains(page, "The password must have 8 to 256 characters.") {
		t.Errorf("a short password = %d:\n%s", res.StatusCode, page)
	}
	res, _ = choose("correct horse battery")
	loc, err = url.Parse(res.Header.Get("Location"))
	if res.StatusCode != http.StatusSeeOther || err != nil || !strings.HasPrefix(loc.String(), "https://app.example.com/callback?") ||
		loc.Query().Get("code") == "" {
		t.Fatalf("password = %d to %q, want a code for the client", res.StatusCode, res.Header.Get("Location"))
	}
	checkCookie(t, res, sessionCookieName(s.defaultTenant.ID))

	// The new account signs in, and the session answers the next request.
	if _, err := app.AuthenticatePassword(t.Context(), s.deps, s.passwords, s.defaultTenant.ID, "grace@example.com",
		"correct horse battery"); err != nil {
		t.Errorf("signing in with the new account = %v", err)
	}
	if res, _ = b.get(issuer + "/oauth2/authorize?" + authorizeQuery().Encode()); !strings.HasPrefix(
		res.Header.Get("Location"), "https://app.example.com/callback?code=") {
		t.Errorf("authorize after signup = %d to %q, want single sign-on", res.StatusCode, res.Header.Get("Location"))
	}
	// The verification is used.
	if res, _ = b.get(passwordPage); res.StatusCode != http.StatusBadRequest {
		t.Errorf("password page after signup = %d, want 400", res.StatusCode)
	}
}

// After signup, a client that asks for consent gets it, as after a sign-in
// (ADR 0020).
func TestSignupWithConsent(t *testing.T) {
	t.Parallel()
	const issuer = signupIssuer
	s, tn, mail := newSignupServer(t)
	if _, _, err := app.CreateClient(t.Context(), s.deps, tn.ID, app.ClientSpec{
		ClientID: "partner", Name: "Partner App", Type: store.ClientConfidential,
		RedirectURIs: []string{"https://partner.example.com/callback"},
	}); err != nil {
		t.Fatalf("CreateClient() unexpected error: %v", err)
	}
	query := authorizeQuery()
	query.Set("client_id", "partner")
	query.Set("redirect_uri", "https://partner.example.com/callback")
	b := newBrowser(t, s.Handler())
	id := b.startLogin(issuer, query)
	res, _ := b.post(issuer+"/signup", url.Values{"request": {id}, "email": {"grace@example.com"}}, "same-origin")
	loc, err := url.Parse(res.Header.Get("Location"))
	if res.StatusCode != http.StatusSeeOther || err != nil {
		t.Fatalf("signup = %d to %q, want the code page", res.StatusCode, res.Header.Get("Location"))
	}
	verification := loc.Query().Get("verification")
	code := signupCode.FindStringSubmatch(mail.last(t, "grace@example.com").Text)
	if res, _ = b.post(issuer+"/signup/verify", url.Values{"verification": {verification}, "code": {code[1]}},
		"same-origin"); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("code = %d, want a redirect to the password page", res.StatusCode)
	}

	consent := issuer + "/consent?request=" + id
	res, _ = b.post(issuer+"/signup/password", url.Values{"verification": {verification},
		"password": {"correct horse battery"}}, "same-origin")
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != consent {
		t.Fatalf("password = %d to %q, want the consent page", res.StatusCode, res.Header.Get("Location"))
	}
	// The signup page of a request that waits for consent leads to it.
	if res, _ = b.get(issuer + "/signup?request=" + id); res.StatusCode != http.StatusSeeOther ||
		res.Header.Get("Location") != consent {
		t.Errorf("signup page while consent waits = %d to %q, want the consent page", res.StatusCode,
			res.Header.Get("Location"))
	}
	if res, page := b.get(consent); res.StatusCode != http.StatusOK || !strings.Contains(page, "Partner App") ||
		!strings.Contains(page, "grace@example.com") {
		t.Fatalf("consent page = %d:\n%s", res.StatusCode, page)
	}
	res, _ = b.post(issuer+"/consent", url.Values{"request": {id}, "decision": {"allow"}}, "same-origin")
	loc, err = url.Parse(res.Header.Get("Location"))
	if res.StatusCode != http.StatusSeeOther || err != nil ||
		!strings.HasPrefix(loc.String(), "https://partner.example.com/callback?") || loc.Query().Get("code") == "" {
		t.Errorf("consent = %d to %q, want a code for the client", res.StatusCode, res.Header.Get("Location"))
	}
}

func TestSignupWithTheLink(t *testing.T) {
	t.Parallel()
	const issuer = signupIssuer
	s, _, mail := newSignupServer(t)
	b := newBrowser(t, s.Handler())
	verification := b.startSignup(issuer, "grace@example.com")
	link := signupLink.FindString(mail.last(t, "grace@example.com").Text)
	if !strings.HasPrefix(link, issuer+"/signup/verify?") {
		t.Fatalf("message link = %q", link)
	}

	// Another browser, or a mail scanner, gets nothing from the link.
	if res, page := newBrowser(t, s.Handler()).get(link); res.StatusCode != http.StatusBadRequest ||
		!strings.Contains(page, "<title>Sign-up no longer valid</title>") ||
		!strings.Contains(page, "In the browser where you started, open the link or type the code") {
		t.Errorf("link in another browser = %d:\n%s", res.StatusCode, page)
	}
	// Opening the link asks for a confirmation, which verifies nothing yet.
	res, page := b.get(link)
	if res.StatusCode != http.StatusOK || !strings.Contains(page, "<title>Confirm your email address</title>") ||
		!strings.Contains(page, `<input type="hidden" name="token"`) {
		t.Fatalf("link page = %d:\n%s", res.StatusCode, page)
	}
	if res, _ = b.get(issuer + "/signup/password?verification=" + verification); res.StatusCode != http.StatusSeeOther {
		t.Errorf("password page before the confirmation = %d, want a redirect to the code page", res.StatusCode)
	}
	if res, _ = b.get(issuer + "/signup/verify?verification=" + verification + "&token=short"); res.StatusCode != http.StatusBadRequest {
		t.Errorf("link with a malformed token = %d, want 400", res.StatusCode)
	}
	u, _ := url.Parse(link)
	form := url.Values{"verification": {verification}, "token": {u.Query().Get("token")}}
	res, _ = b.post(issuer+"/signup/verify", form, "same-origin")
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != issuer+"/signup/password?verification="+verification {
		t.Fatalf("confirmation = %d to %q, want the password page", res.StatusCode, res.Header.Get("Location"))
	}
	form.Set("token", strings.Repeat("A", tokenLength))
	if res, _ = b.post(issuer+"/signup/verify", form, "same-origin"); res.StatusCode != http.StatusBadRequest {
		t.Errorf("confirmation with another token = %d, want 400", res.StatusCode)
	}
}

// ADR 0026: the responses to a signup do not tell whether the address has an
// account, even when the message cannot be queued. Only the message itself
// differs.
func TestSignupDoesNotRevealAccounts(t *testing.T) {
	t.Parallel()
	const issuer = signupIssuer
	ids := regexp.MustCompile(`[A-Za-z0-9_-]{22}`)
	for _, queueErr := range []error{nil, mailer.ErrQueueFull} {
		s, _, mail := newSignupServer(t)
		mail.err = queueErr
		var pages []string
		for _, address := range []string{"ada@example.com", "grace@example.com"} {
			b := newBrowser(t, s.Handler())
			id := b.startLogin(issuer, authorizeQuery())
			res, body := b.post(issuer+"/signup", url.Values{"request": {id}, "email": {address}}, "same-origin")
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
		if pages[0] != pages[1] {
			t.Errorf("queue error %v: responses differ for an existing and a new account:\n%s\n=====\n%s",
				queueErr, pages[0], pages[1])
		}
		if queueErr == nil {
			if existing := mail.last(t, "ada@example.com"); existing.Subject != "You already have an account" ||
				signupCode.MatchString(existing.Text) {
				t.Errorf("message to the existing account = %+v", existing)
			}
		}
	}
}

func TestSignupUnavailable(t *testing.T) {
	t.Parallel()
	const issuer = signupIssuer
	open, _, _ := newSignupServer(t)
	closed, _ := newLoginServer(t, issuer, "")
	mute, tn := newLoginServer(t, issuer, "")
	on := true
	if _, err := app.UpdateTenant(t.Context(), mute.deps, tn.Slug, app.TenantChanges{SignupEnabled: &on}); err != nil {
		t.Fatalf("UpdateTenant() unexpected error: %v", err)
	}
	for name, s := range map[string]*Server{"without signup": closed, "without email": mute} {
		b := newBrowser(t, s.Handler())
		id := b.startLogin(issuer, authorizeQuery())
		if _, page := b.get(issuer + "/login?request=" + id); strings.Contains(page, `id="signup"`) {
			t.Errorf("%s: the login page links to signup", name)
		}
		if res, page := b.get(issuer + "/signup?request=" + id); res.StatusCode != http.StatusNotFound ||
			!strings.Contains(page, "<title>Sign-up not available</title>") {
			t.Errorf("%s: signup page = %d:\n%s", name, res.StatusCode, page)
		}
		for _, path := range []string{"/signup", "/signup/verify", "/signup/password"} {
			if res, _ := b.post(issuer+path, url.Values{"request": {id}, "email": {"grace@example.com"}},
				"same-origin"); res.StatusCode != http.StatusNotFound {
				t.Errorf("%s: POST %s = %d, want 404", name, path, res.StatusCode)
			}
		}
		query := authorizeQuery()
		query.Set("prompt", "create")
		res, _ := b.get(issuer + "/oauth2/authorize?" + query.Encode())
		loc, _ := url.Parse(res.Header.Get("Location"))
		if res.StatusCode != http.StatusSeeOther || loc.Query().Get("error") != "invalid_request" {
			t.Errorf("%s: prompt=create = %d to %q, want invalid_request", name, res.StatusCode, res.Header.Get("Location"))
		}
		if _, body := b.get(issuer + "/.well-known/openid-configuration"); strings.Contains(body, `"create"`) {
			t.Errorf("%s: the metadata announces prompt=create:\n%s", name, body)
		}
	}
	if _, body := newBrowser(t, open.Handler()).get(issuer + "/.well-known/openid-configuration"); !strings.Contains(body, `"create"`) {
		t.Errorf("the metadata of a tenant with signup does not announce prompt=create:\n%s", body)
	}
}

// ADR 0026: the admin tenant never offers signup, whatever its stored
// setting says.
func TestAdminTenantNeverOffersSignup(t *testing.T) {
	t.Parallel()
	s, _, _ := newSignupServer(t)
	now := time.Now()
	admin := store.Tenant{ID: uuid.NewV7(), Slug: app.AdminTenantSlug, Name: "Admin", SignupEnabled: true,
		CreatedAt: now, UpdatedAt: now}
	if err := s.deps.Store.Tenants().Create(t.Context(), admin); err != nil {
		t.Fatalf("creating the admin tenant: %v", err)
	}
	b := newBrowser(t, s.Handler())
	if res, body := b.get(signupIssuer + "/t/admin/.well-known/openid-configuration"); res.StatusCode != http.StatusOK ||
		strings.Contains(body, `"create"`) {
		t.Errorf("admin tenant metadata = %d, want no prompt=create:\n%s", res.StatusCode, body)
	}
	if res, _ := b.get(signupIssuer + "/t/admin/signup?request=" + strings.Repeat("A", 22)); res.StatusCode != http.StatusNotFound {
		t.Errorf("admin tenant signup page = %d, want 404", res.StatusCode)
	}
}

// Initiating User Registration via OpenID Connect 1.0, section 4.
func TestPromptCreateOpensTheSignupPage(t *testing.T) {
	t.Parallel()
	const issuer = signupIssuer
	s, _, _ := newSignupServer(t)
	b := newBrowser(t, s.Handler())
	query := authorizeQuery()
	query.Set("prompt", "create")
	query.Set("login_hint", "grace@example.com")
	res, _ := b.get(issuer + "/oauth2/authorize?" + query.Encode())
	loc, err := url.Parse(res.Header.Get("Location"))
	if res.StatusCode != http.StatusSeeOther || err != nil || loc.Path != "/signup" {
		t.Fatalf("prompt=create = %d to %q, want the signup page", res.StatusCode, res.Header.Get("Location"))
	}
	if _, page := b.get(loc.String()); !strings.Contains(page, `value="grace@example.com"`) {
		t.Errorf("the signup page does not offer the login hint:\n%s", page)
	}
}

func TestSignupRejectsCrossOriginPosts(t *testing.T) {
	t.Parallel()
	const issuer = signupIssuer
	s, _, mail := newSignupServer(t)
	b := newBrowser(t, s.Handler())
	id := b.startLogin(issuer, authorizeQuery())
	for _, path := range []string{"/signup", "/signup/verify", "/signup/password"} {
		if res, _ := b.post(issuer+path, url.Values{"request": {id}, "email": {"grace@example.com"}},
			"cross-site"); res.StatusCode != http.StatusForbidden {
			t.Errorf("cross-site POST %s = %d, want 403", path, res.StatusCode)
		}
	}
	if len(mail.sent) != 0 {
		t.Errorf("a cross-site signup queued %d messages", len(mail.sent))
	}
}

func TestSignupEndsAfterTooManyCodes(t *testing.T) {
	t.Parallel()
	const issuer = signupIssuer
	s, _, _ := newSignupServer(t)
	b := newBrowser(t, s.Handler())
	verification := b.startSignup(issuer, "grace@example.com")
	for i := range app.MaxCodeAttempts {
		res, page := b.post(issuer+"/signup/verify", url.Values{"verification": {verification}, "code": {"12345"}},
			"same-origin")
		if last := i == app.MaxCodeAttempts-1; last != (res.StatusCode == http.StatusBadRequest) ||
			last && !strings.Contains(page, "<title>Too many attempts</title>") {
			t.Fatalf("attempt %d = %d:\n%s", i+1, res.StatusCode, page)
		}
	}
	if res, _ := b.get(issuer + "/signup/verify?verification=" + verification); res.StatusCode != http.StatusBadRequest {
		t.Errorf("code page after too many attempts = %d, want 400", res.StatusCode)
	}
}

// A signup whose authorization request expired still creates the account
// and signs the user in.
func TestSignupAfterTheRequestExpired(t *testing.T) {
	t.Parallel()
	const issuer = signupIssuer
	s, tn, mail := newSignupServer(t)
	b := newBrowser(t, s.Handler())
	verification := b.startSignup(issuer, "grace@example.com")
	code := signupCode.FindStringSubmatch(mail.last(t, "grace@example.com").Text)
	if res, _ := b.post(issuer+"/signup/verify", url.Values{"verification": {verification}, "code": {code[1]}},
		"same-origin"); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("code = %d, want a redirect", res.StatusCode)
	}
	v, err := s.deps.Store.EmailVerifications().Get(t.Context(), tn.ID, verification)
	if err != nil {
		t.Fatalf("looking up the verification: %v", err)
	}
	if err := s.deps.Store.AuthorizationRequests().Delete(t.Context(), tn.ID, v.AuthorizationRequestID); err != nil {
		t.Fatalf("deleting the authorization request: %v", err)
	}
	res, page := b.post(issuer+"/signup/password", url.Values{"verification": {verification},
		"password": {"correct horse battery"}}, "same-origin")
	if res.StatusCode != http.StatusOK || !strings.Contains(page, "<title>Your account is ready</title>") {
		t.Fatalf("password after the request expired = %d:\n%s", res.StatusCode, page)
	}
	checkCookie(t, res, sessionCookieName(tn.ID))
}

// The pages and the message follow the request's ui_locales, like the rest
// of the hosted pages (ADR 0025).
func TestSignupLanguage(t *testing.T) {
	t.Parallel()
	const issuer = signupIssuer
	s, _, mail := newSignupServer(t)
	b := newBrowser(t, s.Handler())
	query := authorizeQuery()
	query.Set("ui_locales", "es")
	id := b.startLogin(issuer, query)
	if _, page := b.get(issuer + "/signup?request=" + id); !strings.Contains(page, "<title>Crear una cuenta</title>") ||
		!strings.Contains(page, `<form method="GET" action="/signup">`) {
		t.Errorf("signup page with ui_locales es:\n%s", page)
	}
	res, _ := b.post(issuer+"/signup", url.Values{"request": {id}, "email": {"grace@example.com"}}, "same-origin")
	if _, page := b.get(res.Header.Get("Location")); !strings.Contains(page, "<title>Revisa tu correo</title>") {
		t.Errorf("code page with ui_locales es:\n%s", page)
	}
	if msg := mail.last(t, "grace@example.com"); msg.Subject != "Confirma tu dirección de correo electrónico" ||
		!strings.Contains(msg.HTML, `<html lang="es">`) {
		t.Errorf("message with ui_locales es = %+v", msg)
	}
}
