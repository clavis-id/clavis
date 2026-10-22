package clavis

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"clavisid.org/clavis/internal/app"
	"clavisid.org/clavis/store"
)

// signInToAccount signs ada in to the account pages of signupIssuer and
// checks that the browser lands on them.
func (b *browser) signInToAccount() {
	b.t.Helper()
	res, _ := b.post(signupIssuer+"/account/login", url.Values{"email": {"ada@example.com"}, "password": {testPassword}},
		"same-origin")
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != signupIssuer+"/account" {
		b.t.Fatalf("account sign-in = %d to %q, want the account page", res.StatusCode, res.Header.Get("Location"))
	}
}

// The root of an issuer leads to the account pages (from the maintainer,
// in #32).
func TestRootLeadsToTheAccountPages(t *testing.T) {
	t.Parallel()
	const issuer = "https://auth.example.com"
	s, _ := newLoginServer(t, issuer, "acme")
	b := newBrowser(t, s.Handler())
	for root, want := range map[string]string{
		issuer + "/":        issuer + "/account",
		issuer + "/t/acme/": issuer + "/t/acme/account",
	} {
		if res, _ := b.get(root); res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != want {
			t.Errorf("GET %s = %d to %q, want %s", root, res.StatusCode, res.Header.Get("Location"), want)
		}
	}
	if res, _ := b.get(issuer + "/account"); res.StatusCode != http.StatusSeeOther ||
		res.Header.Get("Location") != issuer+"/account/login" {
		t.Errorf("account page without a session = %d to %q, want the sign-in page", res.StatusCode,
			res.Header.Get("Location"))
	}
	if res, _ := b.get(issuer + "/unknown"); res.StatusCode != http.StatusNotFound {
		t.Errorf("GET /unknown = %d, want 404", res.StatusCode)
	}
}

func TestAccountSignIn(t *testing.T) {
	t.Parallel()
	const issuer = signupIssuer
	s, tn, _ := newResetServer(t)
	b := newBrowser(t, s.Handler())
	res, page := b.get(issuer + "/account/login")
	if res.StatusCode != http.StatusOK || !strings.Contains(page, "to manage your account") ||
		strings.Contains(page, `name="request"`) || !strings.Contains(page, `<a id="reset" href="`+issuer+`/reset">`) ||
		!strings.Contains(page, `<main class="card">`) {
		t.Fatalf("account sign-in page = %d:\n%s", res.StatusCode, page)
	}
	if _, page = b.post(issuer+"/account/login", url.Values{"email": {"ada@example.com"}, "password": {"wrong"}},
		"same-origin"); !strings.Contains(page, "The email or password is incorrect.") {
		t.Errorf("a wrong password:\n%s", page)
	}
	b.signInToAccount()
	res, page = b.get(issuer + "/account")
	if res.StatusCode != http.StatusOK || !strings.Contains(page, "<title>Your account</title>") ||
		!strings.Contains(page, "<strong>ada@example.com</strong>") ||
		!strings.Contains(page, `<a href="/account" aria-current="page">Profile</a>`) ||
		!strings.Contains(page, `<main class="card wide">`) || !strings.Contains(page, `<div class="field full">`) ||
		!strings.Contains(page, `<legend>Your name</legend>`) {
		t.Fatalf("account page = %d:\n%s", res.StatusCode, page)
	}
	if csp := res.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self';") {
		t.Errorf("Content-Security-Policy = %q, want forms to Clavis only", csp)
	}
	// The session is the one of single sign-on.
	if res, _ = b.get(issuer + "/oauth2/authorize?" + authorizeQuery().Encode()); !strings.HasPrefix(
		res.Header.Get("Location"), "https://app.example.com/callback?code=") {
		t.Errorf("authorize after the account sign-in = %d to %q, want single sign-on", res.StatusCode,
			res.Header.Get("Location"))
	}
	if res, _ = b.get(issuer + "/account/login"); res.Header.Get("Location") != issuer+"/account" {
		t.Errorf("sign-in page with a session = %d to %q, want the account page", res.StatusCode, res.Header.Get("Location"))
	}

	// Signing out ends the session.
	res, page = b.post(issuer+"/account/logout", url.Values{}, "same-origin")
	if res.StatusCode != http.StatusOK || !strings.Contains(page, "You are signed out.") {
		t.Errorf("sign-out = %d:\n%s", res.StatusCode, page)
	}
	if c := checkCookie(t, res, sessionCookieName(tn.ID)); c == nil || c.MaxAge >= 0 {
		t.Errorf("session cookie = %+v, want it removed", c)
	}
	if res, _ = b.get(issuer + "/account"); res.Header.Get("Location") != issuer+"/account/login" {
		t.Errorf("account page after signing out = %d to %q, want the sign-in page", res.StatusCode,
			res.Header.Get("Location"))
	}
}

func TestAccountProfile(t *testing.T) {
	t.Parallel()
	const issuer = signupIssuer
	s, tn := newLoginServer(t, issuer, "")
	b := newBrowser(t, s.Handler())
	b.signInToAccount()
	form := url.Values{
		"name":           {" Ada Lovelace "},
		"given_name":     {"Ada"},
		"birthdate":      {"1815-12-10"},
		"zoneinfo":       {"Europe/London"},
		"locale":         {"en_GB"},
		"phone_number":   {"+44 20 7946 0958"},
		"street_address": {"12 St James's Square\r\nFlat 3"},
		"website":        {"https://ada.example.com"},
	}
	res, page := b.post(issuer+"/account", form, "same-origin")
	if res.StatusCode != http.StatusOK || !strings.Contains(page, "Your profile has been saved.") ||
		!strings.Contains(page, `value="Ada Lovelace"`) || !strings.Contains(page, `value="en-GB"`) {
		t.Fatalf("saving the profile = %d:\n%s", res.StatusCode, page)
	}
	u, err := app.FindUser(t.Context(), s.deps, tn.ID, "ada@example.com")
	if err != nil || u.Profile.Name != "Ada Lovelace" || u.Profile.PhoneNumber != "+442079460958" ||
		u.Profile.Address.StreetAddress != "12 St James's Square\nFlat 3" || u.Profile.Website != "https://ada.example.com" {
		t.Errorf("stored profile = %+v, %v", u.Profile, err)
	}

	// An invalid profile is refused whole, with every problem explained.
	form.Set("name", "Countess")
	form.Set("website", "ftp://ada.example.com")
	form.Set("phone_number", "020 7946 0958")
	res, page = b.post(issuer+"/account", form, "same-origin")
	for _, want := range []string{"Website: enter a web address that starts with https:// or http://.",
		"Phone number: enter the number in international format", `value="ftp://ada.example.com"`} {
		if res.StatusCode != http.StatusOK || !strings.Contains(page, want) {
			t.Errorf("an invalid profile = %d, want %q:\n%s", res.StatusCode, want, page)
		}
	}
	if u, err := app.FindUser(t.Context(), s.deps, tn.ID, "ada@example.com"); err != nil || u.Profile.Name != "Ada Lovelace" {
		t.Errorf("stored profile after an invalid one = %+v, %v; want it unchanged", u.Profile, err)
	}
	// The page and its messages follow the user's language.
	if _, page = b.get(issuer + "/account?clavis_locale=es"); !strings.Contains(page, "<title>Tu cuenta</title>") ||
		!strings.Contains(page, "<legend>Teléfono y dirección</legend>") {
		t.Errorf("account page in Spanish:\n%s", page)
	}
}

// ADR 0028: the formatted address, which the profile form does not show,
// stays only while the other parts of the address do not change and it is
// valid.
func TestAccountProfileFormattedAddress(t *testing.T) {
	t.Parallel()
	s, tn := newLoginServer(t, signupIssuer, "")
	setAddress := func(a store.Address) {
		t.Helper()
		u, err := app.FindUser(t.Context(), s.deps, tn.ID, "ada@example.com")
		if err != nil {
			t.Fatalf("FindUser() unexpected error: %v", err)
		}
		u.Profile.Address = a
		if err := s.deps.Store.Users().Update(t.Context(), u); err != nil {
			t.Fatalf("Update() unexpected error: %v", err)
		}
	}
	formatted := func() string {
		t.Helper()
		u, err := app.FindUser(t.Context(), s.deps, tn.ID, "ada@example.com")
		if err != nil {
			t.Fatalf("FindUser() unexpected error: %v", err)
		}
		return u.Profile.Address.Formatted
	}
	b := newBrowser(t, s.Handler())
	b.signInToAccount()
	save := func(form url.Values) {
		t.Helper()
		if _, page := b.post(signupIssuer+"/account", form, "same-origin"); !strings.Contains(page,
			"Your profile has been saved.") {
			t.Fatalf("saving the profile:\n%s", page)
		}
	}
	london := store.Address{Formatted: "12 Old Street\nFlat 3\nLondon", StreetAddress: "12 Old Street\nFlat 3",
		Locality: "London"}

	// Browsers post the lines of a text area with CRLF.
	setAddress(london)
	save(url.Values{"name": {"Ada"}, "street_address": {"12 Old Street\r\nFlat 3"}, "locality": {"London"}})
	if got := formatted(); got != london.Formatted {
		t.Errorf("formatted address after a save that keeps the address = %q, want it kept", got)
	}
	save(url.Values{"street_address": {"3 Rue de Rivoli"}, "locality": {"Paris"}})
	if got := formatted(); got != "" {
		t.Errorf("formatted address after a new address = %q, want it dropped", got)
	}
	invalid := london
	invalid.Formatted = "12 Old Street\tLondon"
	setAddress(invalid)
	save(url.Values{"name": {"Ada"}, "street_address": {"12 Old Street\nFlat 3"}, "locality": {"London"}})
	if got := formatted(); got != "" {
		t.Errorf("formatted address that the rules refuse = %q, want it dropped", got)
	}
}

func TestAccountPassword(t *testing.T) {
	t.Parallel()
	const issuer = signupIssuer
	s, tn := newLoginServer(t, issuer, "")
	other := newBrowser(t, s.Handler())
	other.signInToAccount()
	b := newBrowser(t, s.Handler())
	b.signInToAccount()
	if _, page := b.get(issuer + "/account/password"); !strings.Contains(page, "<title>Change your password</title>") ||
		!strings.Contains(page, `autocomplete="current-password"`) {
		t.Errorf("password page:\n%s", page)
	}
	change := func(current, next string) (response, string) {
		t.Helper()
		return b.post(issuer+"/account/password", url.Values{"current_password": {current}, "new_password": {next}},
			"same-origin")
	}
	if _, page := change("wrong", "battery staple horse"); !strings.Contains(page, "The current password is incorrect.") {
		t.Errorf("a wrong current password:\n%s", page)
	}
	if _, page := change(testPassword, "short"); !strings.Contains(page, "The password must have 8 to 256 characters.") {
		t.Errorf("a short new password:\n%s", page)
	}
	if res, page := change(testPassword, "battery staple horse"); res.StatusCode != http.StatusOK ||
		!strings.Contains(page, "Your password has been changed, and your other sessions have been signed out.") {
		t.Fatalf("changing the password = %d:\n%s", res.StatusCode, page)
	}
	if _, err := app.AuthenticatePassword(t.Context(), s.deps, s.passwords, tn.ID, "ada@example.com",
		"battery staple horse"); err != nil {
		t.Errorf("signing in with the new password = %v", err)
	}
	if res, _ := b.get(issuer + "/account"); res.StatusCode != http.StatusOK {
		t.Errorf("account page in the browser that changed the password = %d, want 200", res.StatusCode)
	}
	if res, _ := other.get(issuer + "/account"); res.Header.Get("Location") != issuer+"/account/login" {
		t.Errorf("account page in another browser = %d to %q, want the sign-in page", res.StatusCode,
			res.Header.Get("Location"))
	}
}

func TestAccountApplications(t *testing.T) {
	t.Parallel()
	const issuer = signupIssuer
	s, tn := newLoginServer(t, issuer, "")
	if _, err := app.CreateAPIResource(t.Context(), s.deps, tn.ID, app.APIResourceSpec{
		Identifier: "https://orders.example.com", Name: "Orders", Scopes: []string{"orders:read"},
	}); err != nil {
		t.Fatalf("CreateAPIResource() unexpected error: %v", err)
	}
	if _, _, err := app.CreateClient(t.Context(), s.deps, tn.ID, app.ClientSpec{
		ClientID: "partner", Name: "Partner App", Type: store.ClientConfidential,
		RedirectURIs: []string{"https://partner.example.com/callback"},
		Scopes:       []string{"openid", "orders:read"},
	}); err != nil {
		t.Fatalf("CreateClient() unexpected error: %v", err)
	}
	b := newBrowser(t, s.Handler())
	b.signInToAccount()
	if _, page := b.get(issuer + "/account/applications"); !strings.Contains(page,
		"No application has access to your account.") {
		t.Errorf("applications page without grants:\n%s", page)
	}
	// Allow the partner client, which asks for consent.
	query := authorizeQuery()
	query.Set("client_id", "partner")
	query.Set("redirect_uri", "https://partner.example.com/callback")
	query.Set("scope", "openid orders:read")
	res, _ := b.get(issuer + "/oauth2/authorize?" + query.Encode())
	consent, err := url.Parse(res.Header.Get("Location"))
	if err != nil || consent.Path != "/consent" {
		t.Fatalf("authorize = %d to %q, want the consent page", res.StatusCode, res.Header.Get("Location"))
	}
	if res, _ = b.post(issuer+"/consent", url.Values{"request": {consent.Query().Get("request")}, "decision": {"allow"}},
		"same-origin"); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("consent = %d", res.StatusCode)
	}

	res, page := b.get(issuer + "/account/applications")
	// Each scope reads as on the consent page, which names the API it
	// belongs to.
	if res.StatusCode != http.StatusOK || !strings.Contains(page, "<strong>Partner App</strong>") ||
		!strings.Contains(page, "Know who you are") || !strings.Contains(page, "<li>Use Orders (orders:read)</li>") ||
		!strings.Contains(page, `name="client_id" value="partner"`) {
		t.Fatalf("applications page = %d:\n%s", res.StatusCode, page)
	}
	res, page = b.post(issuer+"/account/applications", url.Values{"client_id": {"partner"}}, "same-origin")
	if res.StatusCode != http.StatusOK || !strings.Contains(page, "Partner App no longer has access to your account.") ||
		!strings.Contains(page, "No application has access to your account.") {
		t.Errorf("removing the access = %d:\n%s", res.StatusCode, page)
	}
	if grants, err := app.ListGrants(t.Context(), s.deps, tn.ID, "ada@example.com"); err != nil || len(grants) != 0 {
		t.Errorf("grants after the removal = %+v, %v; want none", grants, err)
	}
	// Removing an application without access changes nothing.
	if res, page = b.post(issuer+"/account/applications", url.Values{"client_id": {"partner"}}, "same-origin"); res.StatusCode != http.StatusOK ||
		strings.Contains(page, "no longer has access") {
		t.Errorf("removing it again = %d:\n%s", res.StatusCode, page)
	}
}

func TestAccountRejectsCrossOriginPostsAndBrowsersWithoutASession(t *testing.T) {
	t.Parallel()
	const issuer = signupIssuer
	s, _ := newLoginServer(t, issuer, "")
	b := newBrowser(t, s.Handler())
	b.signInToAccount()
	stranger := newBrowser(t, s.Handler())
	for _, path := range []string{"/account", "/account/login", "/account/logout", "/account/password", "/account/applications"} {
		if res, _ := b.post(issuer+path, url.Values{"name": {"Mallory"}, "email": {"ada@example.com"}},
			"cross-site"); res.StatusCode != http.StatusForbidden {
			t.Errorf("cross-site POST %s = %d, want 403", path, res.StatusCode)
		}
		if path == "/account/login" {
			continue
		}
		if res, _ := stranger.post(issuer+path, url.Values{"name": {"Mallory"}}, "same-origin"); res.StatusCode != http.StatusSeeOther ||
			res.Header.Get("Location") != issuer+"/account/login" {
			t.Errorf("POST %s without a session = %d to %q, want the sign-in page", path, res.StatusCode,
				res.Header.Get("Location"))
		}
	}
	if _, page := b.get(issuer + "/account"); strings.Contains(page, "Mallory") {
		t.Error("a cross-site POST changed the profile")
	}
}

// The account pages reset a password without an authorization request
// (ADR 0028), and send the user back to their sign-in page.
func TestAccountPasswordReset(t *testing.T) {
	t.Parallel()
	const issuer = signupIssuer
	s, tn, mail := newResetServer(t)
	b := newBrowser(t, s.Handler())
	if res, page := b.get(issuer + "/reset"); res.StatusCode != http.StatusOK || strings.Contains(page, `name="request"`) ||
		!strings.Contains(page, `<a id="login" href="`+issuer+`/account/login">`) {
		t.Fatalf("reset page of the account pages = %d:\n%s", res.StatusCode, page)
	}
	res, _ := b.post(issuer+"/reset", url.Values{"email": {"ada@example.com"}}, "same-origin")
	loc, err := url.Parse(res.Header.Get("Location"))
	if res.StatusCode != http.StatusSeeOther || err != nil || loc.Path != "/reset/verify" {
		t.Fatalf("reset = %d to %q, want the code page", res.StatusCode, res.Header.Get("Location"))
	}
	checkCookie(t, res, bindingCookie)
	verification := loc.Query().Get("verification")
	msg := mail.last(t, "ada@example.com")
	if !strings.Contains(msg.Text, "the password of your account.") {
		t.Errorf("message = %+v, want one that names no application", msg)
	}
	code := signupCode.FindStringSubmatch(msg.Text)
	if res, _ = b.post(issuer+"/reset/verify", url.Values{"verification": {verification}, "code": {code[1]}},
		"same-origin"); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("code = %d, want a redirect to the password page", res.StatusCode)
	}
	res, page := b.post(issuer+"/reset/password", url.Values{"verification": {verification},
		"password": {"battery staple horse"}}, "same-origin")
	if res.StatusCode != http.StatusOK || !strings.Contains(page, "to manage your account") ||
		!strings.Contains(page, "Your password has been changed. Sign in with the new one.") ||
		!strings.Contains(page, `value="ada@example.com"`) {
		t.Fatalf("after the new password = %d:\n%s", res.StatusCode, page)
	}
	if _, err := app.AuthenticatePassword(t.Context(), s.deps, s.passwords, tn.ID, "ada@example.com",
		"battery staple horse"); err != nil {
		t.Errorf("signing in with the new password = %v", err)
	}
}
