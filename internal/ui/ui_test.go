package ui

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"clavisid.org/clavis/internal/i18n"
	"clavisid.org/clavis/store"
)

// testLayout returns the layout of a page in locale l.
func testLayout(t testing.TB, l i18n.Locale) Layout {
	t.Helper()
	catalogs, err := i18n.Load()
	if err != nil {
		t.Fatalf("i18n.Load() unexpected error: %v", err)
	}
	return Layout{Stylesheet: "/assets/clavis-0123456789ab.css", Text: catalogs.Printer(l)}
}

func TestAssets(t *testing.T) {
	t.Parallel()
	a, err := NewAssets()
	if err != nil {
		t.Fatalf("NewAssets() unexpected error: %v", err)
	}
	if !regexp.MustCompile(`^clavis-[0-9a-f]{12}\.css$`).MatchString(a.Stylesheet()) {
		t.Fatalf("Stylesheet() = %q, want a name with a content hash", a.Stylesheet())
	}

	rec := httptest.NewRecorder()
	a.ServeAsset(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody), a.Stylesheet())
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "--clavis-accent") {
		t.Fatalf("ServeAsset() = %d, %q", rec.Code, rec.Body.String())
	}
	for name, want := range map[string]string{
		"Content-Type":           "text/css; charset=utf-8",
		"Cache-Control":          "public, max-age=31536000, immutable",
		"X-Content-Type-Options": "nosniff",
	} {
		if got := rec.Header().Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}

	for _, name := range []string{"clavis.css", "missing.css", "", "../ui.go"} {
		rec := httptest.NewRecorder()
		a.ServeAsset(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody), name)
		if rec.Code != http.StatusNotFound {
			t.Errorf("ServeAsset(%q) = %d, want 404", name, rec.Code)
		}
	}
}

func TestContentSecurityPolicy(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		allowSelf bool
		targets   []string
		want      string
	}{
		{false, nil, "form-action 'none';"},
		{true, nil, "form-action 'self';"},
		{true, []string{"https://app.example.com"}, "form-action 'self' https://app.example.com;"},
	} {
		got := Layout{}.ContentSecurityPolicy(tt.allowSelf, tt.targets...)
		if !strings.Contains(got, tt.want) {
			t.Errorf("ContentSecurityPolicy(%v, %q) = %q, want it to contain %q", tt.allowSelf, tt.targets, got, tt.want)
		}
		for _, directive := range []string{"default-src 'none'", "frame-ancestors 'none'", "base-uri 'none'"} {
			if !strings.Contains(got, directive) {
				t.Errorf("ContentSecurityPolicy() = %q, want %q", got, directive)
			}
		}
	}
}

func TestFormTarget(t *testing.T) {
	t.Parallel()
	for uri, want := range map[string]string{
		"https://app.example.com/callback?x=1":      "https://app.example.com",
		"https://app.example.com:8443/callback":     "https://app.example.com:8443",
		"http://127.0.0.1:51004/callback":           "http://127.0.0.1:51004",
		"http://localhost/callback":                 "http://localhost",
		"http://[::1]:8080/callback":                "http:",
		"com.example.app:/oauth2redirect":           "com.example.app:",
		"https://app.example.com;script-src:443/cb": "https:",
		"https://APP.example.com/cb":                "https:",
		"https://app.example.com:/cb":               "https:",
		"https://a'b.example.com/cb":                "https:",
		"not a uri":                                 "",
		"1http://example.com/":                      "",
		"":                                          "",
	} {
		if got := FormTarget(uri); got != want {
			t.Errorf("FormTarget(%q) = %q, want %q", uri, got, want)
		}
	}
}

func TestSetPageHeaders(t *testing.T) {
	t.Parallel()
	h := http.Header{}
	SetPageHeaders(h, "default-src 'none'")
	for name, want := range map[string]string{
		"Content-Type":            "text/html; charset=utf-8",
		"Cache-Control":           "no-store",
		"Content-Security-Policy": "default-src 'none'",
		"X-Frame-Options":         "DENY",
		"X-Content-Type-Options":  "nosniff",
		"Referrer-Policy":         "no-referrer",
	} {
		if got := h.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

func TestLoginEscapesItsInput(t *testing.T) {
	t.Parallel()
	var b bytes.Buffer
	err := Login(LoginPage{
		Layout:     testLayout(t, i18n.English),
		ClientName: `<script>alert(1)</script>`,
		Action:     "/login",
		RequestID:  `"><img src=x>`,
		Email:      `ada@example.com" onfocus="x`,
		Error:      "The email or password is incorrect.",
	}).Render(t.Context(), &b)
	if err != nil {
		t.Fatalf("Render() unexpected error: %v", err)
	}
	page := b.String()
	for _, unsafe := range []string{"<script>", "<img", `" onfocus="`} {
		if strings.Contains(page, unsafe) {
			t.Errorf("the page contains %q unescaped:\n%s", unsafe, page)
		}
	}
	for _, want := range []string{
		`<html lang="en">`, `href="/assets/clavis-0123456789ab.css"`, `action="/login"`,
		`id="email"`, `id="password"`, `id="submit"`, `autocomplete="current-password"`,
		`role="alert"`, "The email or password is incorrect.",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the page does not contain %q:\n%s", want, page)
		}
	}
}

func TestError(t *testing.T) {
	t.Parallel()
	var b bytes.Buffer
	err := Error(ErrorPage{Layout: testLayout(t, i18n.English), Title: "Request expired",
		Message: "Return to <the application>."}).Render(t.Context(), &b)
	if err != nil {
		t.Fatalf("Render() unexpected error: %v", err)
	}
	if page := b.String(); !strings.Contains(page, "<title>Request expired</title>") ||
		!strings.Contains(page, "Return to &lt;the application&gt;.") || strings.Contains(page, "<form") {
		t.Errorf("Error() rendered:\n%s", page)
	}
}

func TestConsentEscapesItsInput(t *testing.T) {
	t.Parallel()
	english := testLayout(t, i18n.English).Text
	var b bytes.Buffer
	err := Consent(ConsentPage{
		Layout:     testLayout(t, i18n.English),
		ClientName: `<script>alert(1)</script>`,
		Account:    `ada@example.com<img src=x>`,
		Scopes: []string{ScopeDescription(english, "openid", ""),
			ScopeDescription(english, "orders:read", `<b>Orders</b>`)},
		Action:    "/consent",
		RequestID: `"><img src=x>`,
	}).Render(t.Context(), &b)
	if err != nil {
		t.Fatalf("Render() unexpected error: %v", err)
	}
	page := b.String()
	for _, unsafe := range []string{"<script>", "<img", "<b>"} {
		if strings.Contains(page, unsafe) {
			t.Errorf("the page contains %q unescaped:\n%s", unsafe, page)
		}
	}
	for _, want := range []string{
		`<title>Allow access</title>`, `action="/consent"`, `id="allow"`, `id="deny"`, `name="decision"`,
		"<li>Know who you are</li>", "orders:read",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the page does not contain %q:\n%s", want, page)
		}
	}
}

func TestFormPostEscapesItsInputAndRunsOnlyItsScript(t *testing.T) {
	t.Parallel()
	var b bytes.Buffer
	err := FormPost(FormPostPage{
		Layout: testLayout(t, i18n.English),
		Action: "https://app.example.com/callback?x=1&y=2",
		Fields: []Field{{"code", "abc"}, {"state", `"><script>alert(1)</script>`}},
	}).Render(t.Context(), &b)
	if err != nil {
		t.Fatalf("Render() unexpected error: %v", err)
	}
	page := b.String()
	if strings.Count(page, "<script>") != 1 || strings.Contains(page, "alert(1)</script>") {
		t.Errorf("the page has a script besides its own, or input unescaped:\n%s", page)
	}
	for _, want := range []string{
		`<form id="response" method="post" action="https://app.example.com/callback?x=1&amp;y=2">`,
		`<input type="hidden" name="code" value="abc">`, `name="state"`, `id="continue"`,
		"<script>" + formPostScript + "</script>",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the page does not contain %q:\n%s", want, page)
		}
	}

	// The policy allows the page's script by its hash, and the form only to
	// the client.
	sum := sha256.Sum256([]byte(formPostScript))
	policy := Layout{}.FormPostContentSecurityPolicy("https://app.example.com")
	for _, want := range []string{
		"script-src 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "';",
		"form-action https://app.example.com;", "default-src 'none'", "frame-ancestors 'none'",
	} {
		if !strings.Contains(policy, want) {
			t.Errorf("FormPostContentSecurityPolicy() = %q, want %q", policy, want)
		}
	}
	if policy := (Layout{}).FormPostContentSecurityPolicy(""); !strings.Contains(policy, "form-action 'none';") {
		t.Errorf("FormPostContentSecurityPolicy(\"\") = %q, want no form target", policy)
	}
	if strings.Contains(Layout{}.ContentSecurityPolicy(true), "script-src") {
		t.Error("ContentSecurityPolicy() allows scripts")
	}
}

func TestLogoutPagesEscapeTheirInput(t *testing.T) {
	t.Parallel()
	var b bytes.Buffer
	err := Logout(LogoutPage{
		Layout:     testLayout(t, i18n.English),
		Account:    `ada@example.com<img src=x>`,
		ClientName: `<script>alert(1)</script>`,
		Problem:    "post_logout_redirect_uri <b>needs</b> an id_token_hint",
		Action:     "/logout",
		Fields:     []Field{{"state", `"><img src=x>`}},
	}).Render(t.Context(), &b)
	if err != nil {
		t.Fatalf("Render() unexpected error: %v", err)
	}
	page := b.String()
	for _, unsafe := range []string{"<script>", "<img", "<b>"} {
		if strings.Contains(page, unsafe) {
			t.Errorf("the page contains %q unescaped:\n%s", unsafe, page)
		}
	}
	for _, want := range []string{
		"<title>Sign out</title>", `action="/logout"`, `id="logout"`, `name="state"`, `role="alert"`,
		"cannot be completed as sent", "To stay signed in, close this page.",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the page does not contain %q:\n%s", want, page)
		}
	}

	b.Reset()
	if err := SignedOut(SignedOutPage{Layout: testLayout(t, i18n.English)}).Render(t.Context(), &b); err != nil {
		t.Fatalf("Render() unexpected error: %v", err)
	}
	if page := b.String(); !strings.Contains(page, "<title>You are signed out</title>") ||
		strings.Contains(page, "<form") || strings.Contains(page, `role="alert"`) {
		t.Errorf("SignedOut() rendered:\n%s", page)
	}
}

func TestScopeDescription(t *testing.T) {
	t.Parallel()
	english, spanish := testLayout(t, i18n.English).Text, testLayout(t, i18n.Spanish).Text
	if got := ScopeDescription(spanish, "email", ""); got != "Ver tu dirección de correo electrónico" {
		t.Errorf("ScopeDescription() in Spanish = %q", got)
	}
	for _, tt := range []struct{ scope, resource, want string }{
		{"openid", "", "Know who you are"},
		{"profile", "", "See your name and profile"},
		{"email", "", "See your email address"},
		{"address", "", "See your postal address"},
		{"phone", "", "See your phone number"},
		{"offline_access", "", "Keep access while you are signed out"},
		{"orders:read", "Orders", "Use Orders (orders:read)"},
		{"unknown", "", "unknown"},
	} {
		if got := ScopeDescription(english, tt.scope, tt.resource); got != tt.want {
			t.Errorf("ScopeDescription(%q, %q) = %q, want %q", tt.scope, tt.resource, got, tt.want)
		}
	}
}

func TestThemeStyle(t *testing.T) {
	t.Parallel()
	if got := ThemeStyle(store.Theme{}); got != "" {
		t.Errorf("ThemeStyle() of the default theme = %q, want empty", got)
	}
	radius, tooLarge := 6, 65
	got := ThemeStyle(store.Theme{
		Light:  store.ThemeColors{Accent: "#0b5cad", AccentText: "#FFFFFF", Text: "red;}body{display:none"},
		Dark:   store.ThemeColors{Background: "#0d1117", Border: "#30363d}"},
		Radius: &radius,
	})
	want := ":root{--clavis-radius:6px}" +
		"@media not all and (prefers-color-scheme: dark){:root{--clavis-accent:#0b5cad;--clavis-accent-text:#FFFFFF;}}" +
		"@media (prefers-color-scheme: dark){:root{--clavis-background:#0d1117;}}"
	if got != want {
		t.Errorf("ThemeStyle() =\n%s\nwant\n%s", got, want)
	}
	if got := ThemeStyle(store.Theme{Radius: &tooLarge}); got != "" {
		t.Errorf("ThemeStyle() with a radius out of bounds = %q, want empty", got)
	}
}

// A page with a tenant theme allows exactly its style element, and shows
// the tenant's logo.
func TestBrandedPage(t *testing.T) {
	t.Parallel()
	l := testLayout(t, i18n.English)
	l.Theme = ThemeStyle(store.Theme{Light: store.ThemeColors{Accent: "#0b5cad"}})
	l.LogoURL, l.TenantName = "/t/acme/branding/logo-0123456789ab.png", `Acme "Corp"`
	var b bytes.Buffer
	if err := SignedOut(SignedOutPage{Layout: l}).Render(t.Context(), &b); err != nil {
		t.Fatalf("Render() unexpected error: %v", err)
	}
	page := b.String()
	for _, want := range []string{
		"<style>" + l.Theme + "</style>",
		`<img class="logo" src="/t/acme/branding/logo-0123456789ab.png" alt="Acme &#34;Corp&#34;">`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the page does not contain %q:\n%s", want, page)
		}
	}
	sum := sha256.Sum256([]byte(l.Theme))
	hash := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	if csp := l.ContentSecurityPolicy(false); !strings.Contains(csp, "style-src 'self' "+hash+";") {
		t.Errorf("ContentSecurityPolicy() = %q, want the theme's hash in style-src", csp)
	}
	if csp := l.FormPostContentSecurityPolicy(""); !strings.Contains(csp, "style-src 'self' "+hash+";") {
		t.Errorf("FormPostContentSecurityPolicy() = %q, want the theme's hash in style-src", csp)
	}
	if csp := (Layout{}).ContentSecurityPolicy(false); !strings.Contains(csp, "style-src 'self';") {
		t.Errorf("ContentSecurityPolicy() without a theme = %q, want only the page's origin in style-src", csp)
	}
}

func TestLanguageSelector(t *testing.T) {
	t.Parallel()
	l := testLayout(t, i18n.Spanish)
	l.Languages = &LanguageSelector{Method: http.MethodGet, Action: "/login", Fields: []Field{{"request", `"><x`}}}
	var b bytes.Buffer
	if err := Error(ErrorPage{Layout: l, Title: "t", Message: "m"}).Render(t.Context(), &b); err != nil {
		t.Fatalf("Render() unexpected error: %v", err)
	}
	page := b.String()
	for _, want := range []string{
		`<html lang="es">`,
		`<nav class="languages" aria-label="Idioma"><form method="GET" action="/login">`,
		`<input type="hidden" name="request" value="&#34;&gt;&lt;x">`,
		`<button type="submit" class="link" name="clavis_locale" value="en" lang="en">English</button>`,
		`<button type="submit" class="link" lang="es" disabled aria-current="true">Español</button>`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the page does not contain %q:\n%s", want, page)
		}
	}

	b.Reset()
	l.Languages = nil
	if err := Error(ErrorPage{Layout: l, Title: "t", Message: "m"}).Render(t.Context(), &b); err != nil {
		t.Fatalf("Render() unexpected error: %v", err)
	}
	if strings.Contains(b.String(), "languages") {
		t.Errorf("a page without a selector shows one:\n%s", b.String())
	}
}

// Every page renders in every locale without a key or a placeholder in
// place of a message.
func TestEveryPageInEveryLocale(t *testing.T) {
	t.Parallel()
	for _, locale := range i18n.Supported() {
		l := testLayout(t, locale)
		l.Languages = &LanguageSelector{Method: http.MethodGet, Action: "/login"}
		for name, page := range map[string]interface {
			Render(context.Context, io.Writer) error
		}{
			"login": Login(LoginPage{Layout: l, ClientName: "Shop", Action: "/login", RequestID: "r",
				Error: l.T(i18n.LoginInvalidCredentials), SignupURL: "/signup?request=r", ResetURL: "/reset?request=r"}),
			"login after a reset": Login(LoginPage{Layout: l, ClientName: "Shop", Action: "/login", RequestID: "r",
				Email: "ada@example.com", Notice: l.T(i18n.LoginPasswordChanged)}),
			"reset": Reset(ResetPage{Layout: l, Action: "/reset", RequestID: "r", Error: l.T(i18n.SignupInvalidEmail),
				LoginURL: "/login?request=r"}),
			"reset code": Verify(VerifyPage{Layout: l, Reset: true, Email: "ada@example.com", Action: "/reset/verify",
				VerificationID: "v", Error: l.T(i18n.VerifyWrongCode), RestartURL: "/reset?request=r"}),
			"reset link": Verify(VerifyPage{Layout: l, Reset: true, Email: "ada@example.com", Action: "/reset/verify",
				VerificationID: "v", Token: "t"}),
			"new password": Password(PasswordPage{Layout: l, Reset: true, Email: "ada@example.com",
				Action: "/reset/password", VerificationID: "v", MinLength: 8, MaxLength: 256}),
			"password changed": PasswordChanged(PasswordChangedPage{Layout: l}),
			"account login": Login(LoginPage{Layout: l, Action: "/account/login", Notice: l.T(i18n.AccountSignedOut),
				ResetURL: "/reset"}),
			"account": Account(AccountPage{Layout: l, Nav: AccountNav{ProfileURL: "/account", PasswordURL: "/account/password", ApplicationsURL: "/account/applications", LogoutURL: "/account/logout", Current: "/account"},
				Email: "ada@example.com", Action: "/account", Notice: l.T(i18n.AccountProfileSaved),
				Errors: []string{l.T(i18n.AccountInvalidURL, "field", l.T(i18n.ProfileWebsite))},
				Sections: []ProfileSection{{Title: l.T(i18n.AccountSectionName), Fields: []ProfileField{
					{Name: "name", Label: l.T(i18n.ProfileName), Value: "Ada", Type: "text", Autocomplete: "name"},
					{Name: "birthdate", Label: l.T(i18n.ProfileBirthdate), Hint: l.T(i18n.ProfileBirthdateHint), Type: "text"},
					{Name: "street_address", Label: l.T(i18n.ProfileStreetAddress), Value: "12 Square\nFlat 3", Lines: true},
				}}}}),
			"account password": AccountPassword(AccountPasswordPage{Layout: l, Nav: AccountNav{ProfileURL: "/account", PasswordURL: "/account/password", ApplicationsURL: "/account/applications", LogoutURL: "/account/logout", Current: "/account"},
				Email: "ada@example.com", Action: "/account/password", MinLength: 8, MaxLength: 256,
				Errors: []string{l.T(i18n.AccountWrongPassword)}}),
			"applications": AccountApplications(AccountApplicationsPage{Layout: l, Nav: AccountNav{ProfileURL: "/account", PasswordURL: "/account/password", ApplicationsURL: "/account/applications", LogoutURL: "/account/logout", Current: "/account"},
				Action: "/account/applications", Notice: l.T(i18n.AccountApplicationRemoved, "client", "Shop"),
				Applications: []AccountApplication{{Name: "Shop", ClientID: "shop",
					Scopes: []string{ScopeDescription(l.Text, "email", "")}}}}),
			"no applications": AccountApplications(AccountApplicationsPage{Layout: l, Nav: AccountNav{ProfileURL: "/account", PasswordURL: "/account/password", ApplicationsURL: "/account/applications", LogoutURL: "/account/logout", Current: "/account"},
				Action: "/account/applications"}),
			"signup": Signup(SignupPage{Layout: l, ClientName: "Shop", Action: "/signup", RequestID: "r",
				Error: l.T(i18n.SignupInvalidEmail), LoginURL: "/login?request=r"}),
			"code": Verify(VerifyPage{Layout: l, Email: "grace@example.com", Action: "/signup/verify",
				VerificationID: "v", Error: l.T(i18n.VerifyWrongCode), RestartURL: "/signup?request=r"}),
			"link": Verify(VerifyPage{Layout: l, Email: "grace@example.com", Action: "/signup/verify",
				VerificationID: "v", Token: "t"}),
			"password": Password(PasswordPage{Layout: l, Email: "grace@example.com", Action: "/signup/password",
				VerificationID: "v", MinLength: 8, MaxLength: 256, Error: l.T(i18n.PasswordPolicy, "min", "8", "max", "256")}),
			"signed up": SignedUp(SignedUpPage{Layout: l}),
			"consent": Consent(ConsentPage{Layout: l, ClientName: "Shop", Account: "ada@example.com",
				Scopes: []string{ScopeDescription(l.Text, "openid", ""), ScopeDescription(l.Text, "orders:read", "Orders")},
				Action: "/consent", RequestID: "r"}),
			"form post": FormPost(FormPostPage{Layout: l, Action: "https://app.example.com/cb"}),
			"logout": Logout(LogoutPage{Layout: l, Account: "ada@example.com", ClientName: "Shop",
				Problem: "state is repeated", Action: "/logout"}),
			"signed out": SignedOut(SignedOutPage{Layout: l, Problem: "state is repeated"}),
			"error": Error(ErrorPage{Layout: l, Title: l.T(i18n.ErrorExpiredSignInTitle),
				Message: l.T(i18n.ErrorRejectedSignIn, "problem", "redirect_uri is not registered")}),
		} {
			var b bytes.Buffer
			if err := page.Render(t.Context(), &b); err != nil {
				t.Fatalf("%s, %s: Render() unexpected error: %v", locale, name, err)
			}
			text := b.String()
			if !strings.Contains(text, `<html lang="`+string(locale)+`">`) {
				t.Errorf("%s, %s: the page is not marked as %s", locale, name, locale)
			}
			// Only the form post script holds braces, and its page has none.
			if i := strings.IndexAny(text, "{}"); i >= 0 {
				t.Errorf("%s, %s: a placeholder is left at %q", locale, name, text[max(0, i-20):min(len(text), i+20)])
			}
			if key := regexp.MustCompile(`\b[a-z_]+\.[a-z_]+(\.[a-z_]+)?\b`).FindString(
				regexp.MustCompile(`"[^"]*"`).ReplaceAllString(text, `""`)); key != "" &&
				!strings.Contains(key, "example.com") {
				t.Errorf("%s, %s: a key is shown instead of its message: %q", locale, name, key)
			}
		}
	}
}
