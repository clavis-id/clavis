package clavis

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"image"
	"image/png"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"

	"clavisid.org/clavis/internal/app"
	"clavisid.org/clavis/store"
)

// getIn sends a GET request with an Accept-Language header.
func (b *browser) getIn(target, acceptLanguage string) (res response, body string) {
	b.t.Helper()
	req := httptest.NewRequestWithContext(b.t.Context(), http.MethodGet, target, http.NoBody)
	req.Header.Set("Accept-Language", acceptLanguage)
	return b.send(req)
}

// ADR 0025: a page is in the language the user picked with the selector,
// then in the request's ui_locales, then in the browser's language.
func TestHostedPagesFollowTheUsersLanguage(t *testing.T) {
	t.Parallel()
	const issuer = "https://auth.example.com"
	s, _ := newLoginServer(t, issuer, "")
	b := newBrowser(t, s.Handler())

	query := authorizeQuery()
	query.Set("ui_locales", "es-419 en")
	id := b.startLogin(issuer, query)
	login := issuer + "/login?request=" + id
	res, page := b.getIn(login, "en-US,en;q=0.9")
	for _, want := range []string{`<html lang="es">`, "<title>Iniciar sesión</title>", "para continuar en",
		`<nav class="languages" aria-label="Idioma"><form method="GET" action="/login">`,
		`<input type="hidden" name="request" value="` + id + `">`,
		`name="clavis_locale" value="en" lang="en">English</button>`} {
		if res.StatusCode != http.StatusOK || !strings.Contains(page, want) {
			t.Errorf("login page with ui_locales = %d, want %q:\n%s", res.StatusCode, want, page)
		}
	}

	// The selector's choice applies at once and is remembered.
	res, page = b.getIn(login+"&clavis_locale=en", "es")
	if !strings.Contains(page, `<html lang="en">`) || !strings.Contains(page, "<title>Sign in</title>") {
		t.Errorf("login page after choosing English:\n%s", page)
	}
	if c := checkCookie(t, res, localeCookie); c == nil || c.Value != "en" || c.MaxAge != localeCookieMaxAge {
		t.Errorf("locale cookie = %+v, want en for a year", c)
	}
	if res, page = b.post(issuer+"/login", loginForm(id, "wrong password"), "same-origin"); res.StatusCode != http.StatusOK ||
		!strings.Contains(page, "The email or password is incorrect.") {
		t.Errorf("failed sign-in = %d, want the English message:\n%s", res.StatusCode, page)
	}
	if res, _ = b.getIn(login+"&clavis_locale=fr", "es"); len(res.Cookies()) != 0 {
		t.Errorf("an unsupported choice set cookies %v", res.Cookies())
	}

	// Without a choice or ui_locales, the browser's language applies, also to
	// error pages.
	other := newBrowser(t, s.Handler())
	id = other.startLogin(issuer, authorizeQuery())
	if _, page = other.getIn(issuer+"/login?request="+id, "de-DE, es;q=0.5"); !strings.Contains(page, `<html lang="es">`) {
		t.Errorf("login page with Accept-Language es:\n%s", page)
	}
	if _, page = other.getIn(issuer+"/login?request=unknown", "es"); !strings.Contains(page,
		"<title>La solicitud de inicio de sesión ya no es válida</title>") {
		t.Errorf("error page with Accept-Language es:\n%s", page)
	}
	if _, page = other.getIn(issuer+"/login?request="+id, ""); !strings.Contains(page, `<html lang="en">`) {
		t.Errorf("login page without preferences:\n%s", page)
	}
}

// A language chosen in a request from another site applies to its page but
// is not remembered, so a link or a form elsewhere cannot change the
// language of the browser's later pages.
func TestLocaleChoiceFromAnotherSite(t *testing.T) {
	t.Parallel()
	const issuer = "https://auth.example.com"
	s, _ := newLoginServer(t, issuer, "")
	remembers := func(res response) bool {
		return slices.ContainsFunc(res.Cookies(), func(c *http.Cookie) bool { return c.Name == localeCookie })
	}

	b := newBrowser(t, s.Handler())
	id := b.startLogin(issuer, authorizeQuery())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		issuer+"/login?request="+id+"&clavis_locale=es", http.NoBody)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	if res, page := b.send(req); !strings.Contains(page, `<html lang="es">`) || remembers(res) {
		t.Errorf("login page linked from another site with a choice: remembered %v, page:\n%s", remembers(res), page)
	}

	// The end session endpoint shows its confirmation to a POST without the
	// session cookie, so any site can send one.
	for _, tc := range []struct {
		name, site, origin string
		remembered         bool
	}{
		{name: "same origin", site: "same-origin", remembered: true},
		{name: "typed by the user", site: "none", remembered: true},
		{name: "same site", site: "same-site"},
		{name: "cross site", site: "cross-site"},
		{name: "old browser, same origin", origin: issuer, remembered: true},
		{name: "old browser, other origin", origin: "https://evil.example"},
		{name: "not a browser", remembered: true},
	} {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, issuer+"/oauth2/logout",
			strings.NewReader("clavis_locale=es"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if tc.site != "" {
			req.Header.Set("Sec-Fetch-Site", tc.site)
		}
		if tc.origin != "" {
			req.Header.Set("Origin", tc.origin)
		}
		res, page := newBrowser(t, s.Handler()).send(req)
		if !strings.Contains(page, "<title>Cerrar sesión</title>") || remembers(res) != tc.remembered {
			t.Errorf("%s: remembered %v, want %v; page:\n%s", tc.name, remembers(res), tc.remembered, page)
		}
	}
}

func TestLogoutPageLanguage(t *testing.T) {
	t.Parallel()
	const issuer = "https://id.example.com"
	s, tn := newLoginServer(t, issuer, "")
	b := newBrowser(t, s.Handler())
	idToken := signInForLogout(t, s, tn, b, issuer)

	query := url.Values{"id_token_hint": {idToken}, "post_logout_redirect_uri": {"https://app.example.com/signed-out"},
		"ui_locales": {"es"}}
	_, page := b.get(issuer + "/oauth2/logout?" + query.Encode())
	if !strings.Contains(page, "<title>Cerrar sesión</title>") ||
		!strings.Contains(page, `<form method="POST" action="/oauth2/logout">`) {
		t.Fatalf("logout page with ui_locales:\n%s", page)
	}
	if fields := hiddenFields(page); fields.Get("ui_locales") != "es" || fields.Get("id_token_hint") != idToken {
		t.Errorf("the confirmation carries %v, want the request and its ui_locales", fields)
	}

	// The selector sends the logout request again with the choice.
	form := url.Values{"clavis_locale": {"en"}}
	for name, values := range query {
		form[name] = values
	}
	res, page := b.post(issuer+"/oauth2/logout", form, "same-origin")
	if res.StatusCode != http.StatusOK || !strings.Contains(page, "<title>Sign out</title>") {
		t.Fatalf("logout page after choosing English = %d:\n%s", res.StatusCode, page)
	}
	res, _ = b.post(issuer+"/logout", hiddenFields(page), "same-origin")
	if res.StatusCode != http.StatusSeeOther {
		t.Errorf("confirmation = %d, want the redirect to the client", res.StatusCode)
	}
	if _, page = b.get(issuer + "/oauth2/logout?ui_locales=es"); !strings.Contains(page, "<title>You are signed out</title>") {
		t.Errorf("signed-out page after choosing English:\n%s", page)
	}
}

func TestBrandedPages(t *testing.T) {
	t.Parallel()
	const issuer = "https://auth.example.com"
	s, tn := newLoginServer(t, issuer, "acme")
	b := newBrowser(t, s.Handler())
	radius := 4
	if err := app.SetTheme(t.Context(), s.deps, tn.ID, store.Theme{Light: store.ThemeColors{Accent: "#0b5cad"},
		Radius: &radius}); err != nil {
		t.Fatalf("SetTheme() unexpected error: %v", err)
	}
	var data bytes.Buffer
	if err := png.Encode(&data, image.NewRGBA(image.Rect(0, 0, 40, 20))); err != nil {
		t.Fatalf("encoding the logo: %v", err)
	}
	logo, err := app.SetLogo(t.Context(), s.deps, tn.ID, data.Bytes())
	if err != nil {
		t.Fatalf("SetLogo() unexpected error: %v", err)
	}

	tenantIssuer := issuer + "/t/acme"
	id := b.startLogin(tenantIssuer, authorizeQuery())
	res, page := b.get(tenantIssuer + "/login?request=" + id)
	style := regexp.MustCompile(`<style>([^<]*)</style>`).FindStringSubmatch(page)
	if res.StatusCode != http.StatusOK || style == nil || !strings.Contains(style[1], "--clavis-accent:#0b5cad;") {
		t.Fatalf("branded login page = %d:\n%s", res.StatusCode, page)
	}
	sum := sha256.Sum256([]byte(style[1]))
	if csp := res.Header.Get("Content-Security-Policy"); !strings.Contains(csp,
		"style-src 'self' 'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"';") {
		t.Errorf("Content-Security-Policy = %q, want the hash of the theme", csp)
	}
	logoURL := "/t/acme/branding/logo-" + logo.Hash + ".png"
	if !strings.Contains(page, `<img class="logo" src="`+logoURL+`" alt="acme">`) {
		t.Errorf("the login page does not show the logo:\n%s", page)
	}

	res, body := b.get(issuer + logoURL)
	for name, want := range map[string]string{
		"Content-Type":            "image/png",
		"Cache-Control":           "public, max-age=31536000, immutable",
		"X-Content-Type-Options":  "nosniff",
		"Content-Security-Policy": "default-src 'none'; sandbox",
	} {
		if got := res.Header.Get(name); got != want {
			t.Errorf("logo %s = %q, want %q", name, got, want)
		}
	}
	if res.StatusCode != http.StatusOK || body != data.String() {
		t.Errorf("logo = %d with %d bytes, want the stored image", res.StatusCode, len(body))
	}
	for _, target := range []string{
		issuer + "/t/acme/branding/logo-000000000000.png",      // a replaced logo
		issuer + "/t/acme/branding/logo-" + logo.Hash + ".jpg", // another type
		issuer + "/branding/logo-" + logo.Hash + ".png",        // another tenant
		issuer + "/t/acme/branding/clavis.db",
	} {
		if res, _ := b.get(target); res.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", target, res.StatusCode)
		}
	}

	// The default tenant keeps the default look.
	if res, page = b.get(issuer + "/login?request=unknown"); strings.Contains(page, "<style>") ||
		strings.Contains(page, `class="logo"`) || !strings.Contains(res.Header.Get("Content-Security-Policy"), "style-src 'self';") {
		t.Errorf("default tenant's login page:\n%s", page)
	}
}
