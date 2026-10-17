package ui

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

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
		got := ContentSecurityPolicy(tt.allowSelf, tt.targets...)
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
		Layout:     Layout{Stylesheet: "/assets/clavis-0123456789ab.css"},
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
	err := Error(ErrorPage{Title: "Request expired", Message: "Return to <the application>."}).Render(t.Context(), &b)
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
	var b bytes.Buffer
	err := Consent(ConsentPage{
		Layout:     Layout{Stylesheet: "/assets/clavis-0123456789ab.css"},
		ClientName: `<script>alert(1)</script>`,
		Account:    `ada@example.com<img src=x>`,
		Scopes:     []string{ScopeDescription("openid", ""), ScopeDescription("orders:read", `<b>Orders</b>`)},
		Action:     "/consent",
		RequestID:  `"><img src=x>`,
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

func TestScopeDescription(t *testing.T) {
	t.Parallel()
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
		if got := ScopeDescription(tt.scope, tt.resource); got != tt.want {
			t.Errorf("ScopeDescription(%q, %q) = %q, want %q", tt.scope, tt.resource, got, tt.want)
		}
	}
}
