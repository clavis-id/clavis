package clavis

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"clavisid.org/clavis/internal/app"
	"clavisid.org/clavis/internal/oauth"
	"clavisid.org/clavis/store"
)

// testChallenge is a valid S256 code challenge (RFC 7636, appendix B).
const testChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

const testPassword = "correct horse battery"

// newLoginServer returns a server whose tenant, the default one unless a
// slug is given, has the client "web" and the user ada@example.com.
func newLoginServer(t testing.TB, issuer, slug string) (*Server, store.Tenant) {
	t.Helper()
	cfg := testConfig(t, openStore(t))
	cfg.Issuer = issuer
	s := mustNew(t, cfg)
	tn := s.defaultTenant
	if slug != "" {
		var err error
		if tn, err = app.CreateTenant(t.Context(), s.deps, s.keys.Rotate, slug, ""); err != nil {
			t.Fatalf("CreateTenant() unexpected error: %v", err)
		}
	}
	if _, _, err := app.CreateClient(t.Context(), s.deps, tn.ID, app.ClientSpec{
		ClientID:     "web",
		Name:         "Web App",
		Type:         store.ClientConfidential,
		RedirectURIs: []string{"https://app.example.com/callback"},
	}); err != nil {
		t.Fatalf("CreateClient() unexpected error: %v", err)
	}
	u, err := app.CreateUser(t.Context(), s.deps, tn.ID, app.UserSpec{Email: "ada@example.com"})
	if err != nil {
		t.Fatalf("CreateUser() unexpected error: %v", err)
	}
	if err := app.SetPassword(t.Context(), s.deps, s.passwords, u, testPassword); err != nil {
		t.Fatalf("SetPassword() unexpected error: %v", err)
	}
	return s, tn
}

// authorizeQuery returns a valid authorization request of the client "web".
func authorizeQuery() url.Values {
	return url.Values{
		"response_type":         {"code"},
		"client_id":             {"web"},
		"redirect_uri":          {"https://app.example.com/callback"},
		"scope":                 {"openid profile"},
		"state":                 {"af0ifjsldkj"},
		"nonce":                 {"n-0S6_WzA2Mj"},
		"code_challenge":        {testChallenge},
		"code_challenge_method": {"S256"},
	}
}

// browser sends requests to a handler and keeps the cookies it receives,
// like a browser would for one host.
type browser struct {
	t   *testing.T
	h   http.Handler
	jar map[string]string
}

func newBrowser(t *testing.T, h http.Handler) *browser {
	return &browser{t: t, h: h, jar: make(map[string]string)}
}

// response is what a test needs from an HTTP response.
type response struct {
	StatusCode int
	Header     http.Header
	cookies    []*http.Cookie
}

// Cookies returns the cookies the response sets.
func (r response) Cookies() []*http.Cookie { return r.cookies }

func (b *browser) get(target string) (res response, body string) {
	b.t.Helper()
	return b.send(httptest.NewRequestWithContext(b.t.Context(), http.MethodGet, target, http.NoBody))
}

// post submits a form; site is the Sec-Fetch-Site header a browser sends.
func (b *browser) post(target string, form url.Values, site string) (res response, body string) {
	b.t.Helper()
	req := httptest.NewRequestWithContext(b.t.Context(), http.MethodPost, target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", site)
	return b.send(req)
}

func (b *browser) send(req *http.Request) (res response, body string) {
	b.t.Helper()
	for name, value := range b.jar {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	rec := httptest.NewRecorder()
	b.h.ServeHTTP(rec, req)
	result := rec.Result()
	defer result.Body.Close()
	raw, err := io.ReadAll(result.Body)
	if err != nil {
		b.t.Fatalf("reading the response: %v", err)
	}
	for _, c := range result.Cookies() {
		b.jar[c.Name] = c.Value
	}
	return response{StatusCode: result.StatusCode, Header: result.Header, cookies: result.Cookies()}, string(raw)
}

// startLogin sends an authorization request and follows it to the login
// page, returning the request ID.
func (b *browser) startLogin(issuer string, query url.Values) string {
	b.t.Helper()
	res, _ := b.get(issuer + "/oauth2/authorize?" + query.Encode())
	loc := res.Header.Get("Location")
	if res.StatusCode != http.StatusSeeOther || !strings.HasPrefix(loc, issuer+"/login?request=") {
		b.t.Fatalf("authorize = %d to %q, want a redirect to the login page", res.StatusCode, loc)
	}
	u, err := url.Parse(loc)
	if err != nil {
		b.t.Fatalf("parsing %q: %v", loc, err)
	}
	return u.Query().Get("request")
}

func loginForm(id, password string) url.Values {
	return url.Values{"request": {id}, "email": {"ada@example.com"}, "password": {password}}
}

// checkCookie checks the security attributes of a cookie that a response
// sets (ADR 0013).
func checkCookie(t *testing.T, res response, name string) *http.Cookie {
	t.Helper()
	for _, c := range res.Cookies() {
		if c.Name != name {
			continue
		}
		if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.Domain != "" {
			t.Errorf("cookie %s = %+v, want Secure, HttpOnly, SameSite=Lax, Path=/ and no Domain", name, c)
		}
		return c
	}
	t.Fatalf("the response sets no %s cookie", name)
	return nil
}

func TestAuthorizationCodeFlow(t *testing.T) {
	t.Parallel()
	const issuer = "https://auth.example.com"
	s, tn := newLoginServer(t, issuer, "")
	b := newBrowser(t, s.Handler())

	res, _ := b.get(issuer + "/oauth2/authorize?" + authorizeQuery().Encode())
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("authorize = %d, %v", res.StatusCode, res.Header)
	}
	checkCookie(t, res, bindingCookie)
	id := strings.TrimPrefix(res.Header.Get("Location"), issuer+"/login?request=")
	if !oauth.ValidRequestID(id) {
		t.Fatalf("Location = %q, want the login page of a stored request", res.Header.Get("Location"))
	}

	res, page := b.get(issuer + "/login?request=" + id)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("login page = %d:\n%s", res.StatusCode, page)
	}
	csp := res.Header.Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "form-action 'self' https://app.example.com;", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("Content-Security-Policy = %q, want %q", csp, want)
		}
	}
	if res.Header.Get("X-Frame-Options") != "DENY" || res.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("login page headers = %v", res.Header)
	}
	stylesheet := regexp.MustCompile(`href="(/assets/clavis-[0-9a-f]{12}\.css)"`).FindStringSubmatch(page)
	if !strings.Contains(page, "Web App") || !strings.Contains(page, `action="/login"`) || stylesheet == nil {
		t.Fatalf("login page:\n%s", page)
	}
	if res, _ := b.get(issuer + stylesheet[1]); res.StatusCode != http.StatusOK ||
		res.Header.Get("Content-Type") != "text/css; charset=utf-8" {
		t.Errorf("GET %s = %d, %q", stylesheet[1], res.StatusCode, res.Header.Get("Content-Type"))
	}

	res, page = b.post(issuer+"/login", loginForm(id, "wrong password"), "same-origin")
	if res.StatusCode != http.StatusOK || !strings.Contains(page, "The email or password is incorrect.") ||
		!strings.Contains(page, `value="ada@example.com"`) || strings.Contains(page, "wrong password") {
		t.Fatalf("login with a wrong password = %d:\n%s", res.StatusCode, page)
	}

	res, _ = b.post(issuer+"/login", loginForm(id, testPassword), "same-origin")
	loc, err := url.Parse(res.Header.Get("Location"))
	if res.StatusCode != http.StatusSeeOther || err != nil ||
		!strings.HasPrefix(loc.String(), "https://app.example.com/callback?") {
		t.Fatalf("login = %d to %q", res.StatusCode, res.Header.Get("Location"))
	}
	if q := loc.Query(); q.Get("state") != "af0ifjsldkj" || q.Get("iss") != issuer || q.Get("code") == "" {
		t.Errorf("authorization response = %v", q)
	}
	if res.Header.Get("Cache-Control") != "no-store" || res.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("authorization response headers = %v", res.Header)
	}
	session := checkCookie(t, res, "__Host-clavis-session-"+tn.ID.String())
	if session.MaxAge < int((app.SessionLifetime - time.Minute).Seconds()) {
		t.Errorf("session cookie Max-Age = %d, want the session lifetime", session.MaxAge)
	}
	code, err := s.store.AuthorizationCodes().Get(t.Context(), tn.ID, oauth.HashToken(loc.Query().Get("code")))
	if err != nil || code.Nonce != "n-0S6_WzA2Mj" || code.CodeChallenge != testChallenge {
		t.Errorf("stored code = %+v, %v", code, err)
	}

	// The request is single use.
	res, page = b.post(issuer+"/login", loginForm(id, testPassword), "same-origin")
	if res.StatusCode != http.StatusBadRequest || !strings.Contains(page, "Sign-in expired") {
		t.Errorf("a second login = %d:\n%s", res.StatusCode, page)
	}
}

func TestAuthorizeAcceptsPOST(t *testing.T) {
	t.Parallel()
	const issuer = "https://auth.example.com"
	s, _ := newLoginServer(t, issuer, "")
	b := newBrowser(t, s.Handler())
	// A relying party posts the request from its own site, so cross-site
	// submissions must be accepted here.
	res, _ := b.post(issuer+"/oauth2/authorize", authorizeQuery(), "cross-site")
	if res.StatusCode != http.StatusSeeOther || !strings.HasPrefix(res.Header.Get("Location"), issuer+"/login?request=") {
		t.Errorf("POST authorize = %d to %q", res.StatusCode, res.Header.Get("Location"))
	}
	// Parameters of a POST request come from the body only.
	res, _ = b.post(issuer+"/oauth2/authorize?"+authorizeQuery().Encode(), url.Values{}, "cross-site")
	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("POST authorize with a query = %d, want 400", res.StatusCode)
	}
}

func TestAuthorizeErrorPages(t *testing.T) {
	t.Parallel()
	const issuer = "https://auth.example.com"
	s, _ := newLoginServer(t, issuer, "")
	b := newBrowser(t, s.Handler())
	for name, edit := range map[string]func(url.Values){
		"unknown client":            func(q url.Values) { q.Set("client_id", "nobody") },
		"unregistered redirect URI": func(q url.Values) { q.Set("redirect_uri", "https://evil.example/callback") },
		"missing redirect URI":      func(q url.Values) { q.Del("redirect_uri") },
	} {
		q := authorizeQuery()
		edit(q)
		res, page := b.get(issuer + "/oauth2/authorize?" + q.Encode())
		if res.StatusCode != http.StatusBadRequest || res.Header.Get("Location") != "" ||
			!strings.Contains(page, "Invalid sign-in request") ||
			!strings.Contains(res.Header.Get("Content-Security-Policy"), "form-action 'none'") {
			t.Errorf("%s: authorize = %d, %v:\n%s", name, res.StatusCode, res.Header, page)
		}
	}
	res, _ := b.get(issuer + "/oauth2/authorize?client_id=web&state=%zz")
	if res.StatusCode != http.StatusBadRequest || res.Header.Get("Location") != "" {
		t.Errorf("malformed query: authorize = %d to %q", res.StatusCode, res.Header.Get("Location"))
	}
}

func TestAuthorizeRedirectsErrors(t *testing.T) {
	t.Parallel()
	const issuer = "https://auth.example.com"
	s, _ := newLoginServer(t, issuer, "")
	b := newBrowser(t, s.Handler())
	q := authorizeQuery()
	q.Set("response_type", "token")
	res, _ := b.get(issuer + "/oauth2/authorize?" + q.Encode())
	loc, err := url.Parse(res.Header.Get("Location"))
	if res.StatusCode != http.StatusSeeOther || err != nil ||
		!strings.HasPrefix(loc.String(), "https://app.example.com/callback?") {
		t.Fatalf("authorize = %d to %q", res.StatusCode, res.Header.Get("Location"))
	}
	if r := loc.Query(); r.Get("error") != "unsupported_response_type" || r.Get("state") != "af0ifjsldkj" ||
		r.Get("iss") != issuer {
		t.Errorf("error response = %v", r)
	}
}

func TestLoginRequiresTheBrowserThatStarted(t *testing.T) {
	t.Parallel()
	const issuer = "https://auth.example.com"
	s, _ := newLoginServer(t, issuer, "")
	attacker := newBrowser(t, s.Handler())
	id := attacker.startLogin(issuer, authorizeQuery())

	victim := newBrowser(t, s.Handler())
	victim.jar[bindingCookie] = oauth.NewToken()
	for name, b := range map[string]*browser{"another browser": victim, "no cookie": newBrowser(t, s.Handler())} {
		if res, page := b.get(issuer + "/login?request=" + id); res.StatusCode != http.StatusBadRequest ||
			!strings.Contains(page, "Sign-in expired") {
			t.Errorf("%s: login page = %d", name, res.StatusCode)
		}
		if res, _ := b.post(issuer+"/login", loginForm(id, testPassword), "same-origin"); res.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: login = %d, want 400", name, res.StatusCode)
		}
	}
	// The browser that started the request can still finish it.
	if res, _ := attacker.post(issuer+"/login", loginForm(id, testPassword), "same-origin"); res.StatusCode != http.StatusSeeOther {
		t.Errorf("login from the browser that started = %d, want 303", res.StatusCode)
	}
}

func TestLoginRejectsCrossOriginPosts(t *testing.T) {
	t.Parallel()
	const issuer = "https://auth.example.com"
	s, _ := newLoginServer(t, issuer, "")
	b := newBrowser(t, s.Handler())
	id := b.startLogin(issuer, authorizeQuery())
	res, page := b.post(issuer+"/login", loginForm(id, testPassword), "cross-site")
	if res.StatusCode != http.StatusForbidden || res.Header.Get("Location") != "" || !strings.Contains(page, "Request blocked") {
		t.Errorf("cross-site login = %d:\n%s", res.StatusCode, page)
	}
	if res, _ := b.post(issuer+"/login", loginForm(id, testPassword), "same-origin"); res.StatusCode != http.StatusSeeOther {
		t.Errorf("same-origin login after a blocked one = %d, want 303", res.StatusCode)
	}
}

func TestLoginReplacesTheSession(t *testing.T) {
	t.Parallel()
	const issuer = "https://auth.example.com"
	s, tn := newLoginServer(t, issuer, "")
	b := newBrowser(t, s.Handler())
	name := "__Host-clavis-session-" + tn.ID.String()
	var tokens []string
	for range 2 {
		id := b.startLogin(issuer, authorizeQuery())
		if res, _ := b.post(issuer+"/login", loginForm(id, testPassword), "same-origin"); res.StatusCode != http.StatusSeeOther {
			t.Fatalf("login = %d, want 303", res.StatusCode)
		}
		tokens = append(tokens, b.jar[name])
	}
	if tokens[0] == tokens[1] {
		t.Fatal("the second login kept the session token")
	}
	if _, err := s.store.Sessions().GetByTokenHash(t.Context(), tn.ID, oauth.HashToken(tokens[0])); err == nil {
		t.Error("the first session still exists after the second login")
	}
}

func TestTenantLogin(t *testing.T) {
	t.Parallel()
	const issuer = "https://auth.example.com"
	s, tn := newLoginServer(t, issuer, "acme")
	b := newBrowser(t, s.Handler())
	tenantIssuer := issuer + "/t/acme"
	id := b.startLogin(tenantIssuer, authorizeQuery())

	if res, page := b.get(tenantIssuer + "/login?request=" + id); res.StatusCode != http.StatusOK ||
		!strings.Contains(page, `action="/t/acme/login"`) {
		t.Fatalf("tenant login page = %d:\n%s", res.StatusCode, page)
	}
	// A request belongs to its tenant.
	if res, _ := b.get(issuer + "/login?request=" + id); res.StatusCode != http.StatusBadRequest {
		t.Errorf("login page of the default tenant = %d, want 400", res.StatusCode)
	}
	res, _ := b.post(tenantIssuer+"/login", loginForm(id, testPassword), "same-origin")
	loc, _ := url.Parse(res.Header.Get("Location"))
	if res.StatusCode != http.StatusSeeOther || loc.Query().Get("iss") != tenantIssuer {
		t.Fatalf("tenant login = %d to %q", res.StatusCode, res.Header.Get("Location"))
	}
	checkCookie(t, res, "__Host-clavis-session-"+tn.ID.String())
}

func TestLoginUnderAnIssuerPath(t *testing.T) {
	t.Parallel()
	const issuer = "https://example.com/auth"
	s, _ := newLoginServer(t, issuer, "")
	mux := http.NewServeMux()
	mux.Handle("/auth/", http.StripPrefix("/auth", s.Handler()))
	b := newBrowser(t, mux)
	id := b.startLogin(issuer, authorizeQuery())
	res, page := b.get(issuer + "/login?request=" + id)
	stylesheet := regexp.MustCompile(`href="(/auth/assets/clavis-[0-9a-f]{12}\.css)"`).FindStringSubmatch(page)
	if res.StatusCode != http.StatusOK || !strings.Contains(page, `action="/auth/login"`) || stylesheet == nil {
		t.Fatalf("login page = %d:\n%s", res.StatusCode, page)
	}
	if res, _ := b.get("https://example.com" + stylesheet[1]); res.StatusCode != http.StatusOK {
		t.Errorf("GET %s = %d, want 200", stylesheet[1], res.StatusCode)
	}
}

func TestLoginPageRejectsBadRequests(t *testing.T) {
	t.Parallel()
	const issuer = "https://auth.example.com"
	s, _ := newLoginServer(t, issuer, "")
	b := newBrowser(t, s.Handler())
	for _, target := range []string{"/login", "/login?request=x", "/login?request=" + oauth.NewRequestID()} {
		if res, _ := b.get(issuer + target); res.StatusCode != http.StatusBadRequest {
			t.Errorf("GET %s = %d, want 400", target, res.StatusCode)
		}
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, issuer+"/login", strings.NewReader("request=%zz"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if res, _ := b.send(req); res.StatusCode != http.StatusBadRequest {
		t.Errorf("POST /login with a malformed form = %d, want 400", res.StatusCode)
	}
	if res, _ := b.get(issuer + "/assets/clavis.css"); res.StatusCode != http.StatusNotFound {
		t.Errorf("GET an unhashed asset = %d, want 404", res.StatusCode)
	}
}

// FuzzAuthorizationEndpoint checks that no query makes the authorization
// endpoint fail or redirect anywhere but the login page or a registered
// redirect URI.
func FuzzAuthorizationEndpoint(f *testing.F) {
	const issuer = "https://auth.example.com"
	s, _ := newLoginServer(f, issuer, "")
	h := s.Handler()
	f.Add(authorizeQuery().Encode())
	for _, seed := range []string{
		"client_id=web&redirect_uri=https://app.example.com/callback&response_type=token&state=x",
		"client_id=web&redirect_uri=https://evil.example/&response_type=code",
		"client_id=web&response_type=code&scope=profile",
		"client_id=web&client_id=web",
		"client_id=%zz",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, query string) {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/oauth2/authorize", http.NoBody)
		req.URL.RawQuery = query
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		loc := rec.Header().Get("Location")
		switch rec.Code {
		case http.StatusBadRequest:
			if loc != "" {
				t.Errorf("query %q: an error page redirects to %q", query, loc)
			}
		case http.StatusSeeOther:
			if !strings.HasPrefix(loc, issuer+"/login?request=") &&
				(!strings.HasPrefix(loc, "https://app.example.com/callback?") || !strings.Contains(loc, "iss=")) {
				t.Errorf("query %q: redirect to %q", query, loc)
			}
		default:
			t.Errorf("query %q: status %d", query, rec.Code)
		}
	})
}

func TestServerDeletesExpiredRequests(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const issuer = "https://auth.example.com"
		s, tn := newLoginServer(t, issuer, "")
		id := newBrowser(t, s.Handler()).startLogin(issuer, authorizeQuery())
		stored := func() bool {
			_, err := s.store.AuthorizationRequests().Get(t.Context(), tn.ID, id)
			return err == nil
		}

		time.Sleep(cleanupInterval - time.Second)
		synctest.Wait()
		if !stored() {
			t.Fatal("the request was deleted before it expired")
		}
		// The request expires when the first cleanup runs.
		time.Sleep(time.Second)
		synctest.Wait()
		if stored() {
			t.Error("the expired request is still stored after the cleanup")
		}
	})
}

func TestAuthorizeRejectsHEAD(t *testing.T) {
	t.Parallel()
	const issuer = "https://auth.example.com"
	s, _ := newLoginServer(t, issuer, "")
	req := httptest.NewRequestWithContext(t.Context(), http.MethodHead, "/oauth2/authorize?"+authorizeQuery().Encode(), http.NoBody)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "GET, POST" ||
		rec.Header().Get("Set-Cookie") != "" || rec.Header().Get("Location") != "" {
		t.Errorf("HEAD authorize = %d, %v; want 405 without a cookie or a redirect", rec.Code, rec.Header())
	}
	// Nothing was stored: the first request a browser starts afterwards is
	// the only one.
	if n, err := s.store.AuthorizationRequests().DeleteExpired(t.Context(), time.Now().Add(time.Hour)); err != nil || n != 0 {
		t.Errorf("stored requests after HEAD = %d, %v; want none", n, err)
	}
}
