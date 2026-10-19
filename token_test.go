package clavis

import (
	"encoding/base64"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/synctest"
	"time"
	"uuid"

	"clavisid.org/clavis/internal/app"
	"clavisid.org/clavis/internal/oauth"
	"clavisid.org/clavis/store"
)

// tokenServer returns a server with a confidential client "web" whose
// secret it returns, and the user ada.
func tokenServer(t *testing.T) (s *Server, secret string) {
	t.Helper()
	s = newTestServer(t, openStore(t))
	_, secret, err := app.CreateClient(t.Context(), s.deps, s.defaultTenant.ID, app.ClientSpec{
		ClientID: "web", Type: store.ClientConfidential, RedirectURIs: []string{"https://app.example.com/callback"},
	})
	if err != nil {
		t.Fatalf("CreateClient() unexpected error: %v", err)
	}
	return s, secret
}

func post(t *testing.T, h http.Handler, path, contentType, body string, header http.Header) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for name, values := range header {
		req.Header[name] = values
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func errorCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding %q: %v", rec.Body.String(), err)
	}
	return body.Error
}

func TestTokenEndpointErrors(t *testing.T) {
	t.Parallel()
	s, secret := tokenServer(t)
	h := s.Handler()
	basic := http.Header{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte("web:"+secret))}}
	tests := []struct {
		name        string
		contentType string
		body        string
		header      http.Header
		status      int
		code        string
	}{
		{"JSON body", "application/json", `{"grant_type":"client_credentials"}`, basic, 400, "invalid_request"},
		{"no client", formContentType, "grant_type=authorization_code&code=x", nil, 401, "invalid_client"},
		{"wrong secret", formContentType, "grant_type=authorization_code&code=x&client_id=web&client_secret=no", nil, 401, "invalid_client"},
		{"two methods", formContentType, "grant_type=authorization_code&client_secret=" + secret, basic, 400, "invalid_request"},
		{"unknown grant", formContentType, "grant_type=password", basic, 400, "unsupported_grant_type"},
		{"missing grant", formContentType, "code=x", basic, 400, "invalid_request"},
		{"unknown code", formContentType, "grant_type=authorization_code&code=x&redirect_uri=https://app.example.com/callback", basic, 400, "invalid_grant"},
		{"client credentials not allowed", formContentType, "grant_type=client_credentials", basic, 400, "unauthorized_client"},
		{"missing refresh token", formContentType, "grant_type=refresh_token", basic, 400, "invalid_request"},
		{"unknown refresh token", formContentType, "grant_type=refresh_token&refresh_token=x", basic, 400, "invalid_grant"},
		{"malformed form", formContentType, "grant_type=%zz", basic, 400, "invalid_request"},
	}
	for _, tt := range tests {
		rec := post(t, h, "/oauth2/token", tt.contentType, tt.body, tt.header)
		if rec.Code != tt.status || errorCode(t, rec) != tt.code || rec.Header().Get("Cache-Control") != "no-store" ||
			rec.Header().Get("Content-Type") != "application/json" {
			t.Errorf("%s: token = %d %s, %v", tt.name, rec.Code, rec.Body.String(), rec.Header())
		}
		if (tt.status == http.StatusUnauthorized) != (rec.Header().Get("WWW-Authenticate") != "") {
			t.Errorf("%s: WWW-Authenticate = %q", tt.name, rec.Header().Get("WWW-Authenticate"))
		}
	}
	// GET is not a token request.
	if rec := serve(t, h, http.MethodGet, "/oauth2/token"); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /oauth2/token = %d, want 405", rec.Code)
	}
}

func TestTokenAndUserinfoAllowCORS(t *testing.T) {
	t.Parallel()
	s, _ := tokenServer(t)
	h := s.Handler()
	for path, methods := range map[string]string{"/oauth2/token": "POST", "/oauth2/userinfo": "GET, POST"} {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodOptions, path, http.NoBody)
		req.Header.Set("Origin", "https://spa.example")
		req.Header.Set("Access-Control-Request-Method", "POST")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent || rec.Header().Get("Access-Control-Allow-Origin") != "*" ||
			rec.Header().Get("Access-Control-Allow-Methods") != methods ||
			!strings.Contains(rec.Header().Get("Access-Control-Allow-Headers"), "Authorization") ||
			rec.Header().Get("Access-Control-Allow-Credentials") != "" {
			t.Errorf("preflight %s = %d, %v", path, rec.Code, rec.Header())
		}
	}
	rec := post(t, h, "/oauth2/token", formContentType, "grant_type=x", nil)
	if rec.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("token error response headers = %v", rec.Header())
	}
}

func TestUserinfoTokenMethods(t *testing.T) {
	t.Parallel()
	const issuer = "https://auth.example.com"
	s, _ := newLoginServer(t, issuer, "")
	h := s.Handler()
	secret, err := app.RotateClientSecret(t.Context(), s.deps, s.defaultTenant.ID, "web")
	if err != nil {
		t.Fatalf("RotateClientSecret() unexpected error: %v", err)
	}
	b := newBrowser(t, h)
	id := b.startLogin(issuer, authorizeQuery())
	res, _ := b.post(issuer+"/login", loginForm(id, testPassword), "same-origin")
	loc, _ := url.Parse(res.Header.Get("Location"))
	rec := post(t, h, "/oauth2/token", formContentType, url.Values{
		"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")},
		"redirect_uri": {"https://app.example.com/callback"}, "client_id": {"web"}, "client_secret": {secret},
		"code_verifier": {"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"},
	}.Encode(), nil)
	var token app.TokenResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &token); err != nil || rec.Code != http.StatusOK || token.IDToken == "" {
		t.Fatalf("token = %d %s", rec.Code, rec.Body.String())
	}
	bearer := http.Header{"Authorization": {"Bearer " + token.AccessToken}}

	get := func(header http.Header, rawQuery string) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/oauth2/userinfo?"+rawQuery, http.NoBody)
		for name, values := range header {
			req.Header[name] = values
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	for name, rec := range map[string]*httptest.ResponseRecorder{
		"GET with header":  get(bearer, ""),
		"POST with header": post(t, h, "/oauth2/userinfo", "", "", bearer),
		"POST with body":   post(t, h, "/oauth2/userinfo", formContentType, "access_token="+token.AccessToken, nil),
	} {
		var claims map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &claims); err != nil || rec.Code != http.StatusOK || claims["sub"] == nil ||
			rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s: userinfo = %d %s", name, rec.Code, rec.Body.String())
		}
	}

	for name, tt := range map[string]struct {
		rec    *httptest.ResponseRecorder
		status int
		header string
	}{
		"no token":        {get(nil, ""), 401, `Bearer realm="clavis"`},
		"query parameter": {get(nil, "access_token="+token.AccessToken), 401, `Bearer realm="clavis"`},
		"invalid token":   {get(http.Header{"Authorization": {"Bearer abc"}}, ""), 401, `error="invalid_token"`},
		"ID token":        {get(http.Header{"Authorization": {"Bearer " + token.IDToken}}, ""), 401, `error="invalid_token"`},
		"basic scheme":    {get(http.Header{"Authorization": {"Basic abc"}}, ""), 400, `error="invalid_request"`},
		"two methods": {post(t, h, "/oauth2/userinfo", formContentType, "access_token="+token.AccessToken, bearer),
			400, `error="invalid_request"`},
	} {
		if tt.rec.Code != tt.status || !strings.Contains(tt.rec.Header().Get("WWW-Authenticate"), tt.header) {
			t.Errorf("%s: userinfo = %d, WWW-Authenticate %q", name, tt.rec.Code, tt.rec.Header().Get("WWW-Authenticate"))
		}
	}
}

func TestJSONResponsesCannotBeReadAsHTML(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, openStore(t))
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
	s.writeNoStoreJSON(rec, req, http.StatusOK, map[string]string{"name": "<script>alert(1)</script>&"})
	if strings.ContainsAny(rec.Body.String(), "<>&") || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("response = %q, %v", rec.Body.String(), rec.Header())
	}
}

func TestServerDeletesExpiredRefreshTokens(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, tn := newLoginServer(t, "https://auth.example.com", "")
		client, err := s.store.Clients().GetByClientID(t.Context(), tn.ID, "web")
		if err != nil {
			t.Fatalf("looking up the client: %v", err)
		}
		u, err := s.store.Users().GetByEmail(t.Context(), tn.ID, "ada@example.com")
		if err != nil {
			t.Fatalf("looking up the user: %v", err)
		}
		// The family ends unless it is used before the first cleanup.
		now := time.Now()
		family := store.RefreshTokenFamily{
			ID: uuid.NewV7(), TenantID: tn.ID, ClientID: client.ID, UserID: u.ID,
			Scopes: []string{"openid", "offline_access"}, AuthTime: now, CreatedAt: now,
			IdleExpiresAt: now.Add(cleanupInterval), ExpiresAt: now.Add(app.DefaultRefreshTokenAbsoluteLifetime),
		}
		token := store.RefreshToken{Hash: oauth.HashToken(oauth.NewToken()), TenantID: tn.ID, FamilyID: family.ID,
			IssuedAt: now, ExpiresAt: family.IdleExpiresAt}
		if err := s.store.RefreshTokens().Create(t.Context(), family, token); err != nil {
			t.Fatalf("storing a refresh token: %v", err)
		}
		stored := func() bool {
			_, _, err := s.store.RefreshTokens().Get(t.Context(), tn.ID, token.Hash)
			return err == nil
		}

		time.Sleep(cleanupInterval - time.Second)
		synctest.Wait()
		if !stored() {
			t.Fatal("the refresh token was deleted before it expired")
		}
		time.Sleep(time.Second)
		synctest.Wait()
		if stored() {
			t.Error("the expired refresh token is still stored after the cleanup")
		}
	})
}

func TestRevocationAndIntrospectionEndpoints(t *testing.T) {
	t.Parallel()
	s, webSecret := tokenServer(t)
	h := s.Handler()
	ctx := t.Context()
	if _, err := app.CreateAPIResource(ctx, s.deps, s.defaultTenant.ID, app.APIResourceSpec{
		Identifier: "https://api.example.com/orders", Scopes: []string{"orders:read"},
	}); err != nil {
		t.Fatalf("CreateAPIResource() unexpected error: %v", err)
	}
	_, secret, err := app.CreateClient(ctx, s.deps, s.defaultTenant.ID, app.ClientSpec{
		ClientID: "service", Type: store.ClientConfidential, GrantTypes: []string{"client_credentials"},
		Scopes: []string{"orders:read"},
	})
	if err != nil {
		t.Fatalf("CreateClient() unexpected error: %v", err)
	}
	if _, _, err := app.CreateClient(ctx, s.deps, s.defaultTenant.ID, app.ClientSpec{
		ClientID: "spa", Type: store.ClientPublic, RedirectURIs: []string{"http://127.0.0.1/callback"},
	}); err != nil {
		t.Fatalf("CreateClient() unexpected error: %v", err)
	}
	basicFor := func(id, secret string) http.Header {
		return http.Header{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte(id+":"+secret))}}
	}
	service, web := basicFor("service", secret), basicFor("web", webSecret)
	rec := post(t, h, "/oauth2/token", formContentType, "grant_type=client_credentials", service)
	var token app.TokenResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &token); rec.Code != http.StatusOK || err != nil {
		t.Fatalf("token = %d %s", rec.Code, rec.Body.String())
	}
	tokenForm := "token=" + url.QueryEscape(token.AccessToken)
	introspect := func(header http.Header) app.Introspection {
		t.Helper()
		rec := post(t, h, "/oauth2/introspect", formContentType, tokenForm+"&token_type_hint=access_token", header)
		var got app.Introspection
		if err := json.Unmarshal(rec.Body.Bytes(), &got); rec.Code != http.StatusOK || err != nil ||
			rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatalf("introspect = %d %s, %v", rec.Code, rec.Body.String(), rec.Header())
		}
		return got
	}
	if got := introspect(service); !got.Active || got.ClientID != "service" || got.Scope != "orders:read" {
		t.Errorf("introspection = %+v", got)
	}
	if got := introspect(web); got.Active {
		t.Errorf("introspection by another client = %+v, want inactive", got)
	}

	tests := []struct {
		name   string
		path   string
		body   string
		header http.Header
		status int
		code   string
	}{
		{"revoke without a token", "/oauth2/revoke", "token_type_hint=access_token", service, 400, "invalid_request"},
		{"introspect without a token", "/oauth2/introspect", "", service, 400, "invalid_request"},
		{"revoke with a wrong secret", "/oauth2/revoke", tokenForm, basicFor("service", "wrong"), 401, "invalid_client"},
		{"introspect without credentials", "/oauth2/introspect", tokenForm, nil, 401, "invalid_client"},
		{"introspect as a public client", "/oauth2/introspect", tokenForm + "&client_id=spa", nil, 401, "invalid_client"},
		{"revoke the token of another client", "/oauth2/revoke", tokenForm, web, 400, "unauthorized_client"},
	}
	for _, tt := range tests {
		rec := post(t, h, tt.path, formContentType, tt.body, tt.header)
		if rec.Code != tt.status || errorCode(t, rec) != tt.code {
			t.Errorf("%s: %d %s", tt.name, rec.Code, rec.Body.String())
		}
	}

	// RFC 7009, section 2.2: success and unknown tokens both answer 200.
	for _, body := range []string{tokenForm, "token=unknown"} {
		rec := post(t, h, "/oauth2/revoke", formContentType, body, service)
		if rec.Code != http.StatusOK || rec.Body.Len() != 0 || rec.Header().Get("Cache-Control") != "no-store" ||
			rec.Header().Get("Access-Control-Allow-Origin") != "*" {
			t.Errorf("revoke %q = %d %q, %v", body, rec.Code, rec.Body.String(), rec.Header())
		}
	}
	if got := introspect(service); got.Active {
		t.Errorf("introspection of a revoked token = %+v, want inactive", got)
	}

	if rec := serve(t, h, http.MethodOptions, "/oauth2/revoke"); rec.Code != http.StatusNoContent ||
		rec.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("OPTIONS /oauth2/revoke = %d, %v", rec.Code, rec.Header())
	}
	for _, path := range []string{"/oauth2/revoke", "/oauth2/introspect"} {
		if rec := serve(t, h, http.MethodGet, path); rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET %s = %d, want 405", path, rec.Code)
		}
	}
}
