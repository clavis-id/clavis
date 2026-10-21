package oauth

import (
	"errors"
	"net/url"
	"slices"
	"strings"
	"testing"
)

// challenge is a valid S256 code challenge (RFC 7636, appendix B).
const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

// validParams returns the parameters of a valid OpenID Connect request.
func validParams() url.Values {
	return url.Values{
		"response_type":         {"code"},
		"client_id":             {"app"},
		"redirect_uri":          {"https://app.example.com/callback"},
		"scope":                 {"openid profile"},
		"state":                 {"af0ifjsldkj"},
		"nonce":                 {"n-0S6_WzA2Mj"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
}

func TestAuthorizationTarget(t *testing.T) {
	t.Parallel()
	clientID, redirectURI, err := AuthorizationTarget(validParams())
	if err != nil || clientID != "app" || redirectURI != "https://app.example.com/callback" {
		t.Errorf("AuthorizationTarget() = %q, %q, %v", clientID, redirectURI, err)
	}
	if _, redirectURI, err := AuthorizationTarget(url.Values{"client_id": {"app"}}); err != nil || redirectURI != "" {
		t.Errorf("AuthorizationTarget() without redirect_uri = %q, %v; want an empty URI", redirectURI, err)
	}

	for name, params := range map[string]url.Values{
		"missing client_id":   {"redirect_uri": {"https://app.example.com/callback"}},
		"empty client_id":     {"client_id": {""}},
		"repeated client_id":  {"client_id": {"app", "app"}},
		"invalid client_id":   {"client_id": {"app\nx"}},
		"repeated redirect":   {"client_id": {"app"}, "redirect_uri": {"https://a.example/", "https://b.example/"}},
		"repeated empty item": {"client_id": {"app", ""}},
	} {
		if _, _, err := AuthorizationTarget(params); !errors.Is(err, ErrInvalidAuthorizationTarget) {
			t.Errorf("%s: AuthorizationTarget() = %v, want ErrInvalidAuthorizationTarget", name, err)
		}
	}
}

func TestParseAuthorizationRequest(t *testing.T) {
	t.Parallel()
	got, err := ParseAuthorizationRequest(validParams())
	if err != nil {
		t.Fatalf("ParseAuthorizationRequest() unexpected error: %v", err)
	}
	if got.ClientID != "app" || got.RedirectURI != "https://app.example.com/callback" ||
		!slices.Equal(got.Scopes, []string{"openid", "profile"}) || got.State != "af0ifjsldkj" ||
		got.Nonce != "n-0S6_WzA2Mj" || got.CodeChallenge != challenge || len(got.Prompt) != 0 ||
		got.MaxAge != -1 || !got.OpenID() || got.LoginHint != "" || got.IDTokenHint != "" ||
		got.ResponseMode != ResponseModeQuery || got.UILocales != "" ||
		got.Claims.UserInfo != nil || got.Claims.IDToken != nil {
		t.Errorf("ParseAuthorizationRequest() = %+v", got)
	}

	tests := []struct {
		name  string
		edit  func(url.Values)
		check func(AuthorizationRequest) bool
	}{
		{"OAuth request", func(p url.Values) { p.Set("scope", "api:read") },
			func(r AuthorizationRequest) bool { return !r.OpenID() }},
		{"duplicate scopes and extra spaces", func(p url.Values) { p.Set("scope", " openid  email openid ") },
			func(r AuthorizationRequest) bool { return slices.Equal(r.Scopes, []string{"openid", "email"}) }},
		{"without PKCE", func(p url.Values) { p.Del("code_challenge"); p.Del("code_challenge_method") },
			func(r AuthorizationRequest) bool { return r.CodeChallenge == "" }},
		{"empty parameters count as omitted", func(p url.Values) { p.Set("state", ""); p.Set("nonce", ""); p.Set("prompt", "") },
			func(r AuthorizationRequest) bool { return r.State == "" && r.Nonce == "" && len(r.Prompt) == 0 }},
		{"state with spaces and symbols", func(p url.Values) { p.Set("state", `a b~!"#\`) },
			func(r AuthorizationRequest) bool { return r.State == `a b~!"#\` }},
		{"longest state", func(p url.Values) { p.Set("state", strings.Repeat("s", MaxStateLength)) },
			func(r AuthorizationRequest) bool { return len(r.State) == MaxStateLength }},
		{"response_mode query", func(p url.Values) { p.Set("response_mode", "query") },
			func(r AuthorizationRequest) bool { return r.ResponseMode == ResponseModeQuery }},
		{"response_mode form_post", func(p url.Values) { p.Set("response_mode", "form_post") },
			func(r AuthorizationRequest) bool { return r.ResponseMode == ResponseModeFormPost }},
		{"prompt values", func(p url.Values) { p.Set("prompt", "login consent login") },
			func(r AuthorizationRequest) bool {
				return slices.Equal(r.Prompt, []string{"login", "consent"}) && r.HasPrompt(PromptLogin)
			}},
		{"prompt none", func(p url.Values) { p.Set("prompt", "none") },
			func(r AuthorizationRequest) bool { return r.HasPrompt(PromptNone) }},
		{"prompt create", func(p url.Values) { p.Set("prompt", "create") },
			func(r AuthorizationRequest) bool { return slices.Equal(r.Prompt, []string{PromptCreate}) }},
		{"max_age zero", func(p url.Values) { p.Set("max_age", "0") },
			func(r AuthorizationRequest) bool { return r.MaxAge == 0 }},
		{"largest max_age", func(p url.Values) { p.Set("max_age", "2147483647") },
			func(r AuthorizationRequest) bool { return r.MaxAge == maxMaxAge }},
		{"empty unsupported parameters count as omitted", func(p url.Values) {
			p.Set("request", "")
			p.Set("request_uri", "")
			p.Set("registration", "")
		}, nil},
		{"login_hint", func(p url.Values) { p.Set("login_hint", "Ada Lovelace <ada@exämple.com>") },
			func(r AuthorizationRequest) bool { return r.LoginHint == "Ada Lovelace <ada@exämple.com>" }},
		{"longest login_hint", func(p url.Values) { p.Set("login_hint", strings.Repeat("a", MaxLoginHintLength)) },
			func(r AuthorizationRequest) bool { return len(r.LoginHint) == MaxLoginHintLength }},
		{"id_token_hint", func(p url.Values) { p.Set("id_token_hint", "header.payload.sig-_") },
			func(r AuthorizationRequest) bool {
				return r.IDTokenHint == "header.payload.sig-_"
			}},
		{"claims", func(p url.Values) {
			p.Set("claims", `{"userinfo":{"name":{"essential":true},"email":null},"id_token":{"acr":{"values":["a","b"]}}}`)
		}, func(r AuthorizationRequest) bool {
			return len(r.Claims.UserInfo) == 2 && r.Claims.UserInfo["name"].Essential &&
				slices.Equal(r.Claims.IDToken["acr"].Values, []string{"a", "b"})
		}},
		{"empty claims object", func(p url.Values) { p.Set("claims", " {} ") },
			func(r AuthorizationRequest) bool { return r.Claims.UserInfo == nil && r.Claims.IDToken == nil }},
		{"ui_locales", func(p url.Values) { p.Set("ui_locales", "es-419 en") },
			func(r AuthorizationRequest) bool { return r.UILocales == "es-419 en" }},
		{"unusable ui_locales are ignored", func(p url.Values) { p.Set("ui_locales", "es\x00") },
			func(r AuthorizationRequest) bool { return r.UILocales == "" }},
		{"ignored parameters", func(p url.Values) {
			p.Set("acr_values", "urn:a urn:b")
			p["unknown"] = []string{"a", "b"}
		}, nil},
	}
	for _, tt := range tests {
		params := validParams()
		tt.edit(params)
		got, err := ParseAuthorizationRequest(params)
		if err != nil {
			t.Errorf("%s: ParseAuthorizationRequest() unexpected error: %v", tt.name, err)
			continue
		}
		if tt.check != nil && !tt.check(got) {
			t.Errorf("%s: ParseAuthorizationRequest() = %+v", tt.name, got)
		}
	}
}

func TestParseAuthorizationRequestErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		edit      func(url.Values)
		code      string
		wantState string
	}{
		{"repeated state", func(p url.Values) { p["state"] = []string{"a", "b"} }, ErrorInvalidRequest, ""},
		{"state with a line break", func(p url.Values) { p.Set("state", "a\nb") }, ErrorInvalidRequest, ""},
		{"non-ASCII state", func(p url.Values) { p.Set("state", "café") }, ErrorInvalidRequest, ""},
		{"long state", func(p url.Values) { p.Set("state", strings.Repeat("s", MaxStateLength+1)) }, ErrorInvalidRequest, ""},
		{"request object", func(p url.Values) { p.Set("request", "eyJ") }, ErrorRequestNotSupported, "af0ifjsldkj"},
		{"repeated empty request object", func(p url.Values) { p["request"] = []string{"", ""} }, ErrorRequestNotSupported, "af0ifjsldkj"},
		{"request_uri", func(p url.Values) { p.Set("request_uri", "https://a.example/r") }, ErrorRequestURINotSupported, "af0ifjsldkj"},
		{"registration", func(p url.Values) { p.Set("registration", "{}") }, ErrorRegistrationNotSupported, "af0ifjsldkj"},
		{"missing response_type", func(p url.Values) { p.Del("response_type") }, ErrorInvalidRequest, "af0ifjsldkj"},
		{"repeated response_type", func(p url.Values) { p["response_type"] = []string{"code", "code"} }, ErrorInvalidRequest, "af0ifjsldkj"},
		{"implicit flow", func(p url.Values) { p.Set("response_type", "token") }, ErrorUnsupportedResponseType, "af0ifjsldkj"},
		{"hybrid flow", func(p url.Values) { p.Set("response_type", "code id_token") }, ErrorUnsupportedResponseType, "af0ifjsldkj"},
		{"fragment response mode", func(p url.Values) { p.Set("response_mode", "fragment") }, ErrorInvalidRequest, "af0ifjsldkj"},
		{"repeated response_mode", func(p url.Values) { p["response_mode"] = []string{"query", "query"} }, ErrorInvalidRequest, "af0ifjsldkj"},
		{"missing scope", func(p url.Values) { p.Del("scope") }, ErrorInvalidScope, "af0ifjsldkj"},
		{"blank scope", func(p url.Values) { p.Set("scope", "   ") }, ErrorInvalidScope, "af0ifjsldkj"},
		{"repeated scope", func(p url.Values) { p["scope"] = []string{"openid", "email"} }, ErrorInvalidRequest, "af0ifjsldkj"},
		{"invalid scope token", func(p url.Values) { p.Set("scope", `openid "email"`) }, ErrorInvalidScope, "af0ifjsldkj"},
		{"plain PKCE", func(p url.Values) { p.Set("code_challenge_method", "plain") }, ErrorInvalidRequest, "af0ifjsldkj"},
		{"challenge without method", func(p url.Values) { p.Del("code_challenge_method") }, ErrorInvalidRequest, "af0ifjsldkj"},
		{"method without challenge", func(p url.Values) { p.Del("code_challenge") }, ErrorInvalidRequest, "af0ifjsldkj"},
		{"short challenge", func(p url.Values) { p.Set("code_challenge", challenge[1:]) }, ErrorInvalidRequest, "af0ifjsldkj"},
		{"padded challenge", func(p url.Values) { p.Set("code_challenge", challenge[1:]+"=") }, ErrorInvalidRequest, "af0ifjsldkj"},
		{"challenge outside base64url", func(p url.Values) { p.Set("code_challenge", challenge[1:]+"~") }, ErrorInvalidRequest, "af0ifjsldkj"},
		{"repeated challenge", func(p url.Values) { p["code_challenge"] = []string{challenge, challenge} }, ErrorInvalidRequest, "af0ifjsldkj"},
		{"repeated method", func(p url.Values) { p["code_challenge_method"] = []string{"S256", "S256"} }, ErrorInvalidRequest, "af0ifjsldkj"},
		{"repeated nonce", func(p url.Values) { p["nonce"] = []string{"a", "b"} }, ErrorInvalidRequest, "af0ifjsldkj"},
		{"nonce with a control character", func(p url.Values) { p.Set("nonce", "a\x00b") }, ErrorInvalidRequest, "af0ifjsldkj"},
		{"long nonce", func(p url.Values) { p.Set("nonce", strings.Repeat("n", MaxNonceLength+1)) }, ErrorInvalidRequest, "af0ifjsldkj"},
		{"unknown prompt", func(p url.Values) { p.Set("prompt", "login register") }, ErrorInvalidRequest, "af0ifjsldkj"},
		{"prompt none with create", func(p url.Values) { p.Set("prompt", "none create") }, ErrorInvalidRequest, "af0ifjsldkj"},
		{"prompt none with login", func(p url.Values) { p.Set("prompt", "none login") }, ErrorInvalidRequest, "af0ifjsldkj"},
		{"prompt separated by a tab", func(p url.Values) { p.Set("prompt", "login\tconsent") }, ErrorInvalidRequest, "af0ifjsldkj"},
		{"repeated prompt", func(p url.Values) { p["prompt"] = []string{"login", "login"} }, ErrorInvalidRequest, "af0ifjsldkj"},
		{"negative max_age", func(p url.Values) { p.Set("max_age", "-1") }, ErrorInvalidRequest, "af0ifjsldkj"},
		{"fractional max_age", func(p url.Values) { p.Set("max_age", "1.5") }, ErrorInvalidRequest, "af0ifjsldkj"},
		{"huge max_age", func(p url.Values) { p.Set("max_age", "2147483648") }, ErrorInvalidRequest, "af0ifjsldkj"},
		{"overflowing max_age", func(p url.Values) { p.Set("max_age", strings.Repeat("9", 40)) }, ErrorInvalidRequest, "af0ifjsldkj"},
		{"repeated max_age", func(p url.Values) { p["max_age"] = []string{"1", "1"} }, ErrorInvalidRequest, "af0ifjsldkj"},
		{"repeated login_hint", func(p url.Values) { p["login_hint"] = []string{"a", "b"} }, ErrorInvalidRequest, "af0ifjsldkj"},
		{"login_hint with a line break", func(p url.Values) { p.Set("login_hint", "ada\n@example.com") }, ErrorInvalidRequest, "af0ifjsldkj"},
		{"login_hint with invalid UTF-8", func(p url.Values) { p.Set("login_hint", "ada\xff") }, ErrorInvalidRequest, "af0ifjsldkj"},
		{"long login_hint", func(p url.Values) { p.Set("login_hint", strings.Repeat("a", MaxLoginHintLength+1)) }, ErrorInvalidRequest, "af0ifjsldkj"},
		{"repeated id_token_hint", func(p url.Values) { p["id_token_hint"] = []string{"a.b.c", "a.b.c"} }, ErrorInvalidRequest, "af0ifjsldkj"},
		{"id_token_hint with two parts", func(p url.Values) { p.Set("id_token_hint", "a.b") }, ErrorInvalidRequest, "af0ifjsldkj"},
		{"id_token_hint with an empty part", func(p url.Values) { p.Set("id_token_hint", "a..c") }, ErrorInvalidRequest, "af0ifjsldkj"},
		{"id_token_hint outside base64url", func(p url.Values) { p.Set("id_token_hint", "a.b+.c") }, ErrorInvalidRequest, "af0ifjsldkj"},
		{"JSON id_token_hint", func(p url.Values) { p.Set("id_token_hint", `{"payload":"a"}`) }, ErrorInvalidRequest, "af0ifjsldkj"},
		{"long id_token_hint", func(p url.Values) {
			p.Set("id_token_hint", "a."+strings.Repeat("b", MaxIDTokenHintLength)+".c")
		}, ErrorInvalidRequest, "af0ifjsldkj"},
		{"repeated claims", func(p url.Values) { p["claims"] = []string{"{}", "{}"} }, ErrorInvalidRequest, "af0ifjsldkj"},
		{"claims that are not JSON", func(p url.Values) { p.Set("claims", "{userinfo}") }, ErrorInvalidRequest, "af0ifjsldkj"},
		{"null claims", func(p url.Values) { p.Set("claims", "null") }, ErrorInvalidRequest, "af0ifjsldkj"},
		{"claims array", func(p url.Values) { p.Set("claims", `[{"userinfo":{}}]`) }, ErrorInvalidRequest, "af0ifjsldkj"},
		{"long claims", func(p url.Values) {
			p.Set("claims", `{"userinfo":{"`+strings.Repeat("n", MaxClaimsLength)+`":null}}`)
		}, ErrorInvalidRequest, "af0ifjsldkj"},
	}
	for _, tt := range tests {
		params := validParams()
		tt.edit(params)
		got, err := ParseAuthorizationRequest(params)
		var oauthErr *Error
		if !errors.As(err, &oauthErr) || oauthErr.Code != tt.code {
			t.Errorf("%s: ParseAuthorizationRequest() = %v, want %s", tt.name, err, tt.code)
			continue
		}
		if got.State != tt.wantState {
			t.Errorf("%s: state = %q, want %q", tt.name, got.State, tt.wantState)
		}
		if !validDescription(oauthErr.Description) || oauthErr.Error() != oauthErr.Code+": "+oauthErr.Description {
			t.Errorf("%s: description %q is not a valid error_description", tt.name, oauthErr.Description)
		}
	}
}

// An error after the response mode goes back in that mode; an error about the
// response mode itself goes back in the default one.
func TestParseAuthorizationRequestErrorsKeepTheResponseMode(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name string
		edit func(url.Values)
		want string
	}{
		{"form_post", func(p url.Values) { p.Set("response_mode", "form_post"); p.Del("scope") }, ResponseModeFormPost},
		{"invalid response mode", func(p url.Values) { p.Set("response_mode", "fragment") }, ""},
		{"error before the response mode", func(p url.Values) {
			p.Set("response_mode", "form_post")
			p["state"] = []string{"a", "b"}
		}, ""},
	} {
		params := validParams()
		tt.edit(params)
		got, err := ParseAuthorizationRequest(params)
		if err == nil || got.ResponseMode != tt.want {
			t.Errorf("%s: ParseAuthorizationRequest() = %q, %v; want response mode %q and an error", tt.name,
				got.ResponseMode, err, tt.want)
		}
	}
}

// validDescription reports whether s uses only the characters RFC 6749,
// section 4.1.2.1, allows in error_description.
func validDescription(s string) bool {
	for _, c := range []byte(s) {
		if c < 0x20 || c > 0x7e || c == '"' || c == '\\' {
			return false
		}
	}
	return s != ""
}

func TestAuthorizationResponseURI(t *testing.T) {
	t.Parallel()
	params := url.Values{"code": {"c d"}, "state": {"s&t"}}
	for redirect, want := range map[string]string{
		"https://app.example.com/cb":             "https://app.example.com/cb?code=c+d&state=s%26t",
		"https://app.example.com/cb?":            "https://app.example.com/cb?code=c+d&state=s%26t",
		"https://app.example.com/cb?a=b%20c":     "https://app.example.com/cb?a=b%20c&code=c+d&state=s%26t",
		"https://app.example.com/cb?a=b&":        "https://app.example.com/cb?a=b&code=c+d&state=s%26t",
		"com.example.app:/cb":                    "com.example.app:/cb?code=c+d&state=s%26t",
		"http://127.0.0.1:51004/cb?x=%2F&y=a+b;": "http://127.0.0.1:51004/cb?x=%2F&y=a+b;&code=c+d&state=s%26t",
	} {
		if got := AuthorizationResponseURI(redirect, params); got != want {
			t.Errorf("AuthorizationResponseURI(%q) = %q, want %q", redirect, got, want)
		}
	}
}

// FuzzParseAuthorizationRequest checks that parsing any query never panics
// and that an accepted request only holds values within the documented
// bounds.
func FuzzParseAuthorizationRequest(f *testing.F) {
	f.Add(validParams().Encode())
	for _, seed := range []string{
		"response_type=code&client_id=app&scope=openid&prompt=none",
		"response_type=code&client_id=app&scope=openid&state=a%0Ab",
		"response_type=code&scope=openid&code_challenge=x&code_challenge_method=plain",
		"response_type=code&scope=+openid++openid&max_age=007",
		"response_type=code&scope=openid&request=x&state=s",
		"client_id=a&client_id=b",
		"response_type=code&scope=openid&login_hint=ada%40example.com&id_token_hint=a.b.c",
		`response_type=code&scope=openid&claims={"userinfo":{"name":{"essential":true}},"id_token":{"acr":{"values":["x"]}}}`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, query string) {
		params, err := url.ParseQuery(query)
		if err != nil {
			return
		}
		if _, _, err := AuthorizationTarget(params); err != nil && !errors.Is(err, ErrInvalidAuthorizationTarget) {
			t.Fatalf("AuthorizationTarget(%q) returned an unexpected error type: %v", query, err)
		}
		r, err := ParseAuthorizationRequest(params)
		if len(r.State) > MaxStateLength || !visibleASCII(r.State) {
			t.Errorf("ParseAuthorizationRequest(%q) kept an invalid state %q", query, r.State)
		}
		if err != nil {
			var oauthErr *Error
			if !errors.As(err, &oauthErr) || !validDescription(oauthErr.Description) {
				t.Errorf("ParseAuthorizationRequest(%q) = %v, want an *Error with a valid description", query, err)
			}
			return
		}
		if len(r.Scopes) == 0 || r.MaxAge < -1 || len(r.Nonce) > MaxNonceLength || !visibleASCII(r.Nonce) {
			t.Errorf("ParseAuthorizationRequest(%q) = %+v, outside the bounds", query, r)
		}
		for i, s := range r.Scopes {
			if ValidateScope(s) != nil || slices.Contains(r.Scopes[:i], s) {
				t.Errorf("ParseAuthorizationRequest(%q) accepted scopes %q", query, r.Scopes)
			}
		}
		if r.CodeChallenge != "" && len(r.CodeChallenge) != s256ChallengeLength {
			t.Errorf("ParseAuthorizationRequest(%q) accepted the challenge %q", query, r.CodeChallenge)
		}
		if r.HasPrompt(PromptNone) && len(r.Prompt) != 1 ||
			slices.ContainsFunc(r.Prompt, func(v string) bool { return !slices.Contains(PromptValues(), v) }) {
			t.Errorf("ParseAuthorizationRequest(%q) accepted prompt %q", query, r.Prompt)
		}
		if len(r.LoginHint) > MaxLoginHintLength || !printableText(r.LoginHint) ||
			len(r.IDTokenHint) > MaxIDTokenHintLength || !compactJWS(r.IDTokenHint) {
			t.Errorf("ParseAuthorizationRequest(%q) accepted the hints %q and %q", query, r.LoginHint, r.IDTokenHint)
		}
	})
}

func TestUILocales(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		values []string
		want   string
	}{
		{nil, ""},
		{[]string{"es-419 en"}, "es-419 en"},
		{[]string{"es", "en"}, ""},
		{[]string{strings.Repeat("a", MaxUILocalesLength)}, strings.Repeat("a", MaxUILocalesLength)},
		{[]string{strings.Repeat("a", MaxUILocalesLength+1)}, ""},
		{[]string{"es\nen"}, ""},
		{[]string{"español"}, ""},
	} {
		if got := UILocales(url.Values{"ui_locales": tt.values}); got != tt.want {
			t.Errorf("UILocales(%q) = %q, want %q", tt.values, got, tt.want)
		}
	}
}
