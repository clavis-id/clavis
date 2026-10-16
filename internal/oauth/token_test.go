package oauth

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"slices"
	"strings"
	"testing"
)

func TestNewToken(t *testing.T) {
	t.Parallel()
	a, b := NewToken(), NewToken()
	if a == b {
		t.Fatalf("NewToken() returned %q twice", a)
	}
	raw, err := base64.RawURLEncoding.DecodeString(a)
	if err != nil || len(raw) != 32 {
		t.Errorf("NewToken() = %q, want 32 bytes in unpadded base64url (err %v)", a, err)
	}
	if h := HashToken(a); len(h) != sha256.Size || bytes.Equal(h, HashToken(b)) {
		t.Errorf("HashToken() = %x", h)
	}
}

func TestRequestIDs(t *testing.T) {
	t.Parallel()
	id := NewRequestID()
	if !ValidRequestID(id) || id == NewRequestID() {
		t.Fatalf("NewRequestID() = %q, want a valid, random identifier", id)
	}
	for _, invalid := range []string{"", id[1:], id + "A", strings.Repeat("=", requestIDLength), id[:21] + "/"} {
		if ValidRequestID(invalid) {
			t.Errorf("ValidRequestID(%q) = true, want false", invalid)
		}
	}
}

// basic returns the Basic credentials of the client "app".
func basic(secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte("app:"+url.QueryEscape(secret)))
}

func TestParseClientCredentials(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		authorization string
		form          url.Values
		want          ClientCredentials
	}{
		{"basic", basic("s3cret"), url.Values{}, ClientCredentials{"app", "s3cret", AuthMethodClientSecretBasic}},
		{"basic with form-urlencoded parts", basic("a:b+c%d"), url.Values{},
			ClientCredentials{"app", "a:b+c%d", AuthMethodClientSecretBasic}},
		{"basic in lowercase with a matching client_id", "basic " + basic("s")[6:], url.Values{"client_id": {"app"}},
			ClientCredentials{"app", "s", AuthMethodClientSecretBasic}},
		{"post", "", url.Values{"client_id": {"app"}, "client_secret": {"s3cret"}},
			ClientCredentials{"app", "s3cret", AuthMethodClientSecretPost}},
		{"none", "", url.Values{"client_id": {"spa"}}, ClientCredentials{"spa", "", AuthMethodNone}},
		{"empty secret means none", "", url.Values{"client_id": {"spa"}, "client_secret": {""}},
			ClientCredentials{"spa", "", AuthMethodNone}},
	}
	for _, tt := range tests {
		got, err := ParseClientCredentials(tt.authorization, tt.form)
		if err != nil || got != tt.want {
			t.Errorf("%s: ParseClientCredentials() = %+v, %v; want %+v", tt.name, got, err, tt.want)
		}
	}

	errorTests := []struct {
		name          string
		authorization string
		form          url.Values
		code          string
	}{
		{"no client", "", url.Values{}, ErrorInvalidClient},
		{"invalid client_id", "", url.Values{"client_id": {"a b"}}, ErrorInvalidClient},
		{"repeated client_id", "", url.Values{"client_id": {"a", "a"}}, ErrorInvalidRequest},
		{"repeated client_secret", "", url.Values{"client_id": {"a"}, "client_secret": {"s", "s"}}, ErrorInvalidRequest},
		{"bearer scheme", "Bearer abc", url.Values{}, ErrorInvalidClient},
		{"scheme only", "Basic", url.Values{}, ErrorInvalidClient},
		{"two methods", basic("s"), url.Values{"client_secret": {"s"}}, ErrorInvalidRequest},
		{"client_id differs from basic", basic("s"), url.Values{"client_id": {"other"}}, ErrorInvalidRequest},
		{"not base64", "Basic %%%", url.Values{}, ErrorInvalidClient},
		{"no colon", "Basic " + base64.StdEncoding.EncodeToString([]byte("app")), url.Values{}, ErrorInvalidClient},
		{"bad escape", "Basic " + base64.StdEncoding.EncodeToString([]byte("app:%zz")), url.Values{}, ErrorInvalidClient},
		{"empty secret", "Basic " + base64.StdEncoding.EncodeToString([]byte("app:")), url.Values{}, ErrorInvalidClient},
		{"empty client_id", "Basic " + base64.StdEncoding.EncodeToString([]byte(":s")), url.Values{}, ErrorInvalidClient},
	}
	for _, tt := range errorTests {
		_, err := ParseClientCredentials(tt.authorization, tt.form)
		var oauthErr *Error
		if !errors.As(err, &oauthErr) || oauthErr.Code != tt.code || !validDescription(oauthErr.Description) {
			t.Errorf("%s: ParseClientCredentials() = %v, want %s", tt.name, err, tt.code)
		}
	}
}

// verifier is the code verifier of RFC 7636, appendix B, whose S256
// challenge is the challenge constant.
const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

func TestParseTokenRequest(t *testing.T) {
	t.Parallel()
	got, err := ParseTokenRequest(url.Values{
		"grant_type": {"authorization_code"}, "code": {"c"}, "redirect_uri": {"https://a.example/cb"},
		"code_verifier": {verifier}, "scope": {" api:read  api:write api:read"},
	})
	if err != nil || got.GrantType != "authorization_code" || got.Code != "c" || got.RedirectURI != "https://a.example/cb" ||
		got.CodeVerifier != verifier || !slices.Equal(got.Scopes, []string{"api:read", "api:write"}) {
		t.Errorf("ParseTokenRequest() = %+v, %v", got, err)
	}
	if got, err := ParseTokenRequest(url.Values{"grant_type": {"client_credentials"}}); err != nil || len(got.Scopes) != 0 {
		t.Errorf("ParseTokenRequest() without scope = %+v, %v", got, err)
	}
	for name, form := range map[string]url.Values{
		"missing grant_type":  {"code": {"c"}},
		"repeated grant_type": {"grant_type": {"a", "a"}},
		"repeated code":       {"grant_type": {"authorization_code"}, "code": {"a", "b"}},
		"repeated scope":      {"grant_type": {"client_credentials"}, "scope": {"a", "b"}},
		"short verifier":      {"grant_type": {"authorization_code"}, "code_verifier": {verifier[1:]}},
		"long verifier":       {"grant_type": {"authorization_code"}, "code_verifier": {strings.Repeat("a", 129)}},
		"verifier outside":    {"grant_type": {"authorization_code"}, "code_verifier": {verifier[1:] + "/"}},
		"invalid scope":       {"grant_type": {"client_credentials"}, "scope": {`a "b"`}},
	} {
		var oauthErr *Error
		if _, err := ParseTokenRequest(form); !errors.As(err, &oauthErr) || !validDescription(oauthErr.Description) {
			t.Errorf("%s: ParseTokenRequest() = %v, want an *Error", name, err)
		}
	}
}

func TestVerifyPKCE(t *testing.T) {
	t.Parallel()
	if !VerifyPKCE(challenge, verifier) {
		t.Error("VerifyPKCE() rejected the RFC 7636 example")
	}
	for _, wrong := range []string{"", verifier[1:], verifier + "a"} {
		if VerifyPKCE(challenge, wrong) {
			t.Errorf("VerifyPKCE(%q) = true, want false", wrong)
		}
	}
}

// FuzzParseClientCredentials checks that any Authorization header and form
// either fail with an *Error or yield a valid client identifier and method.
func FuzzParseClientCredentials(f *testing.F) {
	f.Add(basic("s"), "")
	f.Add("Basic YXBwOnM=", "client_id=app")
	f.Add("", "client_id=spa&client_secret=x")
	f.Add("Basic %%%", "")
	f.Fuzz(func(t *testing.T, authorization, query string) {
		form, err := url.ParseQuery(query)
		if err != nil {
			return
		}
		got, err := ParseClientCredentials(authorization, form)
		if err != nil {
			var oauthErr *Error
			if !errors.As(err, &oauthErr) || !validDescription(oauthErr.Description) {
				t.Fatalf("ParseClientCredentials(%q, %q) = %v, want an *Error", authorization, query, err)
			}
			return
		}
		if ValidateClientID(got.ClientID) != nil || (got.Method == AuthMethodNone) != (got.Secret == "") {
			t.Errorf("ParseClientCredentials(%q, %q) = %+v", authorization, query, got)
		}
	})
}
