package oauth

import (
	"errors"
	"net/url"
	"strings"
	"testing"
)

func TestParseLogoutRequest(t *testing.T) {
	t.Parallel()
	params := url.Values{
		"id_token_hint":            {"header.payload.sig-_"},
		"client_id":                {"web"},
		"post_logout_redirect_uri": {"https://app.example.com/signed-out?x=1"},
		"state":                    {"a b~!"},
		"logout_hint":              {"ada@example.com"},
		"ui_locales":               {"es"},
	}
	got, err := ParseLogoutRequest(params)
	want := LogoutRequest{IDTokenHint: "header.payload.sig-_", ClientID: "web",
		PostLogoutRedirectURI: "https://app.example.com/signed-out?x=1", State: "a b~!"}
	if err != nil || got != want {
		t.Errorf("ParseLogoutRequest() = %+v, %v; want %+v", got, err, want)
	}
	// Every parameter is optional, and an empty one counts as omitted.
	for _, params := range []url.Values{nil, {"state": {""}, "id_token_hint": {""}, "client_id": {""}}} {
		if got, err := ParseLogoutRequest(params); err != nil || got != (LogoutRequest{}) {
			t.Errorf("ParseLogoutRequest(%v) = %+v, %v; want an empty request", params, got, err)
		}
	}

	for name, params := range map[string]url.Values{
		"repeated id_token_hint":       {"id_token_hint": {"a.b.c", "a.b.c"}},
		"id_token_hint not a JWS":      {"id_token_hint": {"a.b"}},
		"long id_token_hint":           {"id_token_hint": {"a.b." + strings.Repeat("c", MaxIDTokenHintLength)}},
		"invalid client_id":            {"client_id": {"a b"}},
		"repeated client_id":           {"client_id": {"web", "web"}},
		"post_logout_redirect_uri ctl": {"post_logout_redirect_uri": {"https://app.example.com/\n"}},
		"long post_logout_redirect_uri": {"post_logout_redirect_uri": {
			"https://app.example.com/" + strings.Repeat("a", MaxRedirectURILength)}},
		"repeated state":    {"state": {"a", "b"}},
		"non-ASCII state":   {"state": {"café"}},
		"long state":        {"state": {strings.Repeat("s", MaxStateLength+1)}},
		"state with a line": {"state": {"a\nb"}},
	} {
		got, err := ParseLogoutRequest(params)
		if !errors.Is(err, ErrInvalidLogoutRequest) || got != (LogoutRequest{}) {
			t.Errorf("%s: ParseLogoutRequest() = %+v, %v; want ErrInvalidLogoutRequest", name, got, err)
		}
	}
}

func TestLogoutResponseURI(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct{ uri, state, want string }{
		{"https://app.example.com/out", "", "https://app.example.com/out"},
		{"https://app.example.com/out", "s&t", "https://app.example.com/out?state=s%26t"},
		{"https://app.example.com/out?x=1", "s", "https://app.example.com/out?x=1&state=s"},
	} {
		if got := LogoutResponseURI(tt.uri, tt.state); got != tt.want {
			t.Errorf("LogoutResponseURI(%q, %q) = %q, want %q", tt.uri, tt.state, got, tt.want)
		}
	}
}

func FuzzParseLogoutRequest(f *testing.F) {
	f.Add("id_token_hint=a.b.c&client_id=web&post_logout_redirect_uri=https%3A%2F%2Fapp.example.com%2F&state=s")
	f.Add("state=a&state=b")
	f.Add("id_token_hint=a..c")
	f.Fuzz(func(t *testing.T, query string) {
		params, err := url.ParseQuery(query)
		if err != nil {
			return
		}
		r, err := ParseLogoutRequest(params)
		switch {
		case err != nil && !errors.Is(err, ErrInvalidLogoutRequest):
			t.Fatalf("ParseLogoutRequest() error %v does not wrap ErrInvalidLogoutRequest", err)
		case err != nil:
			return
		}
		if !compactJWS(r.IDTokenHint) || !visibleASCII(r.State) || !visibleASCII(r.PostLogoutRedirectURI) ||
			(r.ClientID != "" && ValidateClientID(r.ClientID) != nil) {
			t.Fatalf("ParseLogoutRequest(%q) accepted %+v", query, r)
		}
	})
}
