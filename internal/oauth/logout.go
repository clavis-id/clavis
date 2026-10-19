package oauth

import (
	"errors"
	"fmt"
	"net/url"
)

// ErrInvalidLogoutRequest reports a logout request with a parameter that
// cannot be used. The user may still sign out, but the browser goes nowhere
// afterwards.
var ErrInvalidLogoutRequest = errors.New("invalid logout request")

// LogoutRequest holds the parameters of a logout request that Clavis acts on
// (OpenID Connect RP-Initiated Logout 1.0, section 2). Other parameters, such
// as logout_hint and ui_locales, are ignored.
type LogoutRequest struct {
	// IDTokenHint has the syntax of a compact JWS. The caller verifies it.
	IDTokenHint string
	ClientID    string
	// PostLogoutRedirectURI is where the client asks the browser to go after
	// the logout. The caller compares it with the registered ones.
	PostLogoutRedirectURI string
	State                 string
}

// ParseLogoutRequest parses a logout request. Every parameter is optional,
// and an empty one counts as omitted. An error wraps ErrInvalidLogoutRequest,
// and its message holds only fixed text.
func ParseLogoutRequest(params url.Values) (LogoutRequest, error) {
	var r LogoutRequest
	for _, p := range []struct {
		name    string
		value   *string
		valid   func(string) bool
		problem string
	}{
		{"id_token_hint", &r.IDTokenHint, func(s string) bool {
			return len(s) <= MaxIDTokenHintLength && compactJWS(s)
		}, "id_token_hint must be an ID token"},
		{"client_id", &r.ClientID, func(s string) bool {
			return s == "" || ValidateClientID(s) == nil
		}, "client_id is not a valid client identifier"},
		{"post_logout_redirect_uri", &r.PostLogoutRedirectURI, func(s string) bool {
			return len(s) <= MaxRedirectURILength && visibleASCII(s)
		}, "post_logout_redirect_uri is not a valid URI"},
		{"state", &r.State, func(s string) bool {
			return len(s) <= MaxStateLength && visibleASCII(s)
		}, "state must have at most 4096 printable ASCII characters"},
	} {
		value, ok := single(params, p.name)
		switch {
		case !ok:
			return LogoutRequest{}, fmt.Errorf("%w: %s is repeated", ErrInvalidLogoutRequest, p.name)
		case !p.valid(value):
			return LogoutRequest{}, fmt.Errorf("%w: %s", ErrInvalidLogoutRequest, p.problem)
		}
		*p.value = value
	}
	return r, nil
}

// LogoutResponseURI returns the post-logout redirect URI with the state of
// the logout request, if any (OpenID Connect RP-Initiated Logout 1.0,
// section 3).
func LogoutResponseURI(postLogoutRedirectURI, state string) string {
	if state == "" {
		return postLogoutRedirectURI
	}
	return AuthorizationResponseURI(postLogoutRedirectURI, url.Values{"state": {state}})
}
