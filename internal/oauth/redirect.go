package oauth

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// MaxRedirectURILength is the longest redirect URI that can be registered, in
// bytes.
const MaxRedirectURILength = 2000

// ErrInvalidRedirectURI reports a redirect URI that cannot be registered.
var ErrInvalidRedirectURI = errors.New("invalid redirect URI")

// loopbackIPPrefixes start the http redirect URIs whose port is ignored when
// matching (RFC 8252, section 7.3). Only the IP literals qualify: RFC 8252,
// section 8.3, does not recommend "localhost", whose URIs match exactly.
var loopbackIPPrefixes = [...]string{"http://127.0.0.1", "http://[::1]"}

// uriCharacters lists every character that can appear in a URI (RFC 3986,
// section 2): unreserved and reserved characters, and "%" for
// percent-encoding. Browsers read some others, such as "\", as delimiters.
const uriCharacters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" +
	"-._~" + ":/?#[]@" + "!$&'()*+,;=" + "%"

// ValidateRedirectURI reports whether raw can be registered as a redirect URI
// or a post-logout redirect URI. It accepts:
//
//   - https URIs;
//   - http URIs on a loopback interface: 127.0.0.1, [::1] or localhost
//     (RFC 8252, sections 7.3 and 8.3);
//   - private-use URI schemes of native apps, which RFC 8252, section 7.1,
//     requires to be a reverse domain name, such as com.example.app:/callback.
//
// Requests must later send the same string (RFC 9700, section 4.1.3), so the
// rules also reject what could only be matched by normalization or by a
// pattern: fragments (RFC 6749, section 3.1.2), user information, wildcards,
// uppercase schemes or hosts, and characters that RFC 3986 does not allow.
func ValidateRedirectURI(raw string) error {
	if raw == "" || len(raw) > MaxRedirectURILength {
		return fmt.Errorf("%w: must have 1 to %d characters", ErrInvalidRedirectURI, MaxRedirectURILength)
	}
	for i := range len(raw) {
		if strings.IndexByte(uriCharacters, raw[i]) < 0 {
			return fmt.Errorf("%w: %q must contain only the characters that RFC 3986 allows in a URI",
				ErrInvalidRedirectURI, raw)
		}
	}
	switch {
	case strings.Contains(raw, "#"):
		return fmt.Errorf("%w: %q must not contain a fragment", ErrInvalidRedirectURI, raw)
	case strings.Contains(raw, "*"):
		return fmt.Errorf("%w: %q contains a wildcard; redirect URIs match exactly, so register "+
			"each one in full", ErrInvalidRedirectURI, raw)
	}
	u, err := url.Parse(raw)
	switch {
	case err != nil:
		return fmt.Errorf("%w: %q is not a valid URI", ErrInvalidRedirectURI, raw)
	case u.Scheme == "":
		return fmt.Errorf("%w: %q must be an absolute URI", ErrInvalidRedirectURI, raw)
	case !strings.HasPrefix(raw, u.Scheme+":"):
		// url.Parse lowercases the scheme it returns.
		return fmt.Errorf("%w: the scheme of %q must be lowercase", ErrInvalidRedirectURI, raw)
	case u.Opaque != "":
		return fmt.Errorf("%w: %q must have a path that starts with a slash", ErrInvalidRedirectURI, raw)
	case u.User != nil:
		return fmt.Errorf("%w: %q must not contain user information", ErrInvalidRedirectURI, raw)
	case u.Host != strings.ToLower(u.Host) || strings.Contains(u.Host, "%"):
		return fmt.Errorf("%w: the host of %q must be lowercase and not percent-encoded",
			ErrInvalidRedirectURI, raw)
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("%w: the port of %q must be between 1 and 65535", ErrInvalidRedirectURI, raw)
		}
	}

	switch u.Scheme {
	case "https":
		if u.Hostname() == "" {
			return fmt.Errorf("%w: %q must have a host", ErrInvalidRedirectURI, raw)
		}
	case "http":
		switch u.Hostname() {
		case "127.0.0.1", "::1", "localhost":
		default:
			return fmt.Errorf("%w: %q uses http, which is allowed only on a loopback interface "+
				"(127.0.0.1, [::1] or localhost); use https", ErrInvalidRedirectURI, raw)
		}
	default:
		if !strings.Contains(u.Scheme, ".") {
			return fmt.Errorf("%w: the scheme of %q must be https, http on a loopback interface, or "+
				"a reverse domain name such as com.example.app", ErrInvalidRedirectURI, raw)
		}
	}
	return nil
}

// MatchRedirectURI reports whether requested is one of the registered redirect
// URIs. Strings are compared exactly (RFC 9700, section 4.1.3), except that
// the port of an http URI on a loopback IP literal is ignored, so native apps
// can listen on an ephemeral port (RFC 8252, section 7.3).
func MatchRedirectURI(registered []string, requested string) bool {
	for _, r := range registered {
		if r == requested {
			return true
		}
	}
	want, ok := withoutLoopbackPort(requested)
	if !ok {
		return false
	}
	for _, r := range registered {
		if got, ok := withoutLoopbackPort(r); ok && got == want {
			return true
		}
	}
	return false
}

// withoutLoopbackPort returns raw without its port when raw is an http URI on
// a loopback IP literal. It works on the string rather than on a parsed URL,
// so the comparison stays exact everywhere except the port.
func withoutLoopbackPort(raw string) (string, bool) {
	for _, prefix := range loopbackIPPrefixes {
		rest, ok := strings.CutPrefix(raw, prefix)
		if !ok {
			continue
		}
		if afterColon, ok := strings.CutPrefix(rest, ":"); ok {
			digits := len(afterColon) - len(strings.TrimLeft(afterColon, "0123456789"))
			if digits == 0 || digits > 5 {
				return "", false
			}
			if n, _ := strconv.Atoi(afterColon[:digits]); n < 1 || n > 65535 {
				return "", false
			}
			rest = afterColon[digits:]
		}
		// The authority must end here; anything else, such as "@host" or
		// a longer host name, is a different URI.
		if rest != "" && rest[0] != '/' && rest[0] != '?' {
			return "", false
		}
		return prefix + rest, true
	}
	return "", false
}
