// Package issuer validates OpenID Connect issuer identifiers.
package issuer

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ErrInvalid is returned for issuer values that do not satisfy the rules
// enforced by Parse.
var ErrInvalid = errors.New("invalid issuer")

// Parse validates raw as an issuer identifier and returns it as a URL.
//
// The rules follow OpenID Connect Discovery 1.0, section 3, and RFC 8414,
// section 2: the issuer is an absolute URL using the https scheme with no
// query or fragment components. Plain http is accepted only for loopback
// hosts, so local development works without TLS. User information and a
// trailing slash are rejected because issuers are compared as exact strings
// and both invite mismatches.
func Parse(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, fmt.Errorf("%w: value is empty", ErrInvalid)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	switch {
	case !u.IsAbs() || u.Host == "":
		return nil, fmt.Errorf("%w: %q is not an absolute URL", ErrInvalid, raw)
	case u.Scheme != "https" && (u.Scheme != "http" || !isLoopback(u.Hostname())):
		return nil, fmt.Errorf("%w: %q must use https (http is allowed only for loopback hosts)", ErrInvalid, raw)
	case u.User != nil:
		return nil, fmt.Errorf("%w: %q must not contain user information", ErrInvalid, raw)
	case u.RawQuery != "" || u.ForceQuery:
		return nil, fmt.Errorf("%w: %q must not contain a query", ErrInvalid, raw)
	case u.Fragment != "" || strings.Contains(raw, "#"):
		return nil, fmt.Errorf("%w: %q must not contain a fragment", ErrInvalid, raw)
	case strings.HasSuffix(u.Path, "/"):
		return nil, fmt.Errorf("%w: %q must not end with a slash", ErrInvalid, raw)
	}
	return u, nil
}

// isLoopback reports whether host names the local machine.
func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
