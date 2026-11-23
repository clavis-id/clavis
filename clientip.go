package clavis

import (
	"net/http"
	"net/netip"
	"strings"
)

// clientIP returns the address of the client of r, as audit events record it
// (ADR 0029), or "" when the address of the connection cannot be parsed.
func clientIP(r *http.Request, trusted []netip.Prefix) string {
	if addr := clientAddr(r, trusted); addr.IsValid() {
		return addr.String()
	}
	return ""
}

// clientAddr returns the address of the client of r, or the zero address
// when the address of the connection cannot be parsed.
//
// The address is that of the connection, unless the connection comes from a
// trusted proxy. Then the X-Forwarded-For header names the client: each
// proxy appends the address it received the request from, so the header is
// read from the right, over the addresses of trusted proxies, and the first
// other address is the client. Addresses to its left were sent by the client
// and prove nothing. When every address is a trusted proxy, the leftmost one
// is the client; an entry that is not an address ends the search at the
// trusted proxy that forwarded it. Without trusted proxies the header is
// ignored, so a client cannot choose its own address.
func clientAddr(r *http.Request, trusted []netip.Prefix) netip.Addr {
	addr, ok := parseAddr(r.RemoteAddr)
	if !ok {
		return netip.Addr{}
	}
	if !isTrusted(addr, trusted) {
		return addr
	}
	values := r.Header.Values("X-Forwarded-For")
	for i := len(values) - 1; i >= 0; i-- {
		rest := values[i]
		for rest != "" {
			var entry string
			if j := strings.LastIndexByte(rest, ','); j >= 0 {
				rest, entry = rest[:j], rest[j+1:]
			} else {
				rest, entry = "", rest
			}
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			next, ok := parseAddr(entry)
			if !ok {
				return addr
			}
			addr = next
			if !isTrusted(addr, trusted) {
				return addr
			}
		}
	}
	return addr
}

// parseAddr parses an IP address, with or without a port, as a connection or
// a proxy writes it, and returns it without an IPv6 zone and with an IPv4
// address mapped to IPv6 unmapped.
func parseAddr(s string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		ap, err := netip.ParseAddrPort(s)
		if err != nil {
			return netip.Addr{}, false
		}
		addr = ap.Addr()
	}
	return addr.WithZone("").Unmap(), true
}

// isTrusted reports whether addr belongs to a trusted proxy.
func isTrusted(addr netip.Addr, trusted []netip.Prefix) bool {
	for _, p := range trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
