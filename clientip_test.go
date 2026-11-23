package clavis

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"clavisid.org/clavis/internal/app"
	"clavisid.org/clavis/store"
)

func TestClientIP(t *testing.T) {
	t.Parallel()
	proxies := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("fd00::/8")}
	for _, tc := range []struct {
		name    string
		remote  string
		forward []string
		trusted []netip.Prefix
		want    string
	}{
		{name: "connection", remote: "192.0.2.1:4711", want: "192.0.2.1"},
		{name: "header without trusted proxies", remote: "192.0.2.1:4711", forward: []string{"203.0.113.9"},
			want: "192.0.2.1"},
		{name: "header from an untrusted address", remote: "192.0.2.1:4711", forward: []string{"203.0.113.9"},
			trusted: proxies, want: "192.0.2.1"},
		{name: "client of a trusted proxy", remote: "10.0.0.2:4711", forward: []string{"203.0.113.9"},
			trusted: proxies, want: "203.0.113.9"},
		{name: "addresses the client sent", remote: "10.0.0.2:4711",
			forward: []string{"198.51.100.1, 192.0.2.77, 203.0.113.9"}, trusted: proxies, want: "203.0.113.9"},
		{name: "chain of trusted proxies", remote: "10.0.0.2:4711", forward: []string{"203.0.113.9, 10.1.1.1",
			"fd00::7"}, trusted: proxies, want: "203.0.113.9"},
		{name: "every address trusted", remote: "10.0.0.2:4711", forward: []string{"10.9.9.9, 10.1.1.1"},
			trusted: proxies, want: "10.9.9.9"},
		{name: "trusted proxy without the header", remote: "10.0.0.2:4711", trusted: proxies, want: "10.0.0.2"},
		{name: "entry that is not an address", remote: "10.0.0.2:4711", forward: []string{"203.0.113.9, nonsense, 10.1.1.1"},
			trusted: proxies, want: "10.1.1.1"},
		{name: "empty entries", remote: "10.0.0.2:4711", forward: []string{"203.0.113.9, ,", ""}, trusted: proxies,
			want: "203.0.113.9"},
		{name: "entries with ports", remote: "10.0.0.2:4711", forward: []string{"[2001:db8::1]:443, 10.1.1.1:80"},
			trusted: proxies, want: "2001:db8::1"},
		{name: "IPv6 connection with a zone", remote: "[fe80::1%eth0]:4711", want: "fe80::1"},
		{name: "IPv4 in IPv6", remote: "[::ffff:192.0.2.1]:4711", want: "192.0.2.1"},
		{name: "IPv4 in IPv6 proxy", remote: "[::ffff:10.0.0.2]:4711", forward: []string{"::ffff:203.0.113.9"},
			trusted: proxies, want: "203.0.113.9"},
		{name: "connection that is not an address", remote: "pipe", want: ""},
	} {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
		req.RemoteAddr = tc.remote
		for _, v := range tc.forward {
			req.Header.Add("X-Forwarded-For", v)
		}
		if got := clientIP(req, tc.trusted); got != tc.want {
			t.Errorf("%s: clientIP() = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func FuzzClientIP(f *testing.F) {
	f.Add("10.0.0.2:4711", "198.51.100.1, 203.0.113.9")
	f.Add("[fd00::1]:1", "[2001:db8::1]:443,,10.1.1.1")
	f.Add("192.0.2.1:1", "x")
	proxies := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("fd00::/8")}
	f.Fuzz(func(t *testing.T, remote, forward string) {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
		req.RemoteAddr = remote
		req.Header.Set("X-Forwarded-For", forward)
		got := clientIP(req, proxies)
		if got == "" {
			if _, ok := parseAddr(remote); ok {
				t.Errorf("clientIP() = \"\" for the connection %q", remote)
			}
			return
		}
		addr, err := netip.ParseAddr(got)
		if err != nil || addr.String() != got || addr.Zone() != "" || addr.Is4In6() {
			t.Errorf("clientIP() = %q, not a plain address", got)
		}
		// Without trusted proxies the header never counts.
		connection, _ := parseAddr(remote)
		if got := clientIP(req, nil); got != connection.String() {
			t.Errorf("clientIP() without trusted proxies = %q, want %q", got, connection)
		}
	})
}

func TestTrustedProxies(t *testing.T) {
	t.Parallel()
	got, err := trustedProxies([]netip.Prefix{netip.MustParsePrefix("10.1.2.3/8"),
		netip.MustParsePrefix("::ffff:192.168.0.0/112"), netip.MustParsePrefix("2001:db8::1/32")})
	want := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("2001:db8::/32")}
	if err != nil || !slices.Equal(got, want) {
		t.Errorf("trustedProxies() = %v, %v; want %v", got, err, want)
	}
	cfg := testConfig(t, openStore(t))
	cfg.TrustedProxies = []netip.Prefix{{}}
	if _, err := New(t.Context(), cfg); err == nil || !strings.Contains(err.Error(), "TrustedProxies") {
		t.Errorf("New() with an invalid network = %v, want an error", err)
	}
}

// ADR 0029: an audit event records the client behind the trusted proxies
// and its user agent.
func TestRequestsRecordTheirOrigin(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t, openStore(t))
	cfg.Issuer = signupIssuer
	cfg.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	s := mustNew(t, cfg)
	if _, err := app.CreateUser(t.Context(), s.deps, s.defaultTenant.ID, app.UserSpec{Email: "ada@example.com"}); err != nil {
		t.Fatalf("CreateUser() unexpected error: %v", err)
	}

	form := url.Values{"email": {"ada@example.com"}, "password": {"wrong password"}}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, signupIssuer+"/account/login",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("User-Agent", "TestAgent/1.0")
	req.Header.Set("X-Forwarded-For", "198.51.100.1, 203.0.113.5")
	req.RemoteAddr = "10.1.2.3:5555"
	if res, _ := newBrowser(t, s.Handler()).send(req); res.StatusCode != http.StatusOK {
		t.Fatalf("account sign-in = %d, want the page with the error", res.StatusCode)
	}
	events, err := s.store.AuditEvents().List(t.Context(), s.defaultTenant.ID,
		store.AuditQuery{Type: app.EventSignInFailed, Limit: 10})
	if err != nil || len(events) != 1 {
		t.Fatalf("sign-in failures = %+v, %v; want one", events, err)
	}
	if e := events[0]; e.IP != "203.0.113.5" || e.UserAgent != "TestAgent/1.0" || e.Actor != store.ActorAnonymous {
		t.Errorf("event = %+v, want the client behind the proxy", e)
	}
}

func TestServerDeletesOldAuditEvents(t *testing.T) {
	for _, tc := range []struct {
		name      string
		retention time.Duration
		kept      bool
	}{
		{"retention", time.Minute, false},
		{"forever", -1, true},
		// The default keeps events for 90 days.
		{"default", 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cfg := testConfig(t, openStore(t))
				cfg.AuditRetention = tc.retention
				s := mustNew(t, cfg)
				if _, err := app.CreateUser(t.Context(), s.deps, s.defaultTenant.ID,
					app.UserSpec{Email: "ada@example.com"}); err != nil {
					t.Fatalf("CreateUser() unexpected error: %v", err)
				}
				time.Sleep(cleanupInterval)
				synctest.Wait()
				events, err := s.store.AuditEvents().List(t.Context(), s.defaultTenant.ID,
					store.AuditQuery{Limit: 10})
				if err != nil || (len(events) == 1) != tc.kept || len(events) > 1 {
					t.Errorf("events after the cleanup = %+v, %v; want kept %v", events, err, tc.kept)
				}
			})
		})
	}
}
