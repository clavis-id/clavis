package oauth

import (
	"errors"
	"net/url"
	"strings"
	"testing"
)

func TestValidateRedirectURI(t *testing.T) {
	t.Parallel()
	valid := []string{
		"https://app.example.com/callback",
		"https://app.example.com",
		"https://app.example.com:8443/callback?tenant=acme&x=1",
		"https://app.example.com/a/b%20c",
		"https://[2001:db8::1]/callback",
		"http://127.0.0.1/callback",
		"http://127.0.0.1:8080/callback",
		"http://[::1]/callback",
		"http://[::1]:65535",
		"http://localhost:3000/callback",
		"com.example.app:/oauth2redirect/example-provider",
		"com.example.app://callback",
		"https://app.example.com/" + strings.Repeat("a", MaxRedirectURILength-len("https://app.example.com/")),
	}
	for _, raw := range valid {
		if err := ValidateRedirectURI(raw); err != nil {
			t.Errorf("ValidateRedirectURI(%q) = %v, want nil", raw, err)
		}
	}

	invalid := map[string]string{
		"empty":                     "",
		"too long":                  "https://app.example.com/" + strings.Repeat("a", MaxRedirectURILength),
		"relative":                  "/callback",
		"no scheme":                 "app.example.com/callback",
		"fragment":                  "https://app.example.com/callback#done",
		"empty fragment":            "https://app.example.com/callback#",
		"wildcard host":             "https://*.example.com/callback",
		"wildcard path":             "https://app.example.com/*",
		"space":                     "https://app.example.com/a b",
		"tab":                       "https://app.example.com/\tb",
		"newline":                   "https://app.example.com/\nb",
		"non-ASCII host":            "https://exämple.com/callback",
		"backslash":                 `https://app.example.com\.evil.com/`,
		"angle bracket":             "https://app.example.com/<script>",
		"user information":          "https://app.example.com@evil.com/callback",
		"user and password":         "https://user:pass@app.example.com/callback",
		"uppercase scheme":          "HTTPS://app.example.com/callback",
		"mixed-case scheme":         "Https://app.example.com/callback",
		"uppercase host":            "https://App.Example.com/callback",
		"percent-encoded host":      "https://app%2eexample.com/callback",
		"https without host":        "https:///callback",
		"https with only a port":    "https://:443/callback",
		"port zero":                 "https://app.example.com:0/callback",
		"port too large":            "https://app.example.com:65536/callback",
		"invalid port":              "https://app.example.com:http/callback",
		"invalid escape":            "https://app.example.com/%zz",
		"http on a public host":     "http://app.example.com/callback",
		"http on a private IP":      "http://192.168.1.10/callback",
		"http on another loopback":  "http://127.0.0.2/callback",
		"http on long-form ::1":     "http://[0:0:0:0:0:0:0:1]/callback",
		"http on localhost.":        "http://localhost./callback",
		"http on LOCALHOST":         "http://LOCALHOST/callback",
		"javascript":                "javascript:alert(1)",
		"javascript with slashes":   "javascript://app.example.com/%0aalert(1)",
		"data":                      "data:text/html,hello",
		"file":                      "file:///etc/passwd",
		"custom scheme without dot": "myapp://callback",
		"opaque custom scheme":      "com.example.app:callback",
		"mailto":                    "mailto:admin@example.com",
	}
	for name, raw := range invalid {
		if err := ValidateRedirectURI(raw); !errors.Is(err, ErrInvalidRedirectURI) {
			t.Errorf("%s: ValidateRedirectURI(%q) = %v, want ErrInvalidRedirectURI", name, raw, err)
		}
	}
}

func TestMatchRedirectURI(t *testing.T) {
	t.Parallel()
	registered := []string{
		"https://app.example.com/callback",
		"https://app.example.com/callback?tenant=acme",
		"http://127.0.0.1/native",
		"http://[::1]:8080/native",
		"http://localhost:3000/callback",
		"com.example.app:/callback",
	}
	tests := []struct {
		requested string
		want      bool
	}{
		{"https://app.example.com/callback", true},
		{"https://app.example.com/callback?tenant=acme", true},
		{"com.example.app:/callback", true},
		{"http://localhost:3000/callback", true},

		// RFC 8252, section 7.3: any port on a loopback IP literal.
		{"http://127.0.0.1:51234/native", true},
		{"http://127.0.0.1:1/native", true},
		{"http://127.0.0.1:65535/native", true},
		{"http://127.0.0.1/native", true},
		{"http://[::1]/native", true},
		{"http://[::1]:49152/native", true},

		// Anything else must match exactly.
		{"https://app.example.com/callback/", false},
		{"https://app.example.com/Callback", false},
		{"https://app.example.com/callback?tenant=other", false},
		{"https://app.example.com/callback?tenant=acme&x=1", false},
		{"https://app.example.com/callback#fragment", false},
		{"https://APP.example.com/callback", false},
		{"HTTPS://app.example.com/callback", false},
		{"https://app.example.com:443/callback", false},
		{"https://app.example.com/callback/../callback", false},
		{"https://app.example.com/%63allback", false},
		{"https://app.example.com.evil.com/callback", false},
		{"https://app.example.com@evil.com/callback", false},
		{"http://app.example.com/callback", false},
		{"http://localhost:3001/callback", false},
		{"http://localhost/callback", false},
		{"com.example.app://callback", false},
		{"", false},

		// The port exception does not loosen the rest of the URI.
		{"http://127.0.0.1:8080/native/other", false},
		{"http://127.0.0.1:8080/native?x=1", false},
		{"http://127.0.0.1:8080/native#x", false},
		{"https://127.0.0.1:8080/native", false},
		{"http://127.0.0.10/native", false},
		{"http://127.0.0.1.evil.com/native", false},
		{"http://127.0.0.1:8080@evil.com/native", false},
		{"http://127.0.0.1:8080.evil.com/native", false},
		{"http://127.0.0.1:/native", false},
		{"http://127.0.0.1:0/native", false},
		{"http://127.0.0.1:65536/native", false},
		{"http://127.0.0.1:123456/native", false},
		{"http://127.0.0.1:-1/native", false},
		{"http://localhost:8080/native", false},
		{"http://[::1]:8080/other", false},
	}
	for _, tt := range tests {
		if got := MatchRedirectURI(registered, tt.requested); got != tt.want {
			t.Errorf("MatchRedirectURI(%q) = %v, want %v", tt.requested, got, tt.want)
		}
	}
	if MatchRedirectURI(nil, "https://app.example.com/callback") {
		t.Error("MatchRedirectURI with no registered URIs = true, want false")
	}
}

// FuzzValidateRedirectURI checks that every accepted redirect URI parses,
// carries no fragment or user information, uses an allowed scheme and
// matches itself.
func FuzzValidateRedirectURI(f *testing.F) {
	for _, seed := range []string{
		"https://app.example.com/callback?x=1",
		"http://127.0.0.1:8080/cb",
		"http://[::1]/cb",
		"http://localhost/cb",
		"com.example.app:/cb",
		"https://user@app.example.com/",
		"https://app.example.com/#x",
		"javascript:alert(1)",
		"https://[::1%25en0]/",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if ValidateRedirectURI(raw) != nil {
			return
		}
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("accepted %q, which does not parse: %v", raw, err)
		}
		if u.Fragment != "" || strings.Contains(raw, "#") || u.User != nil || u.Opaque != "" {
			t.Errorf("accepted %q, which has a fragment, user information or an opaque part", raw)
		}
		switch u.Scheme {
		case "https":
			if u.Hostname() == "" {
				t.Errorf("accepted https URI %q without a host", raw)
			}
		case "http":
			if h := u.Hostname(); h != "127.0.0.1" && h != "::1" && h != "localhost" {
				t.Errorf("accepted http URI %q on host %q", raw, h)
			}
		default:
			if !strings.Contains(u.Scheme, ".") {
				t.Errorf("accepted %q with scheme %q", raw, u.Scheme)
			}
		}
		if !MatchRedirectURI([]string{raw}, raw) {
			t.Errorf("accepted %q, which does not match itself", raw)
		}
	})
}

// FuzzMatchRedirectURI checks that a requested URI matches a valid registered
// one only when it is the same string, or the same loopback URI with another
// port, so a match never sends the browser to another host.
func FuzzMatchRedirectURI(f *testing.F) {
	for _, seed := range [][2]string{
		{"https://app.example.com/callback", "https://app.example.com/callback"},
		{"http://127.0.0.1/cb", "http://127.0.0.1:8080/cb"},
		{"http://[::1]:80/cb", "http://[::1]/cb"},
		{"http://127.0.0.1/cb", "http://127.0.0.1:8080@evil.com/cb"},
		{"http://127.0.0.1/cb", "http://127.0.0.1.evil.com/cb"},
		{"http://localhost/cb", "http://localhost:8080/cb"},
	} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, registered, requested string) {
		if ValidateRedirectURI(registered) != nil || !MatchRedirectURI([]string{registered}, requested) {
			return
		}
		if requested == registered {
			return
		}
		r, err := url.Parse(registered)
		if err != nil {
			t.Fatalf("valid registered URI %q does not parse: %v", registered, err)
		}
		q, err := url.Parse(requested)
		if err != nil {
			t.Fatalf("%q matched %q but does not parse: %v", requested, registered, err)
		}
		loopback := func(u *url.URL) bool {
			return u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")
		}
		if !loopback(r) || !loopback(q) || q.User != nil || strings.Contains(requested, "#") ||
			r.Hostname() != q.Hostname() || r.EscapedPath() != q.EscapedPath() || r.RawQuery != q.RawQuery {
			t.Errorf("%q matched %q, but they differ in more than the loopback port", requested, registered)
		}
	})
}
