package issuer

import (
	"errors"
	"testing"
)

func TestParse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		raw     string
		wantErr bool
	}{
		{raw: "https://auth.example.com"},
		{raw: "https://auth.example.com:8443"},
		{raw: "https://example.com/auth"},
		{raw: "https://example.com/t/acme"},
		{raw: "http://localhost:8080"},
		{raw: "http://LOCALHOST:8080"},
		{raw: "http://127.0.0.1:8080"},
		{raw: "http://[::1]:8080"},
		{raw: "", wantErr: true},
		{raw: "auth.example.com", wantErr: true},
		{raw: "/auth", wantErr: true},
		{raw: "https://", wantErr: true},
		{raw: "http://auth.example.com", wantErr: true},
		{raw: "http://10.0.0.1:8080", wantErr: true},
		{raw: "http://localhost.example.com", wantErr: true},
		{raw: "ftp://auth.example.com", wantErr: true},
		{raw: "https://user:pass@auth.example.com", wantErr: true},
		{raw: "https://auth.example.com?tenant=a", wantErr: true},
		{raw: "https://auth.example.com?", wantErr: true},
		{raw: "https://auth.example.com#section", wantErr: true},
		{raw: "https://auth.example.com#", wantErr: true},
		{raw: "https://auth.example.com/", wantErr: true},
		{raw: "https://example.com/auth/", wantErr: true},
		{raw: "https://auth.example.com/%zz", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			t.Parallel()
			u, err := Parse(tt.raw)
			if tt.wantErr {
				if !errors.Is(err, ErrInvalid) {
					t.Fatalf("Parse(%q) error = %v, want ErrInvalid", tt.raw, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse(%q) unexpected error: %v", tt.raw, err)
			}
			if got := u.String(); got != tt.raw {
				t.Errorf("Parse(%q).String() = %q, want the input unchanged", tt.raw, got)
			}
		})
	}
}

func FuzzParse(f *testing.F) {
	for _, seed := range []string{
		"https://auth.example.com",
		"http://localhost:8080",
		"https://example.com/t/acme",
		"https://user@example.com",
		"https://example.com?#",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		u, err := Parse(raw)
		if err != nil {
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("Parse(%q) returned an error not wrapping ErrInvalid: %v", raw, err)
			}
			return
		}
		if u.Scheme != "https" && !isLoopback(u.Hostname()) {
			t.Fatalf("Parse(%q) accepted a non-https issuer for a non-loopback host", raw)
		}
		if u.RawQuery != "" || u.Fragment != "" || u.User != nil {
			t.Fatalf("Parse(%q) accepted a query, fragment or user information", raw)
		}
	})
}
