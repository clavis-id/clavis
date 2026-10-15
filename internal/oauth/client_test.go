package oauth

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func TestNewClientIDIsRandomAndValid(t *testing.T) {
	t.Parallel()
	seen := make(map[string]bool)
	for range 100 {
		id := NewClientID()
		if len(id) != 26 {
			t.Errorf("NewClientID() = %q, want 26 characters", id)
		}
		if err := ValidateClientID(id); err != nil {
			t.Errorf("NewClientID() = %q, which is invalid: %v", id, err)
		}
		if strings.ToLower(id) != id {
			t.Errorf("NewClientID() = %q, want lowercase", id)
		}
		if seen[id] {
			t.Fatalf("NewClientID() repeated %q", id)
		}
		seen[id] = true
	}
}

func TestValidateClientID(t *testing.T) {
	t.Parallel()
	for _, id := range []string{"a", "web-app", "Web.App_2~x", "0abc", strings.Repeat("x", MaxClientIDLength)} {
		if err := ValidateClientID(id); err != nil {
			t.Errorf("ValidateClientID(%q) = %v, want nil", id, err)
		}
	}
	for _, id := range []string{
		"", strings.Repeat("x", MaxClientIDLength+1), "-app", ".app", "_app", "~app",
		"web app", "web:app", "web/app", "web%20app", "app\n", "apé", "a\x00",
	} {
		if err := ValidateClientID(id); !errors.Is(err, ErrInvalidClientID) {
			t.Errorf("ValidateClientID(%q) = %v, want ErrInvalidClientID", id, err)
		}
	}
}

func TestNewClientSecret(t *testing.T) {
	t.Parallel()
	secret, hash := NewClientSecret()
	raw, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil || len(raw) != 32 {
		t.Fatalf("secret %q is not 256 bits in base64url: %d bytes, %v", secret, len(raw), err)
	}
	if want := sha256.Sum256([]byte(secret)); !bytes.Equal(hash, want[:]) {
		t.Errorf("hash = %x, want the SHA-256 of the secret", hash)
	}
	if other, _ := NewClientSecret(); other == secret {
		t.Error("NewClientSecret() returned the same secret twice")
	}
}

func TestClientSecretMatches(t *testing.T) {
	t.Parallel()
	secret, hash := NewClientSecret()
	if !ClientSecretMatches(hash, secret) {
		t.Error("the secret does not match its own hash")
	}
	for name, candidate := range map[string]string{
		"other secret":   "x" + secret[1:],
		"prefix":         secret[:len(secret)-1],
		"empty":          "",
		"hash as secret": string(hash),
	} {
		if ClientSecretMatches(hash, candidate) {
			t.Errorf("%s: ClientSecretMatches() = true, want false", name)
		}
	}
	// A missing or truncated hash, such as the nil hash of a public client,
	// never matches.
	for _, h := range [][]byte{nil, {}, hash[:16]} {
		if ClientSecretMatches(h, secret) {
			t.Errorf("ClientSecretMatches(%x) = true, want false", h)
		}
	}
	emptyHash := HashClientSecret("")
	if !ClientSecretMatches(emptyHash, "") {
		t.Error("an empty secret does not match its own hash")
	}
}

func TestValidateScope(t *testing.T) {
	t.Parallel()
	for _, s := range []string{"openid", "orders:read", "https://api.example.com/orders.read", "!#[]~",
		strings.Repeat("s", MaxScopeLength)} {
		if err := ValidateScope(s); err != nil {
			t.Errorf("ValidateScope(%q) = %v, want nil", s, err)
		}
	}
	for _, s := range []string{"", "openid profile", "a\"b", `a\b`, "a\tb", "a\x7f", "é",
		strings.Repeat("s", MaxScopeLength+1)} {
		if err := ValidateScope(s); !errors.Is(err, ErrInvalidScope) {
			t.Errorf("ValidateScope(%q) = %v, want ErrInvalidScope", s, err)
		}
	}
}
