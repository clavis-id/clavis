package oauth

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
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
