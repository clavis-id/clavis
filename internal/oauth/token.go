package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

// requestIDLength is the length of a request identifier: 128 bits in
// unpadded base64url.
const requestIDLength = 22

// NewToken returns a random 256-bit value in unpadded base64url. Clavis uses
// tokens for authorization codes, session cookies and other bearer values
// that it stores only as hashes (ADR 0013, ADR 0014).
func NewToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b) // Never fails; see crypto/rand.Read.
	return base64.RawURLEncoding.EncodeToString(b)
}

// HashToken returns the SHA-256 hash under which a token is stored. A fast
// hash suffices because tokens have 256 bits of entropy.
func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// NewRequestID returns a random 128-bit identifier in unpadded base64url,
// which names a stored authorization request (ADR 0013).
func NewRequestID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // Never fails; see crypto/rand.Read.
	return base64.RawURLEncoding.EncodeToString(b)
}

// ValidRequestID reports whether id has the form NewRequestID returns, so
// other values can be rejected without a lookup.
func ValidRequestID(id string) bool {
	return len(id) == requestIDLength && strings.Trim(id, base64URLAlphabet) == ""
}
