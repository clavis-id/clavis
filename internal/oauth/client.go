package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// MaxClientIDLength is the longest client identifier, in bytes.
const MaxClientIDLength = 128

// ErrInvalidClientID reports a client identifier that does not follow
// ValidateClientID.
var ErrInvalidClientID = errors.New("invalid client ID")

// clientIDEncoding writes generated client identifiers in lowercase letters
// and digits only.
var clientIDEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// NewClientID returns a random client identifier: 128 bits in 26 lowercase
// letters and digits.
func NewClientID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // Never fails; see crypto/rand.Read.
	return clientIDEncoding.EncodeToString(b)
}

// ValidateClientID reports whether id can identify a client: 1 to 128 ASCII
// letters, digits and the characters "-", ".", "_" and "~", starting with a
// letter or digit. RFC 6749, appendix A.1, allows any printable ASCII
// character; this subset needs no encoding in URLs, forms and HTTP Basic
// credentials (RFC 6749, section 2.3.1), and cannot be read as a command-line
// flag.
func ValidateClientID(id string) error {
	if id == "" || len(id) > MaxClientIDLength {
		return fmt.Errorf("%w: must have 1 to %d characters", ErrInvalidClientID, MaxClientIDLength)
	}
	for i, c := range []byte(id) {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case i > 0 && strings.IndexByte("-._~", c) >= 0:
		default:
			return fmt.Errorf("%w: %q must start with a letter or digit and contain only letters, "+
				"digits, hyphens, periods, underscores and tildes", ErrInvalidClientID, id)
		}
	}
	return nil
}

// NewClientSecret returns a new client secret and the hash to store for it.
// Clavis generates every secret: 256 random bits, base64url encoded
// (ADR 0014).
func NewClientSecret() (secret string, hash []byte) {
	b := make([]byte, 32)
	_, _ = rand.Read(b) // Never fails; see crypto/rand.Read.
	secret = base64.RawURLEncoding.EncodeToString(b)
	return secret, HashClientSecret(secret)
}

// HashClientSecret returns the SHA-256 hash of secret, which is what Clavis
// stores. A fast hash suffices because generated secrets have 256 bits of
// entropy (ADR 0014).
func HashClientSecret(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

// ClientSecretMatches reports whether secret hashes to hash. The comparison
// takes constant time.
func ClientSecretMatches(hash []byte, secret string) bool {
	if len(hash) != sha256.Size {
		return false
	}
	return subtle.ConstantTimeCompare(HashClientSecret(secret), hash) == 1
}
