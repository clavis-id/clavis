package oauth

import (
	"errors"
	"fmt"
)

// MaxScopeLength is the longest scope token, in bytes.
const MaxScopeLength = 128

// ErrInvalidScope reports a scope token that does not follow RFC 6749,
// section 3.3.
var ErrInvalidScope = errors.New("invalid scope")

// ValidateScope reports whether s is a single scope token: 1 to 128
// characters from %x21, %x23-5B and %x5D-7E, that is, printable ASCII except
// space, double quote and backslash (RFC 6749, section 3.3).
func ValidateScope(s string) error {
	if s == "" || len(s) > MaxScopeLength {
		return fmt.Errorf("%w: must have 1 to %d characters", ErrInvalidScope, MaxScopeLength)
	}
	for _, c := range []byte(s) {
		if c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
			return fmt.Errorf("%w: %q must contain only printable ASCII characters other than "+
				"space, double quote and backslash", ErrInvalidScope, s)
		}
	}
	return nil
}
