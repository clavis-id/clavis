package oauth

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// MaxResourceIdentifierLength is the longest API resource identifier, in
// bytes.
const MaxResourceIdentifierLength = 2000

// ErrInvalidResourceIdentifier reports an API resource identifier that does
// not follow ValidateResourceIdentifier.
var ErrInvalidResourceIdentifier = errors.New("invalid API resource identifier")

// ValidateResourceIdentifier reports whether id can identify an API
// resource: an absolute URI without a fragment (RFC 8707, section 2), such
// as https://api.example.com/orders or urn:example:orders, made only of the
// characters RFC 3986 allows.
func ValidateResourceIdentifier(id string) error {
	if id == "" || len(id) > MaxResourceIdentifierLength {
		return fmt.Errorf("%w: must have 1 to %d characters", ErrInvalidResourceIdentifier, MaxResourceIdentifierLength)
	}
	for i := range len(id) {
		if strings.IndexByte(uriCharacters, id[i]) < 0 {
			return fmt.Errorf("%w: %q must contain only the characters that RFC 3986 allows in a URI",
				ErrInvalidResourceIdentifier, id)
		}
	}
	u, err := url.Parse(id)
	switch {
	case err != nil || u.Scheme == "":
		return fmt.Errorf("%w: %q must be an absolute URI", ErrInvalidResourceIdentifier, id)
	case strings.Contains(id, "#"):
		return fmt.Errorf("%w: %q must not contain a fragment", ErrInvalidResourceIdentifier, id)
	case u.User != nil:
		return fmt.Errorf("%w: %q must not contain user information", ErrInvalidResourceIdentifier, id)
	}
	return nil
}
