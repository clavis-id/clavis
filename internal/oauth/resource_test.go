package oauth

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateResourceIdentifier(t *testing.T) {
	t.Parallel()
	for _, valid := range []string{
		"https://api.example.com",
		"https://api.example.com/orders",
		"urn:example:orders",
		"http://localhost:8080/api",
		"https://api.example.com/" + strings.Repeat("a", MaxResourceIdentifierLength-len("https://api.example.com/")),
	} {
		if err := ValidateResourceIdentifier(valid); err != nil {
			t.Errorf("ValidateResourceIdentifier(%q) = %v, want nil", valid, err)
		}
	}
	for name, invalid := range map[string]string{
		"empty":     "",
		"too long":  "https://api.example.com/" + strings.Repeat("a", MaxResourceIdentifierLength),
		"relative":  "/orders",
		"no scheme": "api.example.com",
		"fragment":  "https://api.example.com/#orders",
		"space":     "https://api.example.com/a b",
		"userinfo":  "https://user@api.example.com",
		"bad port":  "https://api.example.com:port",
	} {
		if err := ValidateResourceIdentifier(invalid); !errors.Is(err, ErrInvalidResourceIdentifier) {
			t.Errorf("%s: ValidateResourceIdentifier(%q) = %v, want ErrInvalidResourceIdentifier", name, invalid, err)
		}
	}
}
