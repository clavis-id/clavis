package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/url"
	"slices"
	"strings"
)

// Error codes of token error responses (RFC 6749, section 5.2) and of
// protected resource errors (RFC 6750, section 3.1).
const (
	ErrorInvalidClient        = "invalid_client"
	ErrorInvalidGrant         = "invalid_grant"
	ErrorUnsupportedGrantType = "unsupported_grant_type"
	ErrorInvalidToken         = "invalid_token"
	ErrorInsufficientScope    = "insufficient_scope"
)

// Client authentication methods at the token endpoint (OpenID Connect Core
// 1.0, section 9).
const (
	AuthMethodClientSecretBasic = "client_secret_basic"
	AuthMethodClientSecretPost  = "client_secret_post"
	AuthMethodNone              = "none"
)

// requestIDLength is the length of a request identifier: 128 bits in
// unpadded base64url.
const requestIDLength = 22

// Bounds of a PKCE code verifier (RFC 7636, section 4.1).
const (
	minVerifierLength = 43
	maxVerifierLength = 128
)

// unreservedCharacters are the characters of a code verifier (RFC 7636,
// section 4.1) and of a code challenge (section 4.2).
const unreservedCharacters = base64URLAlphabet + ".~"

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

// ClientCredentials are the credentials a client presents at the token
// endpoint.
type ClientCredentials struct {
	ClientID string
	// Secret is empty for the none method.
	Secret string
	// Method is AuthMethodClientSecretBasic, AuthMethodClientSecretPost or
	// AuthMethodNone.
	Method string
}

// ParseClientCredentials reads the client authentication of a token request
// from its Authorization header and form (RFC 6749, section 2.3.1). A
// request must use one method only. An error is an *Error with the code
// invalid_client, or invalid_request for a malformed request.
func ParseClientCredentials(authorization string, form url.Values) (ClientCredentials, error) {
	formID, ok := single(form, "client_id")
	if !ok {
		return ClientCredentials{}, invalidRequest("client_id is repeated")
	}
	formSecret, ok := single(form, "client_secret")
	if !ok {
		return ClientCredentials{}, invalidRequest("client_secret is repeated")
	}

	if authorization != "" {
		scheme, encoded, found := strings.Cut(authorization, " ")
		if !found || !strings.EqualFold(scheme, "Basic") {
			return ClientCredentials{}, invalidClient("the Authorization header must use the Basic scheme")
		}
		if formSecret != "" {
			return ClientCredentials{}, invalidRequest("the request uses more than one client authentication method")
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
		if err != nil {
			return ClientCredentials{}, invalidClient("the Basic credentials are not valid base64")
		}
		rawID, rawSecret, found := strings.Cut(string(decoded), ":")
		if !found {
			return ClientCredentials{}, invalidClient("the Basic credentials have no secret")
		}
		// RFC 6749, section 2.3.1: both parts are form-urlencoded first.
		id, errID := url.QueryUnescape(rawID)
		secret, errSecret := url.QueryUnescape(rawSecret)
		switch {
		case errID != nil || errSecret != nil:
			return ClientCredentials{}, invalidClient("the Basic credentials are not form-urlencoded")
		case formID != "" && formID != id:
			return ClientCredentials{}, invalidRequest("client_id does not match the Basic credentials")
		case ValidateClientID(id) != nil || secret == "":
			return ClientCredentials{}, invalidClient("the Basic credentials are not valid")
		}
		return ClientCredentials{ClientID: id, Secret: secret, Method: AuthMethodClientSecretBasic}, nil
	}

	if ValidateClientID(formID) != nil {
		return ClientCredentials{}, invalidClient("the request does not identify the client")
	}
	if formSecret != "" {
		return ClientCredentials{ClientID: formID, Secret: formSecret, Method: AuthMethodClientSecretPost}, nil
	}
	return ClientCredentials{ClientID: formID, Method: AuthMethodNone}, nil
}

// TokenRequest holds the parameters of a token request (RFC 6749, sections
// 4.1.3, 4.4.2 and 6) other than client authentication.
type TokenRequest struct {
	GrantType    string
	Code         string
	RedirectURI  string
	CodeVerifier string
	RefreshToken string
	// Scopes holds the requested scopes in order, without duplicates; it is
	// empty when the request has no scope parameter.
	Scopes []string
}

// ParseTokenRequest parses the form of a token request. Errors are *Error
// values for the token error response.
func ParseTokenRequest(form url.Values) (TokenRequest, error) {
	var r TokenRequest
	fields := []struct {
		name string
		dst  *string
	}{
		{"grant_type", &r.GrantType},
		{"code", &r.Code},
		{"redirect_uri", &r.RedirectURI},
		{"code_verifier", &r.CodeVerifier},
		{"refresh_token", &r.RefreshToken},
	}
	for _, f := range fields {
		value, ok := single(form, f.name)
		if !ok {
			return TokenRequest{}, invalidRequest(f.name + " is repeated")
		}
		*f.dst = value
	}
	if r.GrantType == "" {
		return TokenRequest{}, invalidRequest("grant_type is missing")
	}
	if r.CodeVerifier != "" && (len(r.CodeVerifier) < minVerifierLength || len(r.CodeVerifier) > maxVerifierLength ||
		strings.Trim(r.CodeVerifier, unreservedCharacters) != "") {
		return TokenRequest{}, invalidRequest("code_verifier must have 43 to 128 unreserved characters")
	}
	scope, ok := single(form, "scope")
	if !ok {
		return TokenRequest{}, invalidRequest("scope is repeated")
	}
	for token := range strings.SplitSeq(scope, " ") {
		if token == "" || slices.Contains(r.Scopes, token) {
			continue
		}
		if ValidateScope(token) != nil {
			return TokenRequest{}, &Error{Code: ErrorInvalidScope, Description: "scope contains an invalid scope token"}
		}
		r.Scopes = append(r.Scopes, token)
	}
	return r, nil
}

// VerifyPKCE reports whether verifier matches an S256 code challenge (RFC
// 7636, section 4.6). The comparison takes constant time.
func VerifyPKCE(challenge, verifier string) bool {
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}

func invalidClient(description string) *Error {
	return &Error{Code: ErrorInvalidClient, Description: description}
}
