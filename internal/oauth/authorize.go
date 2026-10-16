package oauth

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// Error codes of authorization error responses (RFC 6749, section 4.1.2.1;
// OpenID Connect Core 1.0, sections 3.1.2.6 and 6).
const (
	ErrorInvalidRequest           = "invalid_request"
	ErrorUnauthorizedClient       = "unauthorized_client"
	ErrorUnsupportedResponseType  = "unsupported_response_type"
	ErrorInvalidScope             = "invalid_scope"
	ErrorLoginRequired            = "login_required"
	ErrorRequestNotSupported      = "request_not_supported"
	ErrorRequestURINotSupported   = "request_uri_not_supported"
	ErrorRegistrationNotSupported = "registration_not_supported"
)

// Error is an OAuth error response. Description is meant for the client's
// developer: it never contains request input, and it uses only the
// characters that RFC 6749, section 4.1.2.1, allows in error_description.
type Error struct {
	Code        string
	Description string
}

func (e *Error) Error() string { return e.Code + ": " + e.Description }

// CodeChallengeMethodS256 is the only code challenge method Clavis accepts
// (RFC 7636, section 4.2; ADR 0018).
const CodeChallengeMethodS256 = "S256"

// Values of the prompt parameter (OpenID Connect Core 1.0, section 3.1.2.1).
const (
	PromptNone          = "none"
	PromptLogin         = "login"
	PromptConsent       = "consent"
	PromptSelectAccount = "select_account"
)

// Bounds of authorization request parameters, in bytes. They limit what one
// request can make Clavis store and send back.
const (
	MaxStateLength = 4096
	MaxNonceLength = 4096
	// maxMaxAge keeps max_age within a 32-bit integer: about 68 years.
	maxMaxAge = 1<<31 - 1
)

// s256ChallengeLength is the length of an S256 code challenge: a SHA-256
// hash in unpadded base64url (RFC 7636, section 4.2).
const s256ChallengeLength = 43

// ErrInvalidAuthorizationTarget reports an authorization request whose
// client_id or redirect_uri cannot be used. The error must be shown to the
// user, never sent to the redirect URI (RFC 6749, section 4.1.2.1).
var ErrInvalidAuthorizationTarget = errors.New("invalid client_id or redirect_uri")

// AuthorizationRequest holds the parameters of an authorization request that
// Clavis acts on (RFC 6749, section 4.1.1; OpenID Connect Core 1.0, section
// 3.1.2.1). Requests that use a feature Clavis does not support are rejected;
// other parameters are ignored.
type AuthorizationRequest struct {
	ClientID string
	// RedirectURI is empty when the request omits it.
	RedirectURI string
	// Scopes holds the requested scopes in order, without duplicates.
	Scopes []string
	State  string
	Nonce  string
	// CodeChallenge is the PKCE challenge, empty when the request has none.
	// Its method is always S256.
	CodeChallenge string
	Prompt        []string
	// MaxAge is the max_age parameter in seconds, or -1 when it is absent.
	MaxAge int
}

// OpenID reports whether r is an OpenID Connect request, which is one whose
// scope includes openid (OpenID Connect Core 1.0, section 3.1.2.1).
func (r AuthorizationRequest) OpenID() bool { return slices.Contains(r.Scopes, ScopeOpenID) }

// HasPrompt reports whether r carries the prompt value p.
func (r AuthorizationRequest) HasPrompt(p string) bool { return slices.Contains(r.Prompt, p) }

// AuthorizationTarget returns the client_id and redirect_uri parameters of an
// authorization request; redirectURI is empty when the request omits it. It
// checks their syntax only: the caller must still find the client and match
// the redirect URI against its registered ones. An error wraps
// ErrInvalidAuthorizationTarget.
func AuthorizationTarget(params url.Values) (clientID, redirectURI string, err error) {
	clientID, ok := single(params, "client_id")
	switch {
	case !ok:
		return "", "", fmt.Errorf("%w: client_id is repeated", ErrInvalidAuthorizationTarget)
	case clientID == "":
		return "", "", fmt.Errorf("%w: client_id is missing", ErrInvalidAuthorizationTarget)
	case ValidateClientID(clientID) != nil:
		return "", "", fmt.Errorf("%w: client_id is not a valid client identifier", ErrInvalidAuthorizationTarget)
	}
	redirectURI, ok = single(params, "redirect_uri")
	if !ok {
		return "", "", fmt.Errorf("%w: redirect_uri is repeated", ErrInvalidAuthorizationTarget)
	}
	return clientID, redirectURI, nil
}

// ParseAuthorizationRequest parses an authorization request for the
// authorization code flow. Call it once AuthorizationTarget has succeeded and
// the client and redirect URI are known to be valid. An error is an *Error to
// send to the redirect URI; the returned request then holds the state
// parameter when it is valid, so the response can carry it.
func ParseAuthorizationRequest(params url.Values) (AuthorizationRequest, error) {
	var r AuthorizationRequest
	r.ClientID, r.RedirectURI, _ = AuthorizationTarget(params)

	// The state goes first, so every later error can carry it.
	state, ok := single(params, "state")
	switch {
	case !ok:
		return r, invalidRequest("state is repeated")
	case len(state) > MaxStateLength || !visibleASCII(state):
		return r, invalidRequest("state must have at most 4096 printable ASCII characters")
	}
	r.State = state

	// OpenID Connect Core 1.0, section 6, and section 7.2.1 for registration.
	for _, unsupported := range []struct{ param, code string }{
		{"request", ErrorRequestNotSupported},
		{"request_uri", ErrorRequestURINotSupported},
		{"registration", ErrorRegistrationNotSupported},
	} {
		if params.Has(unsupported.param) {
			return r, &Error{Code: unsupported.code, Description: unsupported.param + " is not supported"}
		}
	}

	responseType, ok := single(params, "response_type")
	switch {
	case !ok:
		return r, invalidRequest("response_type is repeated")
	case responseType == "":
		return r, invalidRequest("response_type is missing")
	case responseType != "code":
		// OAuth 2.1 keeps only the authorization code flow.
		return r, &Error{Code: ErrorUnsupportedResponseType, Description: "only response_type code is supported"}
	}
	switch mode, ok := single(params, "response_mode"); {
	case !ok:
		return r, invalidRequest("response_mode is repeated")
	case mode != "" && mode != "query":
		return r, invalidRequest("only response_mode query is supported")
	}

	scope, ok := single(params, "scope")
	switch {
	case !ok:
		return r, invalidRequest("scope is repeated")
	case scope == "":
		// RFC 6749, section 3.3: without a default, a request without a
		// scope fails.
		return r, &Error{Code: ErrorInvalidScope, Description: "scope is missing"}
	}
	for token := range strings.SplitSeq(scope, " ") {
		if token == "" || slices.Contains(r.Scopes, token) {
			continue
		}
		if ValidateScope(token) != nil {
			return r, &Error{Code: ErrorInvalidScope, Description: "scope contains an invalid scope token"}
		}
		r.Scopes = append(r.Scopes, token)
	}
	if len(r.Scopes) == 0 {
		return r, &Error{Code: ErrorInvalidScope, Description: "scope is missing"}
	}

	if err := r.parsePKCE(params); err != nil {
		return r, err
	}

	nonce, ok := single(params, "nonce")
	switch {
	case !ok:
		return r, invalidRequest("nonce is repeated")
	case len(nonce) > MaxNonceLength || !visibleASCII(nonce):
		return r, invalidRequest("nonce must have at most 4096 printable ASCII characters")
	}
	r.Nonce = nonce

	if err := r.parsePrompt(params); err != nil {
		return r, err
	}
	err := r.parseMaxAge(params)
	return r, err
}

// parsePKCE reads code_challenge and code_challenge_method (RFC 7636,
// section 4.3). A challenge without a method uses the plain method, which
// Clavis rejects (RFC 9700, section 2.1.1).
func (r *AuthorizationRequest) parsePKCE(params url.Values) error {
	challenge, ok := single(params, "code_challenge")
	if !ok {
		return invalidRequest("code_challenge is repeated")
	}
	method, ok := single(params, "code_challenge_method")
	switch {
	case !ok:
		return invalidRequest("code_challenge_method is repeated")
	case challenge == "" && method != "":
		return invalidRequest("code_challenge_method is present without code_challenge")
	case challenge == "":
		return nil
	case method != CodeChallengeMethodS256:
		return invalidRequest("code_challenge_method must be S256")
	case len(challenge) != s256ChallengeLength || strings.Trim(challenge, base64URLAlphabet) != "":
		return invalidRequest("code_challenge must be a SHA-256 hash in unpadded base64url")
	}
	r.CodeChallenge = challenge
	return nil
}

// base64URLAlphabet is the alphabet of base64url (RFC 4648, section 5).
const base64URLAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// parsePrompt reads the prompt parameter (OpenID Connect Core 1.0, section
// 3.1.2.1). Unknown values and none combined with another value are errors.
func (r *AuthorizationRequest) parsePrompt(params url.Values) error {
	prompt, ok := single(params, "prompt")
	if !ok {
		return invalidRequest("prompt is repeated")
	}
	for value := range strings.SplitSeq(prompt, " ") {
		switch value {
		case "":
			continue
		case PromptNone, PromptLogin, PromptConsent, PromptSelectAccount:
		default:
			return invalidRequest("prompt contains an unsupported value")
		}
		if !slices.Contains(r.Prompt, value) {
			r.Prompt = append(r.Prompt, value)
		}
	}
	if r.HasPrompt(PromptNone) && len(r.Prompt) > 1 {
		return invalidRequest("prompt none cannot be combined with other values")
	}
	return nil
}

// parseMaxAge reads the max_age parameter (OpenID Connect Core 1.0, section
// 3.1.2.1): a number of seconds.
func (r *AuthorizationRequest) parseMaxAge(params url.Values) error {
	r.MaxAge = -1
	maxAge, ok := single(params, "max_age")
	switch {
	case !ok:
		return invalidRequest("max_age is repeated")
	case maxAge == "":
		return nil
	case strings.Trim(maxAge, "0123456789") != "":
		return invalidRequest("max_age must be a non-negative number of seconds")
	}
	n, err := strconv.Atoi(maxAge)
	if err != nil || n > maxMaxAge {
		return invalidRequest("max_age is too large")
	}
	r.MaxAge = n
	return nil
}

// single returns the value of a parameter that must not repeat (RFC 6749,
// section 3.1). An empty value counts as an omitted parameter. ok is false
// when the parameter repeats.
func single(params url.Values, name string) (value string, ok bool) {
	switch values := params[name]; len(values) {
	case 0:
		return "", true
	case 1:
		return values[0], true
	default:
		return "", false
	}
}

// visibleASCII reports whether s contains only the characters that RFC 6749,
// appendix A.5, allows in state: %x20-7E.
func visibleASCII(s string) bool {
	for _, c := range []byte(s) {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

func invalidRequest(description string) *Error {
	return &Error{Code: ErrorInvalidRequest, Description: description}
}

// AuthorizationResponseURI returns redirectURI with params added to its
// query. An existing query is kept byte for byte, as RFC 6749, section
// 3.1.2, requires; redirectURI must have no fragment, which registration
// guarantees.
func AuthorizationResponseURI(redirectURI string, params url.Values) string {
	switch {
	case !strings.Contains(redirectURI, "?"):
		return redirectURI + "?" + params.Encode()
	case strings.HasSuffix(redirectURI, "?"), strings.HasSuffix(redirectURI, "&"):
		return redirectURI + params.Encode()
	default:
		return redirectURI + "&" + params.Encode()
	}
}
