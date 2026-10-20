package oauth

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Error codes of authorization error responses (RFC 6749, section 4.1.2.1;
// OpenID Connect Core 1.0, sections 3.1.2.6 and 6).
const (
	ErrorInvalidRequest           = "invalid_request"
	ErrorUnauthorizedClient       = "unauthorized_client"
	ErrorAccessDenied             = "access_denied"
	ErrorUnsupportedResponseType  = "unsupported_response_type"
	ErrorInvalidScope             = "invalid_scope"
	ErrorLoginRequired            = "login_required"
	ErrorConsentRequired          = "consent_required"
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

// Response modes Clavis supports: the parameters of the response go in the
// query of the redirect URI, or the browser posts them to it (OAuth 2.0
// Multiple Response Type Encoding Practices, section 2.1; OAuth 2.0 Form Post
// Response Mode, section 2).
const (
	ResponseModeQuery    = "query"
	ResponseModeFormPost = "form_post"
)

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
	MaxStateLength     = 4096
	MaxNonceLength     = 4096
	MaxLoginHintLength = 1024
	// MaxIDTokenHintLength leaves ample room for the ID tokens Clavis
	// issues, which hold a few claims.
	MaxIDTokenHintLength = 16 << 10
	MaxClaimsLength      = 4096
	// MaxUILocalesLength holds several language tags.
	MaxUILocalesLength = 256
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
	// ResponseMode is ResponseModeQuery or ResponseModeFormPost.
	ResponseMode string
	Nonce        string
	// CodeChallenge is the PKCE challenge, empty when the request has none.
	// Its method is always S256.
	CodeChallenge string
	Prompt        []string
	// MaxAge is the max_age parameter in seconds, or -1 when it is absent.
	MaxAge int
	// LoginHint is the login_hint parameter. Its only check is that it is
	// text of bounded length; its meaning is up to the caller.
	LoginHint string
	// IDTokenHint is the id_token_hint parameter, which has the syntax of a
	// compact JWS. The caller verifies it.
	IDTokenHint string
	// Claims holds the claims parameter (OpenID Connect Core 1.0, section
	// 5.5).
	Claims ClaimsRequest
	// UILocales is the ui_locales parameter, or empty; see UILocales.
	UILocales string
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
// send to the redirect URI; the returned request then holds the state and
// response_mode parameters when they are valid, so the response can carry
// the state in the requested response mode.
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

	// The response mode goes next, so every later error goes back the way the
	// client asked. An error about the response mode itself uses the default.
	switch mode, ok := single(params, "response_mode"); {
	case !ok:
		return r, invalidRequest("response_mode is repeated")
	case mode == "" || mode == ResponseModeQuery:
		r.ResponseMode = ResponseModeQuery
	case mode == ResponseModeFormPost:
		r.ResponseMode = ResponseModeFormPost
	default:
		return r, invalidRequest("only response_mode query and form_post are supported")
	}

	// OpenID Connect Core 1.0, section 6, and section 7.2.1 for registration.
	// Like any parameter, an empty one counts as omitted.
	for _, unsupported := range []struct{ param, code string }{
		{"request", ErrorRequestNotSupported},
		{"request_uri", ErrorRequestURINotSupported},
		{"registration", ErrorRegistrationNotSupported},
	} {
		if value, ok := single(params, unsupported.param); !ok || value != "" {
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
	if err := r.parseMaxAge(params); err != nil {
		return r, err
	}
	if err := r.parseHints(params); err != nil {
		return r, err
	}
	r.UILocales = UILocales(params)

	claims, ok := single(params, "claims")
	switch {
	case !ok:
		return r, invalidRequest("claims is repeated")
	case len(claims) > MaxClaimsLength:
		return r, invalidRequest("claims is too long")
	case claims != "":
		var err error
		if r.Claims, err = ParseClaimsRequest(claims); err != nil {
			return r, invalidRequest("claims must be a JSON object as defined in OpenID Connect Core 1.0, section 5.5")
		}
	}
	return r, nil
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

// parseHints reads login_hint and id_token_hint (OpenID Connect Core 1.0,
// section 3.1.2.1).
func (r *AuthorizationRequest) parseHints(params url.Values) error {
	hint, ok := single(params, "login_hint")
	switch {
	case !ok:
		return invalidRequest("login_hint is repeated")
	case len(hint) > MaxLoginHintLength || !printableText(hint):
		return invalidRequest("login_hint must be text of at most 1024 bytes")
	}
	r.LoginHint = hint
	hint, ok = single(params, "id_token_hint")
	switch {
	case !ok:
		return invalidRequest("id_token_hint is repeated")
	case len(hint) > MaxIDTokenHintLength || !compactJWS(hint):
		return invalidRequest("id_token_hint must be an ID token")
	}
	r.IDTokenHint = hint
	return nil
}

// UILocales returns the ui_locales parameter of an authorization or logout
// request: the user's preferred languages for the hosted pages, as BCP 47
// tags separated by spaces (OpenID Connect Core 1.0, section 3.1.2.1;
// RP-Initiated Logout 1.0, section 2). The parameter only expresses a
// preference, so a value that is repeated, longer than MaxUILocalesLength
// or not printable ASCII is ignored rather than refused.
func UILocales(params url.Values) string {
	locales, ok := single(params, "ui_locales")
	if !ok || len(locales) > MaxUILocalesLength || !visibleASCII(locales) {
		return ""
	}
	return locales
}

// printableText reports whether s is valid UTF-8 without control
// characters.
func printableText(s string) bool {
	return utf8.ValidString(s) && !strings.ContainsFunc(s, unicode.IsControl)
}

// compactJWS reports whether s is empty or has the syntax of a compact JWS:
// three base64url parts separated by dots (RFC 7515, section 7.1).
func compactJWS(s string) bool {
	if s == "" {
		return true
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" || strings.Trim(part, base64URLAlphabet) != "" {
			return false
		}
	}
	return true
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
