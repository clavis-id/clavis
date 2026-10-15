// Package oauth implements the rules of OAuth 2.1 that depend on neither
// storage nor transport: client identifiers and secrets, redirect URI
// registration and matching, and scope syntax.
package oauth

// Grant types that a client can be allowed to use.
const (
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeRefreshToken      = "refresh_token"
	GrantTypeClientCredentials = "client_credentials"
)

// OpenID Connect scopes (OpenID Connect Core 1.0, sections 5.4 and 11).
const (
	ScopeOpenID        = "openid"
	ScopeProfile       = "profile"
	ScopeEmail         = "email"
	ScopeOfflineAccess = "offline_access"
)
