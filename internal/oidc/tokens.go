package oidc

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
)

// Media types of the typ header of Clavis tokens. Access tokens follow RFC
// 9068, section 2.1; ID tokens use the generic JWT type.
const (
	AccessTokenType = "at+jwt"
	IDTokenType     = "JWT"
)

// IDTokenSigningAlgorithm signs every ID token. Clients cannot choose
// another algorithm yet, so the metadata announces only this one even when
// keys of other algorithms are published.
const IDTokenSigningAlgorithm = "RS256"

// IDTokenClaims are the claims of an ID token (OpenID Connect Core 1.0,
// section 2). Times are seconds since the Unix epoch.
type IDTokenClaims struct {
	Issuer          string   `json:"iss"`
	Subject         string   `json:"sub"`
	Audience        string   `json:"aud"`
	Expiry          int64    `json:"exp"`
	IssuedAt        int64    `json:"iat"`
	AuthTime        int64    `json:"auth_time"`
	Nonce           string   `json:"nonce,omitzero"`
	ACR             string   `json:"acr,omitzero"`
	AMR             []string `json:"amr,omitzero"`
	AccessTokenHash string   `json:"at_hash,omitzero"`
}

// AccessTokenClaims are the claims of a JWT access token (RFC 9068, section
// 2.2). AuthTime, ACR and AMR describe the user's authentication and are
// absent from tokens issued to a client for itself.
type AccessTokenClaims struct {
	Issuer   string   `json:"iss"`
	Subject  string   `json:"sub"`
	Audience []string `json:"aud"`
	Expiry   int64    `json:"exp"`
	IssuedAt int64    `json:"iat"`
	JWTID    string   `json:"jti"`
	ClientID string   `json:"client_id"`
	Scope    string   `json:"scope,omitzero"`
	AuthTime int64    `json:"auth_time,omitzero"`
	ACR      string   `json:"acr,omitzero"`
	AMR      []string `json:"amr,omitzero"`
}

// AccessTokenHash returns the at_hash claim of an ID token signed with alg
// that is issued with accessToken: the left half of the hash of the token,
// in unpadded base64url (OpenID Connect Core 1.0, section 3.1.3.6). The hash
// is the one of alg: SHA-256 for RS256 and ES256, and SHA-512 for EdDSA with
// Ed25519.
func AccessTokenHash(alg, accessToken string) (string, error) {
	var h hash.Hash
	switch alg {
	case "RS256", "ES256":
		h = sha256.New()
	case "EdDSA":
		h = sha512.New()
	default:
		return "", fmt.Errorf("oidc: no at_hash for algorithm %q", alg)
	}
	h.Write([]byte(accessToken))
	sum := h.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2]), nil
}

// Scopes of OpenID Connect that request claims (OpenID Connect Core 1.0,
// section 5.4).
const (
	ScopeProfile = "profile"
	ScopeEmail   = "email"
	ScopeAddress = "address"
	ScopePhone   = "phone"
)

// ScopeClaims returns the claims that a scope requests (OpenID Connect Core
// 1.0, section 5.4), or nil for a scope that requests none.
func ScopeClaims(scope string) []string {
	switch scope {
	case ScopeProfile:
		return []string{
			"name", "family_name", "given_name", "middle_name", "nickname", "preferred_username",
			"profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale", "updated_at",
		}
	case ScopeEmail:
		return []string{"email", "email_verified"}
	case ScopeAddress:
		return []string{"address"}
	case ScopePhone:
		return []string{"phone_number", "phone_number_verified"}
	default:
		return nil
	}
}

// ScopeOfflineAccess requests a refresh token (OpenID Connect Core 1.0,
// section 11).
const ScopeOfflineAccess = "offline_access"

// IsOpenIDScope reports whether scope belongs to OpenID Connect rather than
// to an API resource: openid, offline_access or a scope that requests
// claims.
func IsOpenIDScope(scope string) bool {
	return scope == "openid" || scope == ScopeOfflineAccess || ScopeClaims(scope) != nil
}
