package oidc

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json/v2"
	"fmt"
	"hash"
	"slices"
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

// ACRPassword is the authentication context class reference of a sign-in
// with a password alone (ADR 0019).
const ACRPassword = "https://clavisid.org/acr/password" //nolint:gosec // G101: a class identifier, not a credential.

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

// IDTokenPayload returns the JSON payload of an ID token: claims, plus the
// claims about the user that the claims parameter asked for in the ID token
// (section 5.5). A user claim must not repeat the name of a claim in claims.
func IDTokenPayload(claims IDTokenClaims, userClaims map[string]any) ([]byte, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("oidc: encoding ID token claims: %w", err)
	}
	if len(userClaims) == 0 {
		return payload, nil
	}
	var doc map[string]any
	if err := json.Unmarshal(payload, &doc); err != nil {
		return nil, fmt.Errorf("oidc: decoding ID token claims: %w", err)
	}
	for name, value := range userClaims {
		if _, ok := doc[name]; ok {
			return nil, fmt.Errorf("oidc: the user claim %q repeats an ID token claim", name)
		}
		doc[name] = value
	}
	payload, err = json.Marshal(doc, json.Deterministic(true))
	if err != nil {
		return nil, fmt.Errorf("oidc: encoding ID token claims: %w", err)
	}
	return payload, nil
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

// ClaimScope returns the scope that requests claim (OpenID Connect Core
// 1.0, section 5.4), or "" for a claim that no scope requests.
func ClaimScope(claim string) string {
	for _, scope := range []string{ScopeProfile, ScopeEmail, ScopeAddress, ScopePhone} {
		if slices.Contains(ScopeClaims(scope), claim) {
			return scope
		}
	}
	return ""
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
