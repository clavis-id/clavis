package oidc

import (
	"bytes"
	"encoding/json/v2"
	"strings"
	"testing"
)

func TestAccessTokenHash(t *testing.T) {
	t.Parallel()
	// The example of OpenID Connect Core 1.0, appendix A.3 and A.4.
	const token = "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y" // gitleaks:allow
	for alg, want := range map[string]string{
		"RS256": "77QmUPtjPfzWtF2AnpK9RQ",
		"ES256": "77QmUPtjPfzWtF2AnpK9RQ",
	} {
		if got, err := AccessTokenHash(alg, token); err != nil || got != want {
			t.Errorf("AccessTokenHash(%s) = %q, %v; want %q", alg, got, err, want)
		}
	}
	if got, err := AccessTokenHash("EdDSA", token); err != nil || len(got) != 43 {
		t.Errorf("AccessTokenHash(EdDSA) = %q, %v; want half of a SHA-512 hash", got, err)
	}
	if _, err := AccessTokenHash("HS256", token); err == nil {
		t.Error("AccessTokenHash(HS256) succeeded, want an error")
	}
}

func TestScopeClaims(t *testing.T) {
	t.Parallel()
	for scope, want := range map[string]string{
		"profile": "preferred_username",
		"email":   "email_verified",
		"address": "address",
		"phone":   "phone_number_verified",
	} {
		if !strings.Contains(strings.Join(ScopeClaims(scope), " "), want) || !IsOpenIDScope(scope) {
			t.Errorf("ScopeClaims(%s) = %v, want %s", scope, ScopeClaims(scope), want)
		}
	}
	if ScopeClaims("orders:read") != nil || IsOpenIDScope("orders:read") || !IsOpenIDScope("openid") ||
		!IsOpenIDScope("offline_access") {
		t.Error("an API scope is treated as an OpenID Connect scope")
	}
}

func TestTokenClaimsOmitEmptyValues(t *testing.T) {
	t.Parallel()
	b, err := json.Marshal(AccessTokenClaims{Issuer: "i", Subject: "s", Audience: []string{"a"}, JWTID: "j", ClientID: "c"})
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	for _, absent := range []string{"auth_time", "acr", "amr", "scope"} {
		if strings.Contains(string(b), absent) {
			t.Errorf("access token claims %s contain %s", b, absent)
		}
	}
	b, err = json.Marshal(IDTokenClaims{Issuer: "i", Subject: "s", Audience: "c", AuthTime: 1})
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	if !strings.Contains(string(b), `"auth_time":1`) || strings.Contains(string(b), "nonce") {
		t.Errorf("ID token claims = %s", b)
	}
}

func TestClaimScope(t *testing.T) {
	t.Parallel()
	for claim, want := range map[string]string{
		"name":                  "profile",
		"updated_at":            "profile",
		"email_verified":        "email",
		"address":               "address",
		"phone_number_verified": "phone",
		"sub":                   "",
		"acr":                   "",
		"unknown":               "",
	} {
		if got := ClaimScope(claim); got != want {
			t.Errorf("ClaimScope(%s) = %q, want %q", claim, got, want)
		}
	}
}

func TestIDTokenPayload(t *testing.T) {
	t.Parallel()
	claims := IDTokenClaims{Issuer: "i", Subject: "s", Audience: "c", AuthTime: 1}
	plain, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	if b, err := IDTokenPayload(claims, nil); err != nil || !bytes.Equal(b, plain) {
		t.Errorf("IDTokenPayload() without user claims = %s, %v; want %s", b, err, plain)
	}
	b, err := IDTokenPayload(claims, map[string]any{"name": "Ada", "email_verified": true})
	if err != nil {
		t.Fatalf("IDTokenPayload() unexpected error: %v", err)
	}
	const want = `{"aud":"c","auth_time":1,"email_verified":true,"exp":0,"iat":0,"iss":"i","name":"Ada","sub":"s"}`
	if string(b) != want {
		t.Errorf("IDTokenPayload() = %s, want %s", b, want)
	}
	// A user claim cannot replace a claim of the token.
	if b, err := IDTokenPayload(claims, map[string]any{"sub": "other"}); err == nil {
		t.Errorf("IDTokenPayload() with a user claim named sub = %s, want an error", b)
	}
}
