package oidc

import (
	"encoding/json/v2"
	"testing"
)

func TestNewMetadata(t *testing.T) {
	t.Parallel()

	algs := []string{"RS256", "ES256"}
	m := NewMetadata("https://auth.example.com/t/acme", algs)
	if m.Issuer != "https://auth.example.com/t/acme" ||
		m.AuthorizationEndpoint != "https://auth.example.com/t/acme/oauth2/authorize" ||
		m.TokenEndpoint != "https://auth.example.com/t/acme/oauth2/token" ||
		m.JWKSURI != "https://auth.example.com/t/acme/oauth2/jwks" {
		t.Errorf("endpoints are not derived from the issuer: %+v", m)
	}
	algs[0] = "none"
	if m.IDTokenSigningAlgValuesSupported[0] != "RS256" {
		t.Error("metadata shares the caller's algorithm slice")
	}
}

// TestMetadataOverridesMisleadingDefaults checks the fields whose
// specification defaults would advertise features Clavis does not support.
func TestMetadataOverridesMisleadingDefaults(t *testing.T) {
	t.Parallel()

	body, err := json.Marshal(NewMetadata("https://auth.example.com", []string{"RS256"}))
	if err != nil {
		t.Fatalf("encoding metadata: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("decoding metadata: %v", err)
	}
	for field, want := range map[string]any{
		// OpenID Connect Discovery 1.0, section 3: defaults to true.
		"request_uri_parameter_supported": false,
		"request_parameter_supported":     false,
		"claims_parameter_supported":      false,
	} {
		if doc[field] != want {
			t.Errorf("%s = %v, want %v", field, doc[field], want)
		}
	}
	for field, want := range map[string]string{
		// Defaults include fragment and implicit.
		"response_modes_supported": "query",
		"grant_types_supported":    "authorization_code",
	} {
		values, ok := doc[field].([]any)
		if !ok || len(values) != 1 || values[0] != want {
			t.Errorf("%s = %v, want [%s]", field, doc[field], want)
		}
	}
}
