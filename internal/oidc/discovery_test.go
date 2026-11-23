package oidc

import (
	"encoding/json/v2"
	"slices"
	"testing"
)

func TestNewMetadata(t *testing.T) {
	t.Parallel()

	m := NewMetadata("https://auth.example.com/t/acme", false)
	if m.Issuer != "https://auth.example.com/t/acme" ||
		m.AuthorizationEndpoint != "https://auth.example.com/t/acme/oauth2/authorize" ||
		m.TokenEndpoint != "https://auth.example.com/t/acme/oauth2/token" ||
		m.UserinfoEndpoint != "https://auth.example.com/t/acme/oauth2/userinfo" ||
		m.JWKSURI != "https://auth.example.com/t/acme/oauth2/jwks" {
		t.Errorf("endpoints are not derived from the issuer: %+v", m)
	}
	if !slices.Equal(m.IDTokenSigningAlgValuesSupported, []string{"RS256"}) {
		t.Errorf("id_token_signing_alg_values_supported = %v, want only the algorithm ID tokens use",
			m.IDTokenSigningAlgValuesSupported)
	}
	if !slices.Equal(m.ACRValuesSupported, []string{ACRPassword}) || !m.ClaimsParameterSupported {
		t.Errorf("acr_values_supported = %v, claims_parameter_supported = %v; want the password ACR and true",
			m.ACRValuesSupported, m.ClaimsParameterSupported)
	}
	for _, claim := range []string{"sub", "acr", "email", "address", "phone_number", "updated_at"} {
		if !slices.Contains(m.ClaimsSupported, claim) {
			t.Errorf("claims_supported = %v, want %s", m.ClaimsSupported, claim)
		}
	}
	if !slices.Contains(m.ScopesSupported, "openid") || !slices.Contains(m.ScopesSupported, "offline_access") ||
		!slices.Contains(m.TokenEndpointAuthMethodsSupported, "none") {
		t.Errorf("metadata = %+v", m)
	}
}

// Initiating User Registration via OpenID Connect 1.0, section 4.2: the
// list names every supported prompt value, and create only where a tenant
// offers signup.
func TestMetadataPromptValues(t *testing.T) {
	t.Parallel()
	for signup, want := range map[bool][]string{
		false: {"none", "login", "consent", "select_account"},
		true:  {"none", "login", "consent", "select_account", "create"},
	} {
		if got := NewMetadata("https://auth.example.com", signup).PromptValuesSupported; !slices.Equal(got, want) {
			t.Errorf("prompt_values_supported with signup %v = %v, want %v", signup, got, want)
		}
	}
}

// TestMetadataOverridesMisleadingDefaults checks the fields whose
// specification defaults would advertise features Clavis does not support.
func TestMetadataOverridesMisleadingDefaults(t *testing.T) {
	t.Parallel()

	body, err := json.Marshal(NewMetadata("https://auth.example.com", false))
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
	} {
		if doc[field] != want {
			t.Errorf("%s = %v, want %v", field, doc[field], want)
		}
	}
	for field, want := range map[string][]any{
		// Defaults include fragment and implicit.
		"response_modes_supported": {"query", "form_post"},
		"grant_types_supported":    {"authorization_code", "refresh_token", "client_credentials"},
	} {
		if values, ok := doc[field].([]any); !ok || !slices.Equal(values, want) {
			t.Errorf("%s = %v, want %v", field, doc[field], want)
		}
	}
}
