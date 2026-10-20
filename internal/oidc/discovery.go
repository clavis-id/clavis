// Package oidc implements the OpenID Connect layer of Clavis.
package oidc

import "clavisid.org/clavis/internal/i18n"

// Endpoint paths relative to a tenant's issuer.
const (
	AuthorizationPath = "/oauth2/authorize"
	TokenPath         = "/oauth2/token" //nolint:gosec // G101: a URL path, not a credential.
	UserinfoPath      = "/oauth2/userinfo"
	JWKSPath          = "/oauth2/jwks"
	RevocationPath    = "/oauth2/revoke"
	IntrospectionPath = "/oauth2/introspect"
	EndSessionPath    = "/oauth2/logout"

	// DiscoveryPath is where OpenID Connect Discovery 1.0, section 4, places
	// the provider metadata: appended to the issuer.
	DiscoveryPath = "/.well-known/openid-configuration"
	// AuthorizationServerMetadataPath is the RFC 8414 well-known suffix. RFC
	// 8414, section 3.1, inserts it between the host and the issuer path.
	AuthorizationServerMetadataPath = "/.well-known/oauth-authorization-server"
)

// Metadata is the provider metadata of one tenant, served both as OpenID
// Connect Discovery 1.0 (section 3) and as RFC 8414 authorization server
// metadata (section 2), which share these fields.
//
// Fields are added as the features they describe are implemented. Fields
// whose default value in the specifications would misdescribe Clavis are
// always present, for example request_uri_parameter_supported, which
// defaults to true.
type Metadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	// RevocationEndpoint and IntrospectionEndpoint come from RFC 8414,
	// section 2, which the OpenID Connect metadata may carry too.
	RevocationEndpoint                        string   `json:"revocation_endpoint"`
	RevocationEndpointAuthMethodsSupported    []string `json:"revocation_endpoint_auth_methods_supported"`
	IntrospectionEndpoint                     string   `json:"introspection_endpoint"`
	IntrospectionEndpointAuthMethodsSupported []string `json:"introspection_endpoint_auth_methods_supported"`
	// EndSessionEndpoint comes from OpenID Connect RP-Initiated Logout 1.0,
	// section 2.1.
	EndSessionEndpoint            string   `json:"end_session_endpoint"`
	ClaimsSupported               []string `json:"claims_supported"`
	ACRValuesSupported            []string `json:"acr_values_supported"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
	// UILocalesSupported lists the languages of the hosted pages (ADR 0025).
	UILocalesSupported []string `json:"ui_locales_supported"`
	// AuthorizationResponseIssParameterSupported announces the iss parameter
	// in authorization responses (RFC 9207, section 3).
	AuthorizationResponseIssParameterSupported bool `json:"authorization_response_iss_parameter_supported"`
	ClaimsParameterSupported                   bool `json:"claims_parameter_supported"`
	RequestParameterSupported                  bool `json:"request_parameter_supported"`
	RequestURIParameterSupported               bool `json:"request_uri_parameter_supported"`
}

// uiLocales returns the supported locales as BCP 47 tags.
func uiLocales() []string {
	var tags []string
	for _, l := range i18n.Supported() {
		tags = append(tags, string(l))
	}
	return tags
}

// NewMetadata returns the metadata of the tenant whose issuer is issuer.
func NewMetadata(issuer string) Metadata {
	claims := []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr", "at_hash"}
	for _, scope := range []string{ScopeProfile, ScopeEmail, ScopeAddress, ScopePhone} {
		claims = append(claims, ScopeClaims(scope)...)
	}
	return Metadata{
		Issuer:                issuer,
		AuthorizationEndpoint: issuer + AuthorizationPath,
		TokenEndpoint:         issuer + TokenPath,
		UserinfoEndpoint:      issuer + UserinfoPath,
		JWKSURI:               issuer + JWKSPath,
		ScopesSupported:       []string{"openid", ScopeProfile, ScopeEmail, ScopeAddress, ScopePhone, ScopeOfflineAccess},
		// OAuth 2.1 keeps only the authorization code flow.
		ResponseTypesSupported: []string{"code"},
		// The default is query and fragment; fragment serves implicit flows,
		// which Clavis does not support.
		ResponseModesSupported: []string{"query", "form_post"},
		// The default is authorization_code and implicit.
		GrantTypesSupported:              []string{"authorization_code", "refresh_token", "client_credentials"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{IDTokenSigningAlgorithm},
		// OpenID Connect Core 1.0, section 9; none is for public clients.
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post", "none"},
		RevocationEndpoint:                issuer + RevocationPath,
		// RFC 7009, section 2.1: public clients revoke their tokens too.
		RevocationEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post", "none"},
		IntrospectionEndpoint:                  issuer + IntrospectionPath,
		// ADR 0022: only confidential clients introspect.
		IntrospectionEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post"},
		EndSessionEndpoint:                        issuer + EndSessionPath,
		ClaimsSupported:                           claims,
		// The values Clavis can produce (ADR 0019).
		ACRValuesSupported: []string{ACRPassword},
		// RFC 8414, section 2: without this field, clients cannot tell that
		// PKCE is supported. Only S256 is (ADR 0018).
		CodeChallengeMethodsSupported:              []string{"S256"},
		UILocalesSupported:                         uiLocales(),
		AuthorizationResponseIssParameterSupported: true,
		ClaimsParameterSupported:                   true,
	}
}
