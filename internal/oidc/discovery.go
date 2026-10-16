// Package oidc implements the OpenID Connect layer of Clavis.
package oidc

// Endpoint paths relative to a tenant's issuer.
const (
	AuthorizationPath = "/oauth2/authorize"
	TokenPath         = "/oauth2/token" //nolint:gosec // G101: a URL path, not a credential.
	JWKSPath          = "/oauth2/jwks"

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
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	JWKSURI                          string   `json:"jwks_uri"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	ResponseModesSupported           []string `json:"response_modes_supported"`
	GrantTypesSupported              []string `json:"grant_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	CodeChallengeMethodsSupported    []string `json:"code_challenge_methods_supported"`
	// AuthorizationResponseIssParameterSupported announces the iss parameter
	// in authorization responses (RFC 9207, section 3).
	AuthorizationResponseIssParameterSupported bool `json:"authorization_response_iss_parameter_supported"`
	ClaimsParameterSupported                   bool `json:"claims_parameter_supported"`
	RequestParameterSupported                  bool `json:"request_parameter_supported"`
	RequestURIParameterSupported               bool `json:"request_uri_parameter_supported"`
}

// NewMetadata returns the metadata of the tenant whose issuer is issuer,
// which signs ID tokens with the given JWS algorithms.
func NewMetadata(issuer string, signingAlgorithms []string) Metadata {
	return Metadata{
		Issuer:                issuer,
		AuthorizationEndpoint: issuer + AuthorizationPath,
		TokenEndpoint:         issuer + TokenPath,
		JWKSURI:               issuer + JWKSPath,
		// OAuth 2.1 keeps only the authorization code flow.
		ResponseTypesSupported: []string{"code"},
		// The default is query and fragment; fragment serves implicit flows,
		// which Clavis does not support.
		ResponseModesSupported: []string{"query"},
		// The default is authorization_code and implicit.
		GrantTypesSupported:              []string{"authorization_code"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: append([]string(nil), signingAlgorithms...),
		// RFC 8414, section 2: without this field, clients cannot tell that
		// PKCE is supported. Only S256 is (ADR 0018).
		CodeChallengeMethodsSupported:              []string{"S256"},
		AuthorizationResponseIssParameterSupported: true,
	}
}
