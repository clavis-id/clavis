package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"
	"uuid"

	"clavisid.org/clavis/internal/oauth"
	"clavisid.org/clavis/internal/oidc"
	"clavisid.org/clavis/store"
)

// Default token lifetimes (ADR 0014). Clients may override them.
const (
	DefaultAccessTokenLifetime = 10 * time.Minute
	DefaultIDTokenLifetime     = 10 * time.Minute
)

// accessTokenAlgorithm signs access tokens; RFC 9068, section 2.1, requires
// resource servers to support RS256.
const accessTokenAlgorithm = "RS256"

// ErrInvalidToken reports a token that fails signature or type
// verification. TokenSigner.Verify wraps it.
var ErrInvalidToken = errors.New("invalid token")

// TokenSigner signs and verifies the tokens of a tenant with its signing
// keys. Verify returns an error that wraps ErrInvalidToken for a token that
// fails verification, and other errors only when it cannot check.
type TokenSigner interface {
	Sign(ctx context.Context, tenantID uuid.UUID, alg, typ string, payload []byte) (string, error)
	Verify(ctx context.Context, tenantID uuid.UUID, token, typ string) ([]byte, error)
}

// TokenResponse is a successful token response (RFC 6749, section 5.1;
// OpenID Connect Core 1.0, section 3.1.3.3).
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"scope,omitzero"`
	IDToken     string `json:"id_token,omitzero"`
}

// AuthenticateClient returns the client that creds authenticate (RFC 6749,
// section 2.3). A confidential client must present its secret with
// client_secret_basic or client_secret_post; a public client must present
// none. Every failure returns an *oauth.Error with the code invalid_client.
func AuthenticateClient(ctx context.Context, d Deps, tenantID uuid.UUID, creds oauth.ClientCredentials,
) (store.Client, error) {
	fail := &oauth.Error{Code: oauth.ErrorInvalidClient, Description: "client authentication failed"}
	c, err := d.Store.Clients().GetByClientID(ctx, tenantID, creds.ClientID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return store.Client{}, fail
	case err != nil:
		return store.Client{}, fmt.Errorf("looking up the client: %w", err)
	}
	switch c.Type {
	case store.ClientConfidential:
		if creds.Method == oauth.AuthMethodNone || !oauth.ClientSecretMatches(c.SecretHash, creds.Secret) {
			return store.Client{}, fail
		}
	case store.ClientPublic:
		if creds.Method != oauth.AuthMethodNone {
			return store.Client{}, fail
		}
	default:
		return store.Client{}, fail
	}
	return c, nil
}

// ExchangeCode answers an authorization_code token request (RFC 6749,
// section 4.1.3) from client, which AuthenticateClient returned. A code is
// redeemed once; presenting it again revokes the tokens issued for it
// (section 4.1.2). Protocol errors are *oauth.Error values.
func ExchangeCode(ctx context.Context, d Deps, signer TokenSigner, t AuthorizationTenant, client store.Client,
	r oauth.TokenRequest,
) (TokenResponse, error) {
	if !slices.Contains(client.GrantTypes, oauth.GrantTypeAuthorizationCode) {
		return TokenResponse{}, &oauth.Error{Code: oauth.ErrorUnauthorizedClient,
			Description: "the client may not use the authorization code grant"}
	}
	if r.Code == "" {
		return TokenResponse{}, &oauth.Error{Code: oauth.ErrorInvalidRequest, Description: "code is missing"}
	}
	invalid := func(description string) error {
		return &oauth.Error{Code: oauth.ErrorInvalidGrant, Description: description}
	}
	hash := oauth.HashToken(r.Code)
	code, err := d.Store.AuthorizationCodes().Get(ctx, t.ID, hash)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return TokenResponse{}, invalid("the code is invalid or expired")
	case err != nil:
		return TokenResponse{}, fmt.Errorf("looking up the code: %w", err)
	case code.ClientID != client.ID:
		return TokenResponse{}, invalid("the code was issued to another client")
	case !code.RedeemedAt.IsZero():
		return TokenResponse{}, codeReused(ctx, d, t, client, hash)
	case !d.Now().Before(code.ExpiresAt):
		return TokenResponse{}, invalid("the code is invalid or expired")
	// OAuth 2.1, section 4.1.3: redirect_uri must match when the
	// authorization request sent it.
	case (code.RedirectURIProvided || r.RedirectURI != "") && r.RedirectURI != code.RedirectURI:
		return TokenResponse{}, invalid("redirect_uri does not match the authorization request")
	// RFC 7636, section 4.6, and RFC 9700, section 4.8.2: a verifier
	// without a challenge is a downgrade attempt.
	case code.CodeChallenge == "" && r.CodeVerifier != "":
		return TokenResponse{}, invalid("the authorization request had no code_challenge")
	case code.CodeChallenge != "" && !oauth.VerifyPKCE(code.CodeChallenge, r.CodeVerifier):
		return TokenResponse{}, invalid("code_verifier does not match the code_challenge")
	}
	switch err := d.Store.AuthorizationCodes().Redeem(ctx, t.ID, hash, d.Now()); {
	case errors.Is(err, store.ErrConflict):
		return TokenResponse{}, codeReused(ctx, d, t, client, hash)
	case errors.Is(err, store.ErrNotFound):
		return TokenResponse{}, invalid("the code is invalid or expired")
	case err != nil:
		return TokenResponse{}, fmt.Errorf("redeeming the code: %w", err)
	}
	u, err := d.Store.Users().Get(ctx, t.ID, code.UserID)
	switch {
	case errors.Is(err, store.ErrNotFound) || err == nil && u.Status != store.UserActive:
		return TokenResponse{}, invalid("the user can no longer sign in")
	case err != nil:
		return TokenResponse{}, fmt.Errorf("looking up the user: %w", err)
	}
	g := grant{
		userID:         u.ID,
		scopes:         code.Scopes,
		codeHash:       hash,
		authTime:       code.AuthTime,
		amr:            code.AMR,
		acr:            code.ACR,
		nonce:          code.Nonce,
		userInfoClaims: code.UserInfoClaims,
	}
	if len(code.IDTokenClaims) > 0 {
		g.idTokenClaims = userClaims(u, nil, code.IDTokenClaims)
		// The ID token has its own sub.
		delete(g.idTokenClaims, "sub")
	}
	return issueTokens(ctx, d, signer, t, client, g)
}

// codeReused revokes the tokens issued for a code that is presented again
// and returns the error for the request.
func codeReused(ctx context.Context, d Deps, t AuthorizationTenant, client store.Client, hash []byte) error {
	n, err := d.Store.AccessTokens().RevokeByCode(ctx, t.ID, hash, d.Now())
	if err != nil {
		return fmt.Errorf("revoking the tokens of a reused code: %w", err)
	}
	d.Logger.LogAttrs(ctx, slog.LevelWarn, "authorization code reused; revoked the tokens issued for it",
		slog.String("tenant_id", t.ID.String()),
		slog.String("client_id", client.ClientID),
		slog.Int64("revoked", n))
	return &oauth.Error{Code: oauth.ErrorInvalidGrant, Description: "the code was used already"}
}

// ClientCredentialsToken answers a client_credentials token request (RFC
// 6749, section 4.4.2) from client, which AuthenticateClient returned.
// Without a scope parameter, the token grants every API scope the client
// may request. Protocol errors are *oauth.Error values.
func ClientCredentialsToken(ctx context.Context, d Deps, signer TokenSigner, t AuthorizationTenant,
	client store.Client, r oauth.TokenRequest,
) (TokenResponse, error) {
	if client.Type != store.ClientConfidential || !slices.Contains(client.GrantTypes, oauth.GrantTypeClientCredentials) {
		return TokenResponse{}, &oauth.Error{Code: oauth.ErrorUnauthorizedClient,
			Description: "the client may not use the client credentials grant"}
	}
	invalidScope := func(description string) error {
		return &oauth.Error{Code: oauth.ErrorInvalidScope, Description: description}
	}
	scopes := r.Scopes
	if len(scopes) == 0 {
		for _, s := range client.Scopes {
			if !oidc.IsOpenIDScope(s) {
				scopes = append(scopes, s)
			}
		}
	}
	for _, s := range scopes {
		switch {
		case oidc.IsOpenIDScope(s):
			return TokenResponse{}, invalidScope("OpenID Connect scopes need a user")
		case !slices.Contains(client.Scopes, s):
			return TokenResponse{}, invalidScope("the client may not request every scope in the request")
		}
	}
	if len(scopes) == 0 {
		return TokenResponse{}, invalidScope("the client may request no API scopes")
	}
	return issueTokens(ctx, d, signer, t, client, grant{scopes: scopes})
}

// grant describes what a token response grants.
type grant struct {
	// userID is the zero UUID when the client acts for itself.
	userID   uuid.UUID
	scopes   []string
	codeHash []byte
	authTime time.Time
	amr      []string
	acr      string
	nonce    string
	// userInfoClaims names the claims the userinfo response adds, and
	// idTokenClaims holds the claims about the user that the ID token adds
	// (OpenID Connect Core 1.0, section 5.5).
	userInfoClaims []string
	idTokenClaims  map[string]any
}

// issueTokens signs and records an access token for g, and an ID token when
// g grants openid. Refresh tokens arrive with work item 2.3, so
// offline_access is not granted yet.
func issueTokens(ctx context.Context, d Deps, signer TokenSigner, t AuthorizationTenant, client store.Client, g grant,
) (TokenResponse, error) {
	scopes := slices.DeleteFunc(slices.Clone(g.scopes), func(s string) bool { return s == oidc.ScopeOfflineAccess })
	owners, err := scopeOwners(ctx, d, t.ID)
	if err != nil {
		return TokenResponse{}, err
	}
	if undefinedScope(scopes, owners) != "" {
		return TokenResponse{}, &oauth.Error{Code: oauth.ErrorInvalidScope,
			Description: "the request includes a scope that no API resource defines"}
	}
	audience := audienceOf(scopes, owners, t.Issuer)

	now := d.Now()
	lifetime := orDefault(client.Lifetimes.AccessToken, DefaultAccessTokenLifetime)
	claims := oidc.AccessTokenClaims{
		Issuer:   t.Issuer,
		Subject:  client.ClientID,
		Audience: audience,
		Expiry:   now.Add(lifetime).Unix(),
		IssuedAt: now.Unix(),
		JWTID:    d.NewID().String(),
		ClientID: client.ClientID,
		Scope:    strings.Join(scopes, " "),
	}
	if g.userID != uuid.Nil() {
		// RFC 9068, section 2.2.1: auth_time, acr and amr describe the
		// user's authentication.
		claims.Subject = g.userID.String()
		claims.AuthTime = g.authTime.Unix()
		claims.ACR = g.acr
		claims.AMR = g.amr
	}
	accessToken, err := sign(ctx, signer, t.ID, accessTokenAlgorithm, oidc.AccessTokenType, claims)
	if err != nil {
		return TokenResponse{}, err
	}
	if err := d.Store.AccessTokens().Create(ctx, store.AccessToken{
		ID:             claims.JWTID,
		TenantID:       t.ID,
		ClientID:       client.ID,
		UserID:         g.userID,
		CodeHash:       g.codeHash,
		Scopes:         scopes,
		UserInfoClaims: g.userInfoClaims,
		IssuedAt:       now,
		ExpiresAt:      now.Add(lifetime),
	}); err != nil {
		return TokenResponse{}, fmt.Errorf("recording the access token: %w", err)
	}
	resp := TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(lifetime / time.Second),
		Scope:       claims.Scope,
	}

	if g.userID != uuid.Nil() && slices.Contains(scopes, oauth.ScopeOpenID) {
		atHash, err := oidc.AccessTokenHash(oidc.IDTokenSigningAlgorithm, accessToken)
		if err != nil {
			return TokenResponse{}, fmt.Errorf("hashing the access token: %w", err)
		}
		// OpenID Connect Core 1.0, section 2. auth_time is always present,
		// which also answers requests that sent max_age.
		payload, err := oidc.IDTokenPayload(oidc.IDTokenClaims{
			Issuer:          t.Issuer,
			Subject:         g.userID.String(),
			Audience:        client.ClientID,
			Expiry:          now.Add(orDefault(client.Lifetimes.IDToken, DefaultIDTokenLifetime)).Unix(),
			IssuedAt:        now.Unix(),
			AuthTime:        g.authTime.Unix(),
			Nonce:           g.nonce,
			ACR:             g.acr,
			AMR:             g.amr,
			AccessTokenHash: atHash,
		}, g.idTokenClaims)
		if err != nil {
			return TokenResponse{}, fmt.Errorf("encoding the ID token: %w", err)
		}
		if resp.IDToken, err = signer.Sign(ctx, t.ID, oidc.IDTokenSigningAlgorithm, oidc.IDTokenType, payload); err != nil {
			return TokenResponse{}, fmt.Errorf("signing a token: %w", err)
		}
	}
	d.Logger.LogAttrs(ctx, slog.LevelInfo, "issued tokens",
		slog.String("tenant_id", t.ID.String()),
		slog.String("client_id", client.ClientID),
		slog.String("jti", claims.JWTID))
	return resp, nil
}

// audienceOf returns the aud claim of a token that grants scopes (ADR
// 0014): the identifiers of the API resources that define them, plus the
// issuer, which serves userinfo, when an OpenID Connect scope is granted.
func audienceOf(scopes []string, owners map[string]store.APIResource, issuer string) []string {
	var audience []string
	for _, s := range scopes {
		aud := issuer
		if owner, ok := owners[s]; ok {
			aud = owner.Identifier
		}
		if !slices.Contains(audience, aud) {
			audience = append(audience, aud)
		}
	}
	return audience
}

func sign(ctx context.Context, signer TokenSigner, tenantID uuid.UUID, alg, typ string, claims any) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("encoding token claims: %w", err)
	}
	token, err := signer.Sign(ctx, tenantID, alg, typ, payload)
	if err != nil {
		return "", fmt.Errorf("signing a token: %w", err)
	}
	return token, nil
}

func orDefault(d, fallback time.Duration) time.Duration {
	if d == 0 {
		return fallback
	}
	return d
}

// UserInfo returns the claims about the user that an access token grants
// (OpenID Connect Core 1.0, section 5.3). The token must be valid, issued by
// the tenant for its userinfo endpoint, not revoked, and grant openid.
// Errors are *oauth.Error values with the codes of RFC 6750, section 3.1.
func UserInfo(ctx context.Context, d Deps, signer TokenSigner, t AuthorizationTenant, token string,
) (map[string]any, error) {
	invalid := &oauth.Error{Code: oauth.ErrorInvalidToken, Description: "the access token is not valid"}
	payload, err := signer.Verify(ctx, t.ID, token, oidc.AccessTokenType)
	switch {
	case errors.Is(err, ErrInvalidToken):
		return nil, invalid
	case err != nil:
		return nil, fmt.Errorf("verifying the access token: %w", err)
	}
	var claims oidc.AccessTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, invalid
	}
	now := d.Now()
	switch {
	case claims.Issuer != t.Issuer, !slices.Contains(claims.Audience, t.Issuer), now.Unix() >= claims.Expiry:
		return nil, invalid
	case !slices.Contains(strings.Split(claims.Scope, " "), oauth.ScopeOpenID):
		return nil, &oauth.Error{Code: oauth.ErrorInsufficientScope, Description: "the access token does not grant openid"}
	}
	record, err := d.Store.AccessTokens().Get(ctx, t.ID, claims.JWTID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, invalid
	case err != nil:
		return nil, fmt.Errorf("looking up the access token: %w", err)
	case !record.RevokedAt.IsZero(), record.UserID == uuid.Nil(), record.UserID.String() != claims.Subject:
		return nil, invalid
	}
	u, err := d.Store.Users().Get(ctx, t.ID, record.UserID)
	switch {
	case errors.Is(err, store.ErrNotFound) || err == nil && u.Status != store.UserActive:
		return nil, invalid
	case err != nil:
		return nil, fmt.Errorf("looking up the user: %w", err)
	}
	return userClaims(u, record.Scopes, record.UserInfoClaims), nil
}

// userClaims returns sub and the claims of u that scopes request (OpenID
// Connect Core 1.0, sections 5.1 and 5.4) or that names lists (section 5.5).
// Empty claims are left out.
func userClaims(u store.User, scopes, names []string) map[string]any {
	p := u.Profile
	available := map[string]any{
		"updated_at":     u.UpdatedAt.Unix(),
		"email":          u.Email,
		"email_verified": u.EmailVerified,
	}
	for name, value := range map[string]string{
		"name": p.Name, "family_name": p.FamilyName, "given_name": p.GivenName, "middle_name": p.MiddleName,
		"nickname": p.Nickname, "preferred_username": p.PreferredUsername, "profile": p.ProfileURL,
		"picture": p.Picture, "website": p.Website, "gender": p.Gender, "birthdate": p.Birthdate,
		"zoneinfo": p.Zoneinfo, "locale": p.Locale,
	} {
		if value != "" {
			available[name] = value
		}
	}
	if p.Address != (store.Address{}) {
		available["address"] = p.Address
	}
	if p.PhoneNumber != "" {
		available["phone_number"] = p.PhoneNumber
		available["phone_number_verified"] = p.PhoneNumberVerified
	}
	claims := map[string]any{"sub": u.ID.String()}
	for name, value := range available {
		if slices.Contains(scopes, oidc.ClaimScope(name)) || slices.Contains(names, name) {
			claims[name] = value
		}
	}
	return claims
}
