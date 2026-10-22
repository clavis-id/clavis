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

// Default token lifetimes (ADR 0014). Clients may override them. A refresh
// token family ends after DefaultRefreshTokenIdleLifetime without a refresh,
// and after DefaultRefreshTokenAbsoluteLifetime regardless.
const (
	DefaultAccessTokenLifetime          = 10 * time.Minute
	DefaultIDTokenLifetime              = 10 * time.Minute
	DefaultRefreshTokenIdleLifetime     = 7 * 24 * time.Hour
	DefaultRefreshTokenAbsoluteLifetime = 30 * 24 * time.Hour
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
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitzero"`
	Scope        string `json:"scope,omitzero"`
	IDToken      string `json:"id_token,omitzero"`
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
// (section 4.1.2). The response includes a refresh token when
// issuesRefreshToken allows it. Protocol errors are *oauth.Error values.
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
		return TokenResponse{}, codeReused(ctx, d, t, client, code)
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
	u, err := activeUser(ctx, d, t.ID, code.UserID)
	if err != nil {
		return TokenResponse{}, err
	}
	scopes := code.Scopes
	refresh := issuesRefreshToken(client, scopes)
	if !refresh {
		scopes = slices.DeleteFunc(slices.Clone(scopes), func(s string) bool { return s == oauth.ScopeOfflineAccess })
	}
	resp, jti, err := issueTokens(ctx, d, signer, t, client, grant{
		userID:         u.ID,
		scopes:         scopes,
		codeHash:       hash,
		authTime:       code.AuthTime,
		amr:            code.AMR,
		acr:            code.ACR,
		nonce:          code.Nonce,
		userInfoClaims: code.UserInfoClaims,
		idTokenClaims:  idTokenUserClaims(u, code.IDTokenClaims),
	})
	if err != nil {
		return TokenResponse{}, err
	}
	var attrs []slog.Attr
	if refresh {
		var familyID uuid.UUID
		if resp.RefreshToken, familyID, err = startRefreshTokenFamily(ctx, d, client, code, scopes); err != nil {
			return TokenResponse{}, err
		}
		attrs = append(attrs, slog.String("refresh_token_family", familyID.String()))
	}
	// ADR 0021: the tokens are recorded before the code is redeemed, so a
	// replay that finds the code redeemed revokes them all.
	switch err := d.Store.AuthorizationCodes().Redeem(ctx, t.ID, hash, d.Now()); {
	case errors.Is(err, store.ErrConflict):
		return TokenResponse{}, codeReused(ctx, d, t, client, code)
	case errors.Is(err, store.ErrNotFound):
		return TokenResponse{}, invalid("the code is invalid or expired")
	case err != nil:
		return TokenResponse{}, fmt.Errorf("redeeming the code: %w", err)
	}
	logIssued(ctx, d, t, client, oauth.GrantTypeAuthorizationCode, jti, attrs...)
	return resp, nil
}

// activeUser returns the user of a tenant with the given ID when it may
// still obtain tokens, and an invalid_grant *oauth.Error otherwise.
func activeUser(ctx context.Context, d Deps, tenantID, id uuid.UUID) (store.User, error) {
	u, err := d.Store.Users().Get(ctx, tenantID, id)
	switch {
	case errors.Is(err, store.ErrNotFound) || err == nil && u.Status != store.UserActive:
		return store.User{}, &oauth.Error{Code: oauth.ErrorInvalidGrant, Description: "the user can no longer sign in"}
	case err != nil:
		return store.User{}, fmt.Errorf("looking up the user: %w", err)
	}
	return u, nil
}

// idTokenUserClaims returns the claims of u that names lists for an ID token
// (OpenID Connect Core 1.0, section 5.5), or nil when names is empty.
func idTokenUserClaims(u store.User, names []string) map[string]any {
	if len(names) == 0 {
		return nil
	}
	claims := userClaims(u, nil, names)
	// The ID token has its own sub.
	delete(claims, "sub")
	return claims
}

// codeReused revokes the tokens issued for a code that is presented again,
// refresh token families first, and returns the error for the request.
func codeReused(ctx context.Context, d Deps, t AuthorizationTenant, client store.Client, code store.AuthorizationCode,
) error {
	hash, now := code.Hash, d.Now()
	families, err := d.Store.RefreshTokens().RevokeByCode(ctx, t.ID, hash, now)
	if err != nil {
		return fmt.Errorf("revoking the refresh tokens of a reused code: %w", err)
	}
	tokens, err := d.Store.AccessTokens().RevokeByCode(ctx, t.ID, hash, now)
	if err != nil {
		return fmt.Errorf("revoking the access tokens of a reused code: %w", err)
	}
	d.Logger.LogAttrs(ctx, slog.LevelWarn, "authorization code reused; revoked the tokens issued for it",
		slog.String("tenant_id", t.ID.String()),
		slog.String("client_id", client.ClientID),
		slog.Int64("revoked_refresh_token_families", families),
		slog.Int64("revoked_access_tokens", tokens))
	audit(ctx, d, store.AuditEvent{TenantID: t.ID, Type: EventCodeReplayed, Actor: store.ActorClient,
		UserID: code.UserID, ClientID: client.ClientID, SessionID: code.SessionID})
	return &oauth.Error{Code: oauth.ErrorInvalidGrant, Description: "the code was used already"}
}

// issuesRefreshToken reports whether exchanging a code that grants scopes
// yields a refresh token (ADR 0014, ADR 0021). The client must be allowed
// the refresh token grant. An OpenID Connect request must also have been
// granted offline_access (OpenID Connect Core 1.0, section 11), which needs
// the user's consent unless the client skips consent; an OAuth request
// needs nothing more.
func issuesRefreshToken(client store.Client, scopes []string) bool {
	return slices.Contains(client.GrantTypes, oauth.GrantTypeRefreshToken) &&
		(!slices.Contains(scopes, oauth.ScopeOpenID) || slices.Contains(scopes, oauth.ScopeOfflineAccess))
}

// startRefreshTokenFamily stores a refresh token family for the code, which
// grants scopes, and returns its first token and the family's ID (ADR 0021).
func startRefreshTokenFamily(ctx context.Context, d Deps, client store.Client, code store.AuthorizationCode,
	scopes []string,
) (string, uuid.UUID, error) {
	now := d.Now()
	family := store.RefreshTokenFamily{
		ID:             d.NewID(),
		TenantID:       code.TenantID,
		ClientID:       client.ID,
		UserID:         code.UserID,
		SessionID:      code.SessionID,
		CodeHash:       code.Hash,
		Scopes:         scopes,
		AuthTime:       code.AuthTime,
		AMR:            code.AMR,
		ACR:            code.ACR,
		UserInfoClaims: code.UserInfoClaims,
		IDTokenClaims:  code.IDTokenClaims,
		CreatedAt:      now,
		ExpiresAt:      now.Add(orDefault(client.Lifetimes.RefreshTokenAbsolute, DefaultRefreshTokenAbsoluteLifetime)),
	}
	token, first := newRefreshToken(client, family, now)
	family.IdleExpiresAt = first.ExpiresAt
	if err := d.Store.RefreshTokens().Create(ctx, family, first); err != nil {
		return "", uuid.Nil(), fmt.Errorf("storing the refresh token: %w", err)
	}
	return token, family.ID, nil
}

// newRefreshToken returns a refresh token of family issued at now, and its
// record. It expires after the client's idle lifetime, but not after the
// family.
func newRefreshToken(client store.Client, family store.RefreshTokenFamily, now time.Time) (string, store.RefreshToken) {
	token := oauth.NewToken()
	expires := now.Add(orDefault(client.Lifetimes.RefreshTokenIdle, DefaultRefreshTokenIdleLifetime))
	if family.ExpiresAt.Before(expires) {
		expires = family.ExpiresAt
	}
	return token, store.RefreshToken{
		Hash:      oauth.HashToken(token),
		TenantID:  family.TenantID,
		FamilyID:  family.ID,
		IssuedAt:  now,
		ExpiresAt: expires,
	}
}

// revokeFamily revokes a refresh token family and the access tokens issued
// from it, which carry the hash of its code, and returns how many access
// tokens it revoked.
func revokeFamily(ctx context.Context, d Deps, t AuthorizationTenant, family store.RefreshTokenFamily) (int64, error) {
	now := d.Now()
	if err := d.Store.RefreshTokens().RevokeFamily(ctx, t.ID, family.ID, now); err != nil &&
		!errors.Is(err, store.ErrNotFound) {
		return 0, fmt.Errorf("revoking the family: %w", err)
	}
	if family.CodeHash == nil {
		return 0, nil
	}
	n, err := d.Store.AccessTokens().RevokeByCode(ctx, t.ID, family.CodeHash, now)
	if err != nil {
		return 0, fmt.Errorf("revoking the access tokens of the family: %w", err)
	}
	return n, nil
}

// RefreshToken answers a refresh_token token request (RFC 6749, section 6)
// from client, which AuthenticateClient returned (ADR 0021). Every refresh
// replaces the refresh token with a new one in the same family. Presenting a
// replaced token revokes the family and the access tokens issued from it
// (RFC 9700, section 4.14.2); so do two refreshes with the same token, since
// there is no grace period (ADR 0014). Protocol errors are *oauth.Error
// values.
func RefreshToken(ctx context.Context, d Deps, signer TokenSigner, t AuthorizationTenant, client store.Client,
	r oauth.TokenRequest,
) (TokenResponse, error) {
	if !slices.Contains(client.GrantTypes, oauth.GrantTypeRefreshToken) {
		return TokenResponse{}, &oauth.Error{Code: oauth.ErrorUnauthorizedClient,
			Description: "the client may not use the refresh token grant"}
	}
	if r.RefreshToken == "" {
		return TokenResponse{}, &oauth.Error{Code: oauth.ErrorInvalidRequest, Description: "refresh_token is missing"}
	}
	invalid := func(description string) error {
		return &oauth.Error{Code: oauth.ErrorInvalidGrant, Description: description}
	}
	hash := oauth.HashToken(r.RefreshToken)
	current, family, err := d.Store.RefreshTokens().Get(ctx, t.ID, hash)
	now := d.Now()
	switch {
	case errors.Is(err, store.ErrNotFound):
		return TokenResponse{}, invalid("the refresh token is invalid or expired")
	case err != nil:
		return TokenResponse{}, fmt.Errorf("looking up the refresh token: %w", err)
	// RFC 6749, section 6: the token must have been issued to the client.
	case family.ClientID != client.ID:
		return TokenResponse{}, invalid("the refresh token was issued to another client")
	case !current.RotatedAt.IsZero():
		return TokenResponse{}, refreshTokenReused(ctx, d, t, client, family)
	case !family.RevokedAt.IsZero():
		return TokenResponse{}, invalid("the refresh token was revoked")
	case !now.Before(current.ExpiresAt), !now.Before(family.ExpiresAt):
		return TokenResponse{}, invalid("the refresh token is invalid or expired")
	}
	// RFC 6749, section 6: the request may narrow the scope of the access
	// token, never widen it. The family keeps its scope.
	scopes := family.Scopes
	if len(r.Scopes) > 0 {
		for _, s := range r.Scopes {
			if !slices.Contains(family.Scopes, s) {
				return TokenResponse{}, &oauth.Error{Code: oauth.ErrorInvalidScope,
					Description: "the request includes a scope that was not granted"}
			}
		}
		scopes = r.Scopes
	}
	u, err := activeUser(ctx, d, t.ID, family.UserID)
	if err != nil {
		return TokenResponse{}, err
	}
	// OpenID Connect Core 1.0, section 12.2: an ID token keeps the original
	// authentication and carries no nonce.
	resp, jti, err := issueTokens(ctx, d, signer, t, client, grant{
		userID:         u.ID,
		scopes:         scopes,
		codeHash:       family.CodeHash,
		authTime:       family.AuthTime,
		amr:            family.AMR,
		acr:            family.ACR,
		userInfoClaims: family.UserInfoClaims,
		idTokenClaims:  idTokenUserClaims(u, family.IDTokenClaims),
	})
	if err != nil {
		return TokenResponse{}, err
	}
	// ADR 0021: the access token is recorded before the rotation, so a
	// request that finds the token rotated revokes it too.
	token, next := newRefreshToken(client, family, now)
	switch err := d.Store.RefreshTokens().Rotate(ctx, t.ID, hash, next); {
	case errors.Is(err, store.ErrConflict):
		// Another request rotated the token first, or the family was
		// revoked in the meantime.
		return TokenResponse{}, refreshTokenReused(ctx, d, t, client, family)
	case errors.Is(err, store.ErrNotFound):
		return TokenResponse{}, invalid("the refresh token is invalid or expired")
	case err != nil:
		return TokenResponse{}, fmt.Errorf("rotating the refresh token: %w", err)
	}
	resp.RefreshToken = token
	logIssued(ctx, d, t, client, oauth.GrantTypeRefreshToken, jti,
		slog.String("refresh_token_family", family.ID.String()))
	return resp, nil
}

// refreshTokenReused revokes the family of a refresh token that was
// presented after it was replaced, and the access tokens issued from the
// family (RFC 9700, section 4.14.2), and returns the error for the request.
func refreshTokenReused(ctx context.Context, d Deps, t AuthorizationTenant, client store.Client,
	family store.RefreshTokenFamily,
) error {
	tokens, err := revokeFamily(ctx, d, t, family)
	if err != nil {
		return fmt.Errorf("revoking the family of a reused refresh token: %w", err)
	}
	d.Logger.LogAttrs(ctx, slog.LevelWarn, "refresh token reused; revoked its family",
		slog.String("tenant_id", t.ID.String()),
		slog.String("client_id", client.ClientID),
		slog.String("user_id", family.UserID.String()),
		slog.String("refresh_token_family", family.ID.String()),
		slog.Int64("revoked_access_tokens", tokens))
	audit(ctx, d, store.AuditEvent{TenantID: t.ID, Type: EventRefreshTokenReused, Actor: store.ActorClient,
		UserID: family.UserID, ClientID: client.ClientID, SessionID: family.SessionID,
		Details: map[string]string{"refresh_token_family": family.ID.String()}})
	return &oauth.Error{Code: oauth.ErrorInvalidGrant, Description: "the refresh token was used already"}
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
	resp, jti, err := issueTokens(ctx, d, signer, t, client, grant{scopes: scopes})
	if err != nil {
		return TokenResponse{}, err
	}
	logIssued(ctx, d, t, client, oauth.GrantTypeClientCredentials, jti)
	return resp, nil
}

// grant describes what a token response grants.
type grant struct {
	// userID is the zero UUID when the client acts for itself.
	userID uuid.UUID
	scopes []string
	// codeHash is the hash of the code the tokens derive from.
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
// g grants openid. It returns the response and the jti of the access token.
// Callers add a refresh token and log the issuance.
func issueTokens(ctx context.Context, d Deps, signer TokenSigner, t AuthorizationTenant, client store.Client, g grant,
) (TokenResponse, string, error) {
	scopes := g.scopes
	owners, err := scopeOwners(ctx, d, t.ID)
	if err != nil {
		return TokenResponse{}, "", err
	}
	if undefinedScope(scopes, owners) != "" {
		return TokenResponse{}, "", &oauth.Error{Code: oauth.ErrorInvalidScope,
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
		return TokenResponse{}, "", err
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
		return TokenResponse{}, "", fmt.Errorf("recording the access token: %w", err)
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
			return TokenResponse{}, "", fmt.Errorf("hashing the access token: %w", err)
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
			return TokenResponse{}, "", fmt.Errorf("encoding the ID token: %w", err)
		}
		if resp.IDToken, err = signer.Sign(ctx, t.ID, oidc.IDTokenSigningAlgorithm, oidc.IDTokenType, payload); err != nil {
			return TokenResponse{}, "", fmt.Errorf("signing a token: %w", err)
		}
	}
	return resp, claims.JWTID, nil
}

// logIssued records that client received tokens through the grant type; jti
// identifies the access token.
func logIssued(ctx context.Context, d Deps, t AuthorizationTenant, client store.Client, grantType, jti string,
	attrs ...slog.Attr,
) {
	d.Logger.LogAttrs(ctx, slog.LevelInfo, "issued tokens", append([]slog.Attr{
		slog.String("tenant_id", t.ID.String()),
		slog.String("client_id", client.ClientID),
		slog.String("grant_type", grantType),
		slog.String("jti", jti),
	}, attrs...)...)
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
	claims, ok, err := verifyAccessToken(ctx, signer, t, token)
	switch {
	case err != nil:
		return nil, err
	case !ok:
		return nil, invalid
	}
	now := d.Now()
	switch {
	case !slices.Contains(claims.Audience, t.Issuer), now.Unix() >= claims.Expiry:
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

// verifyAccessToken returns the claims of an access token that the tenant
// signed and issued, or false for any other token. It does not check
// expiry, audience or revocation.
func verifyAccessToken(ctx context.Context, signer TokenSigner, t AuthorizationTenant, token string,
) (oidc.AccessTokenClaims, bool, error) {
	payload, err := signer.Verify(ctx, t.ID, token, oidc.AccessTokenType)
	switch {
	case errors.Is(err, ErrInvalidToken):
		return oidc.AccessTokenClaims{}, false, nil
	case err != nil:
		return oidc.AccessTokenClaims{}, false, fmt.Errorf("verifying the access token: %w", err)
	}
	var claims oidc.AccessTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Issuer != t.Issuer || claims.JWTID == "" {
		return oidc.AccessTokenClaims{}, false, nil //nolint:nilerr // A token that does not decode is invalid.
	}
	return claims, true, nil
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
