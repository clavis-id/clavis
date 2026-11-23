package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"uuid"

	"clavisid.org/clavis/internal/oauth"
	"clavisid.org/clavis/store"
)

// Introspection is an introspection response (RFC 7662, section 2.2). The
// response for a token that is not active has Active false and nothing
// else.
type Introspection struct {
	Active    bool     `json:"active"`
	Scope     string   `json:"scope,omitzero"`
	ClientID  string   `json:"client_id,omitzero"`
	TokenType string   `json:"token_type,omitzero"`
	Expiry    int64    `json:"exp,omitzero"`
	IssuedAt  int64    `json:"iat,omitzero"`
	Subject   string   `json:"sub,omitzero"`
	Audience  []string `json:"aud,omitzero"`
	Issuer    string   `json:"iss,omitzero"`
	JWTID     string   `json:"jti,omitzero"`
}

// isAccessToken reports whether token has the form of an access token, a
// JWT in compact serialization. Refresh tokens are base64url without dots,
// so the two are told apart without a token_type_hint (ADR 0022).
func isAccessToken(token string) bool {
	return strings.Count(token, ".") == 2
}

// RevokeToken answers a revocation request (RFC 7009, section 2.1) of
// client, which AuthenticateClient returned (ADR 0022). Revoking a refresh
// token, current or replaced, revokes its family and the access tokens
// issued from it; revoking an access token revokes that token only. A token
// that is invalid or unknown needs nothing, which is not an error (section
// 2.2). A token issued to another client fails with unauthorized_client.
func RevokeToken(ctx context.Context, d Deps, signer TokenSigner, t AuthorizationTenant, client store.Client,
	token string,
) error {
	if isAccessToken(token) {
		return revokeAccessToken(ctx, d, signer, t, client, token)
	}
	return revokeRefreshToken(ctx, d, t, client, token)
}

// errOtherClient refuses to revoke a token of another client (RFC 7009,
// section 2.1).
var errOtherClient = &oauth.Error{Code: oauth.ErrorUnauthorizedClient,
	Description: "the token was issued to another client"}

func revokeAccessToken(ctx context.Context, d Deps, signer TokenSigner, t AuthorizationTenant, client store.Client,
	token string,
) error {
	claims, ok, err := verifyAccessToken(ctx, signer, t, token)
	if err != nil || !ok {
		return err
	}
	record, err := d.Store.AccessTokens().Get(ctx, t.ID, claims.JWTID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		// Expired and deleted already.
		return nil
	case err != nil:
		return fmt.Errorf("looking up the access token: %w", err)
	case record.ClientID != client.ID:
		return errOtherClient
	}
	if err := d.Store.AccessTokens().Revoke(ctx, t.ID, record.ID, d.Now()); err != nil &&
		!errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("revoking the access token: %w", err)
	}
	d.Logger.LogAttrs(ctx, slog.LevelInfo, "revoked access token",
		slog.String("tenant_id", t.ID.String()),
		slog.String("client_id", client.ClientID),
		slog.String("jti", record.ID))
	audit(ctx, d, store.AuditEvent{TenantID: t.ID, Type: EventTokenRevoked, Actor: store.ActorClient,
		UserID: record.UserID, ClientID: client.ClientID,
		Details: map[string]string{"token_type": "access_token", "jti": record.ID}})
	return nil
}

func revokeRefreshToken(ctx context.Context, d Deps, t AuthorizationTenant, client store.Client, token string) error {
	_, family, err := d.Store.RefreshTokens().Get(ctx, t.ID, oauth.HashToken(token))
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil
	case err != nil:
		return fmt.Errorf("looking up the refresh token: %w", err)
	case family.ClientID != client.ID:
		return errOtherClient
	}
	// RFC 7009, section 2.1: the access tokens of the same grant go too.
	tokens, err := revokeFamily(ctx, d, t, family)
	if err != nil {
		return fmt.Errorf("revoking a refresh token: %w", err)
	}
	d.Logger.LogAttrs(ctx, slog.LevelInfo, "revoked refresh token family",
		slog.String("tenant_id", t.ID.String()),
		slog.String("client_id", client.ClientID),
		slog.String("refresh_token_family", family.ID.String()),
		slog.Int64("revoked_access_tokens", tokens))
	audit(ctx, d, store.AuditEvent{TenantID: t.ID, Type: EventTokenRevoked, Actor: store.ActorClient,
		UserID: family.UserID, ClientID: client.ClientID, SessionID: family.SessionID,
		Details: map[string]string{"token_type": "refresh_token", "refresh_token_family": family.ID.String()}})
	return nil
}

// IntrospectToken answers an introspection request (RFC 7662, section 2.1)
// of client, which AuthenticateClient returned (ADR 0022). Only confidential
// clients may introspect. A client sees the tokens issued to it. A client
// that is the server of API resources also sees the access tokens issued
// for them, with only its own audiences and scopes. Any other token, and any
// token that is not active, is reported as inactive, so the response tells
// nothing about it. Introspection changes nothing: a replaced refresh token
// is inactive, not reused.
func IntrospectToken(ctx context.Context, d Deps, signer TokenSigner, t AuthorizationTenant, client store.Client,
	token string,
) (Introspection, error) {
	if client.Type != store.ClientConfidential {
		return Introspection{}, &oauth.Error{Code: oauth.ErrorInvalidClient,
			Description: "only confidential clients may introspect tokens"}
	}
	if isAccessToken(token) {
		return introspectAccessToken(ctx, d, signer, t, client, token)
	}
	return introspectRefreshToken(ctx, d, t, client, token)
}

func introspectAccessToken(ctx context.Context, d Deps, signer TokenSigner, t AuthorizationTenant,
	client store.Client, token string,
) (Introspection, error) {
	claims, ok, err := verifyAccessToken(ctx, signer, t, token)
	if err != nil || !ok || d.Now().Unix() >= claims.Expiry {
		return Introspection{}, err
	}
	record, err := d.Store.AccessTokens().Get(ctx, t.ID, claims.JWTID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return Introspection{}, nil
	case err != nil:
		return Introspection{}, fmt.Errorf("looking up the access token: %w", err)
	case !record.RevokedAt.IsZero():
		return Introspection{}, nil
	}
	audience, scopes := claims.Audience, strings.Fields(claims.Scope)
	if record.ClientID != client.ID {
		// A resource server sees its own audiences and the scopes of its
		// resources (RFC 7662, section 4). The issuer, the audience of every
		// token that grants OpenID Connect scopes, is never one of them, even
		// when an API resource was registered under its identifier.
		audience = slices.DeleteFunc(slices.Clone(audience), func(aud string) bool {
			return aud == t.Issuer || !slices.Contains(client.ResourceServerFor, aud)
		})
		if len(audience) == 0 {
			return Introspection{}, nil
		}
		owners, err := scopeOwners(ctx, d, t.ID)
		if err != nil {
			return Introspection{}, err
		}
		scopes = slices.DeleteFunc(scopes, func(s string) bool {
			owner, ok := owners[s]
			return !ok || !slices.Contains(audience, owner.Identifier)
		})
	}
	if active, err := userActive(ctx, d, t.ID, record.UserID); err != nil || !active {
		return Introspection{}, err
	}
	return Introspection{
		Active:    true,
		Scope:     strings.Join(scopes, " "),
		ClientID:  claims.ClientID,
		TokenType: "Bearer",
		Expiry:    claims.Expiry,
		IssuedAt:  claims.IssuedAt,
		Subject:   claims.Subject,
		Audience:  audience,
		Issuer:    claims.Issuer,
		JWTID:     claims.JWTID,
	}, nil
}

func introspectRefreshToken(ctx context.Context, d Deps, t AuthorizationTenant, client store.Client, token string,
) (Introspection, error) {
	current, family, err := d.Store.RefreshTokens().Get(ctx, t.ID, oauth.HashToken(token))
	now := d.Now()
	switch {
	case errors.Is(err, store.ErrNotFound):
		return Introspection{}, nil
	case err != nil:
		return Introspection{}, fmt.Errorf("looking up the refresh token: %w", err)
	case family.ClientID != client.ID, !current.RotatedAt.IsZero(), !family.RevokedAt.IsZero(),
		!now.Before(current.ExpiresAt), !now.Before(family.ExpiresAt):
		return Introspection{}, nil
	}
	if active, err := userActive(ctx, d, t.ID, family.UserID); err != nil || !active {
		return Introspection{}, err
	}
	return Introspection{
		Active:   true,
		Scope:    strings.Join(family.Scopes, " "),
		ClientID: client.ClientID,
		Expiry:   current.ExpiresAt.Unix(),
		IssuedAt: current.IssuedAt.Unix(),
		Subject:  family.UserID.String(),
		Issuer:   t.Issuer,
	}, nil
}

// userActive reports whether the user of a tenant with the given ID exists
// and is active. A token that a client obtained for itself has no user, and
// counts as active.
func userActive(ctx context.Context, d Deps, tenantID, userID uuid.UUID) (bool, error) {
	if userID == uuid.Nil() {
		return true, nil
	}
	u, err := d.Store.Users().Get(ctx, tenantID, userID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("looking up the user: %w", err)
	}
	return u.Status == store.UserActive, nil
}
