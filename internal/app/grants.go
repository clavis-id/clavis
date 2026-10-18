package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"uuid"

	"clavisid.org/clavis/store"
)

// ErrGrantNotFound reports that a user has no grant for a client.
var ErrGrantNotFound = errors.New("grant not found")

// UserGrant is a grant of a user, with its client.
type UserGrant struct {
	store.Grant
	Client store.Client
}

// ListGrants returns the grants of the user of a tenant with the given email
// address, oldest first.
func ListGrants(ctx context.Context, d Deps, tenantID uuid.UUID, email string) ([]UserGrant, error) {
	u, err := FindUser(ctx, d, tenantID, email)
	if err != nil {
		return nil, err
	}
	grants, err := d.Store.Grants().List(ctx, tenantID, u.ID)
	if err != nil {
		return nil, fmt.Errorf("listing grants: %w", err)
	}
	list := make([]UserGrant, 0, len(grants))
	for _, g := range grants {
		c, err := d.Store.Clients().Get(ctx, tenantID, g.ClientID)
		switch {
		case errors.Is(err, store.ErrNotFound):
			// The client was deleted, and its grants with it.
			continue
		case err != nil:
			return nil, fmt.Errorf("looking up the client of a grant: %w", err)
		}
		list = append(list, UserGrant{Grant: g, Client: c})
	}
	return list, nil
}

// RevokeGrant deletes the grant of the user of a tenant with the given email
// address for the client with the given client ID, and revokes the refresh
// and access tokens issued to the client for the user (ADR 0020). It also
// deletes the authorization codes issued to the client for the user, so a
// code issued before the revocation cannot yield tokens after it. The next
// authorization request of the client asks the user again.
func RevokeGrant(ctx context.Context, d Deps, tenantID uuid.UUID, email, clientID string) error {
	u, err := FindUser(ctx, d, tenantID, email)
	if err != nil {
		return err
	}
	c, err := GetClient(ctx, d, tenantID, clientID)
	if err != nil {
		return err
	}
	switch err := d.Store.Grants().Delete(ctx, tenantID, u.ID, c.ID); {
	case errors.Is(err, store.ErrNotFound):
		return fmt.Errorf("%w: %s for %s", ErrGrantNotFound, u.Email, c.ClientID)
	case err != nil:
		return fmt.Errorf("deleting the grant: %w", err)
	}
	codes, err := d.Store.AuthorizationCodes().DeleteByUserAndClient(ctx, tenantID, u.ID, c.ID)
	if err != nil {
		return fmt.Errorf("deleting the codes of the grant: %w", err)
	}
	// Refresh token families come before access tokens: a refresh records
	// its access token before it rotates the refresh token, so it either
	// fails on the revoked family or its access token is revoked below
	// (ADR 0021).
	now := d.Now()
	families, err := d.Store.RefreshTokens().RevokeByUserAndClient(ctx, tenantID, u.ID, c.ID, now)
	if err != nil {
		return fmt.Errorf("revoking the refresh tokens of the grant: %w", err)
	}
	tokens, err := d.Store.AccessTokens().RevokeByUserAndClient(ctx, tenantID, u.ID, c.ID, now)
	if err != nil {
		return fmt.Errorf("revoking the access tokens of the grant: %w", err)
	}
	d.Logger.LogAttrs(ctx, slog.LevelInfo, "revoked grant",
		slog.String("tenant_id", tenantID.String()),
		slog.String("user_id", u.ID.String()),
		slog.String("client_id", c.ClientID),
		slog.Int64("deleted_authorization_codes", codes),
		slog.Int64("revoked_refresh_token_families", families),
		slog.Int64("revoked_access_tokens", tokens))
	return nil
}
