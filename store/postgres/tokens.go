package postgres

import (
	"context"
	"fmt"
	"time"
	"uuid"

	"clavisid.org/clavis/store"
	"clavisid.org/clavis/store/postgres/internal/db"
)

func (r authorizationCodes) Redeem(ctx context.Context, tenantID uuid.UUID, hash []byte, at time.Time) error {
	n, err := r.q.RedeemAuthorizationCode(ctx, db.RedeemAuthorizationCodeParams{
		RedeemedAt: &at,
		TenantID:   tenantID,
		Hash:       hash,
	})
	if err != nil {
		return mapError("redeeming authorization code", err)
	}
	if n == 1 {
		return nil
	}
	if _, err := r.Get(ctx, tenantID, hash); err != nil {
		return err
	}
	return fmt.Errorf("postgres: redeeming authorization code: redeemed already: %w", store.ErrConflict)
}

type accessTokens struct {
	q *db.Queries
}

func (r accessTokens) Create(ctx context.Context, t store.AccessToken) error {
	err := r.q.CreateAccessToken(ctx, db.CreateAccessTokenParams{
		ID:             t.ID,
		TenantID:       t.TenantID,
		ClientID:       t.ClientID,
		UserID:         optionalID(t.UserID),
		CodeHash:       t.CodeHash,
		Scopes:         orEmpty(t.Scopes),
		UserinfoClaims: orEmpty(t.UserInfoClaims),
		IssuedAt:       t.IssuedAt,
		ExpiresAt:      t.ExpiresAt,
		RevokedAt:      optionalTime(t.RevokedAt),
	})
	return mapError("creating access token", err)
}

func (r accessTokens) Get(ctx context.Context, tenantID uuid.UUID, id string) (store.AccessToken, error) {
	row, err := r.q.GetAccessToken(ctx, db.GetAccessTokenParams{TenantID: tenantID, ID: id})
	if err != nil {
		return store.AccessToken{}, mapError("getting access token", err)
	}
	t := store.AccessToken{
		ID:             row.ID,
		TenantID:       row.TenantID,
		ClientID:       row.ClientID,
		CodeHash:       row.CodeHash,
		Scopes:         row.Scopes,
		UserInfoClaims: row.UserinfoClaims,
		IssuedAt:       row.IssuedAt.UTC(),
		ExpiresAt:      row.ExpiresAt.UTC(),
	}
	if row.UserID != nil {
		t.UserID = *row.UserID
	}
	if row.RevokedAt != nil {
		t.RevokedAt = row.RevokedAt.UTC()
	}
	return t, nil
}

func (r accessTokens) RevokeByUserAndClient(ctx context.Context, tenantID, userID, clientID uuid.UUID, at time.Time,
) (int64, error) {
	n, err := r.q.RevokeAccessTokensByUserAndClient(ctx, db.RevokeAccessTokensByUserAndClientParams{
		RevokedAt: optionalTime(at),
		TenantID:  tenantID,
		UserID:    optionalID(userID),
		ClientID:  clientID,
	})
	if err != nil {
		return 0, mapError("revoking access tokens", err)
	}
	return n, nil
}

func (r accessTokens) RevokeByUser(ctx context.Context, tenantID, userID uuid.UUID, at time.Time) (int64, error) {
	n, err := r.q.RevokeAccessTokensByUser(ctx, db.RevokeAccessTokensByUserParams{
		RevokedAt: optionalTime(at),
		TenantID:  tenantID,
		UserID:    optionalID(userID),
	})
	if err != nil {
		return 0, mapError("revoking the access tokens of a user", err)
	}
	return n, nil
}

func (r accessTokens) Revoke(ctx context.Context, tenantID uuid.UUID, id string, at time.Time) error {
	n, err := r.q.RevokeAccessToken(ctx, db.RevokeAccessTokenParams{RevokedAt: &at, TenantID: tenantID, ID: id})
	if err != nil {
		return mapError("revoking access token", err)
	}
	if n == 0 {
		// The token was revoked already, or does not exist.
		if _, err := r.Get(ctx, tenantID, id); err != nil {
			return err
		}
	}
	return nil
}

func (r accessTokens) RevokeBySession(ctx context.Context, tenantID, sessionID uuid.UUID, at time.Time) (int64, error) {
	n, err := r.q.RevokeAccessTokensBySession(ctx, db.RevokeAccessTokensBySessionParams{
		RevokedAt: &at,
		TenantID:  tenantID,
		SessionID: sessionID,
	})
	if err != nil {
		return 0, mapError("revoking the access tokens of a session", err)
	}
	return n, nil
}

func (r accessTokens) RevokeByCode(ctx context.Context, tenantID uuid.UUID, codeHash []byte, at time.Time) (int64, error) {
	n, err := r.q.RevokeAccessTokensByCode(ctx, db.RevokeAccessTokensByCodeParams{
		RevokedAt: &at,
		TenantID:  tenantID,
		CodeHash:  codeHash,
	})
	if err != nil {
		return 0, mapError("revoking access tokens", err)
	}
	return n, nil
}

func (r accessTokens) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	n, err := r.q.DeleteExpiredAccessTokens(ctx, now)
	if err != nil {
		return 0, mapError("deleting expired access tokens", err)
	}
	return n, nil
}

type apiResources struct {
	q *db.Queries
}

func (r apiResources) Create(ctx context.Context, a store.APIResource) error {
	err := r.q.CreateAPIResource(ctx, db.CreateAPIResourceParams{
		ID:         a.ID,
		TenantID:   a.TenantID,
		Identifier: a.Identifier,
		Name:       a.Name,
		Scopes:     orEmpty(a.Scopes),
		CreatedAt:  a.CreatedAt,
		UpdatedAt:  a.UpdatedAt,
	})
	return mapError("creating API resource", err)
}

func (r apiResources) GetByIdentifier(ctx context.Context, tenantID uuid.UUID, identifier string) (store.APIResource, error) {
	row, err := r.q.GetAPIResourceByIdentifier(ctx, db.GetAPIResourceByIdentifierParams{
		TenantID:   tenantID,
		Identifier: identifier,
	})
	if err != nil {
		return store.APIResource{}, mapError("getting API resource", err)
	}
	return apiResourceFromRow(row), nil
}

func (r apiResources) List(ctx context.Context, tenantID, after uuid.UUID, limit int) ([]store.APIResource, error) {
	if limit < 1 || limit > store.MaxPageSize {
		return nil, fmt.Errorf("postgres: listing API resources: %w: limit %d is outside [1, %d]",
			store.ErrInvalidArgument, limit, store.MaxPageSize)
	}
	rows, err := r.q.ListAPIResources(ctx, db.ListAPIResourcesParams{TenantID: tenantID, After: after, PageSize: int32(limit)})
	if err != nil {
		return nil, mapError("listing API resources", err)
	}
	out := make([]store.APIResource, 0, len(rows))
	for _, row := range rows {
		out = append(out, apiResourceFromRow(row))
	}
	return out, nil
}

func (r apiResources) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	n, err := r.q.DeleteAPIResource(ctx, db.DeleteAPIResourceParams{TenantID: tenantID, ID: id})
	if err != nil {
		return mapError("deleting API resource", err)
	}
	if n == 0 {
		return fmt.Errorf("postgres: deleting API resource: %w", store.ErrNotFound)
	}
	return nil
}

func apiResourceFromRow(row db.ApiResource) store.APIResource {
	return store.APIResource{
		ID:         row.ID,
		TenantID:   row.TenantID,
		Identifier: row.Identifier,
		Name:       row.Name,
		Scopes:     row.Scopes,
		CreatedAt:  row.CreatedAt.UTC(),
		UpdatedAt:  row.UpdatedAt.UTC(),
	}
}

// optionalID returns nil for the zero UUID, which stores as NULL.
func optionalID(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil() {
		return nil
	}
	return &id
}

// optionalTime returns nil for the zero time, which stores as NULL.
func optionalTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}
