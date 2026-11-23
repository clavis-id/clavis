package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"
	"uuid"

	"clavisid.org/clavis/store"
	"clavisid.org/clavis/store/sqlite/internal/db"
)

func (r authorizationCodes) Redeem(ctx context.Context, tenantID uuid.UUID, hash []byte, at time.Time) error {
	n, err := r.q.RedeemAuthorizationCode(ctx, db.RedeemAuthorizationCodeParams{
		RedeemedAt: optionalTime(at),
		TenantID:   tenantID.String(),
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
	return fmt.Errorf("sqlite: redeeming authorization code: redeemed already: %w", store.ErrConflict)
}

type accessTokens struct {
	q *db.Queries
}

func (r accessTokens) Create(ctx context.Context, t store.AccessToken) error {
	lists, err := encodeLists(t.Scopes, t.UserInfoClaims)
	if err != nil {
		return fmt.Errorf("sqlite: creating access token: %w", err)
	}
	err = r.q.CreateAccessToken(ctx, db.CreateAccessTokenParams{
		ID:             t.ID,
		TenantID:       t.TenantID.String(),
		ClientID:       t.ClientID.String(),
		UserID:         optionalID(t.UserID),
		CodeHash:       t.CodeHash,
		Scopes:         lists[0],
		UserinfoClaims: lists[1],
		IssuedAt:       t.IssuedAt.UnixMicro(),
		ExpiresAt:      t.ExpiresAt.UnixMicro(),
		RevokedAt:      optionalTime(t.RevokedAt),
	})
	return mapError("creating access token", err)
}

func (r accessTokens) Get(ctx context.Context, tenantID uuid.UUID, id string) (store.AccessToken, error) {
	row, err := r.q.GetAccessToken(ctx, db.GetAccessTokenParams{TenantID: tenantID.String(), ID: id})
	if err != nil {
		return store.AccessToken{}, mapError("getting access token", err)
	}
	columns := []string{row.TenantID, row.ClientID}
	if row.UserID.Valid {
		columns = append(columns, row.UserID.String)
	}
	ids, err := parseIDs("access token", columns...)
	if err != nil {
		return store.AccessToken{}, err
	}
	lists, err := decodeLists(row.Scopes, row.UserinfoClaims)
	if err != nil {
		return store.AccessToken{}, fmt.Errorf("sqlite: corrupt list in an access token: %w", err)
	}
	t := store.AccessToken{
		ID:             row.ID,
		TenantID:       ids[0],
		ClientID:       ids[1],
		CodeHash:       row.CodeHash,
		Scopes:         lists[0],
		UserInfoClaims: lists[1],
		IssuedAt:       time.UnixMicro(row.IssuedAt).UTC(),
		ExpiresAt:      time.UnixMicro(row.ExpiresAt).UTC(),
		RevokedAt:      timeOrZero(row.RevokedAt),
	}
	if row.UserID.Valid {
		t.UserID = ids[2]
	}
	return t, nil
}

func (r accessTokens) RevokeByUserAndClient(ctx context.Context, tenantID, userID, clientID uuid.UUID, at time.Time,
) (int64, error) {
	n, err := r.q.RevokeAccessTokensByUserAndClient(ctx, db.RevokeAccessTokensByUserAndClientParams{
		RevokedAt: optionalTime(at),
		TenantID:  tenantID.String(),
		UserID:    optionalID(userID),
		ClientID:  clientID.String(),
	})
	if err != nil {
		return 0, mapError("revoking access tokens", err)
	}
	return n, nil
}

func (r accessTokens) RevokeByUser(ctx context.Context, tenantID, userID uuid.UUID, at time.Time) (int64, error) {
	n, err := r.q.RevokeAccessTokensByUser(ctx, db.RevokeAccessTokensByUserParams{
		RevokedAt: optionalTime(at),
		TenantID:  tenantID.String(),
		UserID:    optionalID(userID),
	})
	if err != nil {
		return 0, mapError("revoking the access tokens of a user", err)
	}
	return n, nil
}

func (r accessTokens) Revoke(ctx context.Context, tenantID uuid.UUID, id string, at time.Time) error {
	n, err := r.q.RevokeAccessToken(ctx, db.RevokeAccessTokenParams{
		RevokedAt: optionalTime(at),
		TenantID:  tenantID.String(),
		ID:        id,
	})
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
		RevokedAt: optionalTime(at),
		TenantID:  tenantID.String(),
		SessionID: sessionID.String(),
	})
	if err != nil {
		return 0, mapError("revoking the access tokens of a session", err)
	}
	return n, nil
}

func (r accessTokens) RevokeByCode(ctx context.Context, tenantID uuid.UUID, codeHash []byte, at time.Time) (int64, error) {
	n, err := r.q.RevokeAccessTokensByCode(ctx, db.RevokeAccessTokensByCodeParams{
		RevokedAt: optionalTime(at),
		TenantID:  tenantID.String(),
		CodeHash:  codeHash,
	})
	if err != nil {
		return 0, mapError("revoking access tokens", err)
	}
	return n, nil
}

func (r accessTokens) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	n, err := r.q.DeleteExpiredAccessTokens(ctx, now.UnixMicro())
	if err != nil {
		return 0, mapError("deleting expired access tokens", err)
	}
	return n, nil
}

type apiResources struct {
	q *db.Queries
}

func (r apiResources) Create(ctx context.Context, a store.APIResource) error {
	scopes, err := encodeList(a.Scopes)
	if err != nil {
		return fmt.Errorf("sqlite: creating API resource: %w", err)
	}
	err = r.q.CreateAPIResource(ctx, db.CreateAPIResourceParams{
		ID:         a.ID.String(),
		TenantID:   a.TenantID.String(),
		Identifier: a.Identifier,
		Name:       a.Name,
		Scopes:     scopes,
		CreatedAt:  a.CreatedAt.UnixMicro(),
		UpdatedAt:  a.UpdatedAt.UnixMicro(),
	})
	return mapError("creating API resource", err)
}

func (r apiResources) GetByIdentifier(ctx context.Context, tenantID uuid.UUID, identifier string) (store.APIResource, error) {
	row, err := r.q.GetAPIResourceByIdentifier(ctx, db.GetAPIResourceByIdentifierParams{
		TenantID:   tenantID.String(),
		Identifier: identifier,
	})
	if err != nil {
		return store.APIResource{}, mapError("getting API resource", err)
	}
	return apiResourceFromRow(row)
}

func (r apiResources) List(ctx context.Context, tenantID, after uuid.UUID, limit int) ([]store.APIResource, error) {
	if limit < 1 || limit > store.MaxPageSize {
		return nil, fmt.Errorf("sqlite: listing API resources: %w: limit %d is outside [1, %d]",
			store.ErrInvalidArgument, limit, store.MaxPageSize)
	}
	rows, err := r.q.ListAPIResources(ctx, db.ListAPIResourcesParams{
		TenantID: tenantID.String(),
		After:    after.String(),
		PageSize: int64(limit),
	})
	if err != nil {
		return nil, mapError("listing API resources", err)
	}
	out := make([]store.APIResource, 0, len(rows))
	for _, row := range rows {
		a, err := apiResourceFromRow(row)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

func (r apiResources) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	n, err := r.q.DeleteAPIResource(ctx, db.DeleteAPIResourceParams{TenantID: tenantID.String(), ID: id.String()})
	if err != nil {
		return mapError("deleting API resource", err)
	}
	if n == 0 {
		return fmt.Errorf("sqlite: deleting API resource: %w", store.ErrNotFound)
	}
	return nil
}

func apiResourceFromRow(row db.ApiResource) (store.APIResource, error) {
	ids, err := parseIDs("API resource", row.ID, row.TenantID)
	if err != nil {
		return store.APIResource{}, err
	}
	scopes, err := decodeList(row.Scopes)
	if err != nil {
		return store.APIResource{}, fmt.Errorf("sqlite: corrupt scopes in API resource %s: %w", ids[0], err)
	}
	return store.APIResource{
		ID:         ids[0],
		TenantID:   ids[1],
		Identifier: row.Identifier,
		Name:       row.Name,
		Scopes:     scopes,
		CreatedAt:  time.UnixMicro(row.CreatedAt).UTC(),
		UpdatedAt:  time.UnixMicro(row.UpdatedAt).UTC(),
	}, nil
}

// optionalID stores the zero UUID as NULL.
func optionalID(id uuid.UUID) sql.NullString {
	if id == uuid.Nil() {
		return sql.NullString{}
	}
	return sql.NullString{String: id.String(), Valid: true}
}

// optionalTime stores the zero time as NULL.
func optionalTime(t time.Time) sql.NullInt64 {
	if t.IsZero() {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: t.UnixMicro(), Valid: true}
}

// timeOrZero returns a stored time in UTC, or the zero time for NULL.
func timeOrZero(v sql.NullInt64) time.Time {
	if !v.Valid {
		return time.Time{}
	}
	return time.UnixMicro(v.Int64).UTC()
}
