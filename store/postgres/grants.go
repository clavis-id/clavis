package postgres

import (
	"context"
	"fmt"
	"uuid"

	"clavisid.org/clavis/store"
	"clavisid.org/clavis/store/postgres/internal/db"
)

type grants struct {
	q *db.Queries
}

func (r grants) Get(ctx context.Context, tenantID, userID, clientID uuid.UUID) (store.Grant, error) {
	row, err := r.q.GetGrant(ctx, db.GetGrantParams{TenantID: tenantID, UserID: userID, ClientID: clientID})
	if err != nil {
		return store.Grant{}, mapError("getting grant", err)
	}
	return grantFromRow(row), nil
}

func (r grants) Put(ctx context.Context, g store.Grant) error {
	err := r.q.PutGrant(ctx, db.PutGrantParams{
		ID:        g.ID,
		TenantID:  g.TenantID,
		UserID:    g.UserID,
		ClientID:  g.ClientID,
		Scopes:    orEmpty(g.Scopes),
		CreatedAt: g.CreatedAt,
		UpdatedAt: g.UpdatedAt,
	})
	return mapError("storing grant", err)
}

func (r grants) List(ctx context.Context, tenantID, userID uuid.UUID) ([]store.Grant, error) {
	rows, err := r.q.ListGrants(ctx, db.ListGrantsParams{TenantID: tenantID, UserID: userID})
	if err != nil {
		return nil, mapError("listing grants", err)
	}
	list := make([]store.Grant, 0, len(rows))
	for _, row := range rows {
		list = append(list, grantFromRow(row))
	}
	return list, nil
}

func (r grants) Delete(ctx context.Context, tenantID, userID, clientID uuid.UUID) error {
	n, err := r.q.DeleteGrant(ctx, db.DeleteGrantParams{TenantID: tenantID, UserID: userID, ClientID: clientID})
	if err != nil {
		return mapError("deleting grant", err)
	}
	if n == 0 {
		return fmt.Errorf("postgres: deleting grant: %w", store.ErrNotFound)
	}
	return nil
}

func grantFromRow(row db.Grant) store.Grant {
	return store.Grant{
		ID:        row.ID,
		TenantID:  row.TenantID,
		UserID:    row.UserID,
		ClientID:  row.ClientID,
		Scopes:    row.Scopes,
		CreatedAt: row.CreatedAt.UTC(),
		UpdatedAt: row.UpdatedAt.UTC(),
	}
}
