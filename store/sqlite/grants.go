package sqlite

import (
	"context"
	"fmt"
	"time"
	"uuid"

	"clavisid.org/clavis/store"
	"clavisid.org/clavis/store/sqlite/internal/db"
)

type grants struct {
	q *db.Queries
}

func (r grants) Get(ctx context.Context, tenantID, userID, clientID uuid.UUID) (store.Grant, error) {
	row, err := r.q.GetGrant(ctx, db.GetGrantParams{
		TenantID: tenantID.String(),
		UserID:   userID.String(),
		ClientID: clientID.String(),
	})
	if err != nil {
		return store.Grant{}, mapError("getting grant", err)
	}
	return grantFromRow(row)
}

func (r grants) Put(ctx context.Context, g store.Grant) error {
	scopes, err := encodeList(g.Scopes)
	if err != nil {
		return fmt.Errorf("sqlite: storing grant: %w", err)
	}
	err = r.q.PutGrant(ctx, db.PutGrantParams{
		ID:        g.ID.String(),
		TenantID:  g.TenantID.String(),
		UserID:    g.UserID.String(),
		ClientID:  g.ClientID.String(),
		Scopes:    scopes,
		CreatedAt: g.CreatedAt.UnixMicro(),
		UpdatedAt: g.UpdatedAt.UnixMicro(),
	})
	return mapError("storing grant", err)
}

func (r grants) List(ctx context.Context, tenantID, userID uuid.UUID) ([]store.Grant, error) {
	rows, err := r.q.ListGrants(ctx, db.ListGrantsParams{TenantID: tenantID.String(), UserID: userID.String()})
	if err != nil {
		return nil, mapError("listing grants", err)
	}
	list := make([]store.Grant, 0, len(rows))
	for _, row := range rows {
		g, err := grantFromRow(row)
		if err != nil {
			return nil, err
		}
		list = append(list, g)
	}
	return list, nil
}

func (r grants) Delete(ctx context.Context, tenantID, userID, clientID uuid.UUID) error {
	n, err := r.q.DeleteGrant(ctx, db.DeleteGrantParams{
		TenantID: tenantID.String(),
		UserID:   userID.String(),
		ClientID: clientID.String(),
	})
	if err != nil {
		return mapError("deleting grant", err)
	}
	if n == 0 {
		return fmt.Errorf("sqlite: deleting grant: %w", store.ErrNotFound)
	}
	return nil
}

func grantFromRow(row db.Grant) (store.Grant, error) {
	ids, err := parseIDs("grant", row.ID, row.TenantID, row.UserID, row.ClientID)
	if err != nil {
		return store.Grant{}, err
	}
	scopes, err := decodeList(row.Scopes)
	if err != nil {
		return store.Grant{}, fmt.Errorf("sqlite: corrupt scopes in grant %s: %w", ids[0], err)
	}
	return store.Grant{
		ID:        ids[0],
		TenantID:  ids[1],
		UserID:    ids[2],
		ClientID:  ids[3],
		Scopes:    scopes,
		CreatedAt: time.UnixMicro(row.CreatedAt).UTC(),
		UpdatedAt: time.UnixMicro(row.UpdatedAt).UTC(),
	}, nil
}
