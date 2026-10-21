package sqlite

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"time"
	"uuid"

	"clavisid.org/clavis/store"
	"clavisid.org/clavis/store/sqlite/internal/db"
)

type brandings struct {
	q *db.Queries
}

func (r brandings) Get(ctx context.Context, tenantID uuid.UUID) (store.Branding, error) {
	row, err := r.q.GetBranding(ctx, tenantID.String())
	if err != nil {
		return store.Branding{}, mapError("getting branding", err)
	}
	ids, err := parseIDs("branding", row.TenantID)
	if err != nil {
		return store.Branding{}, err
	}
	var theme store.Theme
	if err := json.Unmarshal([]byte(row.Theme), &theme); err != nil {
		return store.Branding{}, fmt.Errorf("sqlite: corrupt theme of tenant %s: %w", ids[0], err)
	}
	return store.Branding{
		TenantID:  ids[0],
		Theme:     theme,
		LogoType:  row.LogoType,
		LogoHash:  row.LogoHash,
		UpdatedAt: time.UnixMicro(row.UpdatedAt).UTC(),
	}, nil
}

func (r brandings) GetLogo(ctx context.Context, tenantID uuid.UUID) (store.Logo, error) {
	row, err := r.q.GetBrandingLogo(ctx, tenantID.String())
	if err != nil {
		return store.Logo{}, mapError("getting logo", err)
	}
	return store.Logo{ContentType: row.LogoType, Data: row.Logo, Hash: row.LogoHash}, nil
}

func (r brandings) PutTheme(ctx context.Context, tenantID uuid.UUID, theme store.Theme, updatedAt time.Time) error {
	encoded, err := json.Marshal(theme)
	if err != nil {
		return fmt.Errorf("sqlite: storing theme: %w", err)
	}
	err = r.q.PutBrandingTheme(ctx, db.PutBrandingThemeParams{
		TenantID:  tenantID.String(),
		Theme:     string(encoded),
		UpdatedAt: updatedAt.UnixMicro(),
	})
	return mapError("storing theme", err)
}

func (r brandings) PutLogo(ctx context.Context, tenantID uuid.UUID, logo store.Logo, updatedAt time.Time) error {
	err := r.q.PutBrandingLogo(ctx, db.PutBrandingLogoParams{
		TenantID:  tenantID.String(),
		Theme:     "{}",
		Logo:      logo.Data,
		LogoType:  logo.ContentType,
		LogoHash:  logo.Hash,
		UpdatedAt: updatedAt.UnixMicro(),
	})
	return mapError("storing logo", err)
}

func (r brandings) DeleteLogo(ctx context.Context, tenantID uuid.UUID, updatedAt time.Time) error {
	n, err := r.q.DeleteBrandingLogo(ctx, db.DeleteBrandingLogoParams{
		TenantID:  tenantID.String(),
		UpdatedAt: updatedAt.UnixMicro(),
	})
	if err != nil {
		return mapError("deleting logo", err)
	}
	if n == 0 {
		return fmt.Errorf("sqlite: deleting logo: %w", store.ErrNotFound)
	}
	return nil
}

func (r brandings) Delete(ctx context.Context, tenantID uuid.UUID) error {
	n, err := r.q.DeleteBranding(ctx, tenantID.String())
	if err != nil {
		return mapError("deleting branding", err)
	}
	if n == 0 {
		return fmt.Errorf("sqlite: deleting branding: %w", store.ErrNotFound)
	}
	return nil
}
