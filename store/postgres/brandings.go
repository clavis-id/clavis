package postgres

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"time"
	"uuid"

	"clavisid.org/clavis/store"
	"clavisid.org/clavis/store/postgres/internal/db"
)

type brandings struct {
	q *db.Queries
}

func (r brandings) Get(ctx context.Context, tenantID uuid.UUID) (store.Branding, error) {
	row, err := r.q.GetBranding(ctx, tenantID)
	if err != nil {
		return store.Branding{}, mapError("getting branding", err)
	}
	var theme store.Theme
	if err := json.Unmarshal(row.Theme, &theme); err != nil {
		return store.Branding{}, fmt.Errorf("postgres: corrupt theme of tenant %s: %w", row.TenantID, err)
	}
	return store.Branding{
		TenantID:  row.TenantID,
		Theme:     theme,
		LogoType:  row.LogoType,
		LogoHash:  row.LogoHash,
		UpdatedAt: row.UpdatedAt.UTC(),
	}, nil
}

func (r brandings) GetLogo(ctx context.Context, tenantID uuid.UUID) (store.Logo, error) {
	row, err := r.q.GetBrandingLogo(ctx, tenantID)
	if err != nil {
		return store.Logo{}, mapError("getting logo", err)
	}
	return store.Logo{ContentType: row.LogoType, Data: row.Logo, Hash: row.LogoHash}, nil
}

func (r brandings) PutTheme(ctx context.Context, tenantID uuid.UUID, theme store.Theme, updatedAt time.Time) error {
	encoded, err := json.Marshal(theme)
	if err != nil {
		return fmt.Errorf("postgres: storing theme: %w", err)
	}
	err = r.q.PutBrandingTheme(ctx, db.PutBrandingThemeParams{
		TenantID:  tenantID,
		Theme:     encoded,
		UpdatedAt: updatedAt,
	})
	return mapError("storing theme", err)
}

func (r brandings) PutLogo(ctx context.Context, tenantID uuid.UUID, logo store.Logo, updatedAt time.Time) error {
	err := r.q.PutBrandingLogo(ctx, db.PutBrandingLogoParams{
		TenantID:  tenantID,
		Theme:     []byte("{}"),
		Logo:      logo.Data,
		LogoType:  logo.ContentType,
		LogoHash:  logo.Hash,
		UpdatedAt: updatedAt,
	})
	return mapError("storing logo", err)
}

func (r brandings) DeleteLogo(ctx context.Context, tenantID uuid.UUID, updatedAt time.Time) error {
	n, err := r.q.DeleteBrandingLogo(ctx, db.DeleteBrandingLogoParams{
		TenantID:  tenantID,
		UpdatedAt: updatedAt,
	})
	if err != nil {
		return mapError("deleting logo", err)
	}
	if n == 0 {
		return fmt.Errorf("postgres: deleting logo: %w", store.ErrNotFound)
	}
	return nil
}

func (r brandings) Delete(ctx context.Context, tenantID uuid.UUID) error {
	n, err := r.q.DeleteBranding(ctx, tenantID)
	if err != nil {
		return mapError("deleting branding", err)
	}
	if n == 0 {
		return fmt.Errorf("postgres: deleting branding: %w", store.ErrNotFound)
	}
	return nil
}
