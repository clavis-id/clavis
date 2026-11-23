-- name: GetBranding :one
SELECT tenant_id, theme, logo_type, logo_hash, updated_at
FROM brandings
WHERE tenant_id = sqlc.arg(tenant_id);

-- name: GetBrandingLogo :one
SELECT logo, logo_type, logo_hash
FROM brandings
WHERE tenant_id = sqlc.arg(tenant_id) AND logo IS NOT NULL;

-- name: PutBrandingTheme :exec
INSERT INTO brandings (tenant_id, theme, updated_at)
VALUES (sqlc.arg(tenant_id), sqlc.arg(theme), sqlc.arg(updated_at))
ON CONFLICT (tenant_id) DO UPDATE
SET theme = excluded.theme, updated_at = excluded.updated_at;

-- name: PutBrandingLogo :exec
INSERT INTO brandings (tenant_id, theme, logo, logo_type, logo_hash, updated_at)
VALUES (
    sqlc.arg(tenant_id), sqlc.arg(theme), sqlc.arg(logo), sqlc.arg(logo_type), sqlc.arg(logo_hash),
    sqlc.arg(updated_at)
)
ON CONFLICT (tenant_id) DO UPDATE
SET logo = excluded.logo, logo_type = excluded.logo_type, logo_hash = excluded.logo_hash,
    updated_at = excluded.updated_at;

-- name: DeleteBrandingLogo :execrows
UPDATE brandings
SET logo = NULL, logo_type = '', logo_hash = '', updated_at = sqlc.arg(updated_at)
WHERE tenant_id = sqlc.arg(tenant_id) AND logo IS NOT NULL;

-- name: DeleteBranding :execrows
DELETE FROM brandings
WHERE tenant_id = sqlc.arg(tenant_id);
