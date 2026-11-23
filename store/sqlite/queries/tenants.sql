-- name: CreateTenant :exec
INSERT INTO tenants (id, slug, name, signup_enabled, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetTenant :one
SELECT id, slug, name, created_at, updated_at, signup_enabled
FROM tenants
WHERE id = ?;

-- name: GetTenantBySlug :one
SELECT id, slug, name, created_at, updated_at, signup_enabled
FROM tenants
WHERE slug = ?;

-- name: ListTenants :many
SELECT id, slug, name, created_at, updated_at, signup_enabled
FROM tenants
WHERE id > sqlc.arg(after)
ORDER BY id
LIMIT sqlc.arg(page_size);

-- name: UpdateTenant :execrows
UPDATE tenants
SET name = sqlc.arg(name), signup_enabled = sqlc.arg(signup_enabled), updated_at = sqlc.arg(updated_at)
WHERE id = sqlc.arg(id);

-- name: DeleteTenant :execrows
DELETE FROM tenants
WHERE id = ?;
