-- name: CreateTenant :exec
INSERT INTO tenants (id, slug, name, created_at, updated_at)
VALUES (?, ?, ?, ?, ?);

-- name: GetTenant :one
SELECT id, slug, name, created_at, updated_at
FROM tenants
WHERE id = ?;

-- name: GetTenantBySlug :one
SELECT id, slug, name, created_at, updated_at
FROM tenants
WHERE slug = ?;

-- name: ListTenants :many
SELECT id, slug, name, created_at, updated_at
FROM tenants
WHERE id > sqlc.arg(after)
ORDER BY id
LIMIT sqlc.arg(page_size);

-- name: DeleteTenant :execrows
DELETE FROM tenants
WHERE id = ?;
