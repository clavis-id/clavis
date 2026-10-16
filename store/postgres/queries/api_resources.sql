-- name: CreateAPIResource :exec
INSERT INTO api_resources (id, tenant_id, identifier, name, scopes, created_at, updated_at)
VALUES (
    sqlc.arg(id), sqlc.arg(tenant_id), sqlc.arg(identifier), sqlc.arg(name), sqlc.arg(scopes), sqlc.arg(created_at),
    sqlc.arg(updated_at)
);

-- name: GetAPIResourceByIdentifier :one
SELECT id, tenant_id, identifier, name, scopes, created_at, updated_at
FROM api_resources
WHERE tenant_id = sqlc.arg(tenant_id) AND identifier = sqlc.arg(identifier);

-- name: ListAPIResources :many
SELECT id, tenant_id, identifier, name, scopes, created_at, updated_at
FROM api_resources
WHERE tenant_id = sqlc.arg(tenant_id) AND id > sqlc.arg(after)
ORDER BY id
LIMIT sqlc.arg(page_size);

-- name: DeleteAPIResource :execrows
DELETE FROM api_resources
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id);
