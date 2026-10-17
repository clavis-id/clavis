-- name: GetGrant :one
SELECT id, tenant_id, user_id, client_id, scopes, created_at, updated_at
FROM grants
WHERE tenant_id = sqlc.arg(tenant_id) AND user_id = sqlc.arg(user_id) AND client_id = sqlc.arg(client_id);

-- name: PutGrant :exec
INSERT INTO grants (id, tenant_id, user_id, client_id, scopes, created_at, updated_at)
VALUES (
    sqlc.arg(id), sqlc.arg(tenant_id), sqlc.arg(user_id), sqlc.arg(client_id), sqlc.arg(scopes), sqlc.arg(created_at),
    sqlc.arg(updated_at)
)
ON CONFLICT (tenant_id, user_id, client_id) DO UPDATE
SET scopes = excluded.scopes, updated_at = excluded.updated_at;

-- name: ListGrants :many
SELECT id, tenant_id, user_id, client_id, scopes, created_at, updated_at
FROM grants
WHERE tenant_id = sqlc.arg(tenant_id) AND user_id = sqlc.arg(user_id)
ORDER BY created_at, id;

-- name: DeleteGrant :execrows
DELETE FROM grants
WHERE tenant_id = sqlc.arg(tenant_id) AND user_id = sqlc.arg(user_id) AND client_id = sqlc.arg(client_id);
