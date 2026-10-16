-- name: CreateAccessToken :exec
INSERT INTO access_tokens (id, tenant_id, client_id, user_id, code_hash, scopes, issued_at, expires_at, revoked_at)
VALUES (
    sqlc.arg(id), sqlc.arg(tenant_id), sqlc.arg(client_id), sqlc.narg(user_id), sqlc.narg(code_hash), sqlc.arg(scopes),
    sqlc.arg(issued_at), sqlc.arg(expires_at), sqlc.narg(revoked_at)
);

-- name: GetAccessToken :one
SELECT id, tenant_id, client_id, user_id, code_hash, scopes, issued_at, expires_at, revoked_at
FROM access_tokens
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id);

-- name: RevokeAccessTokensByCode :execrows
UPDATE access_tokens
SET revoked_at = sqlc.arg(revoked_at)
WHERE tenant_id = sqlc.arg(tenant_id) AND code_hash = sqlc.arg(code_hash) AND revoked_at IS NULL;

-- name: DeleteExpiredAccessTokens :execrows
DELETE FROM access_tokens
WHERE expires_at <= sqlc.arg(now);
