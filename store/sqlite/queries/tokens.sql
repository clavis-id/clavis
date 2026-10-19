-- name: CreateAccessToken :exec
INSERT INTO access_tokens (
    id, tenant_id, client_id, user_id, code_hash, scopes, userinfo_claims, issued_at, expires_at, revoked_at
) VALUES (
    sqlc.arg(id), sqlc.arg(tenant_id), sqlc.arg(client_id), sqlc.narg(user_id), sqlc.narg(code_hash), sqlc.arg(scopes),
    sqlc.arg(userinfo_claims), sqlc.arg(issued_at), sqlc.arg(expires_at), sqlc.narg(revoked_at)
);

-- name: GetAccessToken :one
SELECT id, tenant_id, client_id, user_id, code_hash, scopes, userinfo_claims, issued_at, expires_at, revoked_at
FROM access_tokens
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id);

-- name: RevokeAccessTokensByCode :execrows
UPDATE access_tokens
SET revoked_at = sqlc.arg(revoked_at)
WHERE tenant_id = sqlc.arg(tenant_id) AND code_hash = sqlc.arg(code_hash) AND revoked_at IS NULL;

-- name: RevokeAccessTokensByUserAndClient :execrows
UPDATE access_tokens
SET revoked_at = sqlc.arg(revoked_at)
WHERE tenant_id = sqlc.arg(tenant_id) AND user_id = sqlc.arg(user_id) AND client_id = sqlc.arg(client_id)
    AND revoked_at IS NULL;

-- name: DeleteExpiredAccessTokens :execrows
DELETE FROM access_tokens
WHERE expires_at <= sqlc.arg(now);

-- name: RevokeAccessToken :execrows
UPDATE access_tokens
SET revoked_at = sqlc.arg(revoked_at)
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id) AND revoked_at IS NULL;

-- name: RevokeAccessTokensBySession :execrows
UPDATE access_tokens
SET revoked_at = sqlc.arg(revoked_at)
WHERE access_tokens.tenant_id = sqlc.arg(tenant_id) AND access_tokens.revoked_at IS NULL
    AND access_tokens.code_hash IN (
        SELECT c.hash
        FROM authorization_codes c
        WHERE c.tenant_id = sqlc.arg(tenant_id) AND c.session_id = sqlc.arg(session_id)
            AND NOT EXISTS (
                SELECT 1
                FROM refresh_token_families f
                WHERE f.tenant_id = c.tenant_id AND f.code_hash = c.hash
            )
    );
