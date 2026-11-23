-- name: CreateRefreshTokenFamily :exec
INSERT INTO refresh_token_families (
    id, tenant_id, client_id, user_id, session_id, code_hash, scopes, auth_time, amr, acr, userinfo_claims,
    id_token_claims, created_at, idle_expires_at, expires_at
) VALUES (
    sqlc.arg(id), sqlc.arg(tenant_id), sqlc.arg(client_id), sqlc.arg(user_id), sqlc.narg(session_id),
    sqlc.narg(code_hash), sqlc.arg(scopes), sqlc.arg(auth_time), sqlc.arg(amr), sqlc.arg(acr),
    sqlc.arg(userinfo_claims), sqlc.arg(id_token_claims), sqlc.arg(created_at), sqlc.arg(idle_expires_at),
    sqlc.arg(expires_at)
);

-- name: CreateRefreshToken :exec
INSERT INTO refresh_tokens (hash, tenant_id, family_id, issued_at, expires_at)
VALUES (sqlc.arg(hash), sqlc.arg(tenant_id), sqlc.arg(family_id), sqlc.arg(issued_at), sqlc.arg(expires_at));

-- name: GetRefreshToken :one
SELECT sqlc.embed(t), sqlc.embed(f)
FROM refresh_tokens t
JOIN refresh_token_families f ON f.tenant_id = t.tenant_id AND f.id = t.family_id
WHERE t.tenant_id = sqlc.arg(tenant_id) AND t.hash = sqlc.arg(hash);

-- name: ExtendRefreshTokenFamily :execrows
UPDATE refresh_token_families
SET idle_expires_at = sqlc.arg(idle_expires_at)
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id) AND revoked_at IS NULL;

-- name: RotateRefreshToken :execrows
UPDATE refresh_tokens
SET rotated_at = sqlc.arg(rotated_at)
WHERE tenant_id = sqlc.arg(tenant_id) AND hash = sqlc.arg(hash) AND family_id = sqlc.arg(family_id)
    AND rotated_at IS NULL;

-- name: CountRefreshTokensInFamily :one
SELECT count(*)
FROM refresh_tokens
WHERE tenant_id = sqlc.arg(tenant_id) AND hash = sqlc.arg(hash) AND family_id = sqlc.arg(family_id);

-- name: RevokeRefreshTokenFamily :execrows
UPDATE refresh_token_families
SET revoked_at = sqlc.arg(revoked_at)
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id) AND revoked_at IS NULL;

-- name: CountRefreshTokenFamilies :one
SELECT count(*)
FROM refresh_token_families
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id);

-- name: RevokeRefreshTokenFamiliesByCode :execrows
UPDATE refresh_token_families
SET revoked_at = sqlc.arg(revoked_at)
WHERE tenant_id = sqlc.arg(tenant_id) AND code_hash = sqlc.arg(code_hash) AND revoked_at IS NULL;

-- name: RevokeRefreshTokenFamiliesByUser :execrows
UPDATE refresh_token_families
SET revoked_at = sqlc.arg(revoked_at)
WHERE tenant_id = sqlc.arg(tenant_id) AND user_id = sqlc.arg(user_id) AND revoked_at IS NULL;

-- name: RevokeRefreshTokenFamiliesByUserAndClient :execrows
UPDATE refresh_token_families
SET revoked_at = sqlc.arg(revoked_at)
WHERE tenant_id = sqlc.arg(tenant_id) AND user_id = sqlc.arg(user_id) AND client_id = sqlc.arg(client_id)
    AND revoked_at IS NULL;

-- name: DeleteExpiredRefreshTokens :execrows
DELETE FROM refresh_tokens
WHERE expires_at <= sqlc.arg(now);

-- name: DeleteExpiredRefreshTokenFamilies :execrows
DELETE FROM refresh_token_families
WHERE expires_at <= sqlc.arg(now) OR idle_expires_at <= sqlc.arg(now);
