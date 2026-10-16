-- name: CreateClient :exec
INSERT INTO clients (
    id, tenant_id, client_id, name, type, secret_hash, redirect_uris,
    post_logout_redirect_uris, grant_types, scopes, access_token_lifetime_seconds,
    id_token_lifetime_seconds, refresh_token_idle_lifetime_seconds,
    refresh_token_absolute_lifetime_seconds, skip_consent, pkce_exempt, created_at, updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18);

-- name: GetClient :one
SELECT id, tenant_id, client_id, name, type, secret_hash, redirect_uris,
    post_logout_redirect_uris, grant_types, scopes, access_token_lifetime_seconds,
    id_token_lifetime_seconds, refresh_token_idle_lifetime_seconds,
    refresh_token_absolute_lifetime_seconds, skip_consent, pkce_exempt, created_at, updated_at
FROM clients
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id);

-- name: GetClientByClientID :one
SELECT id, tenant_id, client_id, name, type, secret_hash, redirect_uris,
    post_logout_redirect_uris, grant_types, scopes, access_token_lifetime_seconds,
    id_token_lifetime_seconds, refresh_token_idle_lifetime_seconds,
    refresh_token_absolute_lifetime_seconds, skip_consent, pkce_exempt, created_at, updated_at
FROM clients
WHERE tenant_id = sqlc.arg(tenant_id) AND client_id = sqlc.arg(client_id);

-- name: ListClients :many
SELECT id, tenant_id, client_id, name, type, secret_hash, redirect_uris,
    post_logout_redirect_uris, grant_types, scopes, access_token_lifetime_seconds,
    id_token_lifetime_seconds, refresh_token_idle_lifetime_seconds,
    refresh_token_absolute_lifetime_seconds, skip_consent, pkce_exempt, created_at, updated_at
FROM clients
WHERE tenant_id = sqlc.arg(tenant_id) AND id > sqlc.arg(after)
ORDER BY id
LIMIT sqlc.arg(page_size);

-- name: UpdateClientSecret :execrows
UPDATE clients
SET secret_hash = sqlc.arg(secret_hash), updated_at = sqlc.arg(updated_at)
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id);

-- name: DeleteClient :execrows
DELETE FROM clients
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id);
