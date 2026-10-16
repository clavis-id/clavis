-- name: CreateAuthorizationRequest :exec
INSERT INTO authorization_requests (
    id, tenant_id, client_id, binding_hash, redirect_uri, redirect_uri_provided, scopes, state, nonce,
    code_challenge, code_challenge_method, created_at, expires_at
) VALUES (
    sqlc.arg(id), sqlc.arg(tenant_id), sqlc.arg(client_id), sqlc.arg(binding_hash), sqlc.arg(redirect_uri),
    sqlc.arg(redirect_uri_provided), sqlc.arg(scopes), sqlc.arg(state), sqlc.arg(nonce), sqlc.arg(code_challenge),
    sqlc.arg(code_challenge_method), sqlc.arg(created_at), sqlc.arg(expires_at)
);

-- name: GetAuthorizationRequest :one
SELECT id, tenant_id, client_id, binding_hash, redirect_uri, redirect_uri_provided, scopes, state, nonce,
    code_challenge, code_challenge_method, created_at, expires_at
FROM authorization_requests
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id);

-- name: DeleteAuthorizationRequest :execrows
DELETE FROM authorization_requests
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id);

-- name: DeleteExpiredAuthorizationRequests :execrows
DELETE FROM authorization_requests
WHERE expires_at <= $1;

-- name: CreateSession :exec
INSERT INTO sessions (
    id, tenant_id, token_hash, user_id, auth_time, amr, acr, created_at, last_seen_at, idle_expires_at, expires_at
) VALUES (
    sqlc.arg(id), sqlc.arg(tenant_id), sqlc.arg(token_hash), sqlc.arg(user_id), sqlc.arg(auth_time), sqlc.arg(amr),
    sqlc.arg(acr), sqlc.arg(created_at), sqlc.arg(last_seen_at), sqlc.arg(idle_expires_at), sqlc.arg(expires_at)
);

-- name: GetSessionByTokenHash :one
SELECT id, tenant_id, token_hash, user_id, auth_time, amr, acr, created_at, last_seen_at, idle_expires_at, expires_at
FROM sessions
WHERE tenant_id = sqlc.arg(tenant_id) AND token_hash = sqlc.arg(token_hash);

-- name: DeleteSession :execrows
DELETE FROM sessions
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id);

-- name: DeleteExpiredSessions :execrows
DELETE FROM sessions
WHERE expires_at <= sqlc.arg(now) OR idle_expires_at <= sqlc.arg(now);

-- name: CreateAuthorizationCode :exec
INSERT INTO authorization_codes (
    hash, tenant_id, client_id, user_id, session_id, redirect_uri, redirect_uri_provided, scopes, nonce,
    code_challenge, code_challenge_method, auth_time, amr, acr, created_at, expires_at
) VALUES (
    sqlc.arg(hash), sqlc.arg(tenant_id), sqlc.arg(client_id), sqlc.arg(user_id), sqlc.arg(session_id),
    sqlc.arg(redirect_uri), sqlc.arg(redirect_uri_provided), sqlc.arg(scopes), sqlc.arg(nonce),
    sqlc.arg(code_challenge), sqlc.arg(code_challenge_method), sqlc.arg(auth_time), sqlc.arg(amr), sqlc.arg(acr),
    sqlc.arg(created_at), sqlc.arg(expires_at)
);

-- name: GetAuthorizationCode :one
SELECT hash, tenant_id, client_id, user_id, session_id, redirect_uri, redirect_uri_provided, scopes, nonce,
    code_challenge, code_challenge_method, auth_time, amr, acr, created_at, expires_at, redeemed_at
FROM authorization_codes
WHERE tenant_id = sqlc.arg(tenant_id) AND hash = sqlc.arg(hash);

-- name: DeleteExpiredAuthorizationCodes :execrows
DELETE FROM authorization_codes
WHERE expires_at <= $1;

-- name: RedeemAuthorizationCode :execrows
UPDATE authorization_codes
SET redeemed_at = sqlc.arg(redeemed_at)
WHERE tenant_id = sqlc.arg(tenant_id) AND hash = sqlc.arg(hash) AND redeemed_at IS NULL;
