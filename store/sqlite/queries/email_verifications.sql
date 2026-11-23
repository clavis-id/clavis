-- name: CreateEmailVerification :exec
INSERT INTO email_verifications (
    id, tenant_id, purpose, email, code_hash, link_hash, binding_hash, authorization_request_id, attempts,
    verified_at, created_at, expires_at
) VALUES (
    sqlc.arg(id), sqlc.arg(tenant_id), sqlc.arg(purpose), sqlc.arg(email), sqlc.arg(code_hash), sqlc.arg(link_hash),
    sqlc.arg(binding_hash), sqlc.arg(authorization_request_id), sqlc.arg(attempts), sqlc.narg(verified_at),
    sqlc.arg(created_at), sqlc.arg(expires_at)
);

-- name: GetEmailVerification :one
SELECT id, tenant_id, purpose, email, code_hash, link_hash, binding_hash, authorization_request_id, attempts,
    verified_at, created_at, expires_at
FROM email_verifications
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id);

-- name: AddEmailVerificationAttempt :one
UPDATE email_verifications
SET attempts = attempts + 1
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id) AND verified_at IS NULL
RETURNING attempts;

-- name: MarkEmailVerificationVerified :execrows
UPDATE email_verifications
SET verified_at = sqlc.arg(verified_at)
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id) AND verified_at IS NULL;

-- name: DeleteEmailVerification :execrows
DELETE FROM email_verifications
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id);

-- name: DeleteExpiredEmailVerifications :execrows
DELETE FROM email_verifications
WHERE expires_at <= sqlc.arg(now);
