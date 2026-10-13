-- name: CreateSigningKey :exec
INSERT INTO signing_keys (
    id, tenant_id, algorithm, generation, key_id, public_key, private_key,
    encryption_key_id, activates_at, retires_at, expires_at, created_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12);

-- name: ListSigningKeys :many
SELECT id, tenant_id, algorithm, generation, key_id, public_key, private_key,
    encryption_key_id, activates_at, retires_at, expires_at, created_at
FROM signing_keys
WHERE tenant_id = $1
ORDER BY algorithm, generation;

-- name: DeleteExpiredSigningKeys :execrows
DELETE FROM signing_keys
WHERE expires_at <= $1;
