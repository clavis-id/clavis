-- name: CreateUser :exec
INSERT INTO users (id, tenant_id, email, email_verified, status, profile, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: GetUser :one
SELECT id, tenant_id, email, email_verified, status, profile, created_at, updated_at
FROM users
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id);

-- name: GetUserByEmail :one
SELECT id, tenant_id, email, email_verified, status, profile, created_at, updated_at
FROM users
WHERE tenant_id = sqlc.arg(tenant_id) AND email = sqlc.arg(email);

-- name: ListUsers :many
SELECT id, tenant_id, email, email_verified, status, profile, created_at, updated_at
FROM users
WHERE tenant_id = sqlc.arg(tenant_id) AND id > sqlc.arg(after)
ORDER BY id
LIMIT sqlc.arg(page_size);

-- name: UpdateUser :execrows
UPDATE users
SET email_verified = sqlc.arg(email_verified), status = sqlc.arg(status), profile = sqlc.arg(profile),
    updated_at = sqlc.arg(updated_at)
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id);

-- name: DeleteUser :execrows
DELETE FROM users
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id);

-- name: SetPassword :execrows
INSERT INTO passwords (user_id, tenant_id, hash, set_at)
VALUES (sqlc.arg(user_id), sqlc.arg(tenant_id), sqlc.arg(hash), sqlc.arg(set_at))
ON CONFLICT (user_id) DO UPDATE SET hash = EXCLUDED.hash, set_at = EXCLUDED.set_at
WHERE passwords.tenant_id = EXCLUDED.tenant_id;

-- name: GetPassword :one
SELECT user_id, tenant_id, hash, set_at
FROM passwords
WHERE tenant_id = sqlc.arg(tenant_id) AND user_id = sqlc.arg(user_id);

-- name: RehashPassword :execrows
UPDATE passwords
SET hash = sqlc.arg(new_hash)
WHERE tenant_id = sqlc.arg(tenant_id) AND user_id = sqlc.arg(user_id) AND hash = sqlc.arg(old_hash);
