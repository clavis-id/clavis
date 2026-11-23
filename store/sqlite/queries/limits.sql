-- name: PutLimitCounter :exec
INSERT INTO limit_counters (tenant_id, kind, key_hash, hits, ends_at)
VALUES (sqlc.arg(tenant_id), sqlc.arg(kind), sqlc.arg(key_hash), sqlc.arg(hits), sqlc.arg(ends_at))
ON CONFLICT (tenant_id, kind, key_hash) DO UPDATE
SET hits = excluded.hits, ends_at = excluded.ends_at;

-- name: GetLimitCounter :one
SELECT hits, ends_at
FROM limit_counters
WHERE tenant_id = sqlc.arg(tenant_id) AND kind = sqlc.arg(kind) AND key_hash = sqlc.arg(key_hash);

-- name: DeleteLimitCounter :execrows
DELETE FROM limit_counters
WHERE tenant_id = sqlc.arg(tenant_id) AND kind = sqlc.arg(kind) AND key_hash = sqlc.arg(key_hash);

-- name: DeleteExpiredLimitCounters :execrows
DELETE FROM limit_counters
WHERE ends_at <= sqlc.arg(now);
