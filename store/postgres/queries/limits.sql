-- name: AddLimitHit :one
-- Every SET expression reads the row before the update: a counter with
-- hits_before_lock hits reaches lock_at with this hit.
INSERT INTO limit_counters (tenant_id, kind, key_hash, hits, ends_at)
VALUES (sqlc.arg(tenant_id), sqlc.arg(kind), sqlc.arg(key_hash), 1, sqlc.arg(ends_at))
ON CONFLICT (tenant_id, kind, key_hash) DO UPDATE
SET hits = CASE
        WHEN limit_counters.ends_at <= sqlc.arg(now) THEN 1
        ELSE limit_counters.hits + 1
    END,
    ends_at = CASE
        WHEN limit_counters.ends_at <= sqlc.arg(now) OR limit_counters.hits = sqlc.arg(hits_before_lock)
            THEN excluded.ends_at
        ELSE limit_counters.ends_at
    END
RETURNING hits, ends_at;

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
