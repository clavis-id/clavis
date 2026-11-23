-- name: CreateAuditEvent :exec
INSERT INTO audit_events (
    id, tenant_id, occurred_at, type, actor, user_id, client_id, session_id, ip, user_agent, details
) VALUES (
    sqlc.arg(id), sqlc.arg(tenant_id), sqlc.arg(occurred_at), sqlc.arg(type), sqlc.arg(actor), sqlc.narg(user_id),
    sqlc.arg(client_id), sqlc.narg(session_id), sqlc.arg(ip), sqlc.arg(user_agent), sqlc.arg(details)
);

-- name: ListAuditEvents :many
SELECT id, tenant_id, occurred_at, type, actor, user_id, client_id, session_id, ip, user_agent, details
FROM audit_events
WHERE tenant_id = sqlc.arg(tenant_id)
    AND (CAST(sqlc.narg(user_id) AS TEXT) IS NULL OR user_id = CAST(sqlc.narg(user_id) AS TEXT))
    AND (CAST(sqlc.arg(type) AS TEXT) = '' OR type = CAST(sqlc.arg(type) AS TEXT))
    AND (CAST(sqlc.narg(before) AS TEXT) IS NULL OR id < CAST(sqlc.narg(before) AS TEXT))
ORDER BY id DESC
LIMIT sqlc.arg(page_size);

-- name: DeleteAuditEventsBefore :execrows
DELETE FROM audit_events
WHERE occurred_at < sqlc.arg(before);
