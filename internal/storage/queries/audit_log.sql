-- The access trail. Append-only: there is no UPDATE statement in this file, and
-- there never should be — the trigger on the table would reject one anyway.

-- name: AppendAuditEvent :one
INSERT INTO audit_log (
    tenant_id, actor_subject, actor_kind, action, resource_mrn,
    secret_id, version, outcome, reason, ip_address, user_agent, request_id, metadata
) VALUES (
    $1, $2, $3, $4, $5,
    $6, $7, $8, $9, $10, $11, $12, $13
)
RETURNING *;

-- name: ListAuditEventsByTenant :many
SELECT * FROM audit_log
WHERE tenant_id = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- name: ListAuditEventsBySecret :many
SELECT * FROM audit_log
WHERE secret_id = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- name: ListAuditEventsByActor :many
SELECT * FROM audit_log
WHERE actor_subject = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- name: CountAuditEventsByTenant :one
SELECT count(*) FROM audit_log WHERE tenant_id = $1;

-- name: AllowAuditLogDelete :exec
SELECT set_config('maintainerd.allow_audit_log_delete', $1, true);

-- name: DeleteAuditEventsBefore :execrows
DELETE FROM audit_log WHERE created_at < $1;
