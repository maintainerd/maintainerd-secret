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

-- ListAuditEventsFiltered is the console's read, and the reason it exists is that
-- ListAuditEventsByTenant above could only PAGE the trail. A console that fetches
-- one page and filters it client-side answers "no matches" when it means "not on
-- this page" — which on an access trail is the difference between "nobody read that
-- credential" and "nobody read it in the last hundred rows".
--
-- EVERY PREDICATE IS OPTIONAL AND TENANT SCOPING IS NOT. tenant_id is a positional
-- argument, never nullable: a filter that could widen the tenant boundary would be
-- the one bug in this file that matters. The rest use sqlc.narg, so an absent filter
-- is a SQL NULL and the branch short-circuits to TRUE.
--
-- THE TWO PREFIX FILTERS TAKE A READY-MADE LIKE PATTERN, not a bare prefix. The
-- escaping (of %, _ and \) happens in Go — see store.likePrefix — because doing it
-- here would mean three nested replace() calls inside the predicate, which is both
-- unreadable and un-index-able. ESCAPE '\' is stated explicitly rather than relying
-- on the default, so the pattern's meaning does not depend on backslash_quote or on
-- standard_conforming_strings.
--
-- ORDER BY created_at DESC matches the composite indexes' trailing column, so a
-- filtered page is an index scan and not a sort of the whole tenant's trail.
-- name: ListAuditEventsFiltered :many
SELECT * FROM audit_log
WHERE tenant_id = $1
  AND (sqlc.narg(action)::varchar IS NULL OR action = sqlc.narg(action))
  AND (sqlc.narg(outcome)::varchar IS NULL OR outcome = sqlc.narg(outcome))
  AND (sqlc.narg(actor_pattern)::varchar IS NULL OR actor_subject LIKE sqlc.narg(actor_pattern) ESCAPE '\')
  AND (sqlc.narg(resource_pattern)::text IS NULL OR resource_mrn LIKE sqlc.narg(resource_pattern) ESCAPE '\')
  AND (sqlc.narg(from_time)::timestamptz IS NULL OR created_at >= sqlc.narg(from_time))
  AND (sqlc.narg(to_time)::timestamptz IS NULL OR created_at <= sqlc.narg(to_time))
ORDER BY created_at DESC
LIMIT sqlc.arg(row_limit) OFFSET sqlc.arg(row_offset);

-- CountAuditEventsFiltered must apply the SAME predicate list as the query above,
-- word for word. A total computed over a different WHERE clause is a pagination
-- control that walks off the end of its own result set.
-- name: CountAuditEventsFiltered :one
SELECT count(*) FROM audit_log
WHERE tenant_id = $1
  AND (sqlc.narg(action)::varchar IS NULL OR action = sqlc.narg(action))
  AND (sqlc.narg(outcome)::varchar IS NULL OR outcome = sqlc.narg(outcome))
  AND (sqlc.narg(actor_pattern)::varchar IS NULL OR actor_subject LIKE sqlc.narg(actor_pattern) ESCAPE '\')
  AND (sqlc.narg(resource_pattern)::text IS NULL OR resource_mrn LIKE sqlc.narg(resource_pattern) ESCAPE '\')
  AND (sqlc.narg(from_time)::timestamptz IS NULL OR created_at >= sqlc.narg(from_time))
  AND (sqlc.narg(to_time)::timestamptz IS NULL OR created_at <= sqlc.narg(to_time));

-- name: AllowAuditLogDelete :exec
SELECT set_config('maintainerd.allow_audit_log_delete', $1, true);

-- name: DeleteAuditEventsBefore :execrows
DELETE FROM audit_log WHERE created_at < $1;
