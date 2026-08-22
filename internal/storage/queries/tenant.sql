-- The tenant mirror. Auth owns identity; these rows exist so every secret can be
-- keyed to a tenant with one indexed local read instead of a cross-service call.
--
-- created_by / updated_by are left to their NULL defaults throughout this file.
-- This service has no users table — the authenticated principal is an Auth
-- subject string, and it is recorded where it belongs, in audit_log.actor_subject.
-- The BIGINT audit columns are kept for schema parity with core.

-- name: CreateTenant :one
INSERT INTO tenants (auth_tenant_uuid, name, display_name, status, is_system, metadata)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetTenantByID :one
SELECT * FROM tenants WHERE tenant_id = $1 AND deleted_at IS NULL;

-- name: GetTenantByUUID :one
SELECT * FROM tenants WHERE tenant_uuid = $1 AND deleted_at IS NULL;

-- name: GetTenantByName :one
SELECT * FROM tenants WHERE name = $1 AND deleted_at IS NULL;

-- name: GetTenantByAuthTenantUUID :one
SELECT * FROM tenants WHERE auth_tenant_uuid = $1 AND deleted_at IS NULL;

-- name: ListTenants :many
SELECT * FROM tenants
WHERE deleted_at IS NULL
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: CountTenants :one
SELECT count(*) FROM tenants WHERE deleted_at IS NULL;

-- name: UpdateTenant :one
UPDATE tenants
SET display_name = sqlc.arg(display_name),
    status       = sqlc.arg(status),
    metadata     = sqlc.arg(metadata),
    updated_at   = now()
WHERE tenant_uuid = sqlc.arg(tenant_uuid) AND deleted_at IS NULL
RETURNING *;

-- name: SoftDeleteTenant :execrows
UPDATE tenants SET deleted_at = now(), updated_at = now()
WHERE tenant_uuid = $1 AND deleted_at IS NULL;
