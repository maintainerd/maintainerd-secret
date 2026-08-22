-- Dynamic secrets: the role CONFIGURATION an operator registers, and the LEASES
-- issued against it.
--
-- TENANT SCOPING IS IN THE QUERY, not in the service — the same rule the secret
-- queries follow, for the same reason: a WHERE clause that is part of the generated
-- function's signature cannot be forgotten, whereas a service-layer check is one
-- early return away from leaking.
--
-- NOTE WHAT NO QUERY IN THIS FILE DOES: none of them writes or reads a generated
-- password, because there is no column to hold one. The credential is returned to
-- the caller once, in the issue response, and revocation needs only a role name.

-- name: CreateDynamicRole :one
INSERT INTO dynamic_roles (
    tenant_id, project_id, name, description, dsn_secret_ref,
    creation_sql, revocation_sql, default_ttl_seconds, max_ttl_seconds,
    role_name_prefix, status, metadata
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
RETURNING *;

-- name: GetDynamicRoleByName :one
SELECT * FROM dynamic_roles
WHERE tenant_id = sqlc.arg(tenant_id)
  AND project_id = sqlc.arg(project_id)
  AND name = sqlc.arg(name)
  AND deleted_at IS NULL;

-- name: GetDynamicRoleByUUID :one
SELECT * FROM dynamic_roles
WHERE tenant_id = sqlc.arg(tenant_id)
  AND role_uuid = sqlc.arg(role_uuid)
  AND deleted_at IS NULL;

-- GetDynamicRoleByID resolves the config a lease was issued against, for the reaper —
-- which starts from a lease row and needs the revocation template. It is NOT
-- tenant-scoped because a lease row's role_id was itself reached through a
-- tenant-scoped read (or, for the reaper, through a query that carries the tenant
-- alongside), and a background sweep has no caller tenant to scope by. The revocation
-- it performs is bounded by the lease row, not by the caller.
-- name: GetDynamicRoleByID :one
SELECT * FROM dynamic_roles WHERE role_id = $1;

-- ListDynamicRoleMetaByProject is the API/console read. The select list omits nothing
-- sensitive — there is nothing sensitive to omit, because the DSN is a REFERENCE
-- rather than a credential — but it does omit the SQL templates, which are long and
-- belong on the detail read rather than in every page of a listing.
-- name: ListDynamicRoleMetaByProject :many
SELECT role_uuid, project_id, name, description, dsn_secret_ref,
       default_ttl_seconds, max_ttl_seconds, role_name_prefix, status,
       created_at, updated_at
FROM dynamic_roles
WHERE tenant_id = sqlc.arg(tenant_id)
  AND project_id = sqlc.arg(project_id)
  AND deleted_at IS NULL
ORDER BY name
LIMIT sqlc.arg(row_limit) OFFSET sqlc.arg(row_offset);

-- name: CountDynamicRolesByProject :one
SELECT count(*) FROM dynamic_roles
WHERE tenant_id = sqlc.arg(tenant_id) AND project_id = sqlc.arg(project_id) AND deleted_at IS NULL;

-- name: UpdateDynamicRole :one
UPDATE dynamic_roles
SET description         = sqlc.arg(description),
    dsn_secret_ref      = sqlc.arg(dsn_secret_ref),
    creation_sql        = sqlc.arg(creation_sql),
    revocation_sql      = sqlc.arg(revocation_sql),
    default_ttl_seconds = sqlc.arg(default_ttl_seconds),
    max_ttl_seconds     = sqlc.arg(max_ttl_seconds),
    status              = sqlc.arg(status),
    updated_at          = now()
WHERE tenant_id = sqlc.arg(tenant_id)
  AND role_uuid = sqlc.arg(role_uuid)
  AND deleted_at IS NULL
RETURNING *;

-- name: SoftDeleteDynamicRole :execrows
UPDATE dynamic_roles SET deleted_at = now(), updated_at = now()
WHERE tenant_id = sqlc.arg(tenant_id)
  AND role_uuid = sqlc.arg(role_uuid)
  AND deleted_at IS NULL;

-- CountLiveDynamicLeasesByRole is the delete guard: a role config with outstanding
-- credentials must not be soft-deleted out from under them, because the revocation
-- template lives on the config and deleting it would strand every issued account.
-- name: CountLiveDynamicLeasesByRole :one
SELECT count(*) FROM dynamic_leases WHERE role_id = $1 AND revoked_at IS NULL;

-- CreateDynamicLease records an issued credential.
--
-- THE ORDERING AROUND IT IS THE INTERESTING PART, because the lease lives in THIS
-- PostgreSQL database and the role lives in the TARGET one, and no transaction spans
-- both. So the store opens a transaction, INSERTS THE LEASE FIRST, then runs the
-- creation DDL against the target, then commits (see store.IssueDynamicLease):
--
--   creation fails  -> the deferred rollback removes the lease row. No role, no lease.
--   creation works  -> commit. Role and lease both exist.
--
-- The residual window is the commit itself: a process that dies between a successful
-- CREATE ROLE and its own COMMIT leaves a role with no lease demanding its
-- revocation. That is unavoidable without two-phase commit, and it is the SMALL side
-- of the trade — the alternative ordering (create the role, then record the lease)
-- leaves the same orphan for the whole duration of the DDL rather than for the
-- duration of one local commit.
-- name: CreateDynamicLease :one
INSERT INTO dynamic_leases (
    role_id, tenant_id, db_role_name, resource_mrn,
    requester, requester_kind, expires_at, metadata
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: GetDynamicLeaseByUUID :one
SELECT * FROM dynamic_leases
WHERE tenant_id = sqlc.arg(tenant_id) AND lease_uuid = sqlc.arg(lease_uuid);

-- MarkDynamicLeaseRevoked closes a lease. Guarded on revoked_at IS NULL so a
-- concurrent reaper pass and an explicit revoke cannot both claim the same lease —
-- whichever loses gets zero rows and stops, rather than running DROP ROLE twice.
-- name: MarkDynamicLeaseRevoked :execrows
UPDATE dynamic_leases
SET revoked_at      = now(),
    revoke_reason   = sqlc.arg(revoke_reason),
    revoke_error    = '',
    revoke_attempts = revoke_attempts + 1,
    updated_at      = now()
WHERE lease_id = sqlc.arg(lease_id) AND revoked_at IS NULL;

-- RecordDynamicLeaseRevokeFailure leaves the lease OPEN on purpose. A revocation that
-- the target database refused has not happened, and marking it revoked anyway would
-- lose the only record that a live account needs dropping. The attempt count and the
-- error are what an operator sees when a role has been orphaned by an outage.
-- name: RecordDynamicLeaseRevokeFailure :execrows
UPDATE dynamic_leases
SET revoke_error    = sqlc.arg(revoke_error),
    revoke_attempts = revoke_attempts + 1,
    updated_at      = now()
WHERE lease_id = sqlc.arg(lease_id) AND revoked_at IS NULL;

-- ListExpiredDynamicLeases is THE REAPER'S QUERY, and the reason expiry does not
-- depend on the creation template having included VALID UNTIL. now() is the
-- database's, not the caller's: a skewed process clock must not be able to reap early
-- or late.
--
-- Ordered by expires_at so the longest-overdue account is dropped first, and limited
-- so one pass cannot hold a connection to every target database at once.
-- name: ListExpiredDynamicLeases :many
SELECT lease_id, lease_uuid, role_id, tenant_id, db_role_name, resource_mrn,
       requester, requester_kind, expires_at, revoke_attempts
FROM dynamic_leases
WHERE revoked_at IS NULL AND expires_at <= now()
ORDER BY expires_at
LIMIT sqlc.arg(row_limit);

-- name: ListDynamicLeasesByRole :many
SELECT lease_id, lease_uuid, role_id, tenant_id, db_role_name, resource_mrn,
       requester, requester_kind, issued_at, expires_at, revoked_at,
       revoke_reason, revoke_error, revoke_attempts
FROM dynamic_leases
WHERE tenant_id = sqlc.arg(tenant_id) AND role_id = sqlc.arg(role_id)
ORDER BY created_at DESC
LIMIT sqlc.arg(row_limit) OFFSET sqlc.arg(row_offset);

-- name: CountDynamicLeasesByRole :one
SELECT count(*) FROM dynamic_leases
WHERE tenant_id = sqlc.arg(tenant_id) AND role_id = sqlc.arg(role_id);
