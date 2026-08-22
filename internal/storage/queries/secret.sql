-- Secrets: identity and metadata. NO QUERY IN THIS FILE RETURNS A VALUE, because
-- the secrets table has no value column at all — payloads live only in
-- secret_versions (see secret_version.sql).
--
-- TENANT SCOPING IS IN THE QUERY, NOT IN THE SERVICE. Every statement here
-- constrains tenant_id. That is the difference between "we remember to check" and
-- "it cannot happen": a service-layer check is one forgotten early-return away
-- from leaking, whereas a WHERE clause that is part of the generated function's
-- signature cannot be skipped — sqlc will not compile a call that omits the
-- parameter. This is also why tenant_id is denormalized onto secrets rather than
-- reached by joining up through project and environment.

-- name: CreateSecret :one
INSERT INTO secrets (
    tenant_id, project_id, environment_id, folder_id,
    mrn_service, mrn_tenant, mrn_project, mrn_resource_path,
    key, description, tags, keep_versions, rotation_policy, expires_at, metadata
) VALUES (
    $1, $2, $3, $4,
    $5, $6, $7, $8,
    $9, $10, $11, $12, $13, $14, $15
)
RETURNING *;

-- name: GetSecretByAddress :one
SELECT * FROM secrets
WHERE tenant_id = $1 AND environment_id = $2 AND folder_id = $3 AND key = $4 AND deleted_at IS NULL;

-- GetSecretByAddressForUpdate takes a row lock for the write path. Two concurrent
-- writes to one secret must serialize: both would otherwise read the same
-- current_version, and the second would collide on uq_secret_versions_secret_version
-- (or worse, silently reuse a version number if that index were ever relaxed).
-- name: GetSecretByAddressForUpdate :one
SELECT * FROM secrets
WHERE tenant_id = $1 AND environment_id = $2 AND folder_id = $3 AND key = $4 AND deleted_at IS NULL
FOR UPDATE;

-- name: GetSecretByUUID :one
SELECT * FROM secrets WHERE tenant_id = $1 AND secret_uuid = $2 AND deleted_at IS NULL;

-- name: GetDeletedSecretByUUID :one
SELECT * FROM secrets WHERE tenant_id = $1 AND secret_uuid = $2 AND deleted_at IS NOT NULL;

-- ListSecretMetaBySubtree is the hierarchical listing: everything at or under a
-- folder path, in one environment, for one tenant.
--
-- The column list is written out in full rather than `s.*` ON PURPOSE. This query
-- is the one an operator or reviewer reads to confirm that listing cannot leak a
-- value, and an explicit list makes that answerable by inspection — and keeps a
-- future column from joining a list response by accident. (The structural
-- guarantee is stronger still: there is no ciphertext column on secrets to
-- select. Both belts are worn.)
--
-- THE LATERAL JOIN SELECTS value_type AND NOTHING ELSE FROM secret_versions. That
-- is the one column of the current version a listing needs, because it is what
-- distinguishes a `reference` (a pointer of the form ${project/env/KEY}) from a
-- literal credential — and without it a console has to issue one extra call PER ROW
-- to find out. It is deliberately a narrow projection rather than `v.*`: this query
-- is now the only place a listing touches the payload table at all, and the column
-- list above is what makes "listing cannot leak a value" checkable by inspection.
-- ciphertext, nonce, dek_wrapped and dek_nonce are not selected and must never be.
--
-- LEFT JOIN, not JOIN: a secret row can legitimately exist with no version (the
-- window between CreateSecret and CreateSecretVersion, and any row whose
-- current_version is still 0), and an inner join would make such a row vanish from
-- its own listing. COALESCE to '' rather than letting the NULL through, because a
-- NULL here would be a scan error on a listing rather than a missing badge in a UI —
-- the column's absence must degrade, not fail.
-- name: ListSecretMetaBySubtree :many
SELECT
    s.secret_uuid,
    f.path AS folder_path,
    s.key,
    s.description,
    s.tags,
    s.current_version,
    s.keep_versions,
    s.rotation_policy,
    s.mrn_tenant,
    s.mrn_project,
    s.mrn_resource_path,
    s.rotated_at,
    s.expires_at,
    s.created_at,
    s.updated_at,
    COALESCE(v.value_type, '')::varchar AS value_type
FROM secrets s
JOIN folders f ON f.folder_id = s.folder_id
LEFT JOIN LATERAL (
    SELECT sv.value_type FROM secret_versions sv
    WHERE sv.secret_id = s.secret_id AND sv.version = s.current_version
    LIMIT 1
) v ON true
WHERE s.tenant_id = sqlc.arg(tenant_id)
  AND s.environment_id = sqlc.arg(environment_id)
  AND (f.path = sqlc.arg(path) OR f.path LIKE sqlc.arg(path_pattern))
  AND s.deleted_at IS NULL
  AND f.deleted_at IS NULL
ORDER BY f.path, s.key
LIMIT sqlc.arg(row_limit) OFFSET sqlc.arg(row_offset);

-- name: CountSecretsInSubtree :one
SELECT count(*)
FROM secrets s
JOIN folders f ON f.folder_id = s.folder_id
WHERE s.tenant_id = sqlc.arg(tenant_id)
  AND s.environment_id = sqlc.arg(environment_id)
  AND (f.path = sqlc.arg(path) OR f.path LIKE sqlc.arg(path_pattern))
  AND s.deleted_at IS NULL
  AND f.deleted_at IS NULL;

-- ListDeletedSecretMeta is the recovery-window view: what can still be restored,
-- and until when. Metadata only, same rule as the live listing.
-- name: ListDeletedSecretMeta :many
SELECT
    s.secret_uuid,
    f.path AS folder_path,
    s.key,
    s.current_version,
    s.deleted_at,
    s.destroy_after
FROM secrets s
JOIN folders f ON f.folder_id = s.folder_id
WHERE s.tenant_id = sqlc.arg(tenant_id)
  AND s.environment_id = sqlc.arg(environment_id)
  AND s.deleted_at IS NOT NULL
ORDER BY s.deleted_at DESC
LIMIT sqlc.arg(row_limit) OFFSET sqlc.arg(row_offset);

-- SetSecretCurrentVersion publishes a newly written version.
--
-- current_version only ever moves forward. mark_rotated is false for the very
-- first version (a secret being created has not been "rotated") and true for every
-- version after it — a new value for an existing secret IS a rotation, whether it
-- came from an operator or a rotation job.
-- name: SetSecretCurrentVersion :one
UPDATE secrets
SET current_version = sqlc.arg(current_version),
    rotated_at      = CASE WHEN sqlc.arg(mark_rotated)::boolean THEN now() ELSE rotated_at END,
    updated_at      = now()
WHERE tenant_id = sqlc.arg(tenant_id)
  AND secret_id = sqlc.arg(secret_id)
  AND deleted_at IS NULL
  AND current_version < sqlc.arg(current_version)
RETURNING *;

-- name: UpdateSecretMeta :one
UPDATE secrets
SET description     = sqlc.arg(description),
    tags            = sqlc.arg(tags),
    keep_versions   = sqlc.arg(keep_versions),
    rotation_policy = sqlc.arg(rotation_policy),
    expires_at      = sqlc.arg(expires_at),
    metadata        = sqlc.arg(metadata),
    updated_at      = now()
WHERE tenant_id = sqlc.arg(tenant_id) AND secret_uuid = sqlc.arg(secret_uuid) AND deleted_at IS NULL
RETURNING *;

-- SetSecretLeasePolicy is a SEPARATE statement from UpdateSecretMeta, deliberately.
--
-- The lease policy decides whether a value can be read at all and how often; secret
-- metadata is a description and some tags. Folding the two together would mean a
-- routine description edit that omitted the lease fields silently removed the policy —
-- the same argument that already keeps UpdateSecretMeta separate from PutSecret one
-- level down. A caller clearing the policy has to say so by passing NULLs to THIS
-- statement.
--
-- All three columns are set together because they are one policy: a TTL left beside a
-- stale max_reads from a previous policy is not a state any caller asked for.
-- name: SetSecretLeasePolicy :one
UPDATE secrets
SET lease_ttl_seconds     = sqlc.arg(lease_ttl_seconds),
    lease_max_ttl_seconds = sqlc.arg(lease_max_ttl_seconds),
    lease_max_reads       = sqlc.arg(lease_max_reads),
    updated_at            = now()
WHERE tenant_id = sqlc.arg(tenant_id) AND secret_uuid = sqlc.arg(secret_uuid) AND deleted_at IS NULL
RETURNING *;

-- SoftDeleteSecret starts the recovery window. destroy_after is when the row
-- becomes unrecoverable; until then RestoreSecret puts it back untouched, versions
-- and all.
-- name: SoftDeleteSecret :one
UPDATE secrets
SET deleted_at    = now(),
    destroy_after = sqlc.arg(destroy_after),
    updated_at    = now()
WHERE tenant_id = sqlc.arg(tenant_id) AND secret_id = sqlc.arg(secret_id) AND deleted_at IS NULL
RETURNING *;

-- RestoreSecret can fail with a unique violation on uq_secrets_address: the
-- address is only reserved by LIVE rows, so a new secret may have been created at
-- the same path/key while this one sat deleted. That is a genuine conflict for the
-- caller to resolve, not something to paper over by renaming.
-- name: RestoreSecret :one
UPDATE secrets
SET deleted_at    = NULL,
    destroy_after = NULL,
    updated_at    = now()
WHERE tenant_id = sqlc.arg(tenant_id) AND secret_uuid = sqlc.arg(secret_uuid) AND deleted_at IS NOT NULL
RETURNING *;

-- HardDeleteSecret is irreversible. The recovery-window guard is IN THE QUERY and
-- reads now() from the database rather than trusting a timestamp from the caller:
-- destruction inside the window would be unrecoverable data loss, so the check has
-- to hold even against a clock-skewed caller or a future code path that forgets
-- to look. Cascades into secret_versions, which requires the
-- maintainerd.allow_secret_version_delete GUC to be set to 'secret_destroy' in
-- the same transaction.
-- name: HardDeleteSecret :execrows
DELETE FROM secrets
WHERE tenant_id = sqlc.arg(tenant_id)
  AND secret_uuid = sqlc.arg(secret_uuid)
  AND deleted_at IS NOT NULL
  AND destroy_after IS NOT NULL
  AND destroy_after <= now();

-- name: ListSecretsDueForDestruction :many
SELECT secret_id, secret_uuid, tenant_id, destroy_after FROM secrets
WHERE deleted_at IS NOT NULL AND destroy_after IS NOT NULL AND destroy_after <= now()
ORDER BY destroy_after
LIMIT $1;

-- ListSecretsWithRotationPolicy is the background rotator's work queue: every live
-- secret whose rotation_policy declares itself enabled, with the addressing columns
-- the rotator needs to write a new version.
--
-- WHETHER A SECRET IS *DUE* IS DECIDED IN GO, NOT HERE. Expressing "rotated_at +
-- interval <= now()" in SQL means parsing a Go duration string inside Postgres, and
-- an interval this query mis-parses is either a credential that silently stops
-- rotating or one that rotates every tick. The filter that belongs in SQL is the
-- cheap, unambiguous one (enabled, live); the arithmetic belongs next to the parser
-- that owns the format, where it is unit-testable without a database.
--
-- The select list is metadata plus addressing — no ciphertext. The rotator generates
-- a NEW value, so it never needs to read the current one.
-- name: ListSecretsWithRotationPolicy :many
SELECT s.secret_id, s.secret_uuid, t.tenant_uuid, p.slug AS project_slug,
       e.slug AS environment_slug, f.path AS folder_path, s.key,
       s.current_version, s.rotation_policy, s.rotated_at, s.created_at,
       s.mrn_tenant, s.mrn_project, s.mrn_resource_path
FROM secrets s
JOIN tenants t ON t.tenant_id = s.tenant_id
JOIN projects p ON p.project_id = s.project_id
JOIN environments e ON e.environment_id = s.environment_id
JOIN folders f ON f.folder_id = s.folder_id
WHERE s.deleted_at IS NULL
  AND t.deleted_at IS NULL
  AND p.deleted_at IS NULL
  AND e.deleted_at IS NULL
  AND f.deleted_at IS NULL
  AND s.rotation_policy ->> 'enabled' = 'true'
ORDER BY s.secret_id
LIMIT sqlc.arg(row_limit) OFFSET sqlc.arg(row_offset);

-- name: SoftDeleteSecretsInFolderSubtree :execrows
UPDATE secrets
SET deleted_at    = now(),
    destroy_after = sqlc.arg(destroy_after),
    updated_at    = now()
WHERE secrets.tenant_id = sqlc.arg(tenant_id)
  AND secrets.environment_id = sqlc.arg(environment_id)
  AND secrets.deleted_at IS NULL
  AND secrets.folder_id IN (
      SELECT f.folder_id FROM folders f
      WHERE f.environment_id = sqlc.arg(environment_id)
        AND (f.path = sqlc.arg(path) OR f.path LIKE sqlc.arg(path_pattern)));

-- RefreshSecretMrnPathsInSubtree recomputes the materialized MRN resource path
-- after a folder move. mrn_resource_path is derived from the environment slug,
-- folder.path and key, so a move that rewrote folder paths leaves it stale — and a
-- stale MRN is an authorization bug, not a display bug, because policy evaluation
-- compares this column. Call it with the subtree's NEW prefix, in the same
-- transaction as the move.
-- name: RefreshSecretMrnPathsInSubtree :execrows
UPDATE secrets s
SET mrn_resource_path = 'secret/' || e.slug || CASE WHEN f.path = '/' THEN '/' ELSE f.path || '/' END || s.key,
    updated_at = now()
FROM folders f, environments e
WHERE f.folder_id = s.folder_id
  AND e.environment_id = s.environment_id
  AND s.tenant_id = sqlc.arg(tenant_id)
  AND s.environment_id = sqlc.arg(environment_id)
  AND (f.path = sqlc.arg(path) OR f.path LIKE sqlc.arg(path_pattern))
  AND s.deleted_at IS NULL;
