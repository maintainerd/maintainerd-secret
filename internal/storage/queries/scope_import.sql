-- Scope imports: "this folder inherits that folder's secrets".
--
-- Tenant scoping is in the WHERE clause of every statement, same rule as the rest
-- of this directory. The table carries tenant_id of its own (rather than reaching
-- it through folders) precisely so that rule costs nothing here.

-- name: CreateScopeImport :one
INSERT INTO scope_imports (
    tenant_id, environment_id, folder_id,
    source_environment_id, source_folder_id, position, enabled, metadata
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: GetScopeImportByUUID :one
SELECT * FROM scope_imports
WHERE tenant_id = sqlc.arg(tenant_id)
  AND import_uuid = sqlc.arg(import_uuid)
  AND deleted_at IS NULL;

-- ListScopeImportsByTarget is the resolver's read: the enabled imports of one
-- folder, in precedence order. `position, import_id` rather than `position` alone
-- so two imports written at the same position still resolve deterministically —
-- a resolution order that varies between replicas would make "which value did we
-- get" unanswerable.
-- name: ListScopeImportsByTarget :many
SELECT si.*, se.slug AS source_environment_slug, sf.path AS source_folder_path,
       sp.slug AS source_project_slug
FROM scope_imports si
JOIN environments se ON se.environment_id = si.source_environment_id
JOIN projects sp ON sp.project_id = se.project_id
JOIN folders sf ON sf.folder_id = si.source_folder_id
WHERE si.tenant_id = sqlc.arg(tenant_id)
  AND si.folder_id = sqlc.arg(folder_id)
  AND si.deleted_at IS NULL
  AND si.enabled
  AND se.deleted_at IS NULL
  AND sf.deleted_at IS NULL
ORDER BY si.position, si.import_id;

-- ListScopeImportsBySource answers "what imports me", which is what the cycle
-- check walks and what the console shows before letting an operator delete a
-- folder other environments depend on.
-- name: ListScopeImportsBySource :many
SELECT * FROM scope_imports
WHERE tenant_id = sqlc.arg(tenant_id)
  AND source_folder_id = sqlc.arg(source_folder_id)
  AND deleted_at IS NULL;

-- name: ListScopeImportsByEnvironment :many
SELECT si.*, se.slug AS source_environment_slug, sf.path AS source_folder_path,
       sp.slug AS source_project_slug, tf.path AS folder_path
FROM scope_imports si
JOIN environments se ON se.environment_id = si.source_environment_id
JOIN projects sp ON sp.project_id = se.project_id
JOIN folders sf ON sf.folder_id = si.source_folder_id
JOIN folders tf ON tf.folder_id = si.folder_id
WHERE si.tenant_id = sqlc.arg(tenant_id)
  AND si.environment_id = sqlc.arg(environment_id)
  AND si.deleted_at IS NULL
ORDER BY tf.path, si.position, si.import_id;

-- name: SetScopeImportEnabled :one
UPDATE scope_imports
SET enabled = sqlc.arg(enabled), position = sqlc.arg(position), updated_at = now()
WHERE tenant_id = sqlc.arg(tenant_id)
  AND import_uuid = sqlc.arg(import_uuid)
  AND deleted_at IS NULL
RETURNING *;

-- name: SoftDeleteScopeImport :execrows
UPDATE scope_imports SET deleted_at = now(), updated_at = now()
WHERE tenant_id = sqlc.arg(tenant_id)
  AND import_uuid = sqlc.arg(import_uuid)
  AND deleted_at IS NULL;
