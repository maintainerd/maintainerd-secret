-- Environments. The table has no tenant_id column (it hangs off a project), so
-- tenant scoping is applied with a project subquery rather than a join — that
-- keeps the select list a plain `*` (so sqlc returns the Environment struct) while
-- still putting the tenant boundary inside the SQL.

-- name: CreateEnvironment :one
INSERT INTO environments (project_id, name, slug, description, position, status, metadata)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: GetEnvironmentByID :one
SELECT * FROM environments
WHERE environment_id = sqlc.arg(environment_id)
  AND deleted_at IS NULL
  AND project_id IN (SELECT p.project_id FROM projects p WHERE p.tenant_id = sqlc.arg(tenant_id) AND p.deleted_at IS NULL);

-- name: GetEnvironmentByUUID :one
SELECT * FROM environments
WHERE environment_uuid = sqlc.arg(environment_uuid)
  AND deleted_at IS NULL
  AND project_id IN (SELECT p.project_id FROM projects p WHERE p.tenant_id = sqlc.arg(tenant_id) AND p.deleted_at IS NULL);

-- name: GetEnvironmentBySlug :one
SELECT e.* FROM environments e
WHERE e.project_id = sqlc.arg(project_id)
  AND e.slug = sqlc.arg(slug)
  AND deleted_at IS NULL
  AND project_id IN (SELECT p.project_id FROM projects p WHERE p.tenant_id = sqlc.arg(tenant_id) AND p.deleted_at IS NULL);

-- name: ListEnvironmentsByProject :many
SELECT e.* FROM environments e
WHERE e.project_id = sqlc.arg(project_id)
  AND e.deleted_at IS NULL
  AND project_id IN (SELECT p.project_id FROM projects p WHERE p.tenant_id = sqlc.arg(tenant_id) AND p.deleted_at IS NULL)
ORDER BY position, slug;

-- name: UpdateEnvironment :one
UPDATE environments
SET name        = sqlc.arg(name),
    description = sqlc.arg(description),
    position    = sqlc.arg(position),
    status      = sqlc.arg(status),
    metadata    = sqlc.arg(metadata),
    updated_at  = now()
WHERE environment_uuid = sqlc.arg(environment_uuid)
  AND deleted_at IS NULL
  AND project_id IN (SELECT p.project_id FROM projects p WHERE p.tenant_id = sqlc.arg(tenant_id) AND p.deleted_at IS NULL)
RETURNING *;

-- name: SoftDeleteEnvironment :execrows
UPDATE environments SET deleted_at = now(), updated_at = now()
WHERE environment_uuid = sqlc.arg(environment_uuid)
  AND deleted_at IS NULL
  AND project_id IN (SELECT p.project_id FROM projects p WHERE p.tenant_id = sqlc.arg(tenant_id) AND p.deleted_at IS NULL);
