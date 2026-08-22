-- Projects. Every read carries tenant_id in the WHERE clause — see the note in
-- secret.sql on why tenant scoping lives in the query and not in the service.

-- name: CreateProject :one
INSERT INTO projects (tenant_id, name, slug, description, status, metadata)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetProjectByID :one
SELECT * FROM projects WHERE tenant_id = $1 AND project_id = $2 AND deleted_at IS NULL;

-- name: GetProjectByUUID :one
SELECT * FROM projects WHERE tenant_id = $1 AND project_uuid = $2 AND deleted_at IS NULL;

-- name: GetProjectBySlug :one
SELECT * FROM projects WHERE tenant_id = $1 AND slug = $2 AND deleted_at IS NULL;

-- name: ListProjectsByTenant :many
SELECT * FROM projects
WHERE tenant_id = $1 AND deleted_at IS NULL
ORDER BY slug
LIMIT $2 OFFSET $3;

-- name: CountProjectsByTenant :one
SELECT count(*) FROM projects WHERE tenant_id = $1 AND deleted_at IS NULL;

-- name: UpdateProject :one
UPDATE projects
SET name        = sqlc.arg(name),
    description = sqlc.arg(description),
    status      = sqlc.arg(status),
    metadata    = sqlc.arg(metadata),
    updated_at  = now()
WHERE tenant_id = sqlc.arg(tenant_id) AND project_uuid = sqlc.arg(project_uuid) AND deleted_at IS NULL
RETURNING *;

-- name: SoftDeleteProject :execrows
UPDATE projects SET deleted_at = now(), updated_at = now()
WHERE tenant_id = $1 AND project_uuid = $2 AND deleted_at IS NULL;
