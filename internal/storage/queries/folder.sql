-- Folders. Tenant scoping walks up through environments and projects in a
-- subquery, for the same reason environment.sql does it that way.
--
-- Subtree matching is always expressed as `path = @path OR path LIKE @path_pattern`
-- with BOTH values supplied by the caller, rather than building the pattern in SQL
-- with a CASE. That is deliberate: the root folder's path is '/', so the naive
-- `path || '/%'` produces '//%' and matches none of its children. The Go side owns
-- that edge case in one place (store.SubtreePattern) instead of repeating a CASE
-- expression in every query, and the pattern stays a plain runtime constant so the
-- text_pattern_ops index on (environment_id, path) is still a range scan.

-- name: CreateFolder :one
INSERT INTO folders (environment_id, parent_folder_id, name, path, metadata)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetFolderByID :one
SELECT * FROM folders
WHERE folder_id = sqlc.arg(folder_id)
  AND deleted_at IS NULL
  AND environment_id IN (
      SELECT e.environment_id FROM environments e
      JOIN projects p ON p.project_id = e.project_id
      WHERE p.tenant_id = sqlc.arg(tenant_id) AND e.deleted_at IS NULL AND p.deleted_at IS NULL);

-- name: GetFolderByUUID :one
SELECT * FROM folders
WHERE folder_uuid = sqlc.arg(folder_uuid)
  AND deleted_at IS NULL
  AND environment_id IN (
      SELECT e.environment_id FROM environments e
      JOIN projects p ON p.project_id = e.project_id
      WHERE p.tenant_id = sqlc.arg(tenant_id) AND e.deleted_at IS NULL AND p.deleted_at IS NULL);

-- name: GetFolderByPath :one
SELECT f.* FROM folders f
WHERE f.environment_id = sqlc.arg(environment_id)
  AND f.path = sqlc.arg(path)
  AND f.deleted_at IS NULL
  AND f.environment_id IN (
      SELECT e.environment_id FROM environments e
      JOIN projects p ON p.project_id = e.project_id
      WHERE p.tenant_id = sqlc.arg(tenant_id) AND e.deleted_at IS NULL AND p.deleted_at IS NULL);

-- name: ListFoldersBySubtree :many
SELECT f.* FROM folders f
WHERE f.environment_id = sqlc.arg(environment_id)
  AND (f.path = sqlc.arg(path) OR f.path LIKE sqlc.arg(path_pattern))
  AND f.deleted_at IS NULL
  AND f.environment_id IN (
      SELECT e.environment_id FROM environments e
      JOIN projects p ON p.project_id = e.project_id
      WHERE p.tenant_id = sqlc.arg(tenant_id) AND e.deleted_at IS NULL AND p.deleted_at IS NULL)
ORDER BY f.path;

-- name: CountFoldersInSubtree :one
SELECT count(*) FROM folders
WHERE environment_id = sqlc.arg(environment_id)
  AND (path = sqlc.arg(path) OR path LIKE sqlc.arg(path_pattern))
  AND deleted_at IS NULL;

-- ReparentFolder moves one folder node: its parent, its name and its own path.
-- The subtree beneath it is rewritten separately by MoveFolderSubtreePaths, and
-- both statements must run in the same transaction or the materialized paths would
-- be observably inconsistent with parent_folder_id.
-- name: ReparentFolder :one
UPDATE folders
SET parent_folder_id = sqlc.arg(parent_folder_id),
    name             = sqlc.arg(name),
    path             = sqlc.arg(path),
    updated_at       = now()
WHERE folder_id = sqlc.arg(folder_id) AND deleted_at IS NULL
RETURNING *;

-- MoveFolderSubtreePaths rewrites the materialized paths of a moved subtree by
-- prefix substitution: everything at or under old_path is re-rooted at new_path.
-- substring(path FROM length(old_path) + 1) is the part of each descendant's path
-- below the moved node, so '/db/primary' under a '/db' -> '/data' move becomes
-- '/data' || '/primary'.
-- name: MoveFolderSubtreePaths :execrows
UPDATE folders
SET path = sqlc.arg(new_path)::text || substring(path FROM length(sqlc.arg(old_path)::text) + 1),
    updated_at = now()
WHERE environment_id = sqlc.arg(environment_id)
  AND (path = sqlc.arg(old_path)::text OR path LIKE sqlc.arg(old_path_pattern))
  AND deleted_at IS NULL;

-- name: SoftDeleteFolderSubtree :execrows
UPDATE folders SET deleted_at = now(), updated_at = now()
WHERE environment_id = sqlc.arg(environment_id)
  AND (path = sqlc.arg(path) OR path LIKE sqlc.arg(path_pattern))
  AND deleted_at IS NULL;
