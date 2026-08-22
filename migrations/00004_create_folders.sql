-- +goose Up
-- Folders organise secrets hierarchically WITHIN one environment. The tree is
-- adjacency-list (parent_folder_id) for integrity, plus a materialized absolute
-- path for reads.
--
-- Why path is materialized rather than walked:
--
--   1. Prefix listing is the primary read. "List everything under /db" must be
--      one indexed range scan (path LIKE '/db/%' against a text_pattern_ops
--      index), not a recursive CTE that touches every ancestor row per hit. A
--      vault gets listed far more often than its tree gets reshaped.
--   2. The MRN resource path IS this string. An MRN's resource segment
--      (mrn:secret:acme:billing-app:secret/db/primary/password) is assembled from
--      folder.path + secret.key, and policy evaluation compares it as an indexed
--      value. Deriving it per row would put a recursive walk inside authorization.
--
-- The cost is that a move must rewrite the subtree's paths. That is accepted:
-- moves are rare and administrative, reads and policy checks are constant. The
-- rewrite is a single prefix-substitution UPDATE over the subtree (see
-- internal/storage/queries/folder.sql), and parent_folder_id remains the source
-- of truth that the paths are reconciled against.
--
-- Every environment has exactly one root folder: parent_folder_id IS NULL and
-- path = '/'. Making the root a real row (rather than a NULL folder_id on
-- secrets) keeps secrets.folder_id NOT NULL, which in turn lets the secret
-- uniqueness index work — a NULL in a unique index compares distinct, so a
-- nullable folder_id would let the same key be created twice at an
-- environment's root.
CREATE TABLE IF NOT EXISTS folders (
    folder_id        BIGSERIAL PRIMARY KEY,
    folder_uuid      UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    environment_id   BIGINT NOT NULL REFERENCES environments (environment_id) ON DELETE CASCADE,
    parent_folder_id BIGINT REFERENCES folders (folder_id) ON DELETE CASCADE,
    name             VARCHAR(255) NOT NULL,
    path             TEXT NOT NULL,
    metadata         JSONB NOT NULL DEFAULT '{}',
    created_by       BIGINT,
    updated_by       BIGINT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at       TIMESTAMPTZ,
    -- Paths are absolute and slash-delimited: '/' for the root, '/db/primary'
    -- otherwise. No trailing slash except the root, so prefix matching can append
    -- '/%' unconditionally.
    CONSTRAINT chk_folders_path_absolute CHECK (path = '/' OR path ~ '^(/[^/]+)+$'),
    -- The root folder is the only one without a parent, and it is the only one
    -- whose path is '/'. Both directions are pinned so a tree can never grow a
    -- second root or a parentless branch.
    CONSTRAINT chk_folders_root_shape CHECK ((parent_folder_id IS NULL) = (path = '/'))
);

-- A path identifies a folder within its environment. Partial on deleted_at
-- (unlike environments) because folders are genuinely recreated: deleting /tmp
-- and making a new /tmp is ordinary housekeeping, and unlike an environment slug
-- a folder path is not a stable external reference.
CREATE UNIQUE INDEX IF NOT EXISTS uq_folders_environment_path ON folders (environment_id, path) WHERE deleted_at IS NULL;
-- One root per environment.
CREATE UNIQUE INDEX IF NOT EXISTS uq_folders_environment_root ON folders (environment_id) WHERE parent_folder_id IS NULL AND deleted_at IS NULL;
-- Sibling names are unique within a parent; this is the same fact as the path
-- index, enforced at the adjacency level so a name collision fails even if a
-- caller hand-builds a path.
CREATE UNIQUE INDEX IF NOT EXISTS uq_folders_parent_name ON folders (parent_folder_id, name) WHERE parent_folder_id IS NOT NULL AND deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_folders_environment_id ON folders (environment_id);
CREATE INDEX IF NOT EXISTS idx_folders_parent_folder_id ON folders (parent_folder_id);
-- The prefix-listing index. text_pattern_ops is required for LIKE 'prefix%' to
-- be an index range scan under a non-C collation; the plain btree index above
-- serves equality lookups.
CREATE INDEX IF NOT EXISTS idx_folders_environment_path_prefix ON folders (environment_id, path text_pattern_ops) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_folders_deleted_at ON folders (deleted_at) WHERE deleted_at IS NULL;

-- +goose Down
DROP TABLE IF EXISTS folders;
