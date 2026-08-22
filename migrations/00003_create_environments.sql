-- +goose Up
-- An environment is a project's deployment stage (dev / staging / prod). It is a
-- first-class table rather than a folder convention because it is the level every
-- real grant is written at — "the billing-app service account may read staging,
-- humans may not read prod" — and because the same key name is expected to exist
-- once per environment with a different value.
--
--   position   display order. Environments are inherently ordered (dev before
--              prod), and alphabetical ordering gets that wrong every time, so the
--              order is stored rather than derived.
CREATE TABLE IF NOT EXISTS environments (
    environment_id   BIGSERIAL PRIMARY KEY,
    environment_uuid UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    project_id       BIGINT NOT NULL REFERENCES projects (project_id) ON DELETE CASCADE,
    name             VARCHAR(255) NOT NULL,
    slug             VARCHAR(63) NOT NULL,
    description      TEXT NOT NULL DEFAULT '',
    position         INT NOT NULL DEFAULT 0,
    status           VARCHAR(20) NOT NULL DEFAULT 'active',
    metadata         JSONB NOT NULL DEFAULT '{}',
    created_by       BIGINT,
    updated_by       BIGINT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at       TIMESTAMPTZ,
    CONSTRAINT chk_environments_status CHECK (status IN ('active', 'suspended', 'archived')),
    -- Unconditional, NOT partial on deleted_at, unlike projects and folders. An
    -- environment slug is quoted in MRNs, in grants, and in every consumer's
    -- configuration; recycling a deleted slug would silently repoint live
    -- references at a different environment. Reserving the slug forever is the
    -- safe direction: environments are renamed, not recreated.
    CONSTRAINT uq_environments_project_slug UNIQUE (project_id, slug)
);

CREATE INDEX IF NOT EXISTS idx_environments_project_id ON environments (project_id);
-- The console's read: a project's environments in display order.
CREATE INDEX IF NOT EXISTS idx_environments_project_position ON environments (project_id, position) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_environments_status ON environments (status);
CREATE INDEX IF NOT EXISTS idx_environments_metadata ON environments USING GIN (metadata);
CREATE INDEX IF NOT EXISTS idx_environments_deleted_at ON environments (deleted_at) WHERE deleted_at IS NULL;

-- +goose Down
DROP TABLE IF EXISTS environments;
