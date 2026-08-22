-- +goose Up
-- A project is the ownership boundary inside a tenant and the second MRN segment
-- (mrn:secret:acme:billing-app:secret/db-password). Secrets never hang directly
-- off a tenant: the hierarchy is tenant -> project -> environment -> folder ->
-- secret, which is what lets one grant cover "everything billing-app has in
-- staging" without enumerating keys.
CREATE TABLE IF NOT EXISTS projects (
    project_id   BIGSERIAL PRIMARY KEY,
    project_uuid UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    tenant_id    BIGINT NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    name         VARCHAR(255) NOT NULL,
    slug         VARCHAR(63) NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    status       VARCHAR(20) NOT NULL DEFAULT 'active',
    metadata     JSONB NOT NULL DEFAULT '{}',
    created_by   BIGINT,
    updated_by   BIGINT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at   TIMESTAMPTZ,
    CONSTRAINT chk_projects_status CHECK (status IN ('active', 'suspended', 'archived'))
);

-- slug is the MRN project segment; unique per tenant among live rows so a
-- deleted project's slug can be reused.
CREATE UNIQUE INDEX IF NOT EXISTS uq_projects_tenant_slug ON projects (tenant_id, slug) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_projects_tenant_id ON projects (tenant_id);
CREATE INDEX IF NOT EXISTS idx_projects_status ON projects (status);
CREATE INDEX IF NOT EXISTS idx_projects_metadata ON projects USING GIN (metadata);
CREATE INDEX IF NOT EXISTS idx_projects_created_at ON projects (created_at);
CREATE INDEX IF NOT EXISTS idx_projects_deleted_at ON projects (deleted_at) WHERE deleted_at IS NULL;

-- +goose Down
DROP TABLE IF EXISTS projects;
