-- +goose Up
-- Scope imports: one folder (in one environment) inherits another's secrets.
--
-- The motivating case is the one every team has: staging is dev plus a handful of
-- overrides. Without imports the only ways to express that are copying every value
-- into staging — which means N copies of a credential to rotate, and N chances for
-- one of them to go stale — or writing a reference per key, which is the same
-- bookkeeping with extra indirection. An import says it once, at the scope level.
--
-- WHY THE TARGET AND SOURCE ARE BOTH (environment, folder) PAIRS. A folder is
-- already scoped to exactly one environment, so folder_id alone would suffice;
-- environment_id is carried anyway because every read in this schema is scoped by
-- environment and because it makes "environment A imports environment B" (the
-- common case, expressed as the two root folders) an indexed lookup rather than a
-- join through folders.
--
-- PRECEDENCE. Resolution is: the target's OWN value wins, always. Only when the
-- target has no secret at a key is the import chain consulted, in `position`
-- order, first hit wins. That direction is the only safe one — the alternative
-- lets an import silently shadow a value someone deliberately set in this
-- environment, which for a production credential is a data-integrity incident
-- rather than a configuration preference.
--
-- CYCLES. A cycle (staging imports dev, dev imports staging) would make
-- resolution non-terminating. The service refuses to create one (it walks the
-- existing chain before inserting) and the resolver additionally bounds its own
-- depth, because a cycle introduced by any other means — a restore, a manual
-- INSERT — must degrade to a precise error rather than a hung request.
CREATE TABLE IF NOT EXISTS scope_imports (
    import_uuid           UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    import_id             BIGSERIAL PRIMARY KEY,
    tenant_id             BIGINT NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    -- The importing (target) scope: the one that gains the values.
    environment_id        BIGINT NOT NULL REFERENCES environments (environment_id) ON DELETE CASCADE,
    folder_id             BIGINT NOT NULL REFERENCES folders (folder_id) ON DELETE CASCADE,
    -- The imported-from (source) scope.
    source_environment_id BIGINT NOT NULL REFERENCES environments (environment_id) ON DELETE CASCADE,
    source_folder_id      BIGINT NOT NULL REFERENCES folders (folder_id) ON DELETE CASCADE,
    -- position orders multiple imports on one target. Stored rather than derived
    -- for the same reason environments.position is: the order is a decision, and
    -- insertion order is not a decision anyone made.
    position              INT NOT NULL DEFAULT 0,
    enabled               BOOLEAN NOT NULL DEFAULT TRUE,
    metadata              JSONB NOT NULL DEFAULT '{}',
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at            TIMESTAMPTZ,
    -- A scope importing itself is a zero-length cycle. Refused in the schema so no
    -- code path can create one, not even a direct INSERT.
    CONSTRAINT chk_scope_imports_not_self CHECK (folder_id <> source_folder_id)
);

-- One import edge per (target, source) among live rows; re-adding a removed
-- import is ordinary housekeeping.
CREATE UNIQUE INDEX IF NOT EXISTS uq_scope_imports_edge
    ON scope_imports (folder_id, source_folder_id) WHERE deleted_at IS NULL;
-- The resolver's read: this scope's enabled imports in precedence order.
CREATE INDEX IF NOT EXISTS idx_scope_imports_target
    ON scope_imports (folder_id, position) WHERE deleted_at IS NULL AND enabled;
-- The cycle walk in the other direction, and "what imports me" for the console.
CREATE INDEX IF NOT EXISTS idx_scope_imports_source
    ON scope_imports (source_folder_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_scope_imports_tenant_id ON scope_imports (tenant_id);
CREATE INDEX IF NOT EXISTS idx_scope_imports_environment_id ON scope_imports (environment_id);
CREATE INDEX IF NOT EXISTS idx_scope_imports_deleted_at ON scope_imports (deleted_at) WHERE deleted_at IS NULL;

-- +goose Down
DROP TABLE IF EXISTS scope_imports;
