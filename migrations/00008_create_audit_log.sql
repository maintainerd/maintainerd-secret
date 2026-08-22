-- +goose Up
-- The access trail. Append-only, and it RECORDS READS.
--
-- That last part is the whole point and the thing that separates a vault from a
-- database with encrypted columns. For most tables a read is uninteresting; for a
-- secret store the read IS the sensitive event — "who saw the production database
-- password, and when" is the question an incident review opens with. So there is
-- no unaudited get path: secret.read and secret.reveal are first-class actions
-- here, alongside the mutations.
--
--   tenant_id       NULLABLE. Setup-window operations are audited too, and the
--                   bootstrap call that CREATES the first tenant cannot reference
--                   one — the same reason Auth's management_audit_log allows NULL
--                   (auth migration 057). NULL means platform-scoped, pre-tenant.
--   actor_subject   the principal string as authenticated (a user subject, a
--                   service identity, or the setup controller). Stored as text
--                   rather than an FK: this service does not own the identity
--                   table, Auth does, and an audit row must survive the deletion
--                   of the principal it names.
--   actor_kind      user | service | setup.
--   action          'secret.read', 'secret.reveal', 'secret.write', ... A reveal is
--                   deliberately distinct from a read: metadata access and value
--                   access are different grants and must be separately reviewable.
--   resource_mrn    the full MRN string as evaluated. Denormalized text on purpose
--                   — the trail must still read correctly after the folder is moved
--                   or the secret is destroyed.
--   secret_id       NULLABLE, best-effort join back to a live secret; the MRN above
--                   is the durable identifier.
--   outcome         success | denied | error. Denied attempts are the ones that
--                   matter most, so a failed authorization writes a row rather than
--                   returning silently.
CREATE TABLE IF NOT EXISTS audit_log (
    event_id      BIGSERIAL PRIMARY KEY,
    event_uuid    UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    tenant_id     BIGINT REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    actor_subject VARCHAR(255) NOT NULL DEFAULT '',
    actor_kind    VARCHAR(20) NOT NULL DEFAULT 'service',
    action        VARCHAR(50) NOT NULL,
    resource_mrn  TEXT NOT NULL DEFAULT '',
    secret_id     BIGINT REFERENCES secrets (secret_id) ON DELETE SET NULL,
    version       INT,
    outcome       VARCHAR(20) NOT NULL DEFAULT 'success',
    reason        TEXT NOT NULL DEFAULT '',
    ip_address    INET,
    user_agent    TEXT NOT NULL DEFAULT '',
    request_id    VARCHAR(255) NOT NULL DEFAULT '',
    metadata      JSONB NOT NULL DEFAULT '{}',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_audit_log_actor_kind CHECK (actor_kind IN ('user', 'service', 'setup')),
    CONSTRAINT chk_audit_log_outcome CHECK (outcome IN ('success', 'denied', 'error'))
);

-- +goose StatementBegin
-- Same immutability contract as secret_versions and Auth's management_audit_log:
-- an audit row can never be updated, and can only be deleted by a sanctioned
-- lifecycle operation. Note there is NO rewrap exemption here — unlike a version
-- row, an audit row has no legitimate reason to change at all.
CREATE OR REPLACE FUNCTION prevent_audit_log_mutation() RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION 'audit_log rows are immutable and cannot be updated';
    END IF;

    -- retention     age-based purge
    -- tenant_delete full tenant erasure; required because ON DELETE CASCADE from
    --               tenants routes through this trigger and would otherwise abort
    --               the purge transaction.
    IF TG_OP = 'DELETE'
       AND COALESCE(current_setting('maintainerd.allow_audit_log_delete', true), '') NOT IN ('retention', 'tenant_delete') THEN
        RAISE EXCEPTION 'audit_log rows are append-only and may only be deleted by retention or tenant deletion';
    END IF;

    RETURN OLD;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

DROP TRIGGER IF EXISTS trg_audit_log_immutable ON audit_log;
CREATE TRIGGER trg_audit_log_immutable
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_mutation();

-- "what happened in this tenant, newest first" — the console's default read, and
-- the index the DATE-RANGE filter rides: a tenant-scoped BETWEEN on created_at is
-- a range scan on the trailing column of this very index, so no separate index
-- exists for `from`/`to`.
CREATE INDEX IF NOT EXISTS idx_audit_log_tenant_created ON audit_log (tenant_id, created_at DESC);
-- "who has touched THIS secret" — the incident timeline.
CREATE INDEX IF NOT EXISTS idx_audit_log_secret ON audit_log (secret_id, created_at DESC) WHERE secret_id IS NOT NULL;
-- "what has THIS principal been reading" — the compromised-credential review.
-- These three are NOT tenant-scoped on purpose: they answer the cross-tenant
-- platform question ("everything this subject ever did"), which is what an
-- operator asks during an incident with a leaked credential.
CREATE INDEX IF NOT EXISTS idx_audit_log_actor ON audit_log (actor_subject, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log (action, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_outcome ON audit_log (outcome, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_resource_mrn ON audit_log (resource_mrn text_pattern_ops);
CREATE INDEX IF NOT EXISTS idx_audit_log_request_id ON audit_log (request_id) WHERE request_id <> '';
CREATE INDEX IF NOT EXISTS idx_audit_log_metadata ON audit_log USING GIN (metadata);

-- THE FILTERED CONSOLE READ (ListAuditEventsFiltered).
--
-- Every filtered audit query is tenant-scoped FIRST — a caller may only ever read
-- its own tenant's trail — so the four indexes above with a bare leading
-- action/actor/outcome column cannot serve it: Postgres would have to choose
-- between a scan of one action across every tenant or a scan of one tenant across
-- every action. The composites below put tenant_id first and created_at last, so
-- one filter plus the newest-first ordering is a single index scan with no sort.
--
-- Only ONE of these can be used per query, which is the honest bound on the
-- feature: filtering by action AND outcome together uses the action index and
-- filters the outcome as a recheck. A multi-column-per-filter design would need a
-- combinatorial index set for a trail whose selective column is almost always
-- action or actor.
CREATE INDEX IF NOT EXISTS idx_audit_log_tenant_action_created
    ON audit_log (tenant_id, action, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_tenant_outcome_created
    ON audit_log (tenant_id, outcome, created_at DESC);
-- The actor and resource filters are PREFIX matches (LIKE 'prefix%'), which is what
-- an operator types: part of a subject, or an MRN down to a project or environment.
-- A prefix match needs *_pattern_ops so the comparison is byte-wise and index-able
-- under any database collation — the same reason idx_audit_log_resource_mrn above
-- uses text_pattern_ops. actor_subject is VARCHAR, hence varchar_pattern_ops.
CREATE INDEX IF NOT EXISTS idx_audit_log_tenant_actor_prefix
    ON audit_log (tenant_id, actor_subject varchar_pattern_ops);
CREATE INDEX IF NOT EXISTS idx_audit_log_tenant_resource_prefix
    ON audit_log (tenant_id, resource_mrn text_pattern_ops);

-- +goose Down
DROP TRIGGER IF EXISTS trg_audit_log_immutable ON audit_log;
DROP FUNCTION IF EXISTS prevent_audit_log_mutation();
DROP TABLE IF EXISTS audit_log;
