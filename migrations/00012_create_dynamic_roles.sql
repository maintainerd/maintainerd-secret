-- +goose Up
-- DYNAMIC SECRETS: on-demand PostgreSQL credentials with a TTL.
--
-- The difference between this and everything else in the schema is that the
-- credential here does not exist until somebody asks for it, and stops existing
-- when its lease ends. A static secret is a long-lived shared value that a leak
-- compromises until an operator notices; a dynamic credential is minted per
-- consumer, valid for an hour, and revoked automatically — so a leaked one is worth
-- what is left of its TTL and nothing more, and "which consumer leaked it" is
-- answerable because no two consumers ever held the same one.
--
-- THIS IS IMPLEMENTABLE HERE PRECISELY BECAUSE THE PLATFORM IS PostgreSQL-ONLY.
-- Vault needs a plugin per engine because it must speak to whatever database a
-- tenant runs. maintainerd made PostgreSQL a platform decision, so the creation and
-- revocation statements are PostgreSQL DDL and nothing else — no driver abstraction,
-- no per-engine capability matrix.
--
-- TWO TABLES, TWO LIFETIMES. dynamic_roles is CONFIGURATION an operator writes once
-- and edits rarely; dynamic_leases is a high-churn record of credentials that were
-- issued and then destroyed. Keeping them apart is what lets the lease table be
-- pruned without touching the configuration, and what makes "who currently holds a
-- credential against this role" one indexed read.
CREATE TABLE IF NOT EXISTS dynamic_roles (
    role_id         BIGSERIAL PRIMARY KEY,
    role_uuid       UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    tenant_id       BIGINT NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    -- Roles are per PROJECT, like webhook endpoints and for the same reason: a
    -- project is the ownership boundary, and a tenant-wide role would let one team
    -- mint credentials against another team's database.
    project_id      BIGINT NOT NULL REFERENCES projects (project_id) ON DELETE CASCADE,
    -- The role config's own name, the handle a caller issues against.
    name            VARCHAR(63) NOT NULL,
    description     TEXT NOT NULL DEFAULT '',

    -- THE TARGET DSN IS A SECRET REFERENCE, NEVER A LITERAL, and the check
    -- constraint below is what makes that structural rather than aspirational.
    --
    -- A DSN is a credential: it carries the superuser-ish account that CREATE ROLE
    -- needs. Storing it here as text would put the most privileged credential in the
    -- system in a plaintext configuration column — readable by anyone with a psql
    -- prompt, dumped into every backup, and outside the envelope encryption the rest
    -- of this service is built on. So this column holds an ADDRESS in the same
    -- 'project/environment[/folder...]/KEY' form a reference value uses, and the DSN
    -- itself lives in secret_versions like every other credential: encrypted under a
    -- per-version DEK, wrapped by the root key, rotatable, audited on every read.
    dsn_secret_ref  TEXT NOT NULL,

    -- The SQL an issue runs, and the SQL a revoke runs. Templates rather than
    -- generated statements because only the operator knows what the credential
    -- should be able to do — which schemas, which tables, which privileges — and a
    -- service that guessed would either over-grant (a read-only consumer that can
    -- DROP) or under-grant (a credential that authenticates and can read nothing).
    --
    -- Placeholders are {{name}}, {{password}} and {{expiration}}; see
    -- internal/dynamic for the rendering rules and for why the rendered statements
    -- run in ONE transaction against the target database.
    creation_sql    TEXT NOT NULL,
    revocation_sql  TEXT NOT NULL,

    -- The lease's default lifetime, and the ceiling a caller may request. Both are
    -- NOT NULL with real defaults, unlike the static-secret lease policy: a dynamic
    -- credential with no TTL is a permanent database account created by an API call,
    -- which is the opposite of the feature.
    default_ttl_seconds INT NOT NULL DEFAULT 3600,
    max_ttl_seconds     INT NOT NULL DEFAULT 86400,
    -- Generated role names are prefixed so an operator reading pg_roles can tell at
    -- a glance which accounts this service owns — and so a reaper never touches an
    -- account it did not create.
    role_name_prefix VARCHAR(32) NOT NULL DEFAULT 'm9d',
    status          VARCHAR(20) NOT NULL DEFAULT 'active',
    metadata        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at      TIMESTAMPTZ,
    CONSTRAINT chk_dynamic_roles_status CHECK (status IN ('active', 'disabled')),
    CONSTRAINT chk_dynamic_roles_default_ttl CHECK (default_ttl_seconds >= 60),
    CONSTRAINT chk_dynamic_roles_max_ttl CHECK (max_ttl_seconds >= default_ttl_seconds),
    -- THE ANTI-LITERAL GUARD. A DSN contains a scheme ('postgres://') or libpq
    -- keywords ('host=', 'password='); a secret reference contains neither. Refusing
    -- both shapes at the column means a future code path that forgets to validate
    -- still cannot persist a plaintext DSN here.
    CONSTRAINT chk_dynamic_roles_dsn_is_a_reference CHECK (
        dsn_secret_ref <> ''
        AND position('://' in dsn_secret_ref) = 0
        AND position('password=' in lower(dsn_secret_ref)) = 0
        AND position('host=' in lower(dsn_secret_ref)) = 0
    ),
    -- A revocation template that does not drop the role would leave every issued
    -- account behind forever. The reaper cannot compensate for a template that
    -- revokes nothing, so the shape is required here.
    CONSTRAINT chk_dynamic_roles_revocation_drops CHECK (position('drop role' in lower(revocation_sql)) > 0),
    CONSTRAINT chk_dynamic_roles_creation_creates CHECK (position('create role' in lower(creation_sql)) > 0)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_dynamic_roles_project_name
    ON dynamic_roles (project_id, name) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_dynamic_roles_tenant_id ON dynamic_roles (tenant_id);
CREATE INDEX IF NOT EXISTS idx_dynamic_roles_deleted_at ON dynamic_roles (deleted_at) WHERE deleted_at IS NULL;

-- The issued credentials.
--
-- THERE IS NO PASSWORD COLUMN, AND THERE CANNOT BE ONE. The generated password is
-- returned to the caller exactly once, in the issue response, and is never
-- persisted, logged or recoverable — the same one-time posture a rotated secret and
-- a webhook signing key already have. A vault that stored the credentials it minted
-- would have converted a short-lived secret back into a long-lived one, and the
-- revocation path does not need the password: DROP ROLE takes a name.
--
-- expires_at IS ENFORCED BY A REAPER, NOT ONLY BY 'VALID UNTIL'. A template is
-- operator-written and may omit VALID UNTIL entirely, in which case PostgreSQL will
-- happily keep the login working forever. The background sweep over
-- (revoked_at IS NULL AND expires_at <= now()) is therefore the authoritative
-- expiry: an orphaned role cannot outlive its lease because the lease row, not the
-- target database, is the record of truth.
CREATE TABLE IF NOT EXISTS dynamic_leases (
    lease_id        BIGSERIAL PRIMARY KEY,
    lease_uuid      UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    role_id         BIGINT NOT NULL REFERENCES dynamic_roles (role_id) ON DELETE CASCADE,
    tenant_id       BIGINT NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    -- The role name actually created in the target database. UNIQUE across the whole
    -- table, not just per role config: two leases sharing a database role would be
    -- two consumers holding one credential, which is exactly the property dynamic
    -- secrets exist to remove — and revoking one would silently break the other.
    db_role_name    VARCHAR(63) NOT NULL UNIQUE,
    -- Denormalized MRN, for the reason audit_log.resource_mrn is denormalized: the
    -- record must still read correctly after the role config is deleted.
    resource_mrn    TEXT NOT NULL DEFAULT '',
    -- Who asked. Text, because this service does not own the identity table and a
    -- lease record must outlive the principal it names.
    requester       TEXT NOT NULL DEFAULT '',
    requester_kind  VARCHAR(20) NOT NULL DEFAULT 'service',
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ,
    -- Why the lease ended: 'explicit' (a caller revoked it), 'expired' (the reaper
    -- did), or 'failed' (revocation ran and the target database refused). The third
    -- is the one an operator must see: the row stays unrevoked-in-effect and the
    -- reaper retries, so a transient outage does not silently orphan an account.
    revoke_reason   VARCHAR(20) NOT NULL DEFAULT '',
    revoke_error    TEXT NOT NULL DEFAULT '',
    revoke_attempts INT NOT NULL DEFAULT 0,
    metadata        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_dynamic_leases_revoke_reason CHECK (revoke_reason IN ('', 'explicit', 'expired', 'failed')),
    CONSTRAINT chk_dynamic_leases_revoked_has_reason CHECK (revoked_at IS NULL OR revoke_reason <> '')
);

-- THE REAPER'S QUERY. Every index on this table exists for one read; this is the
-- one that matters, because it is what makes expiry enforceable independently of
-- the target database.
CREATE INDEX IF NOT EXISTS idx_dynamic_leases_due
    ON dynamic_leases (expires_at) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_dynamic_leases_role
    ON dynamic_leases (role_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_dynamic_leases_tenant
    ON dynamic_leases (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_dynamic_leases_requester
    ON dynamic_leases (requester) WHERE revoked_at IS NULL;

-- +goose Down
DROP TABLE IF EXISTS dynamic_leases;
DROP TABLE IF EXISTS dynamic_roles;
