-- +goose Up
-- The addressable secret: an identity and its metadata. NO VALUE LIVES HERE.
-- Every encrypted payload is a row in secret_versions; this table is the stable
-- handle consumers reference, list, and are granted access to, which is why it can
-- be read freely to render a console without decrypting anything.
--
-- tenant_id and project_id are denormalized alongside environment_id even though
-- they are reachable by joining upward. Two reasons, both load-bearing:
--   * tenant scoping must be expressible in the WHERE clause of every single
--     secret query without a join, so that no code path can accidentally omit it;
--   * the MRN columns below are only meaningful next to the ids they were parsed
--     from.
--
--   current_version  the newest live version number; 0 until the first write.
--                    Incremented on write, never decremented — a version number
--                    is never reused even after retention prunes the row, because
--                    consumers pin versions.
--   keep_versions    per-secret retention override; NULL inherits the service
--                    default (SECRET_KEEP_VERSIONS).
--   expires_at       advisory expiry for the value (a credential's own lifetime),
--                    distinct from destroy_after which is about this row's
--                    deletion.
--   deleted_at +     the AWS Secrets Manager recovery model: delete is a soft
--   destroy_after    delete that schedules destruction. Until destroy_after the
--                    secret can be restored intact; past it, and only then, the
--                    ciphertext may actually be destroyed. Two columns rather than
--                    one because "when it was deleted" and "when it becomes
--                    unrecoverable" are different questions and the window is
--                    configurable per call.
--
-- THE LEASE POLICY (lease_ttl_seconds / lease_max_ttl_seconds / lease_max_reads).
-- Three nullable columns, and the NULL is the whole design: a secret with no
-- lease_ttl_seconds has NO lease policy and reads behave exactly as they always
-- have. Setting one opts THIS secret into leased reads — every reveal issues (or
-- consumes) a row in secret_leases, and a read past the lease's expiry or beyond
-- its remaining use count is refused rather than served.
--
--   lease_ttl_seconds      the lifetime of an issued read lease. NULL = unleased.
--   lease_max_ttl_seconds  the ceiling a caller may ask for when it requests a
--                          longer lease than the default. NULL = the default is
--                          also the maximum, which is the safe reading of "no
--                          ceiling was configured" — an absent ceiling must never
--                          mean an unbounded one.
--   lease_max_reads        how many reads one lease may serve. NULL = unlimited
--                          within the TTL, which is the useful default for a
--                          workload that re-reads on every boot.
--
-- expires_at (above) is the CREDENTIAL's own lifetime and is advisory for an
-- unleased secret, as it always has been. For a secret that carries a lease policy
-- it becomes a hard gate: once an operator has declared reads of this value
-- lease-governed, serving a value the operator already declared dead would defeat
-- the point. See internal/lease.
CREATE TABLE IF NOT EXISTS secrets (
    secret_id       BIGSERIAL PRIMARY KEY,
    secret_uuid     UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    tenant_id       BIGINT NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    project_id      BIGINT NOT NULL REFERENCES projects (project_id) ON DELETE CASCADE,
    environment_id  BIGINT NOT NULL REFERENCES environments (environment_id) ON DELETE CASCADE,
    folder_id       BIGINT NOT NULL REFERENCES folders (folder_id) ON DELETE CASCADE,
    -- Parsed MRN components, the same cross-repo convention Core uses (see core
    -- migrations/00006_create_resources.sql). The mrn: string
    -- (mrn:secret:acme:billing-app:secret/prod/db/primary/password) is
    -- presentation only; authorization compares these columns, so a policy
    -- decision is an indexed segment-aware comparison rather than a string parse
    -- per row. Keeping the column names identical across core and secret is
    -- deliberate: one policy engine reads both services' rows.
    mrn_service       VARCHAR(63) NOT NULL DEFAULT 'secret',
    mrn_tenant        VARCHAR(63) NOT NULL DEFAULT '',
    mrn_project       VARCHAR(63) NOT NULL DEFAULT '',
    -- 'secret/prod/db/primary/password' — the resource type, then the ENVIRONMENT
    -- SLUG, then the folder path and the key; materialized for the same reason
    -- folders.path is.
    --
    -- The environment segment is not optional. The same key name is expected to
    -- exist once per environment, so without it dev and prod would share an MRN —
    -- and the single most common grant in a secret store ("this account may read
    -- staging, nobody reads prod") would be inexpressible. An identifier that
    -- cannot distinguish the thing being protected is not an identifier.
    mrn_resource_path TEXT NOT NULL DEFAULT '',
    key             VARCHAR(255) NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    tags            JSONB NOT NULL DEFAULT '[]',
    current_version INT NOT NULL DEFAULT 0,
    keep_versions   INT,
    rotation_policy JSONB NOT NULL DEFAULT '{}',
    rotated_at      TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ,
    -- The lease policy. NULL lease_ttl_seconds = no policy = reads behave exactly
    -- as they did before leases existed. See the table comment.
    lease_ttl_seconds     INT,
    lease_max_ttl_seconds INT,
    lease_max_reads       INT,
    metadata        JSONB NOT NULL DEFAULT '{}',
    created_by      BIGINT,
    updated_by      BIGINT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at      TIMESTAMPTZ,
    destroy_after   TIMESTAMPTZ,
    CONSTRAINT chk_secrets_current_version CHECK (current_version >= 0),
    CONSTRAINT chk_secrets_keep_versions CHECK (keep_versions IS NULL OR keep_versions >= 1),
    -- destroy_after is only meaningful for a deleted row; a live secret with a
    -- destruction date would be a scheduled data-loss bug.
    CONSTRAINT chk_secrets_destroy_after CHECK (destroy_after IS NULL OR deleted_at IS NOT NULL),
    -- A lease TTL of zero would issue leases that are already expired, which reads
    -- as "this secret is unreadable" rather than as a policy. Refuse it at the
    -- column rather than discovering it as an unexplained 403.
    CONSTRAINT chk_secrets_lease_ttl CHECK (lease_ttl_seconds IS NULL OR lease_ttl_seconds >= 1),
    CONSTRAINT chk_secrets_lease_max_reads CHECK (lease_max_reads IS NULL OR lease_max_reads >= 1),
    -- The ceiling is only meaningful alongside a default, and it must not be BELOW
    -- it: a maximum smaller than the default would make the default itself
    -- unissuable.
    CONSTRAINT chk_secrets_lease_max_ttl CHECK (
        lease_max_ttl_seconds IS NULL
        OR (lease_ttl_seconds IS NOT NULL AND lease_max_ttl_seconds >= lease_ttl_seconds)
    ),
    -- max_reads without a TTL is a cap nothing enforces, because it is the TTL that
    -- makes a secret leased at all.
    CONSTRAINT chk_secrets_lease_reads_need_ttl CHECK (
        lease_max_reads IS NULL OR lease_ttl_seconds IS NOT NULL
    )
);

-- The address. A secret is identified by environment + folder + key; the same key
-- name legitimately exists in another folder or another environment. Partial on
-- deleted_at so a soft-deleted secret does not block creating a new one at the
-- same address — the deleted row stays restorable but no longer owns the name.
CREATE UNIQUE INDEX IF NOT EXISTS uq_secrets_address ON secrets (environment_id, folder_id, key) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_secrets_tenant_id ON secrets (tenant_id);
CREATE INDEX IF NOT EXISTS idx_secrets_project_id ON secrets (project_id);
CREATE INDEX IF NOT EXISTS idx_secrets_environment_id ON secrets (environment_id);
CREATE INDEX IF NOT EXISTS idx_secrets_folder_id ON secrets (folder_id);
-- The authorization read: match a policy's resource pattern against parsed MRN
-- segments.
CREATE INDEX IF NOT EXISTS idx_secrets_mrn ON secrets (mrn_service, mrn_tenant, mrn_project, mrn_resource_path);
CREATE INDEX IF NOT EXISTS idx_secrets_mrn_resource_path_prefix ON secrets (mrn_resource_path text_pattern_ops) WHERE deleted_at IS NULL;
-- Metadata search without touching a value.
CREATE INDEX IF NOT EXISTS idx_secrets_tags ON secrets USING GIN (tags);
CREATE INDEX IF NOT EXISTS idx_secrets_metadata ON secrets USING GIN (metadata);
CREATE INDEX IF NOT EXISTS idx_secrets_created_at ON secrets (created_at);
CREATE INDEX IF NOT EXISTS idx_secrets_deleted_at ON secrets (deleted_at) WHERE deleted_at IS NULL;
-- The two sweeper reads: what is due for destruction, and what has expired.
CREATE INDEX IF NOT EXISTS idx_secrets_destroy_after ON secrets (destroy_after) WHERE destroy_after IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_secrets_expires_at ON secrets (expires_at) WHERE expires_at IS NOT NULL AND deleted_at IS NULL;
-- Rotation scheduling reads the policy next to the last rotation.
CREATE INDEX IF NOT EXISTS idx_secrets_rotated_at ON secrets (rotated_at) WHERE deleted_at IS NULL;
-- "Which secrets are lease-governed" — the console read, and the sweep that expires
-- their outstanding leases. Partial, because in most installs almost no secret
-- carries a lease policy and a full index would be mostly NULLs.
CREATE INDEX IF NOT EXISTS idx_secrets_lease_policy
    ON secrets (lease_ttl_seconds) WHERE lease_ttl_seconds IS NOT NULL AND deleted_at IS NULL;

-- +goose Down
DROP TABLE IF EXISTS secrets;
