-- +goose Up
-- Rotation/change notification: per-project webhook endpoints plus the delivery
-- log that records what was sent where.
--
-- WHAT A DELIVERY CONTAINS, AND WHAT IT NEVER CONTAINS. The payload carries the
-- MRN, the event name and the new version number — an instruction to RE-READ,
-- never the value itself. That is not a size or a convenience decision: a webhook
-- is an unauthenticated outbound POST to a URL a tenant supplied, retried, logged
-- by the receiver, and (before TLS terminates) visible to whatever is in front of
-- it. Putting a credential in one would move the value outside encrypted custody
-- for no gain, since the consumer must be able to read the secret anyway to use
-- it. The payload column below therefore holds exactly what was signed, and the
-- absence of a value there is asserted by a test.
--
-- THE SIGNING KEY IS ENVELOPE-ENCRYPTED, like every other secret in this service.
-- An HMAC key at rest in plaintext is a forgery primitive: anyone who reads the
-- table can sign a delivery the receiver will trust. The same four columns +
-- kek_id that secret_versions uses are used here, with the AAD identity bound to
-- (tenant_uuid, endpoint_uuid, version 1) — the endpoint UUID plays the part
-- secret_uuid plays there, so a ciphertext moved between endpoint rows fails
-- authentication exactly as it would between secret rows.
CREATE TABLE IF NOT EXISTS webhook_endpoints (
    endpoint_id        BIGSERIAL PRIMARY KEY,
    endpoint_uuid      UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    tenant_id          BIGINT NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    -- Endpoints are per PROJECT: a project is the ownership boundary, and a
    -- tenant-wide endpoint would notify one team about another team's rotations.
    project_id         BIGINT NOT NULL REFERENCES projects (project_id) ON DELETE CASCADE,
    url                TEXT NOT NULL,
    description        TEXT NOT NULL DEFAULT '',
    secret_ciphertext  BYTEA NOT NULL,
    secret_nonce       BYTEA NOT NULL,
    secret_dek_wrapped BYTEA NOT NULL,
    secret_dek_nonce   BYTEA NOT NULL,
    kek_id             VARCHAR(64) NOT NULL REFERENCES root_keys (kek_id) ON DELETE RESTRICT,
    -- Subscribed event names ('secret.changed', 'secret.rotated'). An EMPTY array
    -- means "every event", which is the useful default for a consumer whose only
    -- job is to reload configuration.
    events             JSONB NOT NULL DEFAULT '[]',
    status             VARCHAR(20) NOT NULL DEFAULT 'active',
    timeout_seconds    INT NOT NULL DEFAULT 10,
    max_attempts       INT NOT NULL DEFAULT 3,
    last_triggered_at  TIMESTAMPTZ,
    metadata           JSONB NOT NULL DEFAULT '{}',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at         TIMESTAMPTZ,
    CONSTRAINT chk_webhook_endpoints_status CHECK (status IN ('active', 'disabled')),
    CONSTRAINT chk_webhook_endpoints_timeout CHECK (timeout_seconds BETWEEN 1 AND 60),
    CONSTRAINT chk_webhook_endpoints_attempts CHECK (max_attempts BETWEEN 1 AND 10)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_webhook_endpoints_project_url
    ON webhook_endpoints (project_id, url) WHERE deleted_at IS NULL;
-- The notifier's read: a project's active endpoints.
CREATE INDEX IF NOT EXISTS idx_webhook_endpoints_project_active
    ON webhook_endpoints (project_id) WHERE deleted_at IS NULL AND status = 'active';
CREATE INDEX IF NOT EXISTS idx_webhook_endpoints_tenant_id ON webhook_endpoints (tenant_id);
CREATE INDEX IF NOT EXISTS idx_webhook_endpoints_kek_id ON webhook_endpoints (kek_id);
CREATE INDEX IF NOT EXISTS idx_webhook_endpoints_deleted_at ON webhook_endpoints (deleted_at) WHERE deleted_at IS NULL;

-- The delivery log. One row per (event, endpoint) attempt sequence, so "did the
-- consumer ever learn about that rotation" is answerable — which matters because
-- a consumer that missed the notification is running on a credential that has
-- been replaced.
CREATE TABLE IF NOT EXISTS webhook_deliveries (
    delivery_id     BIGSERIAL PRIMARY KEY,
    delivery_uuid   UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    endpoint_id     BIGINT NOT NULL REFERENCES webhook_endpoints (endpoint_id) ON DELETE CASCADE,
    tenant_id       BIGINT NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    event_type      VARCHAR(50) NOT NULL,
    -- The MRN is denormalized text for the same reason audit_log.resource_mrn is:
    -- the record must still read correctly after the secret is moved or destroyed.
    resource_mrn    TEXT NOT NULL DEFAULT '',
    version         INT,
    attempt_count   INT NOT NULL DEFAULT 0,
    status          VARCHAR(20) NOT NULL DEFAULT 'pending',
    response_status INT,
    error           TEXT NOT NULL DEFAULT '',
    -- The exact JSON that was signed and sent. It is safe to persist BECAUSE it
    -- contains no value — see the table comment above.
    payload         JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_webhook_deliveries_status CHECK (status IN ('pending', 'success', 'failed'))
);

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_endpoint
    ON webhook_deliveries (endpoint_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_tenant
    ON webhook_deliveries (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_status
    ON webhook_deliveries (status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_resource_mrn
    ON webhook_deliveries (resource_mrn text_pattern_ops);

-- +goose Down
DROP TABLE IF EXISTS webhook_deliveries;
DROP TABLE IF EXISTS webhook_endpoints;
