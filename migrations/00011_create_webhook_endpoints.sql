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
--
-- IT IS ALSO THE RE-DRIVE QUEUE. The row is written BEFORE the first attempt, so a
-- delivery that never landed is visible; `next_attempt_at` is what makes it
-- RECOVERABLE rather than merely visible. The inline attempt sequence on the write
-- path is bounded by a latency an operator will accept (a few hundred milliseconds
-- of backoff — see internal/webhook), which is far too short for a receiver that is
-- down for a deploy. So a delivery that fails inline is parked as 'retrying' with a
-- next-attempt time, and a background worker picks it up later with exponential
-- backoff until its budget is spent.
--
--   status = 'pending'   the row is open and the first attempt sequence is running.
--            'success'   a receiver answered 2xx. Terminal.
--            'retrying'  every attempt so far failed and the re-drive worker owns
--                        it. next_attempt_at says when it may be tried again.
--            'failed'    PERMANENTLY failed: the retry budget is spent, or the
--                        endpoint was deleted underneath it. Terminal, and the row
--                        an operator greps for.
--
--   next_attempt_at   when the worker may claim this row. It doubles as the CLAIM
--                     LEASE: the worker pushes it forward before attempting, so a
--                     replica that dies mid-attempt releases the row automatically
--                     when the lease passes instead of stranding it. That is why the
--                     claim needs no lock table and no leader election — see
--                     ClaimWebhookDeliveriesForRedrive, which claims with
--                     FOR UPDATE SKIP LOCKED and is therefore safe in every replica.
--   redrive_attempts  attempts made by the WORKER, counted separately from
--                     attempt_count (the total). Separate because the two budgets
--                     answer different questions: attempt_count is "how hard did we
--                     try", redrive_attempts is "how much of the durable budget is
--                     left", and an endpoint whose inline max_attempts was raised
--                     must not silently consume the durable one.
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
    -- contains no value — see the table comment above. It is ALSO what the re-drive
    -- worker replays: the body is re-signed with a fresh timestamp (the signature
    -- covers the timestamp, so a receiver's replay window stays enforceable) but the
    -- bytes are the ones recorded here, so a retry cannot silently deliver something
    -- different from what the first attempt announced.
    payload         JSONB NOT NULL DEFAULT '{}',
    -- The re-drive schedule. See the table comment.
    next_attempt_at  TIMESTAMPTZ,
    redrive_attempts INT NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_webhook_deliveries_status CHECK (status IN ('pending', 'success', 'retrying', 'failed')),
    -- A scheduled next attempt on a TERMINAL row is a contradiction: it would either
    -- be picked up (re-delivering a success) or ignored (a schedule that means
    -- nothing). Only a 'retrying' row carries one.
    CONSTRAINT chk_webhook_deliveries_next_attempt CHECK (
        next_attempt_at IS NULL OR status = 'retrying'
    ),
    CONSTRAINT chk_webhook_deliveries_redrive_attempts CHECK (redrive_attempts >= 0)
);

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_endpoint
    ON webhook_deliveries (endpoint_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_tenant
    ON webhook_deliveries (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_status
    ON webhook_deliveries (status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_resource_mrn
    ON webhook_deliveries (resource_mrn text_pattern_ops);
-- The re-drive worker's claim: due rows, oldest due first. PARTIAL on the one status
-- that can be claimed, so the index holds only the backlog — on a healthy service
-- that is zero rows, and the worker's tick costs an empty index scan rather than a
-- scan of every delivery ever made.
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_redrive_due
    ON webhook_deliveries (next_attempt_at)
    WHERE status = 'retrying' AND next_attempt_at IS NOT NULL;

-- +goose Down
DROP TABLE IF EXISTS webhook_deliveries;
DROP TABLE IF EXISTS webhook_endpoints;
