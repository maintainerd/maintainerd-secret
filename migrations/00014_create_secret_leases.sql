-- +goose Up
-- LEASES ON STATIC SECRETS: the issued read leases whose policy lives on the secret.
--
-- The policy columns (lease_ttl_seconds, lease_max_ttl_seconds, lease_max_reads) are
-- on `secrets` — see migration 00006 — because they describe the secret. THIS table
-- is the record of leases actually handed out, and it is the enforcement surface: a
-- reveal of a lease-governed secret reads a row here, decides whether the read is
-- still permitted, and consumes one use.
--
-- WHY A LEASE AT ALL, WHEN THE SECRET IS STATIC. Because "who is currently able to
-- read the production database password" is a question a static secret cannot answer
-- and a lease can. A grant says who MAY read; a lease says who HAS, when, and how
-- much of their allowance is left — and a max_reads cap turns an exfiltration loop
-- (the same valid token pulling a value ten thousand times) from an invisible read
-- pattern into a refusal an operator sees.
--
-- ONE LIVE LEASE PER (SECRET, REQUESTER), enforced by the partial unique index below,
-- and a NEW ROW each time one is issued. The alternative — resetting the existing row
-- on expiry — would be less code and would erase the history that makes the table
-- worth having. So the lifecycle is: issue a row; consume reads against it; when it
-- expires, mark it revoked and issue a successor; when it is exhausted before it
-- expires, REFUSE, and keep refusing until the TTL runs out. That last behaviour is
-- the cap actually biting: max_reads is "this many reads per TTL window per
-- requester", which is a rate a human can reason about, rather than a lifetime budget
-- that eventually bricks a working consumer.
CREATE TABLE IF NOT EXISTS secret_leases (
    lease_id        BIGSERIAL PRIMARY KEY,
    lease_uuid      UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    tenant_id       BIGINT NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    secret_id       BIGINT NOT NULL REFERENCES secrets (secret_id) ON DELETE CASCADE,
    -- Denormalized MRN, for the reason audit_log.resource_mrn is: the record must
    -- still read correctly after the secret is moved, deleted or destroyed.
    resource_mrn    TEXT NOT NULL DEFAULT '',
    -- Who holds the lease. Text, because this service does not own the identity table
    -- and a lease record must outlive the principal it names. The requester is part of
    -- the identity of a lease, not metadata on it: two workloads reading the same
    -- secret get two independent allowances, because one noisy consumer must not be
    -- able to exhaust another's.
    requester       TEXT NOT NULL DEFAULT '',
    requester_kind  VARCHAR(20) NOT NULL DEFAULT 'service',
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    -- max_reads is SNAPSHOT AT ISSUE, not read live from the secret. An operator who
    -- tightens the policy should not retroactively invalidate a lease already handed
    -- out — the tightened cap applies to the next lease, which is at most one TTL
    -- away. NULL means unlimited reads within the TTL.
    max_reads       INT,
    reads_used      INT NOT NULL DEFAULT 0,
    last_read_at    TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,
    -- 'expired' (superseded because its TTL ran out), 'explicit' (an operator or the
    -- holder gave it up), 'policy' (the secret's lease policy was removed or the
    -- secret was deleted).
    revoke_reason   VARCHAR(20) NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_secret_leases_max_reads CHECK (max_reads IS NULL OR max_reads >= 1),
    CONSTRAINT chk_secret_leases_reads_used CHECK (reads_used >= 0),
    CONSTRAINT chk_secret_leases_revoke_reason CHECK (revoke_reason IN ('', 'expired', 'explicit', 'policy')),
    CONSTRAINT chk_secret_leases_revoked_has_reason CHECK (revoked_at IS NULL OR revoke_reason <> ''),
    -- reads_used may not exceed the cap. The service refuses first and this is the
    -- backstop: an off-by-one in the consume path becomes a constraint violation
    -- rather than one free read past the limit.
    CONSTRAINT chk_secret_leases_within_cap CHECK (max_reads IS NULL OR reads_used <= max_reads)
);

-- ONE LIVE LEASE PER (SECRET, REQUESTER). Partial on revoked_at so the history of
-- superseded leases accumulates freely while only one can be current — which is what
-- makes "lock the caller's lease, decide, consume" a single indexed read rather than a
-- scan with a tie-break.
CREATE UNIQUE INDEX IF NOT EXISTS uq_secret_leases_live
    ON secret_leases (secret_id, requester) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_secret_leases_secret ON secret_leases (secret_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_secret_leases_tenant ON secret_leases (tenant_id, created_at DESC);
-- The sweep that retires leases whose TTL has run out, so the live-lease index does
-- not fill with expired rows nobody will ever consume again.
CREATE INDEX IF NOT EXISTS idx_secret_leases_due
    ON secret_leases (expires_at) WHERE revoked_at IS NULL;

-- +goose Down
DROP TABLE IF EXISTS secret_leases;
