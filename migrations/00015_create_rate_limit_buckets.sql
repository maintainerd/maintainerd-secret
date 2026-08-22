-- +goose Up
-- The shared rate-limit budget.
--
-- WHY THIS TABLE EXISTS. The limiter used to count in process memory, which is not
-- a budget once there is more than one replica: a client that spreads its requests
-- across N replicas gets N times the configured allowance. The reveal budget is the
-- exfiltration bound on a compromised token, so silently multiplying it by the
-- replica count is precisely the number that must not drift. This table is where
-- the replicas agree.
--
-- IT IS NOT A COUNTER, IT IS A RESERVATION LEDGER. A replica does not increment a
-- row per request — that would put a write in front of every reveal. It reserves a
-- SLICE of the window's budget in one round trip and then serves from that slice
-- out of memory. See internal/platform/middleware/rate_limit.go for the full
-- protocol and the trade-off it accepts (an idle replica strands its unspent
-- slice).
--
--   bucket_key    "<class>|<principal>" — the class ('reveal', 'write', 'setup')
--                 and the principal it is metered against ('sub:<subject>', or
--                 'ip:<address>' on the setup surface, which runs before any
--                 principal exists). NO SECRET, NO VALUE, NO PLAINTEXT — but it is
--                 a record of who was calling, which is one reason old rows are
--                 pruned promptly rather than kept.
--   window_start  the fixed window this row budgets, truncated to the second.
--                 Truncation is load-bearing: replicas compute the boundary from
--                 their own clocks, and a sub-second disagreement would split one
--                 window into two rows and hand out the budget twice.
--   reserved      units of the window's budget claimed so far, across every
--                 replica. Clamped to the configured limit by the reserving
--                 statement, which is what makes "total spend <= limit" hold.
--   last_grant    the size of the most recent grant. SCRATCH, not history: it
--                 exists only because `INSERT ... ON CONFLICT DO UPDATE ...
--                 RETURNING` can return the new row but not the row as it was
--                 before, and a grant is exactly that difference.
--
-- THERE IS NO IMMUTABILITY TRIGGER HERE, unlike secret_versions and audit_log, and
-- the contrast is deliberate. Those tables are the record of what happened to the
-- secrets and must be unrewritable. This one is disposable infrastructure: it holds
-- no history anyone will ever audit, every row is worthless the moment its window
-- closes, and TRUNCATE at any instant costs exactly one window of per-replica
-- metering. Protecting it would imply it means something.
CREATE TABLE IF NOT EXISTS rate_limit_buckets (
    bucket_key   TEXT        NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    reserved     BIGINT      NOT NULL DEFAULT 0,
    last_grant   BIGINT      NOT NULL DEFAULT 0,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT pk_rate_limit_buckets PRIMARY KEY (bucket_key, window_start),
    CONSTRAINT chk_rate_limit_buckets_reserved CHECK (reserved >= 0),
    CONSTRAINT chk_rate_limit_buckets_last_grant CHECK (last_grant >= 0)
);

-- The primary key IS the reservation lookup (exact bucket_key + window_start), so
-- no further index serves the hot path. This one serves the pruner, which deletes
-- by window_start across every key and would otherwise scan the whole table on
-- every pass.
CREATE INDEX IF NOT EXISTS idx_rate_limit_buckets_window_start ON rate_limit_buckets (window_start);

-- +goose Down
DROP TABLE IF EXISTS rate_limit_buckets;
