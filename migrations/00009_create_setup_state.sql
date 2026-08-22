-- +goose Up
-- The durable one-shot setup lock.
--
-- This table exists to fix a specific bug. The prototype held the setup lock in
-- process memory (kit setup.Mode), so the one-time setup window REOPENED on every
-- restart — and with an empty SETUP_BOOTSTRAP_TOKEN it reopened unauthenticated.
-- A crash loop was therefore an unbounded series of chances to register as
-- controller of the vault. A one-shot lock has to be derived from a stored fact,
-- not from whether this particular process has seen a Setup call yet.
--
-- Single row by construction (id = 1 with a CHECK). The row's existence with a
-- non-NULL completed_at IS the lock: it is visible to every replica, it survives
-- restarts, and the primary key settles a race between two concurrent setup calls
-- rather than leaving both to succeed.
--
--   controller       the identity that completed setup (Core's service subject in
--                    ecosystem-attached mode; an operator in standalone mode).
--   controller_kind  service | operator — which of the two modes this install is
--                    in, recorded at setup rather than inferred later from config
--                    that may since have changed.
CREATE TABLE IF NOT EXISTS setup_state (
    id              INT PRIMARY KEY DEFAULT 1,
    completed_at    TIMESTAMPTZ,
    controller      VARCHAR(255) NOT NULL DEFAULT '',
    controller_kind VARCHAR(20) NOT NULL DEFAULT '',
    metadata        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_setup_state_singleton CHECK (id = 1),
    CONSTRAINT chk_setup_state_controller_kind CHECK (controller_kind IN ('', 'service', 'operator')),
    -- Completion and a controller arrive together or not at all; a completed lock
    -- with no recorded controller would be a lock nobody can be held to.
    CONSTRAINT chk_setup_state_completed CHECK (
        (completed_at IS NULL AND controller = '' AND controller_kind = '')
        OR (completed_at IS NOT NULL AND controller <> '' AND controller_kind <> '')
    )
);

-- +goose Down
DROP TABLE IF EXISTS setup_state;
