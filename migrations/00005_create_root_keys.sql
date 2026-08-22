-- +goose Up
-- The KEK (root key) registry.
--
-- THE KEY MATERIAL IS NEVER STORED HERE. A store cannot unlock itself, so the
-- root key always arrives from outside the database — an env var, a sealed file
-- with 0600 permissions, or a cloud KMS that never hands the key over at all.
-- What this table records is only WHICH key wrapped WHAT, so that:
--
--   * a version can be decrypted at all — secret_versions.kek_id says which
--     provider to ask for the unwrap, and a store with three generations of root
--     key in play still knows which one applies to each row;
--   * a rewrap can find every affected version — rotating the root key means
--     re-wrapping DEKs, and the only way to enumerate the work (and to resume it
--     after a crash) is an indexed kek_id on the version rows pointing back here;
--   * retirement is provable — a key may only move to 'retired' when zero
--     versions still reference it, which is a COUNT against secret_versions, not
--     an operator's assertion.
--
-- kek_id is a stable fingerprint derived from the key material (provider name +
-- a truncated SHA-256 of the key), not a random id. That matters: restarting the
-- service with the same key must resolve to the same kek_id, or every restart
-- would orphan the rows the previous process wrote.
--
--   state   active   the key new writes wrap under. Exactly one, enforced below.
--           retiring superseded, still referenced by versions; a rewrap is due.
--           retired  no version references it; safe to decommission the material.
CREATE TABLE IF NOT EXISTS root_keys (
    kek_id       VARCHAR(64) PRIMARY KEY,
    provider     VARCHAR(20) NOT NULL,
    state        VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    activated_at TIMESTAMPTZ,
    retired_at   TIMESTAMPTZ,
    -- 'ephemeral' is a development-only provider: a randomly generated key that
    -- dies with the process. It is registered like any other so the FK from
    -- secret_versions holds and dev behaves structurally like production; outside
    -- APP_ENV=development the service refuses to boot with it (internal/crypto).
    CONSTRAINT chk_root_keys_provider CHECK (provider IN ('env', 'file', 'aws_kms', 'gcp_kms', 'azure_kv', 'ephemeral')),
    CONSTRAINT chk_root_keys_state CHECK (state IN ('active', 'retiring', 'retired'))
);

-- Exactly one active key. Two active KEKs would make "which key do new writes
-- wrap under" ambiguous, and the answer would differ per replica.
CREATE UNIQUE INDEX IF NOT EXISTS uq_root_keys_single_active ON root_keys (state) WHERE state = 'active';
CREATE INDEX IF NOT EXISTS idx_root_keys_state ON root_keys (state);
CREATE INDEX IF NOT EXISTS idx_root_keys_provider ON root_keys (provider);

-- +goose Down
DROP TABLE IF EXISTS root_keys;
