-- +goose Up
-- The immutable encrypted payload. One row per write; a write never mutates a
-- previous row. This is what makes get-by-version, rollback, and "what did this
-- credential used to be" answerable, and it is why the value columns live here
-- rather than on secrets.
--
-- ENVELOPE ENCRYPTION. Each version carries its own data encryption key:
--
--   ciphertext   the plaintext sealed with AES-256-GCM under this version's DEK.
--   nonce        the 12-byte GCM nonce for that seal. Per-version and random —
--                never derived, never reused, because GCM nonce reuse under the
--                same key is a total break.
--   dek_wrapped  the 32-byte DEK, itself sealed under the root key (KEK).
--   dek_nonce    the GCM nonce for the DEK wrap.
--   kek_id       which registered root key performed that wrap (FK to root_keys).
--
-- The payoff is rotation: changing the root key re-wraps dek_wrapped (a few dozen
-- bytes per row) and leaves ciphertext untouched. A vault with a terabyte of
-- secrets rotates its root of trust without re-encrypting a terabyte. The FK is
-- ON DELETE RESTRICT precisely so a root key cannot be removed from the registry
-- while rows still depend on it — that would be unrecoverable data loss.
--
--   value_type   how a consumer should interpret the plaintext once decrypted.
--                'reference' is the template-parameter case: the plaintext is a
--                pointer to another secret, not a credential.
--   checksum     SHA-256 of the PLAINTEXT. Stored so two questions can be answered
--                without decrypting anything: is this row still intact, and is an
--                incoming write actually a change? The second is what stops a
--                rotation job that re-submits the same value from inflating version
--                history forever (see internal/store no-op detection). A hash of
--                the plaintext is safe to store: the values here are
--                high-entropy credentials, and the checksum is never returned to
--                an unauthorized caller.
CREATE TABLE IF NOT EXISTS secret_versions (
    version_id  BIGSERIAL PRIMARY KEY,
    secret_id   BIGINT NOT NULL REFERENCES secrets (secret_id) ON DELETE CASCADE,
    version     INT NOT NULL,
    ciphertext  BYTEA NOT NULL,
    nonce       BYTEA NOT NULL,
    dek_wrapped BYTEA NOT NULL,
    dek_nonce   BYTEA NOT NULL,
    kek_id      VARCHAR(64) NOT NULL REFERENCES root_keys (kek_id) ON DELETE RESTRICT,
    value_type  VARCHAR(20) NOT NULL DEFAULT 'opaque',
    checksum    BYTEA,
    created_by  BIGINT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_secret_versions_secret_version UNIQUE (secret_id, version),
    CONSTRAINT chk_secret_versions_value_type CHECK (value_type IN ('opaque', 'json', 'reference')),
    CONSTRAINT chk_secret_versions_version CHECK (version > 0)
);

-- +goose StatementBegin
-- Append-only enforcement, following the immutability-trigger pattern Auth uses
-- for management_audit_log (auth migration 057). The database, not the
-- application, is the thing that guarantees history cannot be rewritten: a bug, a
-- stray migration, or a compromised service account all hit this wall.
CREATE OR REPLACE FUNCTION prevent_secret_version_mutation() RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        -- There is exactly ONE sanctioned update: a root-key rewrap. It is
        -- permitted because envelope encryption exists so that rotating the KEK
        -- never rewrites a payload — the rewrap replaces the wrapped DEK and
        -- nothing else. Both halves are checked rather than trusting either
        -- alone: the transaction-local GUC proves the caller intended a rewrap,
        -- and the column comparison proves the payload actually survived it. An
        -- UPDATE that sets the GUC but also edits ciphertext still fails.
        IF COALESCE(current_setting('maintainerd.allow_secret_version_rewrap', true), '') <> 'rewrap' THEN
            RAISE EXCEPTION 'secret_versions rows are immutable and cannot be updated';
        END IF;
        IF NEW.version_id  <> OLD.version_id
           OR NEW.secret_id <> OLD.secret_id
           OR NEW.version   <> OLD.version
           OR NEW.ciphertext <> OLD.ciphertext
           OR NEW.nonce      <> OLD.nonce
           OR NEW.value_type <> OLD.value_type
           OR NEW.checksum   IS DISTINCT FROM OLD.checksum
           OR NEW.created_by IS DISTINCT FROM OLD.created_by
           OR NEW.created_at <> OLD.created_at THEN
            RAISE EXCEPTION 'secret_versions rewrap may only change dek_wrapped, dek_nonce and kek_id';
        END IF;
        RETURN NEW;
    END IF;

    -- DELETE is permitted only for sanctioned lifecycle operations, signalled by
    -- a transaction-local GUC:
    --   retention       version-retention pruning (KeepVersions)
    --   secret_destroy  hard destruction of a secret past its recovery window
    --   tenant_delete   full tenant erasure
    -- The last two matter because ON DELETE CASCADE from secrets and tenants
    -- routes through this trigger: without the exemption a tenant purge would
    -- raise here and roll the whole transaction back, making purge impossible.
    IF TG_OP = 'DELETE'
       AND COALESCE(current_setting('maintainerd.allow_secret_version_delete', true), '') NOT IN ('retention', 'secret_destroy', 'tenant_delete') THEN
        RAISE EXCEPTION 'secret_versions rows are append-only and may only be deleted by retention, secret destruction or tenant deletion';
    END IF;

    RETURN OLD;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

DROP TRIGGER IF EXISTS trg_secret_versions_immutable ON secret_versions;
CREATE TRIGGER trg_secret_versions_immutable
    BEFORE UPDATE OR DELETE ON secret_versions
    FOR EACH ROW EXECUTE FUNCTION prevent_secret_version_mutation();

-- The hot read: the newest version of a secret.
CREATE INDEX IF NOT EXISTS idx_secret_versions_secret_version ON secret_versions (secret_id, version DESC);
-- The rewrap read: every version still wrapped under a superseded root key. This
-- index is what makes a rotation enumerable and resumable.
CREATE INDEX IF NOT EXISTS idx_secret_versions_kek_id ON secret_versions (kek_id);
CREATE INDEX IF NOT EXISTS idx_secret_versions_created_at ON secret_versions (created_at);

-- +goose Down
DROP TRIGGER IF EXISTS trg_secret_versions_immutable ON secret_versions;
DROP FUNCTION IF EXISTS prevent_secret_version_mutation();
DROP TABLE IF EXISTS secret_versions;
