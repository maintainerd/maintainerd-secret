-- +goose Up
-- TRANSIT: encryption as a service. The caller sends plaintext and receives a
-- ciphertext token; the key never leaves this service.
--
-- WHAT PROBLEM IT SOLVES. An application that needs to encrypt a column — a national
-- id, a bank account, a medical note — has to hold a key to do it. Once it does, the
-- key is in that application's memory, its config, its crash dumps and its container
-- image, and every service that needs to decrypt gets a copy. Transit inverts that:
-- the application holds no key at all, calls Encrypt/Decrypt, and the key material
-- exists only inside this service, wrapped by the root key, rotatable without the
-- application knowing.
--
-- THERE IS NO EXPORT OPERATION, DELIBERATELY. See the package doc in
-- internal/transit: an exportable key is an ordinary secret with extra steps, and the
-- entire security argument for transit is that possession of the key is not
-- transferable.
--
-- KEY MATERIAL IS SEALED EXACTLY LIKE A SECRET VERSION. The same five columns
-- (ciphertext, nonce, wrapped DEK, DEK nonce, kek_id) with the AAD identity bound to
-- (tenant_uuid, key_uuid, version). That is not a stylistic echo — it is what makes
-- root-key rotation and crypto.RewrapAll cover transit keys with no new machinery,
-- and it gives the same anti-replay property: a material ciphertext moved between
-- key-version rows fails authentication.
CREATE TABLE IF NOT EXISTS transit_keys (
    key_id          BIGSERIAL PRIMARY KEY,
    key_uuid        UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    tenant_id       BIGINT NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    -- Per PROJECT, for the same ownership reason webhook endpoints and dynamic roles
    -- are: a key is a capability, and a tenant-wide one would let one team decrypt
    -- another team's data.
    project_id      BIGINT NOT NULL REFERENCES projects (project_id) ON DELETE CASCADE,
    -- The name a caller encrypts against. It travels INSIDE the ciphertext token, so
    -- it is bounded to a slug: a name that could contain the token's delimiter would
    -- be a way to forge a token that decrypts under a different key.
    name            VARCHAR(63) NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    -- The version new Encrypt calls use. Rotation increments it; OLD VERSIONS ARE
    -- KEPT AND STILL DECRYPT, which is the entire point of versioning a transit key
    -- — rotating a key that could no longer read its own history would make every
    -- stored ciphertext in the calling application unreadable.
    current_version INT NOT NULL DEFAULT 0,
    status          VARCHAR(20) NOT NULL DEFAULT 'active',
    -- min_decrypt_version lets an operator retire compromised material WITHOUT
    -- deleting it: a token under a version below this floor is refused. Deleting the
    -- version row instead would be irreversible and would take the honest historical
    -- ciphertexts with it.
    min_decrypt_version INT NOT NULL DEFAULT 1,
    metadata        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at      TIMESTAMPTZ,
    CONSTRAINT chk_transit_keys_status CHECK (status IN ('active', 'disabled')),
    CONSTRAINT chk_transit_keys_current_version CHECK (current_version >= 0),
    CONSTRAINT chk_transit_keys_min_decrypt_version CHECK (min_decrypt_version >= 1)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_transit_keys_project_name
    ON transit_keys (project_id, name) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_transit_keys_tenant_id ON transit_keys (tenant_id);
CREATE INDEX IF NOT EXISTS idx_transit_keys_deleted_at ON transit_keys (deleted_at) WHERE deleted_at IS NULL;

-- One row per key version: the sealed key material and nothing else.
CREATE TABLE IF NOT EXISTS transit_key_versions (
    version_id      BIGSERIAL PRIMARY KEY,
    key_id          BIGINT NOT NULL REFERENCES transit_keys (key_id) ON DELETE CASCADE,
    version         INT NOT NULL,
    material_ciphertext  BYTEA NOT NULL,
    material_nonce       BYTEA NOT NULL,
    material_dek_wrapped BYTEA NOT NULL,
    material_dek_nonce   BYTEA NOT NULL,
    -- RESTRICT, not CASCADE: dropping a root key row while versions still reference
    -- it would make them permanently unreadable. A root key leaves only after a
    -- rewrap has proved nothing points at it.
    kek_id          VARCHAR(64) NOT NULL REFERENCES root_keys (kek_id) ON DELETE RESTRICT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_transit_key_versions_version CHECK (version >= 1)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_transit_key_versions_key_version
    ON transit_key_versions (key_id, version);
CREATE INDEX IF NOT EXISTS idx_transit_key_versions_kek_id ON transit_key_versions (kek_id);

-- +goose StatementBegin
-- APPEND-ONLY, enforced exactly as secret_versions is (migration 00007), because the
-- failure it prevents is the same one and is worse here. A transit key version whose
-- material could be UPDATED is a key that can be swapped underneath every token that
-- references it: the calling application's stored ciphertexts become undecryptable,
-- silently, with no way to tell whether the data was destroyed or was never there.
--
-- The one sanctioned UPDATE is a root-key rewrap, and both halves are checked rather
-- than either alone: the transaction-local GUC proves the caller intended a rewrap,
-- and the column comparison proves the material actually survived it.
CREATE OR REPLACE FUNCTION prevent_transit_key_version_mutation() RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF COALESCE(current_setting('maintainerd.allow_transit_version_rewrap', true), '') <> 'rewrap' THEN
            RAISE EXCEPTION 'transit_key_versions rows are immutable and cannot be updated';
        END IF;
        IF NEW.version_id <> OLD.version_id
           OR NEW.key_id <> OLD.key_id
           OR NEW.version <> OLD.version
           OR NEW.material_ciphertext <> OLD.material_ciphertext
           OR NEW.material_nonce <> OLD.material_nonce
           OR NEW.created_at <> OLD.created_at THEN
            RAISE EXCEPTION 'a transit key rewrap may only change material_dek_wrapped, material_dek_nonce and kek_id';
        END IF;
        RETURN NEW;
    END IF;

    -- DELETE is permitted only for sanctioned lifecycle operations. 'tenant_delete'
    -- matters because ON DELETE CASCADE from tenants routes through this trigger:
    -- without the exemption a tenant purge would raise here and roll back, making
    -- erasure impossible.
    IF TG_OP = 'DELETE'
       AND COALESCE(current_setting('maintainerd.allow_transit_version_delete', true), '') NOT IN ('key_destroy', 'tenant_delete') THEN
        RAISE EXCEPTION 'transit_key_versions rows are append-only and may only be deleted by a sanctioned key destruction or tenant deletion';
    END IF;

    RETURN OLD;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

DROP TRIGGER IF EXISTS trg_transit_key_versions_immutable ON transit_key_versions;
CREATE TRIGGER trg_transit_key_versions_immutable
    BEFORE UPDATE OR DELETE ON transit_key_versions
    FOR EACH ROW EXECUTE FUNCTION prevent_transit_key_version_mutation();

-- +goose Down
DROP TRIGGER IF EXISTS trg_transit_key_versions_immutable ON transit_key_versions;
DROP FUNCTION IF EXISTS prevent_transit_key_version_mutation();
DROP TABLE IF EXISTS transit_key_versions;
DROP TABLE IF EXISTS transit_keys;
