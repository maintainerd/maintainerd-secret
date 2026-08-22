-- The KEK registry. No key material passes through these queries — only the
-- fingerprint that says which key wrapped what.

-- MarkOtherRootKeysRetiring must run BEFORE UpsertActiveRootKey in the same
-- transaction. uq_root_keys_single_active permits exactly one 'active' row, so
-- activating a new key without demoting the old one is a constraint violation, not
-- a silent overwrite. 'retiring' rather than 'retired' because versions still
-- reference the old key until a rewrap completes.
-- name: MarkOtherRootKeysRetiring :execrows
UPDATE root_keys SET state = 'retiring' WHERE state = 'active' AND kek_id <> $1;

-- name: UpsertActiveRootKey :one
INSERT INTO root_keys (kek_id, provider, state, activated_at)
VALUES ($1, $2, 'active', now())
ON CONFLICT (kek_id) DO UPDATE
   SET state        = 'active',
       provider     = EXCLUDED.provider,
       activated_at = COALESCE(root_keys.activated_at, now()),
       retired_at   = NULL
RETURNING *;

-- name: GetRootKey :one
SELECT * FROM root_keys WHERE kek_id = $1;

-- name: GetActiveRootKey :one
SELECT * FROM root_keys WHERE state = 'active';

-- name: ListRootKeys :many
SELECT * FROM root_keys ORDER BY created_at;

-- name: ListRootKeysByState :many
SELECT * FROM root_keys WHERE state = $1 ORDER BY created_at;

-- RetireRootKey refuses the active key: `state <> 'active'` is in the WHERE clause,
-- so retiring the key that new writes depend on is not expressible. The caller must
-- also have proved that no version references it (CountVersionsByKEK = 0) —
-- retiring a still-referenced key would leave rows that can never be decrypted.
-- name: RetireRootKey :execrows
UPDATE root_keys SET state = 'retired', retired_at = now()
WHERE kek_id = $1 AND state <> 'active';
