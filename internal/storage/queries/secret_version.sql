-- Secret versions: the encrypted payloads.
--
-- These are the only queries in the repo that touch ciphertext, and every one of
-- them is reached through a secret row that was already resolved tenant-scoped
-- (secret.sql). secret_id is therefore a capability: holding one means the tenant
-- check has already happened. Versions carry no tenant_id of their own for the
-- same reason a bank note carries no account number.

-- name: CreateSecretVersion :one
INSERT INTO secret_versions (secret_id, version, ciphertext, nonce, dek_wrapped, dek_nonce, kek_id, value_type, checksum)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING *;

-- name: GetLatestSecretVersion :one
SELECT * FROM secret_versions WHERE secret_id = $1 ORDER BY version DESC LIMIT 1;

-- name: GetSecretVersion :one
SELECT * FROM secret_versions WHERE secret_id = $1 AND version = $2;

-- GetLatestVersionChecksum answers "is this write actually a change?" without
-- decrypting anything, and without the root key being involved at all. That is the
-- whole reason checksum is a stored column.
-- name: GetLatestVersionChecksum :one
SELECT version, checksum FROM secret_versions WHERE secret_id = $1 ORDER BY version DESC LIMIT 1;

-- ListSecretVersionMeta deliberately omits ciphertext, nonce, dek_wrapped and
-- dek_nonce: version history is browsable metadata, not a bulk decryption
-- endpoint. Reading history must never be a way to pull every payload a secret has
-- ever held.
-- name: ListSecretVersionMeta :many
SELECT version_id, secret_id, version, kek_id, value_type, checksum, created_at
FROM secret_versions
WHERE secret_id = $1
ORDER BY version DESC
LIMIT $2 OFFSET $3;

-- name: CountSecretVersions :one
SELECT count(*) FROM secret_versions WHERE secret_id = $1;

-- GetSecretVersionValueType answers "is this secret a reference or a literal?" for
-- ONE secret, which is what the single-secret metadata paths (describe, a metadata
-- edit, a restore) need to fill SecretMeta.ValueType. The listing gets the same
-- column from its own LATERAL join (secret.sql) so it never runs this per row.
--
-- It selects value_type ALONE. A describe that fetched the version row and discarded
-- the payload would put ciphertext in a handler's locals for a metadata read, and
-- would make the "describe never reaches secret_versions' payload" property something
-- a reviewer has to trace rather than read.
-- name: GetSecretVersionValueType :one
SELECT value_type FROM secret_versions WHERE secret_id = $1 AND version = $2;

-- ListVersionWrapsByKEK is the rewrap work queue: every version still wrapped
-- under a given root key, oldest row first, in batches. It selects ONLY the
-- wrapping columns — a rewrap never reads or writes ciphertext, which is the
-- entire point of envelope encryption. Ordering by version_id with a limit is what
-- makes the rewrap resumable: a crashed rotation restarts by asking the same
-- question again, and rows already re-wrapped no longer match.
-- name: ListVersionWrapsByKEK :many
SELECT version_id, kek_id, dek_wrapped, dek_nonce FROM secret_versions
WHERE kek_id = $1
ORDER BY version_id
LIMIT $2;

-- CountVersionsByKEK is the retirement proof: a root key may only be retired when
-- this returns zero.
-- name: CountVersionsByKEK :one
SELECT count(*) FROM secret_versions WHERE kek_id = $1;

-- RewrapSecretVersion is the ONLY sanctioned UPDATE on this table. It requires the
-- maintainerd.allow_secret_version_rewrap GUC (see AllowSecretVersionRewrap) and
-- the trigger additionally verifies that ciphertext, nonce, version, checksum and
-- created_at came through untouched.
-- name: RewrapSecretVersion :execrows
UPDATE secret_versions
SET dek_wrapped = sqlc.arg(dek_wrapped),
    dek_nonce   = sqlc.arg(dek_nonce),
    kek_id      = sqlc.arg(kek_id)
WHERE version_id = sqlc.arg(version_id) AND kek_id = sqlc.arg(from_kek_id);

-- ListPrunableVersions returns the versions that fall outside retention, oldest
-- first. Two independent guards keep the current version out of the result: it is
-- excluded by name, and it is always inside the newest-N subquery because it is
-- always the highest version number. Retention pruning that ate the live value
-- would be a catastrophic bug, so it is prevented twice.
-- name: ListPrunableVersions :many
SELECT v.version_id, v.version FROM secret_versions v
WHERE v.secret_id = sqlc.arg(secret_id)
  AND v.version <> sqlc.arg(current_version)
  AND v.version NOT IN (
      SELECT keep.version FROM secret_versions keep
      WHERE keep.secret_id = sqlc.arg(secret_id)
      ORDER BY keep.version DESC
      LIMIT sqlc.arg(keep_versions))
ORDER BY v.version;

-- name: DeleteSecretVersion :execrows
DELETE FROM secret_versions WHERE version_id = $1;

-- AllowSecretVersionDelete sets the transaction-local GUC the append-only trigger
-- checks. Valid reasons: 'retention', 'secret_destroy', 'tenant_delete'. is_local
-- is true, so the permission dies with the transaction and cannot leak into the
-- next statement on a pooled connection — which is exactly why it must be called
-- inside an explicit transaction to have any effect at all.
-- name: AllowSecretVersionDelete :exec
SELECT set_config('maintainerd.allow_secret_version_delete', $1, true);

-- name: AllowSecretVersionRewrap :exec
SELECT set_config('maintainerd.allow_secret_version_rewrap', 'rewrap', true);
