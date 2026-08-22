-- Transit keys and their versions.
--
-- THE MATERIAL COLUMNS ARE SELECTED BY EXACTLY TWO QUERIES — the one that resolves
-- the version an Encrypt writes under, and the one that resolves the version a
-- Decrypt token names. Every listing and every metadata read goes through a *Meta
-- shape that does not select them at all, the same belt-and-braces rule the secret
-- listing and the webhook listing follow. A transit key's whole value proposition is
-- that the material never leaves the service; a listing query that selected it would
-- be one JSON marshal away from ending that.

-- name: CreateTransitKey :one
INSERT INTO transit_keys (
    tenant_id, project_id, name, description, status, min_decrypt_version, metadata
) VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: GetTransitKeyByName :one
SELECT * FROM transit_keys
WHERE tenant_id = sqlc.arg(tenant_id)
  AND project_id = sqlc.arg(project_id)
  AND name = sqlc.arg(name)
  AND deleted_at IS NULL;

-- GetTransitKeyByNameForUpdate takes a row lock for the rotate path. Two concurrent
-- rotations would otherwise both read the same current_version and the second would
-- collide on uq_transit_key_versions_key_version — the same race
-- GetSecretByAddressForUpdate exists to serialize.
-- name: GetTransitKeyByNameForUpdate :one
SELECT * FROM transit_keys
WHERE tenant_id = sqlc.arg(tenant_id)
  AND project_id = sqlc.arg(project_id)
  AND name = sqlc.arg(name)
  AND deleted_at IS NULL
FOR UPDATE;

-- name: ListTransitKeyMetaByProject :many
SELECT key_uuid, project_id, name, description, current_version, status,
       min_decrypt_version, created_at, updated_at
FROM transit_keys
WHERE tenant_id = sqlc.arg(tenant_id)
  AND project_id = sqlc.arg(project_id)
  AND deleted_at IS NULL
ORDER BY name
LIMIT sqlc.arg(row_limit) OFFSET sqlc.arg(row_offset);

-- name: CountTransitKeysByProject :one
SELECT count(*) FROM transit_keys
WHERE tenant_id = sqlc.arg(tenant_id) AND project_id = sqlc.arg(project_id) AND deleted_at IS NULL;

-- name: UpdateTransitKey :one
UPDATE transit_keys
SET description         = sqlc.arg(description),
    status              = sqlc.arg(status),
    min_decrypt_version = sqlc.arg(min_decrypt_version),
    updated_at          = now()
WHERE tenant_id = sqlc.arg(tenant_id)
  AND key_uuid = sqlc.arg(key_uuid)
  AND deleted_at IS NULL
RETURNING *;

-- SetTransitKeyCurrentVersion publishes a newly created key version. current_version
-- only ever moves forward, for the reason secrets.current_version does: a version
-- number that could be reused would make a stored token ambiguous.
-- name: SetTransitKeyCurrentVersion :one
UPDATE transit_keys
SET current_version = sqlc.arg(current_version),
    updated_at      = now()
WHERE tenant_id = sqlc.arg(tenant_id)
  AND key_id = sqlc.arg(key_id)
  AND deleted_at IS NULL
  AND current_version < sqlc.arg(current_version)
RETURNING *;

-- name: SoftDeleteTransitKey :execrows
UPDATE transit_keys SET deleted_at = now(), updated_at = now()
WHERE tenant_id = sqlc.arg(tenant_id)
  AND key_uuid = sqlc.arg(key_uuid)
  AND deleted_at IS NULL;

-- name: CreateTransitKeyVersion :one
INSERT INTO transit_key_versions (
    key_id, version, material_ciphertext, material_nonce,
    material_dek_wrapped, material_dek_nonce, kek_id
) VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- GetTransitKeyVersion is one of the two queries that select material. It takes an
-- explicit version because a DECRYPT must open the version the TOKEN names, not the
-- current one — that is the whole reason a token carries its key version.
-- name: GetTransitKeyVersion :one
SELECT * FROM transit_key_versions WHERE key_id = $1 AND version = $2;

-- name: GetLatestTransitKeyVersion :one
SELECT * FROM transit_key_versions WHERE key_id = $1 ORDER BY version DESC LIMIT 1;

-- ListTransitKeyVersionMeta omits every material column: version history is
-- browsable metadata, never a way to enumerate key material.
-- name: ListTransitKeyVersionMeta :many
SELECT version_id, key_id, version, kek_id, created_at
FROM transit_key_versions
WHERE key_id = $1
ORDER BY version DESC
LIMIT $2 OFFSET $3;

-- name: CountTransitKeyVersions :one
SELECT count(*) FROM transit_key_versions WHERE key_id = $1;

-- ListTransitVersionWrapsByKEK is the rewrap work queue, the transit twin of
-- ListVersionWrapsByKEK. It selects ONLY the wrapping columns — a rewrap never reads
-- key material, which is the entire point of wrapping it in the first place.
-- name: ListTransitVersionWrapsByKEK :many
SELECT version_id, kek_id, material_dek_wrapped, material_dek_nonce
FROM transit_key_versions
WHERE kek_id = $1
ORDER BY version_id
LIMIT $2;

-- CountTransitVersionsByKEK is half of the retirement proof. A root key may only be
-- retired when NO secret version AND no transit key version references it; retiring
-- one that a transit version still points at would make that key's ciphertexts
-- permanently undecryptable while every secret read kept working, which is the worst
-- kind of partial failure — invisible until the application needs its data.
-- name: CountTransitVersionsByKEK :one
SELECT count(*) FROM transit_key_versions WHERE kek_id = $1;

-- RewrapTransitKeyVersion is the ONLY sanctioned UPDATE on this table. It requires the
-- maintainerd.allow_transit_version_rewrap GUC and the trigger additionally verifies
-- that the material ciphertext, nonce, version and created_at came through untouched.
-- name: RewrapTransitKeyVersion :execrows
UPDATE transit_key_versions
SET material_dek_wrapped = sqlc.arg(material_dek_wrapped),
    material_dek_nonce   = sqlc.arg(material_dek_nonce),
    kek_id               = sqlc.arg(kek_id)
WHERE version_id = sqlc.arg(version_id) AND kek_id = sqlc.arg(from_kek_id);

-- AllowTransitVersionRewrap sets the transaction-local GUC the append-only trigger
-- checks. is_local is true, so the permission dies with the transaction and cannot
-- leak into the next statement on a pooled connection — which is why it only has any
-- effect inside an explicit transaction.
-- name: AllowTransitVersionRewrap :exec
SELECT set_config('maintainerd.allow_transit_version_rewrap', 'rewrap', true);

-- name: AllowTransitVersionDelete :exec
SELECT set_config('maintainerd.allow_transit_version_delete', $1, true);
