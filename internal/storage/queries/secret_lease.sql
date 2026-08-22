-- Read leases on static secrets.
--
-- The policy lives on `secrets` (lease_ttl_seconds, lease_max_ttl_seconds,
-- lease_max_reads — see secret.sql's SetSecretLeasePolicy); these queries manage the
-- leases actually issued against it.
--
-- THE CONSUME PATH IS A LOCK, A DECISION, AND AN UPDATE, in that order, inside one
-- transaction. Anything looser is a bypass: two concurrent reveals that both read
-- reads_used = 9 against a cap of 10 would both be served, which is precisely the
-- exfiltration pattern the cap exists to refuse.

-- GetLiveSecretLeaseForUpdate takes the caller's current lease under a row lock. NULL
-- rows (no lease yet) come back as pgx.ErrNoRows, which the service reads as "issue
-- one".
-- name: GetLiveSecretLeaseForUpdate :one
SELECT * FROM secret_leases
WHERE tenant_id = sqlc.arg(tenant_id)
  AND secret_id = sqlc.arg(secret_id)
  AND requester = sqlc.arg(requester)
  AND revoked_at IS NULL
FOR UPDATE;

-- name: CreateSecretLease :one
INSERT INTO secret_leases (
    tenant_id, secret_id, resource_mrn, requester, requester_kind, expires_at, max_reads
) VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- ConsumeSecretLease records one read against a lease.
--
-- THE CAP IS IN THE WHERE CLAUSE, not only in the service. reads_used < max_reads is
-- re-checked by the database under the row lock the caller already holds, so a service
-- path that forgot to check — or a future second caller of this query — still cannot
-- take a read past the limit. Zero rows returned means "refused", and the service maps
-- that to the precise error rather than serving the value.
-- name: ConsumeSecretLease :execrows
UPDATE secret_leases
SET reads_used   = reads_used + 1,
    last_read_at = now(),
    updated_at   = now()
WHERE lease_id = sqlc.arg(lease_id)
  AND revoked_at IS NULL
  AND expires_at > now()
  AND (max_reads IS NULL OR reads_used < max_reads);

-- name: RevokeSecretLease :execrows
UPDATE secret_leases
SET revoked_at    = now(),
    revoke_reason = sqlc.arg(revoke_reason),
    updated_at    = now()
WHERE lease_id = sqlc.arg(lease_id) AND revoked_at IS NULL;

-- RevokeSecretLeasesForSecret closes every outstanding lease on one secret. Used when
-- the lease policy is removed (the leases it governed no longer mean anything) and
-- when the secret is deleted.
-- name: RevokeSecretLeasesForSecret :execrows
UPDATE secret_leases
SET revoked_at    = now(),
    revoke_reason = sqlc.arg(revoke_reason),
    updated_at    = now()
WHERE tenant_id = sqlc.arg(tenant_id) AND secret_id = sqlc.arg(secret_id) AND revoked_at IS NULL;

-- name: ListSecretLeases :many
SELECT lease_uuid, secret_id, resource_mrn, requester, requester_kind,
       issued_at, expires_at, max_reads, reads_used, last_read_at,
       revoked_at, revoke_reason
FROM secret_leases
WHERE tenant_id = sqlc.arg(tenant_id) AND secret_id = sqlc.arg(secret_id)
ORDER BY created_at DESC
LIMIT sqlc.arg(row_limit) OFFSET sqlc.arg(row_offset);

-- name: CountSecretLeases :one
SELECT count(*) FROM secret_leases
WHERE tenant_id = sqlc.arg(tenant_id) AND secret_id = sqlc.arg(secret_id);

-- ExpireDueSecretLeases retires leases whose TTL has run out, in bulk. now() is the
-- DATABASE's: a skewed process clock must not be able to expire a lease early or keep
-- a dead one alive. This is housekeeping rather than enforcement — the consume path
-- already refuses an expired lease on its own — so it is safe to run on a timer and
-- safe to skip.
-- name: ExpireDueSecretLeases :execrows
UPDATE secret_leases
SET revoked_at    = now(),
    revoke_reason = 'expired',
    updated_at    = now()
WHERE lease_id IN (
    SELECT lease_id FROM secret_leases
    WHERE revoked_at IS NULL AND expires_at <= now()
    ORDER BY expires_at
    LIMIT sqlc.arg(row_limit)
);
