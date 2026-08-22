-- Webhook endpoints and their delivery log.
--
-- The signing-key columns are selected explicitly nowhere except the two reads
-- that actually need to sign a delivery. Everything a console or an API response
-- renders goes through the *Meta shapes below, which do not select the key at all —
-- the same belt-and-braces rule the secret listing follows.

-- CreateWebhookEndpoint takes endpoint_uuid from the CALLER rather than letting the
-- column default supply it. That is not a style preference: the signing key is
-- sealed with the endpoint's UUID bound in as additional authenticated data (so a
-- ciphertext moved between endpoint rows fails to open), and AAD has to be known
-- before the seal — which is before the INSERT. A DB-generated UUID would force
-- either an insert-then-update dance or an AAD that binds nothing row-specific.
-- name: CreateWebhookEndpoint :one
INSERT INTO webhook_endpoints (
    endpoint_uuid, tenant_id, project_id, url, description,
    secret_ciphertext, secret_nonce, secret_dek_wrapped, secret_dek_nonce, kek_id,
    events, status, timeout_seconds, max_attempts, metadata
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
RETURNING *;

-- name: GetWebhookEndpointByUUID :one
SELECT * FROM webhook_endpoints
WHERE tenant_id = sqlc.arg(tenant_id)
  AND endpoint_uuid = sqlc.arg(endpoint_uuid)
  AND deleted_at IS NULL;

-- ListWebhookEndpointMetaByProject is the API/console read. The select list omits
-- every signing-key column: an endpoint listing must never be a way to obtain the
-- key that authenticates deliveries to that endpoint.
-- name: ListWebhookEndpointMetaByProject :many
SELECT endpoint_uuid, project_id, url, description, events, status,
       timeout_seconds, max_attempts, last_triggered_at, created_at, updated_at
FROM webhook_endpoints
WHERE tenant_id = sqlc.arg(tenant_id)
  AND project_id = sqlc.arg(project_id)
  AND deleted_at IS NULL
ORDER BY created_at
LIMIT sqlc.arg(row_limit) OFFSET sqlc.arg(row_offset);

-- name: CountWebhookEndpointsByProject :one
SELECT count(*) FROM webhook_endpoints
WHERE tenant_id = sqlc.arg(tenant_id) AND project_id = sqlc.arg(project_id) AND deleted_at IS NULL;

-- ListActiveWebhookEndpointsByProject IS the delivery read, so it does select the
-- wrapped signing key — the notifier needs it to compute the HMAC.
-- name: ListActiveWebhookEndpointsByProject :many
SELECT * FROM webhook_endpoints
WHERE tenant_id = sqlc.arg(tenant_id)
  AND project_id = sqlc.arg(project_id)
  AND deleted_at IS NULL
  AND status = 'active'
ORDER BY endpoint_id;

-- name: UpdateWebhookEndpoint :one
UPDATE webhook_endpoints
SET url             = sqlc.arg(url),
    description     = sqlc.arg(description),
    events          = sqlc.arg(events),
    status          = sqlc.arg(status),
    timeout_seconds = sqlc.arg(timeout_seconds),
    max_attempts    = sqlc.arg(max_attempts),
    updated_at      = now()
WHERE tenant_id = sqlc.arg(tenant_id)
  AND endpoint_uuid = sqlc.arg(endpoint_uuid)
  AND deleted_at IS NULL
RETURNING *;

-- name: TouchWebhookEndpoint :execrows
UPDATE webhook_endpoints SET last_triggered_at = now(), updated_at = now()
WHERE endpoint_id = sqlc.arg(endpoint_id);

-- name: SoftDeleteWebhookEndpoint :execrows
UPDATE webhook_endpoints SET deleted_at = now(), updated_at = now()
WHERE tenant_id = sqlc.arg(tenant_id)
  AND endpoint_uuid = sqlc.arg(endpoint_uuid)
  AND deleted_at IS NULL;

-- name: CreateWebhookDelivery :one
INSERT INTO webhook_deliveries (
    endpoint_id, tenant_id, event_type, resource_mrn, version, payload
) VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- FinishWebhookDelivery records the outcome of the INLINE attempt sequence.
--
-- next_attempt_at is set (to a time a few seconds out) when the status is 'retrying'
-- and NULL otherwise, which is what hands the row to the re-drive worker. The column
-- check on the table refuses a schedule on a terminal row, so a caller that sets one
-- with status 'success' gets a constraint violation rather than a duplicate delivery.
-- name: FinishWebhookDelivery :one
UPDATE webhook_deliveries
SET attempt_count   = sqlc.arg(attempt_count),
    status          = sqlc.arg(status),
    response_status = sqlc.arg(response_status),
    error           = sqlc.arg(error),
    next_attempt_at = sqlc.narg(next_attempt_at),
    updated_at      = now()
WHERE delivery_id = sqlc.arg(delivery_id)
RETURNING *;

-- GetSignedWebhookEndpointByID is the RE-DRIVE read: a retry has a delivery row and
-- therefore an endpoint_id, never a UUID the caller supplied, so it cannot go through
-- GetWebhookEndpointByUUID.
--
-- It selects the signing-key columns, like ListActiveWebhookEndpointsByProject and
-- for the same reason — a retry has to compute the same HMAC — and it joins tenants
-- for tenant_uuid, which is the AAD the key was sealed under.
--
-- deleted_at IS NULL is load-bearing rather than tidiness: an endpoint deleted while
-- a delivery sat in the backlog must NOT be retried, and a missing row here is how
-- the worker learns to abandon it. `status` is deliberately NOT filtered — a delivery
-- already recorded against an endpoint an operator has since DISABLED is finished
-- rather than dropped, because disabling stops new events, not the acknowledgement of
-- one already announced.
-- name: GetSignedWebhookEndpointByID :one
SELECT e.*, t.tenant_uuid
FROM webhook_endpoints e
JOIN tenants t ON t.tenant_id = e.tenant_id
WHERE e.endpoint_id = sqlc.arg(endpoint_id) AND e.deleted_at IS NULL;

-- ClaimWebhookDeliveriesForRedrive takes ownership of a batch of due deliveries.
--
-- FOR UPDATE SKIP LOCKED is what makes this worker SAFE IN EVERY REPLICA with no
-- leader election: two workers racing the same tick take disjoint batches, because a
-- row another transaction has locked is skipped rather than waited on. A plain
-- SELECT-then-UPDATE would let both claim the same delivery and double-post it to a
-- customer's endpoint.
--
-- THE UPDATE PUSHES next_attempt_at FORWARD BY A VISIBILITY LEASE before the attempt
-- is made. That is the crash-safety half: if this process dies between the claim and
-- the outcome, nothing has to notice — the row simply becomes due again when the
-- lease expires. It also means the lease must be comfortably longer than one
-- attempt's timeout, or a slow receiver produces a concurrent second attempt.
--
-- The counters are NOT touched here. attempt_count and redrive_attempts move on
-- RecordWebhookRedriveOutcome, so a claim that never completes costs no budget.
-- name: ClaimWebhookDeliveriesForRedrive :many
WITH due AS (
    SELECT delivery_id FROM webhook_deliveries
    WHERE status = 'retrying'
      AND next_attempt_at IS NOT NULL
      AND next_attempt_at <= now()
    ORDER BY next_attempt_at
    LIMIT sqlc.arg(row_limit)
    FOR UPDATE SKIP LOCKED
)
UPDATE webhook_deliveries d
SET next_attempt_at = now() + make_interval(secs => sqlc.arg(lease_seconds)::int),
    updated_at      = now()
FROM due
WHERE d.delivery_id = due.delivery_id
RETURNING d.delivery_id, d.delivery_uuid, d.endpoint_id, d.tenant_id, d.event_type,
          d.resource_mrn, d.version, d.attempt_count, d.redrive_attempts, d.payload;

-- RecordWebhookRedriveOutcome records what one WORKER attempt did.
--
-- Both counters advance together: attempt_count is the total an operator reads,
-- redrive_attempts is the durable budget the worker spends. next_attempt_at carries
-- the next backoff on 'retrying' and is NULL on either terminal status, which the
-- table's CHECK enforces.
-- name: RecordWebhookRedriveOutcome :execrows
UPDATE webhook_deliveries
SET attempt_count    = attempt_count + 1,
    redrive_attempts = redrive_attempts + 1,
    status           = sqlc.arg(status),
    response_status  = sqlc.arg(response_status),
    error            = sqlc.arg(error),
    next_attempt_at  = sqlc.narg(next_attempt_at),
    updated_at       = now()
WHERE delivery_id = sqlc.arg(delivery_id);

-- AbandonWebhookDelivery marks a delivery permanently failed WITHOUT spending an
-- attempt, for the case where there is nothing left to attempt against: the endpoint
-- has been deleted. Recording it as an attempt would claim we posted somewhere.
-- name: AbandonWebhookDelivery :execrows
UPDATE webhook_deliveries
SET status          = 'failed',
    error           = sqlc.arg(error),
    next_attempt_at = NULL,
    updated_at      = now()
WHERE delivery_id = sqlc.arg(delivery_id);

-- CountWebhookDeliveriesAwaitingRedrive is the backlog depth, for the worker's log
-- line. An operator watching a receiver come back up wants one number, and a growing
-- one is the signal that the budget is being spent faster than deliveries succeed.
-- name: CountWebhookDeliveriesAwaitingRedrive :one
SELECT count(*) FROM webhook_deliveries WHERE status = 'retrying';

-- name: ListWebhookDeliveriesByEndpoint :many
SELECT * FROM webhook_deliveries
WHERE tenant_id = sqlc.arg(tenant_id)
  AND endpoint_id = sqlc.arg(endpoint_id)
ORDER BY created_at DESC
LIMIT sqlc.arg(row_limit) OFFSET sqlc.arg(row_offset);

-- name: CountWebhookDeliveriesByEndpoint :one
SELECT count(*) FROM webhook_deliveries
WHERE tenant_id = sqlc.arg(tenant_id) AND endpoint_id = sqlc.arg(endpoint_id);
