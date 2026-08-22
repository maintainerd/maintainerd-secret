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

-- name: FinishWebhookDelivery :one
UPDATE webhook_deliveries
SET attempt_count   = sqlc.arg(attempt_count),
    status          = sqlc.arg(status),
    response_status = sqlc.arg(response_status),
    error           = sqlc.arg(error),
    updated_at      = now()
WHERE delivery_id = sqlc.arg(delivery_id)
RETURNING *;

-- name: ListWebhookDeliveriesByEndpoint :many
SELECT * FROM webhook_deliveries
WHERE tenant_id = sqlc.arg(tenant_id)
  AND endpoint_id = sqlc.arg(endpoint_id)
ORDER BY created_at DESC
LIMIT sqlc.arg(row_limit) OFFSET sqlc.arg(row_offset);

-- name: CountWebhookDeliveriesByEndpoint :one
SELECT count(*) FROM webhook_deliveries
WHERE tenant_id = sqlc.arg(tenant_id) AND endpoint_id = sqlc.arg(endpoint_id);
