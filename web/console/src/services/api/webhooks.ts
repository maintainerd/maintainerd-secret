import { apiClient } from './client'
import { API_ENDPOINTS } from './config'
import { query, unwrap, unwrapPaged } from './unwrap'
import type {
  ApiResponse,
  CreatedWebhookEndpoint,
  Paged,
  PageRequest,
  WebhookDelivery,
  WebhookEndpoint,
} from './types'

/**
 * Webhook endpoints, per project.
 *
 * A delivery never carries a value — only the MRN and the new version — so a
 * consumer learns it should re-read rather than receiving the credential over
 * whatever transport the endpoint happens to use.
 *
 * The SIGNING KEY comes back exactly once, on create. There is no read-it-back
 * endpoint because an HMAC key that can be fetched is a forgery primitive, so
 * the create dialog is the only chance to copy it.
 */

export interface CreateWebhookInput {
  project: string
  url: string
  description?: string
  events?: string[]
  timeout_seconds?: number
  max_attempts?: number
}

export interface UpdateWebhookInput {
  project: string
  url: string
  description?: string
  events?: string[]
  status?: string
  timeout_seconds?: number
  max_attempts?: number
}

export async function listWebhooks(
  project: string,
  page: PageRequest = {},
): Promise<Paged<WebhookEndpoint>> {
  const res = await apiClient.get<ApiResponse<WebhookEndpoint[]>>(
    `${API_ENDPOINTS.WEBHOOKS}${query({ project, page: page.page, limit: page.limit })}`,
  )
  return unwrapPaged(res, 'list webhook endpoints')
}

export async function createWebhook(input: CreateWebhookInput): Promise<CreatedWebhookEndpoint> {
  const res = await apiClient.post<ApiResponse<CreatedWebhookEndpoint>>(
    API_ENDPOINTS.WEBHOOKS,
    input,
  )
  return unwrap(res, 'create the webhook endpoint')
}

export async function updateWebhook(
  endpointUuid: string,
  input: UpdateWebhookInput,
): Promise<WebhookEndpoint> {
  const res = await apiClient.patch<ApiResponse<WebhookEndpoint>>(
    `${API_ENDPOINTS.WEBHOOKS}/${encodeURIComponent(endpointUuid)}`,
    input,
  )
  return unwrap(res, 'update the webhook endpoint')
}

export async function deleteWebhook(endpointUuid: string, project: string): Promise<void> {
  await apiClient.delete<void>(
    `${API_ENDPOINTS.WEBHOOKS}/${encodeURIComponent(endpointUuid)}${query({ project })}`,
  )
}

export async function listWebhookDeliveries(
  endpointUuid: string,
  project: string,
  page: PageRequest = {},
): Promise<Paged<WebhookDelivery>> {
  const res = await apiClient.get<ApiResponse<WebhookDelivery[]>>(
    `${API_ENDPOINTS.WEBHOOKS}/${encodeURIComponent(endpointUuid)}/deliveries${query({
      project,
      page: page.page,
      limit: page.limit,
    })}`,
  )
  return unwrapPaged(res, 'list webhook deliveries')
}
