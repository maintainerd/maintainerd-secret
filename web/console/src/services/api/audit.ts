import { apiClient } from './client'
import { API_ENDPOINTS } from './config'
import { query, unwrapPaged } from './unwrap'
import type { ApiResponse, AuditEntry, Paged, PageRequest } from './types'

/**
 * Server-side audit filters. Every one is pushed into the SQL by the service.
 */
export interface AuditQuery extends PageRequest {
  /** Exact action, e.g. `secret.reveal`. */
  action?: string
  /** Exact outcome: `success`, `denied` or `error`. */
  outcome?: string
  /** PREFIX of the actor subject. */
  actor?: string
  /** PREFIX of the resource MRN, so `…:secret/prod` matches everything beneath it. */
  resource?: string
  /** RFC3339 instants, inclusive. */
  from?: string
  to?: string
}

/**
 * The access trail.
 *
 * Reading it is itself audited — `audit.read` appears in the trail you just
 * read, which is intentional and worth knowing before wondering where the row
 * came from. The audit row also records WHICH FILTERS were used, so "somebody
 * searched for every reveal of the production database password" is itself a
 * reviewable event.
 *
 * THE ENDPOINT FILTERS THE TRAIL, NOT THE PAGE. It used to accept only `page`
 * and `limit`, so the console filtered whatever page it had — which answers "no
 * matches" when it means "not on this page", and on an access trail those are
 * "nobody read that credential" and "nobody read it in the last hundred rows".
 * The filters below reach the query and its indexes; `total` is the count of
 * MATCHING rows, so the pagination control walks the filtered result set.
 */
export async function listAudit(params: AuditQuery = {}): Promise<Paged<AuditEntry>> {
  const res = await apiClient.get<ApiResponse<AuditEntry[]>>(
    `${API_ENDPOINTS.AUDIT}${query({
      page: params.page,
      limit: params.limit,
      action: params.action,
      outcome: params.outcome,
      actor: params.actor,
      resource: params.resource,
      from: params.from,
      to: params.to,
    })}`,
  )
  return unwrapPaged(res, 'read the audit trail')
}
