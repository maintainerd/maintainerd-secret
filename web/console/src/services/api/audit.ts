import { apiClient } from './client'
import { API_ENDPOINTS } from './config'
import { query, unwrapPaged } from './unwrap'
import type { ApiResponse, AuditEntry, Paged, PageRequest } from './types'

/**
 * The access trail.
 *
 * Reading it is itself audited — `audit.read` appears in the trail you just
 * read, which is intentional and worth knowing before wondering where the row
 * came from.
 *
 * THE ENDPOINT PAGES; IT DOES NOT FILTER. `GET /audit` accepts only `page` and
 * `limit` today, so the console's action / actor / outcome / date filters are
 * applied to the page it has (see `hooks/useAudit.ts`). That is honest for
 * scanning recent activity and it is NOT a substitute for a server-side search
 * over a long trail; the UI says so rather than implying it searched everything.
 */
export async function listAudit(page: PageRequest = {}): Promise<Paged<AuditEntry>> {
  const res = await apiClient.get<ApiResponse<AuditEntry[]>>(
    `${API_ENDPOINTS.AUDIT}${query({ page: page.page, limit: page.limit })}`,
  )
  return unwrapPaged(res, 'read the audit trail')
}
