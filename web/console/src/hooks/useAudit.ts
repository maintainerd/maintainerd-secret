import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { listAudit } from '@/services/api/audit'
import type { AuditEntry, PageRequest } from '@/services/api/types'

export const auditKeys = {
  all: ['audit'] as const,
  list: (page: PageRequest) => [...auditKeys.all, 'list', page] as const,
}

export interface AuditFilters {
  /** Exact action, e.g. `secret.reveal`. Empty means every action. */
  action: string
  /** Case-insensitive substring of the actor subject. */
  actor: string
  /** Case-insensitive substring of the resource MRN (i.e. "which secret"). */
  resource: string
  outcome: string
  /** Inclusive `yyyy-MM-dd` bounds, interpreted in the viewer's local time. */
  from: string
  to: string
}

export const EMPTY_AUDIT_FILTERS: AuditFilters = {
  action: '',
  actor: '',
  resource: '',
  outcome: '',
  from: '',
  to: '',
}

function matches(entry: AuditEntry, filters: AuditFilters): boolean {
  if (filters.action && entry.action !== filters.action) return false
  if (filters.outcome && entry.outcome !== filters.outcome) return false
  if (filters.actor && !entry.actor_subject.toLowerCase().includes(filters.actor.toLowerCase())) {
    return false
  }
  if (
    filters.resource &&
    !entry.resource_mrn.toLowerCase().includes(filters.resource.toLowerCase())
  ) {
    return false
  }
  const at = Date.parse(entry.created_at)
  if (filters.from) {
    const from = new Date(`${filters.from}T00:00:00`).getTime()
    if (Number.isFinite(from) && at < from) return false
  }
  if (filters.to) {
    const to = new Date(`${filters.to}T23:59:59.999`).getTime()
    if (Number.isFinite(to) && at > to) return false
  }
  return true
}

/**
 * The audit trail for the current tenant.
 *
 * FILTERING IS CLIENT-SIDE, over the page the API returned. `GET /audit` takes
 * only `page` and `limit` today — there is no server-side action/actor/date
 * predicate — so this narrows what was fetched and nothing more. The page says
 * so out loud, because a filter that silently searches one page of a long trail
 * is worse than no filter: it answers "no matches" when it means "not on this
 * page".
 */
export function useAudit(page: PageRequest, filters: AuditFilters) {
  const query = useQuery({
    queryKey: auditKeys.list(page),
    queryFn: () => listAudit(page),
  })

  const filtered = useMemo(
    () => (query.data?.rows ?? []).filter((entry) => matches(entry, filters)),
    [query.data, filters],
  )

  return {
    ...query,
    entries: filtered,
    fetchedCount: query.data?.rows.length ?? 0,
    total: query.data?.meta.total ?? 0,
  }
}
