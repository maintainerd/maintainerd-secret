import { useQuery } from '@tanstack/react-query'
import { listAudit, type AuditQuery } from '@/services/api/audit'
import type { PageRequest } from '@/services/api/types'

export const auditKeys = {
  all: ['audit'] as const,
  list: (params: AuditQuery) => [...auditKeys.all, 'list', params] as const,
}

export interface AuditFilters {
  /** Exact action, e.g. `secret.reveal`. Empty means every action. */
  action: string
  /** PREFIX of the actor subject. Empty means every actor. */
  actor: string
  /** PREFIX of the resource MRN — i.e. "this secret, or everything under this scope". */
  resource: string
  /** Exact outcome: `success`, `denied` or `error`. */
  outcome: string
  /** Inclusive `yyyy-MM-dd` bounds, entered and interpreted in the viewer's local time. */
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

/** True when any filter is set — used to pick the right empty state. */
export function hasAuditFilters(filters: AuditFilters): boolean {
  return Object.values(filters).some((value) => value !== '')
}

/**
 * Converts a local `yyyy-MM-dd` date to the RFC3339 instant the API expects.
 *
 * THE OPERATOR'S DAY, NOT THE SERVER'S. A date input yields a bare calendar day
 * with no zone, and sending it as-is would have the server interpret it in ITS
 * zone — so "from 22 August" would silently start hours early or late depending
 * on where the vault is deployed. `new Date('yyyy-MM-ddTHH:mm:ss')` (no `Z`) is
 * parsed in the BROWSER's zone, and `toISOString` then renders that same instant
 * as UTC. `endOfDay` pushes the upper bound to the last millisecond so a `to`
 * date includes the whole day, which is what an inclusive range control implies.
 *
 * An unparseable value yields undefined rather than an invalid instant: the
 * filter is simply not applied, which is the same as not having typed it.
 */
export function toInstant(day: string, edge: 'start' | 'end'): string | undefined {
  if (!day) return undefined
  const time = edge === 'start' ? 'T00:00:00.000' : 'T23:59:59.999'
  const parsed = new Date(`${day}${time}`)
  if (Number.isNaN(parsed.getTime())) return undefined
  return parsed.toISOString()
}

/** Renders the UI's filter state as the API's query parameters. */
export function toAuditQuery(page: PageRequest, filters: AuditFilters): AuditQuery {
  return {
    page: page.page,
    limit: page.limit,
    action: filters.action || undefined,
    outcome: filters.outcome || undefined,
    actor: filters.actor.trim() || undefined,
    resource: filters.resource.trim() || undefined,
    from: toInstant(filters.from, 'start'),
    to: toInstant(filters.to, 'end'),
  }
}

/**
 * The audit trail for the current tenant.
 *
 * FILTERING IS SERVER-SIDE. `GET /audit` accepts action, outcome, actor (prefix),
 * resource (MRN prefix) and an inclusive date range, and applies every one of
 * them in the query — so `total` is the number of MATCHING events and paging
 * walks the filtered trail. This hook used to filter the fetched page in the
 * browser and the page said so on screen, because a filter that silently
 * searches one page of a long trail is worse than no filter: it answers "no
 * matches" when it means "not on this page". Both the client-side pass and the
 * caveat are gone because the endpoint no longer needs them.
 *
 * The filters are part of the query KEY, so changing one is a new fetch and a
 * cached result is never shown for the wrong filter.
 */
export function useAudit(page: PageRequest, filters: AuditFilters) {
  const params = toAuditQuery(page, filters)
  const queryResult = useQuery({
    queryKey: auditKeys.list(params),
    queryFn: () => listAudit(params),
    // A filtered trail is a moving target and an operator changing filters
    // rapidly should not see a stale page flash in between.
    placeholderData: (previous) => previous,
  })

  return {
    ...queryResult,
    entries: queryResult.data?.rows ?? [],
    total: queryResult.data?.meta.total ?? 0,
  }
}
