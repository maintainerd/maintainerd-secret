import { useEffect, useMemo, useState } from 'react'
import {
  getCoreRowModel,
  getSortedRowModel,
  useReactTable,
  type SortingState,
} from '@tanstack/react-table'
import { ScrollText } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { PageHeader } from '@/components/layout/PageHeader'
import { DataTable, DataTableEmpty, DataTablePagination } from '@/components/data-table'
import { FormInputField, FormSelectField } from '@/components/form'
import { auditRowClassName, buildAuditColumns } from './components/auditColumns'
import { EMPTY_AUDIT_FILTERS, hasAuditFilters, useAudit, type AuditFilters } from '@/hooks/useAudit'
import { AUDIT_ACTIONS } from '@/services/api/types'
import type { AuditEntry } from '@/services/api/types'

const ANY = '__any__'
const PAGE_SIZE = 100
const DEFAULT_SORT: SortingState = [{ id: 'when', desc: true }]

const ACTION_OPTIONS = [
  { value: ANY, label: 'Any action' },
  ...AUDIT_ACTIONS.map((action) => ({ value: action, label: action })),
]

const OUTCOME_OPTIONS = [
  { value: ANY, label: 'Any outcome' },
  { value: 'success', label: 'success' },
  { value: 'denied', label: 'denied' },
  { value: 'error', label: 'error' },
]

/** How long a typed actor/MRN prefix settles before it becomes a request. */
const TEXT_FILTER_DEBOUNCE_MS = 350

/**
 * The access trail.
 *
 * Composed on maintainerd-auth's listing primitives — its page shell,
 * `PageHeader`, `DataTable`, `DataTablePagination` — but NOT on `ResourceListing`,
 * whose toolbar is a single free-text search box. This trail needs six distinct
 * predicates with different semantics (two exact, two prefix, a date range) and
 * collapsing them into one box would hide which of them is being applied.
 *
 * Because it bypasses `ResourceListing`, IT HAS TO REPRODUCE THAT COMPONENT'S
 * `tableInCard` SHELL BY HAND — the `data-md-table-shell` bordered card with the
 * 16px first/last-column gutters, copied verbatim from
 * `components/data-table/ResourceListing.tsx`. It previously used the OTHER branch
 * of that component (the `-mx-6` full-bleed, which only makes sense inside a
 * `PageContainer` card) and so was the one listing in this console framed
 * differently from every other. If that shell ever changes, change it in
 * `ResourceListing` and mirror it here.
 *
 * THE FILTERS SEARCH THE WHOLE TRAIL. They are query parameters the service
 * applies in SQL, so `total` below is the number of matching events and the
 * pagination control walks the filtered result set. This page used to carry an
 * on-screen caveat saying the opposite — that the filters narrowed the fetched
 * page only — because the endpoint could not filter. It can, so the caveat is
 * gone rather than merely reworded: a filter that silently searched one page
 * answered "no matches" when it meant "not on this page", which on an access
 * trail is the difference between closing an incident and missing one.
 *
 * The two text filters are DEBOUNCED. They are prefixes an operator types
 * character by character, and each keystroke would otherwise be a query against
 * an audited endpoint — filling the trail with `audit.read` rows for a word
 * being typed.
 *
 * Reading this page is itself audited — `audit.read` appears in the trail you
 * just read, and it records which filters were used, which is intentional and
 * worth knowing before wondering where the row came from.
 */
export default function AuditPage() {
  const [page, setPage] = useState(1)
  // Two pieces of state for the text filters: `draft` is what the inputs show,
  // `filters` is what has settled and is being queried.
  const [draft, setDraft] = useState<AuditFilters>(EMPTY_AUDIT_FILTERS)
  const [filters, setFilters] = useState<AuditFilters>(EMPTY_AUDIT_FILTERS)
  const [sorting, setSorting] = useState<SortingState>(DEFAULT_SORT)
  const audit = useAudit({ page, limit: PAGE_SIZE }, filters)

  // Any filter change resets to page 1. Staying on page 7 of a narrower result
  // set shows an empty table that reads as "no matches".
  const update = (patch: Partial<AuditFilters>) => {
    setDraft((current) => ({ ...current, ...patch }))
    setPage(1)
  }

  // The dropdowns and dates apply immediately; the two prefixes settle first.
  useEffect(() => {
    const immediate = draft.action !== filters.action ||
      draft.outcome !== filters.outcome ||
      draft.from !== filters.from ||
      draft.to !== filters.to
    if (immediate) {
      setFilters(draft)
      return
    }
    if (draft.actor === filters.actor && draft.resource === filters.resource) return
    const timer = setTimeout(() => setFilters(draft), TEXT_FILTER_DEBOUNCE_MS)
    return () => clearTimeout(timer)
  }, [draft, filters])

  const columns = useMemo(() => buildAuditColumns(), [])
  const lastPage = Math.max(1, Math.ceil(audit.total / PAGE_SIZE))
  const isFiltered = hasAuditFilters(draft)

  const clearFilters = () => {
    setDraft(EMPTY_AUDIT_FILTERS)
    setFilters(EMPTY_AUDIT_FILTERS)
    setPage(1)
  }

  // One TanStack table over the fetched page. Sorting stays CLIENT-SIDE and only
  // reorders the page in view: the API has no sort_by, and it always returns
  // newest-first, which is the ordering that matters on a trail. Filtering is
  // NOT client-side any more — it is the query.
  const table = useReactTable<AuditEntry>({
    data: audit.entries,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    manualPagination: true,
  })

  // The pagination control is server-driven: it walks the API's pages, not the
  // table's, so it gets its own minimal table (auth's `usePaginationTable`
  // pattern) rather than the one rendering rows.
  const paginationTable = useReactTable({
    data: [],
    columns: [],
    pageCount: lastPage,
    state: { pagination: { pageIndex: page - 1, pageSize: PAGE_SIZE } },
    onPaginationChange: (updater) => {
      const next =
        typeof updater === 'function'
          ? updater({ pageIndex: page - 1, pageSize: PAGE_SIZE })
          : updater
      setPage(next.pageIndex + 1)
    },
    getCoreRowModel: getCoreRowModel(),
    manualPagination: true,
  })

  return (
    <div className="mx-auto flex w-full max-w-6xl flex-col gap-4">
      <PageHeader
        title="Audit log"
        icon={ScrollText}
        description="Every read, write, rotation and denial, across the whole trail. Reading this page is itself audited."
      />

      <div className="grid gap-5 md:grid-cols-3 lg:grid-cols-6">
        <FormSelectField
          id="filter-action"
          label="Action"
          options={ACTION_OPTIONS}
          value={draft.action || ANY}
          onValueChange={(value) => update({ action: value === ANY ? '' : value })}
        />
        <FormSelectField
          id="filter-outcome"
          label="Outcome"
          options={OUTCOME_OPTIONS}
          value={draft.outcome || ANY}
          onValueChange={(value) => update({ outcome: value === ANY ? '' : value })}
        />
        <FormInputField
          id="filter-actor"
          label="Actor starts with"
          value={draft.actor}
          autoComplete="off"
          placeholder="svc-reconciler"
          onChange={(event) => update({ actor: event.target.value })}
        />
        <FormInputField
          id="filter-resource"
          label="MRN starts with"
          value={draft.resource}
          autoComplete="off"
          placeholder="mrn:secret:acme:billing-app:secret/prod"
          onChange={(event) => update({ resource: event.target.value })}
        />
        <FormInputField
          id="filter-from"
          label="From"
          type="date"
          value={draft.from}
          onChange={(event) => update({ from: event.target.value })}
        />
        <FormInputField
          id="filter-to"
          label="To"
          type="date"
          value={draft.to}
          onChange={(event) => update({ to: event.target.value })}
        />
      </div>

      <div
        data-md-table-shell
        className="overflow-hidden rounded-[3px] border border-border bg-card [&_table]:border-b-0 [&_tbody_tr:last-child]:border-b-0 md:[&_td:first-child]:pl-4 md:[&_td:last-child]:pr-4 md:[&_th:first-child]:pl-4 md:[&_th:last-child]:pr-4"
      >
        <DataTable
          table={table}
          columnCount={columns.length}
          isLoading={audit.isLoading}
          error={audit.error}
          rowClassName={auditRowClassName}
          emptyState={
            isFiltered ? (
              <DataTableEmpty
                variant="no-results"
                title="No matching events"
                description="Nothing in this tenant's trail matches these filters — the whole trail was searched, not just this page."
              >
                <Button variant="outline" size="sm" className="mt-1" onClick={clearFilters}>
                  Clear filters
                </Button>
              </DataTableEmpty>
            ) : (
              <DataTableEmpty
                title="No events yet"
                description="Nothing has been read, written or denied in this tenant."
              />
            )
          }
        />
      </div>

      <DataTablePagination
        table={paginationTable}
        rowCount={audit.total}
        pageSizeOptions={[PAGE_SIZE]}
      />
    </div>
  )
}
