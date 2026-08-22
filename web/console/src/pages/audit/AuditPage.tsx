import { useMemo, useState } from 'react'
import {
  getCoreRowModel,
  getSortedRowModel,
  useReactTable,
  type SortingState,
} from '@tanstack/react-table'
import { Info, ScrollText } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { PageContainer } from '@/components/layout/PageContainer'
import { PageHeader } from '@/components/layout/PageHeader'
import { DataTable, DataTableEmpty, DataTablePagination } from '@/components/data-table'
import { FormInputField, FormSelectField } from '@/components/form'
import { auditRowClassName, buildAuditColumns } from './components/auditColumns'
import { EMPTY_AUDIT_FILTERS, useAudit, type AuditFilters } from '@/hooks/useAudit'
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

/**
 * The access trail.
 *
 * Composed on maintainerd-auth's listing primitives — `PageContainer`,
 * `PageHeader`, `DataTable`, `DataTablePagination` — but NOT on
 * `ResourceListing`, and the reason is on screen as well as in this comment:
 * `GET /audit` accepts only `page` and `limit`, so the filters below narrow the
 * page that was fetched and nothing more. `ResourceListing`'s toolbar would
 * present a single search box that looks like it searched the whole trail. A
 * filter that silently searches one page of a long trail is worse than no
 * filter: it answers "no matches" when it means "not on this page".
 *
 * Reading this page is itself audited — `audit.read` appears in the trail you
 * just read, which is intentional and worth knowing before wondering where the
 * row came from.
 */
export default function AuditPage() {
  const [page, setPage] = useState(1)
  const [filters, setFilters] = useState<AuditFilters>(EMPTY_AUDIT_FILTERS)
  const [sorting, setSorting] = useState<SortingState>(DEFAULT_SORT)
  const audit = useAudit({ page, limit: PAGE_SIZE }, filters)

  const update = (patch: Partial<AuditFilters>) =>
    setFilters((current) => ({ ...current, ...patch }))

  const columns = useMemo(() => buildAuditColumns(), [])
  const lastPage = Math.max(1, Math.ceil(audit.total / PAGE_SIZE))
  const isFiltered = Object.values(filters).some((value) => value !== '')

  // One TanStack table over the fetched page: sorting is client-side (the API
  // has no sort_by), and pagination is driven by `page` below, so the table's own
  // pagination model is left at a single page of everything it was handed.
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
    <PageContainer>
      <PageHeader
        title="Audit log"
        icon={ScrollText}
        description="Every read, write, rotation and denial. Reading this page is itself audited."
      />

      <Alert>
        <Info className="size-4" aria-hidden="true" />
        <AlertTitle>Filters narrow this page, not the whole trail</AlertTitle>
        <AlertDescription>
          The API pages the trail but does not search it. The filters below apply to the{' '}
          <strong>{audit.fetchedCount}</strong> {audit.fetchedCount === 1 ? 'row' : 'rows'} fetched
          for this page, not to all {audit.total}. Page through to widen the window.
        </AlertDescription>
      </Alert>

      <div className="grid gap-5 md:grid-cols-3 lg:grid-cols-6">
        <FormSelectField
          id="filter-action"
          label="Action"
          options={ACTION_OPTIONS}
          value={filters.action || ANY}
          onValueChange={(value) => update({ action: value === ANY ? '' : value })}
        />
        <FormSelectField
          id="filter-outcome"
          label="Outcome"
          options={OUTCOME_OPTIONS}
          value={filters.outcome || ANY}
          onValueChange={(value) => update({ outcome: value === ANY ? '' : value })}
        />
        <FormInputField
          id="filter-actor"
          label="Actor"
          value={filters.actor}
          autoComplete="off"
          onChange={(event) => update({ actor: event.target.value })}
        />
        <FormInputField
          id="filter-resource"
          label="Secret / MRN"
          value={filters.resource}
          autoComplete="off"
          onChange={(event) => update({ resource: event.target.value })}
        />
        <FormInputField
          id="filter-from"
          label="From"
          type="date"
          value={filters.from}
          onChange={(event) => update({ from: event.target.value })}
        />
        <FormInputField
          id="filter-to"
          label="To"
          type="date"
          value={filters.to}
          onChange={(event) => update({ to: event.target.value })}
        />
      </div>

      <div className="-mx-6 md:[&_td:first-child]:pl-6 md:[&_td:last-child]:pr-6 md:[&_th:first-child]:pl-6 md:[&_th:last-child]:pr-6">
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
                description="Nothing on this page matches. Try another page or clear the filters."
              >
                <Button
                  variant="outline"
                  size="sm"
                  className="mt-1"
                  onClick={() => setFilters(EMPTY_AUDIT_FILTERS)}
                >
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
    </PageContainer>
  )
}
