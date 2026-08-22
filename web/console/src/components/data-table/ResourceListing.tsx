import type { ReactNode } from 'react'
import type { ColumnDef, SortingState } from '@tanstack/react-table'
import { useSearchParams } from 'react-router-dom'
import { Button } from '@/components/ui/button'
import { DataTable } from './DataTable'
import { DataTableEmpty } from './DataTableEmpty'
import { DataTablePagination } from './DataTablePagination'
import { DataTableActiveFilters } from './DataTableActiveFilters'
import { ListingToolbar } from './ListingToolbar'
import { useClientDataTable, type FilterGroup } from './useClientDataTable'

interface ResourceListingProps<TRow> {
  /** The rows for the current API page. */
  rows: TRow[]
  columns: ColumnDef<TRow>[]
  defaultSort: SortingState
  /** Fields on a row the free-text search matches against. */
  searchFields: (row: TRow) => (string | undefined | null)[]
  searchPlaceholder: string
  isLoading?: boolean
  error?: Error | null
  filterGroups?: readonly FilterGroup[]
  /** Reads the value a filter group matches against on a row. */
  filterValue?: (row: TRow, groupKey: string) => string | string[] | undefined
  /** Navigate when a row body is clicked (the actions menu is ignored). */
  onRowClick?: (row: TRow) => void
  onCreate?: () => void
  createLabel?: string
  defaultPageSize?: number
  /** Empty-state headline shown when no rows exist yet (before any search/filter). */
  emptyTitle?: string
  emptyDescription?: string
  /** When true, the table is wrapped in its own bordered card while the toolbar
   *  (above) and pagination (below) render outside it. The page must NOT add its
   *  own encapsulating card in this mode. */
  tableInCard?: boolean
  /** Extra action elements rendered between the column-toggle and create button. */
  extraActions?: ReactNode
  /** Namespace for the URL query keys. Omit to keep state out of the URL. */
  urlKey?: string
}

/**
 * The standard listing: toolbar (search + filters + create) → active-filter
 * chips → table → pagination.
 *
 * Structurally identical to maintainerd-auth's
 * `components/data-table/ResourceListing.tsx`, down to the `-mx-6` bleed and the
 * re-padded first/last columns. The one substitution is the engine: auth drives
 * `useServerDataTable`, secret drives `useClientDataTable`, because secret's list
 * endpoints page but neither search nor sort (see that file's header).
 */
export function ResourceListing<TRow>({
  rows,
  columns,
  defaultSort,
  searchFields,
  searchPlaceholder,
  isLoading = false,
  error = null,
  filterGroups,
  filterValue,
  onRowClick,
  onCreate,
  createLabel,
  defaultPageSize,
  emptyTitle = 'Nothing here yet',
  emptyDescription,
  tableInCard = false,
  extraActions,
  urlKey,
}: ResourceListingProps<TRow>) {
  const [searchParams, setSearchParams] = useSearchParams()
  const { table, search, setSearch, filters, setFilters, activeFilters, clearFilters, isFiltered } =
    useClientDataTable<TRow>({
      rows,
      columns,
      defaultSort,
      searchFields,
      filterGroups,
      filterValue,
      defaultPageSize,
      urlKey,
      syncUrl: Boolean(urlKey),
      searchParams,
      setSearchParams,
    })

  // A search term or applied filter means rows may exist but are hidden — offer
  // a reset rather than a create CTA, which wouldn't help the user here.
  const emptyState = isFiltered ? (
    <DataTableEmpty
      variant="no-results"
      title="No results found"
      description="No records match your current search and filters."
    >
      <Button
        variant="outline"
        size="sm"
        className="mt-1"
        onClick={() => {
          setSearch('')
          clearFilters()
        }}
      >
        Clear search &amp; filters
      </Button>
    </DataTableEmpty>
  ) : (
    <DataTableEmpty
      title={emptyTitle}
      description={emptyDescription}
      onAction={onCreate}
      actionLabel={createLabel}
    />
  )

  return (
    <div className="space-y-4">
      <ListingToolbar
        table={table}
        search={search}
        onSearchChange={setSearch}
        searchPlaceholder={searchPlaceholder}
        filterGroups={filterGroups}
        filters={filters}
        onFiltersChange={setFilters}
        onCreate={onCreate}
        createLabel={createLabel}
        extraActions={extraActions}
      />
      <DataTableActiveFilters activeFilters={activeFilters} onClearAll={clearFilters} />
      {tableInCard ? (
        // Table in its own bordered card; the toolbar (above) and pagination
        // (below) sit outside it.
        <div
          data-md-table-shell
          className="overflow-hidden rounded-[3px] border border-border bg-card [&_table]:border-b-0 [&_tbody_tr:last-child]:border-b-0 md:[&_td:first-child]:pl-4 md:[&_td:last-child]:pr-4 md:[&_th:first-child]:pl-4 md:[&_th:last-child]:pr-4"
        >
          <DataTable
            table={table}
            columnCount={columns.length}
            isLoading={isLoading}
            error={error}
            emptyState={emptyState}
            onRowClick={onRowClick}
          />
        </div>
      ) : (
        // The table bleeds past the card's px-6 to touch its side edges (-mx-6),
        // while the first/last columns re-pad to the same 24px gutter so cell
        // content stays aligned with the toolbar and pagination above/below.
        <div className="-mx-6 md:[&_td:first-child]:pl-6 md:[&_td:last-child]:pr-6 md:[&_th:first-child]:pl-6 md:[&_th:last-child]:pr-6">
          <DataTable
            table={table}
            columnCount={columns.length}
            isLoading={isLoading}
            error={error}
            emptyState={emptyState}
            onRowClick={onRowClick}
          />
        </div>
      )}
      <DataTablePagination table={table} />
    </div>
  )
}
