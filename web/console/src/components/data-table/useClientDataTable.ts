import * as React from 'react'
import type {
  ColumnDef,
  ColumnFiltersState,
  PaginationState,
  SortingState,
  Table,
  VisibilityState,
} from '@tanstack/react-table'
import {
  getCoreRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  useReactTable,
} from '@tanstack/react-table'

/**
 * The listing-table engine, client-side.
 *
 * maintainerd-auth's equivalent is `useServerDataTable`: it maps search, sort and
 * page state onto API params because every auth list endpoint accepts them.
 * THAT ENGINE IS NOT COPIED HERE, and the reason is a property of secret's API
 * rather than a preference. `GET /secrets`, `GET /audit`, `GET /webhooks` and
 * `GET /projects` accept `page` and `limit` and nothing else — no `search`, no
 * `sort_by`. Wiring auth's engine to them would render a sortable header and a
 * search box that send parameters the service silently drops, which is worse
 * than no control at all: the operator reads "no matches" and believes it.
 *
 * So the toolbar, the table, the pagination and the empty states are auth's,
 * verbatim; only the state engine differs. Each page fetches a generous page
 * from the API and this narrows it in the browser. Where that distinction
 * matters — the audit trail, which can be long — the page says so on screen.
 */

/** A filter group for a listing. `key` is the state key and the URL query key. */
export interface FilterGroup {
  key: string
  label: string
  options: readonly string[]
  /** Reads the value a row should be matched on. Defaults to `row[key]`. */
  accessor?: (row: never) => string | string[] | undefined
}

/** Listing filter state: each group key → the selected values. */
export type ListingFilters = Record<string, string[]>

export interface UseClientDataTableOptions<TRow> {
  /** The rows for the current API page. */
  rows: TRow[]
  columns: ColumnDef<TRow>[]
  /** Default sort applied when the URL doesn't specify one. */
  defaultSort: SortingState
  /** Fields on a row the free-text search matches against. */
  searchFields: (row: TRow) => (string | undefined | null)[]
  /** Stable (module-level) filter group config. */
  filterGroups?: readonly FilterGroup[]
  /** Reads the value a filter group matches against on a row. */
  filterValue?: (row: TRow, groupKey: string) => string | string[] | undefined
  defaultPageSize?: number
  /**
   * Namespace for the URL query keys, so two listings on one route (or a page
   * that also carries other params) cannot collide.
   */
  urlKey?: string
  /** Sync state to the URL. Off for listings inside a dialog. */
  syncUrl?: boolean
  /** Reads the URL query, when `syncUrl` is on. */
  searchParams?: URLSearchParams
  setSearchParams?: (next: URLSearchParams, options?: { replace?: boolean }) => void
}

export interface UseClientDataTableResult<TRow> {
  table: Table<TRow>
  search: string
  setSearch: (value: string) => void
  filters: ListingFilters
  setFilters: (filters: ListingFilters) => void
  /** Human-readable "Label: a, b" chips for the active filters. */
  activeFilters: string[]
  clearFilters: () => void
  /** True when a search term or filter is narrowing the fetched page. */
  isFiltered: boolean
  /** How many of the fetched rows survive the current search + filters. */
  matchedCount: number
}

const EMPTY_FILTER_GROUPS: readonly FilterGroup[] = []

function matchesFilters<TRow>(
  row: TRow,
  filterGroups: readonly FilterGroup[],
  filters: ListingFilters,
  filterValue: (row: TRow, groupKey: string) => string | string[] | undefined,
): boolean {
  for (const group of filterGroups) {
    const selected = filters[group.key]
    if (!selected?.length) continue
    const value = filterValue(row, group.key)
    const candidates = Array.isArray(value) ? value : value === undefined ? [] : [value]
    if (!candidates.some((candidate) => selected.includes(candidate))) return false
  }
  return true
}

export function useClientDataTable<TRow>({
  rows,
  columns,
  defaultSort,
  searchFields,
  filterGroups = EMPTY_FILTER_GROUPS,
  filterValue,
  defaultPageSize = 10,
  urlKey = '',
  syncUrl = false,
  searchParams,
  setSearchParams,
}: UseClientDataTableOptions<TRow>): UseClientDataTableResult<TRow> {
  const prefix = urlKey ? `${urlKey}_` : ''
  const readParam = React.useCallback(
    (name: string) => (syncUrl ? (searchParams?.get(`${prefix}${name}`) ?? null) : null),
    // `searchParams` is a new object on every navigation; only the seed read
    // matters, so it is intentionally read lazily rather than tracked.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [syncUrl, prefix],
  )

  const [search, setSearch] = React.useState(() => readParam('search') ?? '')
  const [filters, setFiltersState] = React.useState<ListingFilters>(() => {
    const initial: ListingFilters = {}
    for (const group of filterGroups) {
      initial[group.key] = readParam(group.key)?.split(',').filter(Boolean) ?? []
    }
    return initial
  })
  const [sorting, setSorting] = React.useState<SortingState>(() => {
    const sortBy = readParam('sortBy')
    return sortBy ? [{ id: sortBy, desc: readParam('sortOrder') === 'desc' }] : defaultSort
  })
  const [pagination, setPagination] = React.useState<PaginationState>(() => ({
    pageIndex: Math.max(0, Number(readParam('page') || 1) - 1),
    pageSize: Number(readParam('limit') || defaultPageSize),
  }))
  const [columnFilters, setColumnFilters] = React.useState<ColumnFiltersState>([])
  const [columnVisibility, setColumnVisibility] = React.useState<VisibilityState>({})

  const resolveFilterValue = React.useCallback(
    (row: TRow, groupKey: string) => {
      if (filterValue) return filterValue(row, groupKey)
      return (row as Record<string, unknown>)[groupKey] as string | string[] | undefined
    },
    [filterValue],
  )

  const filtered = React.useMemo(() => {
    const needle = search.trim().toLowerCase()
    return rows.filter((row) => {
      if (!matchesFilters(row, filterGroups, filters, resolveFilterValue)) return false
      if (!needle) return true
      return searchFields(row).some((field) => field?.toLowerCase().includes(needle))
    })
  }, [rows, search, filters, filterGroups, searchFields, resolveFilterValue])

  const table = useReactTable({
    data: filtered,
    columns,
    onSortingChange: setSorting,
    onPaginationChange: setPagination,
    onColumnFiltersChange: setColumnFilters,
    onColumnVisibilityChange: setColumnVisibility,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    state: { sorting, pagination, columnFilters, columnVisibility },
  })

  // A narrowed result set can be shorter than the page the user is on; without
  // this a filter that matches three rows while you are on page four renders an
  // empty table that looks like "no matches" for the whole list.
  React.useEffect(() => {
    const lastPage = Math.max(0, Math.ceil(filtered.length / pagination.pageSize) - 1)
    if (pagination.pageIndex > lastPage) {
      setPagination((current) => ({ ...current, pageIndex: lastPage }))
    }
  }, [filtered.length, pagination.pageIndex, pagination.pageSize])

  // Mirror state to the URL so a listing view is shareable. Nothing written here
  // identifies a secret: it is a search term the operator typed plus sort/page.
  React.useEffect(() => {
    if (!syncUrl || !searchParams || !setSearchParams) return
    const params = new URLSearchParams(searchParams)
    const set = (name: string, value: string | null) => {
      if (value) params.set(`${prefix}${name}`, value)
      else params.delete(`${prefix}${name}`)
    }
    set('search', search || null)
    for (const group of filterGroups) {
      set(group.key, filters[group.key]?.length ? filters[group.key].join(',') : null)
    }
    set('sortBy', sorting.length > 0 ? sorting[0].id : null)
    set('sortOrder', sorting.length > 0 ? (sorting[0].desc ? 'desc' : 'asc') : null)
    set('page', String(pagination.pageIndex + 1))
    set('limit', String(pagination.pageSize))
    setSearchParams(params, { replace: true })
  }, [
    syncUrl,
    prefix,
    search,
    filters,
    sorting,
    pagination,
    filterGroups,
    searchParams,
    setSearchParams,
  ])

  const activeFilters = React.useMemo(() => {
    const chips: string[] = []
    for (const group of filterGroups) {
      const values = filters[group.key]
      if (values?.length) chips.push(`${group.label}: ${values.join(', ')}`)
    }
    return chips
  }, [filters, filterGroups])

  const setFilters = React.useCallback((next: ListingFilters) => setFiltersState(next), [])

  const clearFilters = React.useCallback(() => {
    const cleared: ListingFilters = {}
    for (const group of filterGroups) cleared[group.key] = []
    setFiltersState(cleared)
  }, [filterGroups])

  return {
    table,
    search,
    setSearch,
    filters,
    setFilters,
    activeFilters,
    clearFilters,
    isFiltered: search.trim() !== '' || activeFilters.length > 0,
    matchedCount: filtered.length,
  }
}
