import { describe, expect, it } from 'vitest'
import { act, renderHook } from '@testing-library/react'
import type { ColumnDef } from '@tanstack/react-table'
import { useClientDataTable, type FilterGroup } from './useClientDataTable'

interface Row {
  key: string
  status: string
  tags: string[]
}

const ROWS: Row[] = [
  { key: 'DATABASE_PASSWORD', status: 'active', tags: ['db', 'prod'] },
  { key: 'STRIPE_KEY', status: 'active', tags: ['billing'] },
  { key: 'LEGACY_TOKEN', status: 'archived', tags: ['db'] },
]

const COLUMNS: ColumnDef<Row>[] = [
  { id: 'key', accessorKey: 'key' },
  { id: 'status', accessorKey: 'status' },
]

const FILTER_GROUPS: readonly FilterGroup[] = [
  { key: 'status', label: 'Status', options: ['active', 'archived'] },
]

function setup(overrides: Partial<Parameters<typeof useClientDataTable<Row>>[0]> = {}) {
  return renderHook(() =>
    useClientDataTable<Row>({
      rows: ROWS,
      columns: COLUMNS,
      defaultSort: [{ id: 'key', desc: false }],
      searchFields: (row) => [row.key, row.tags.join(' ')],
      filterGroups: FILTER_GROUPS,
      defaultPageSize: 10,
      ...overrides,
    }),
  )
}

function visibleKeys(result: { current: ReturnType<typeof useClientDataTable<Row>> }) {
  return result.current.table.getRowModel().rows.map((row) => row.original.key)
}

describe('useClientDataTable', () => {
  it('shows every row before any search or filter', () => {
    const { result } = setup()
    expect(visibleKeys(result)).toHaveLength(3)
    expect(result.current.isFiltered).toBe(false)
  })

  it('narrows on a free-text search across the declared fields', () => {
    const { result } = setup()

    act(() => result.current.setSearch('stripe'))
    expect(visibleKeys(result)).toEqual(['STRIPE_KEY'])

    // The search covers tags too, not just the primary column.
    act(() => result.current.setSearch('db'))
    expect(visibleKeys(result).sort()).toEqual(['DATABASE_PASSWORD', 'LEGACY_TOKEN'])
    expect(result.current.isFiltered).toBe(true)
    expect(result.current.matchedCount).toBe(2)
  })

  it('narrows on a filter group and reports it as a chip', () => {
    const { result } = setup()

    act(() => result.current.setFilters({ status: ['archived'] }))
    expect(visibleKeys(result)).toEqual(['LEGACY_TOKEN'])
    expect(result.current.activeFilters).toEqual(['Status: archived'])

    act(() => result.current.clearFilters())
    expect(visibleKeys(result)).toHaveLength(3)
    expect(result.current.activeFilters).toEqual([])
  })

  it('supports selecting several values in one group', () => {
    const { result } = setup()
    act(() => result.current.setFilters({ status: ['active', 'archived'] }))
    expect(visibleKeys(result)).toHaveLength(3)
  })

  it('pulls the page index back when a filter shortens the result set', () => {
    // Page 2 of a 2-per-page list, then filter down to a single row: without the
    // clamp the table renders an empty page that reads as "no matches".
    const { result } = setup({ defaultPageSize: 2 })

    act(() => result.current.table.setPageIndex(1))
    expect(result.current.table.getState().pagination.pageIndex).toBe(1)

    act(() => result.current.setFilters({ status: ['archived'] }))
    expect(result.current.table.getState().pagination.pageIndex).toBe(0)
    expect(visibleKeys(result)).toEqual(['LEGACY_TOKEN'])
  })

  it('keeps search state out of the URL unless a urlKey is given', () => {
    // BrowsePage relies on this: a search term there is a secret key name, and
    // mirroring it into the query string would put it in browser history.
    const { result } = setup()
    act(() => result.current.setSearch('DATABASE'))
    expect(window.location.search).toBe('')
  })
})
