import { describe, expect, it, vi } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { ColumnDef, SortingState } from '@tanstack/react-table'
import { renderWithProviders } from '@/test/utils'
import { ResourceListing } from './ResourceListing'
import { DataTableColumnHeader } from './DataTableColumnHeader'
import type { FilterGroup } from './useClientDataTable'

interface Row {
  id: string
  name: string
  status: string
}

const COLUMNS: ColumnDef<Row>[] = [
  {
    id: 'name',
    accessorKey: 'name',
    header: ({ column }) => <DataTableColumnHeader column={column} title="Name" />,
    cell: ({ row }) => row.original.name,
  },
]
const DEFAULT_SORT: SortingState = [{ id: 'name', desc: false }]
const FILTER_GROUPS: readonly FilterGroup[] = [
  { key: 'status', label: 'Status', options: ['active', 'inactive'] },
]
const SEARCH_FIELDS = (row: Row) => [row.name]

const ROWS: Row[] = [
  { id: '1', name: 'Alice', status: 'active' },
  { id: '2', name: 'Bob', status: 'inactive' },
]

const u = () => userEvent.setup({ pointerEventsCheck: 0 })

/** The bordered table card `tableInCard` puts the table inside. */
function tableShell(): HTMLElement | null {
  return document.querySelector('[data-md-table-shell]')
}

/**
 * The listing shell, held to maintainerd-auth's shape.
 *
 * These are structure assertions on purpose. The components were already auth's —
 * `DataTable`, `ListingToolbar`, `DataTablePagination` and `DataTableEmpty` are
 * byte-identical between the two consoles — but every listing page in secret was
 * composing them the OTHER way round from auth's seventeen: no `tableInCard`, so
 * the table went full-bleed and unbordered inside one page-wide card that also
 * swallowed the toolbar and the pagination. Identical parts, different assembly,
 * which is exactly the sort of drift a rendered-output test catches and a
 * component-level test does not.
 */
describe('ResourceListing tableInCard shell', () => {
  it('puts the table in its own bordered card', () => {
    renderWithProviders(
      <ResourceListing<Row>
        tableInCard
        rows={ROWS}
        columns={COLUMNS}
        defaultSort={DEFAULT_SORT}
        searchFields={SEARCH_FIELDS}
        searchPlaceholder="Search..."
      />,
    )

    const shell = tableShell()
    expect(shell).not.toBeNull()
    expect(shell?.className).toContain('border')
    expect(shell?.querySelector('table')).not.toBeNull()
  })

  it('keeps the toolbar and the pagination OUTSIDE that card', () => {
    renderWithProviders(
      <ResourceListing<Row>
        tableInCard
        rows={ROWS}
        columns={COLUMNS}
        defaultSort={DEFAULT_SORT}
        searchFields={SEARCH_FIELDS}
        searchPlaceholder="Search..."
      />,
    )

    const shell = tableShell()
    // This is the whole visual difference from the old composition: the search box
    // and the pager sit on the page background, not inside the table's frame.
    expect(shell?.contains(screen.getByPlaceholderText('Search...'))).toBe(false)
    expect(shell?.contains(screen.getByText(/rows per page/i))).toBe(false)
  })

  it('bleeds the table to the card edges when tableInCard is off', () => {
    renderWithProviders(
      <ResourceListing<Row>
        rows={ROWS}
        columns={COLUMNS}
        defaultSort={DEFAULT_SORT}
        searchFields={SEARCH_FIELDS}
        searchPlaceholder="Search..."
      />,
    )

    // The other branch is still supported (it is what a listing inside a
    // PageContainer card needs) — it just is not what the listing PAGES use.
    expect(tableShell()).toBeNull()
    expect(document.querySelector('.-mx-6')).not.toBeNull()
  })
})

describe('ResourceListing state', () => {
  it('sorts on a column header and reverses on a second click', async () => {
    const user = u()
    renderWithProviders(
      <ResourceListing<Row>
        tableInCard
        rows={ROWS}
        columns={COLUMNS}
        defaultSort={DEFAULT_SORT}
        searchFields={SEARCH_FIELDS}
        searchPlaceholder="Search..."
      />,
    )

    const bodyNames = () =>
      Array.from(document.querySelectorAll('tbody tr')).map((row) => row.textContent)

    expect(bodyNames()).toEqual(['Alice', 'Bob'])
    await user.click(screen.getByRole('button', { name: /name/i }))
    await waitFor(() => expect(bodyNames()).toEqual(['Bob', 'Alice']))
  })

  it('pages through the rows and reports the range', async () => {
    const user = u()
    renderWithProviders(
      <ResourceListing<Row>
        tableInCard
        rows={ROWS}
        columns={COLUMNS}
        defaultSort={DEFAULT_SORT}
        searchFields={SEARCH_FIELDS}
        searchPlaceholder="Search..."
        defaultPageSize={1}
      />,
    )

    expect(screen.getByText(/1-1 of 2 results/)).toBeInTheDocument()
    expect(screen.getByText('Alice')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: /go to next page/i }))
    await waitFor(() => expect(screen.getByText('Bob')).toBeInTheDocument())
    expect(screen.getByText(/2-2 of 2 results/)).toBeInTheDocument()
  })

  it('offers the create CTA on a genuinely empty listing', () => {
    const onCreate = vi.fn()
    renderWithProviders(
      <ResourceListing<Row>
        tableInCard
        rows={[]}
        columns={COLUMNS}
        defaultSort={DEFAULT_SORT}
        searchFields={SEARCH_FIELDS}
        searchPlaceholder="Search..."
        onCreate={onCreate}
        createLabel="New thing"
        emptyTitle="Nothing yet"
        emptyDescription="Make one."
      />,
    )

    expect(screen.getByText('Nothing yet')).toBeInTheDocument()
    expect(screen.getByText('Make one.')).toBeInTheDocument()
  })

  it('offers a reset — not the create CTA — when a search hid every row', async () => {
    const user = u()
    renderWithProviders(
      <ResourceListing<Row>
        tableInCard
        rows={ROWS}
        columns={COLUMNS}
        defaultSort={DEFAULT_SORT}
        searchFields={SEARCH_FIELDS}
        searchPlaceholder="Search..."
        filterGroups={FILTER_GROUPS}
        onCreate={vi.fn()}
        createLabel="New thing"
        emptyTitle="Nothing yet"
      />,
    )

    const input = screen.getByPlaceholderText('Search...')
    await user.type(input, 'zzz')

    // "Rows exist but are hidden" and "there are no rows" are different answers and
    // must not share an empty state — offering "create one" to somebody whose search
    // simply missed is how a listing teaches an operator to distrust it.
    await waitFor(() => expect(screen.getByText('No results found')).toBeInTheDocument())
    expect(screen.queryByText('Nothing yet')).not.toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: /clear search & filters/i }))
    await waitFor(() => expect(input).toHaveValue(''))
    expect(screen.getByText('Alice')).toBeInTheDocument()
  })
})
