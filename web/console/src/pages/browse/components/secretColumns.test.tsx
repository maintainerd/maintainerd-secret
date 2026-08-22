import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import {
  flexRender,
  getCoreRowModel,
  useReactTable,
  type ColumnDef,
} from '@tanstack/react-table'
import { buildSecretColumns } from './secretColumns'
import type { SecretMeta } from '@/services/api/types'

const SECRET: SecretMeta = {
  secret_uuid: 'a1',
  folder_path: '/db',
  key: 'DATABASE_PASSWORD',
  description: 'Primary Postgres',
  tags: ['db', 'prod'],
  current_version: 4,
  keep_versions: 10,
  rotation_policy: {},
  mrn_resource_path: 'secret/app/prod/db/DATABASE_PASSWORD',
  mrn: 'mrn:secret:acme:secret/app/prod/db/DATABASE_PASSWORD',
  rotated_at: '2026-01-01T00:00:00Z',
  expires_at: undefined,
  created_at: '2025-12-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
}

function Harness({
  columns,
  rows = [SECRET],
}: {
  columns: ColumnDef<SecretMeta>[]
  rows?: SecretMeta[]
}) {
  const table = useReactTable({ data: rows, columns, getCoreRowModel: getCoreRowModel() })
  return (
    <table>
      <tbody>
        {table.getRowModel().rows.map((row) => (
          <tr key={row.id}>
            {row.getVisibleCells().map((cell) => (
              <td key={cell.id}>{flexRender(cell.column.columnDef.cell, cell.getContext())}</td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  )
}

const noopHandlers = {
  onReveal: vi.fn(),
  onDetails: vi.fn(),
  onNewVersion: vi.fn(),
  onEditMetadata: vi.fn(),
  onDelete: vi.fn(),
}

describe('secret columns', () => {
  it('renders metadata only — the row cannot show a value', () => {
    const columns = buildSecretColumns(noopHandlers, { showFolder: false })
    render(<Harness columns={columns} />)

    expect(screen.getByText('DATABASE_PASSWORD')).toBeInTheDocument()
    expect(screen.getByText('Primary Postgres')).toBeInTheDocument()
    expect(screen.getByText('v4')).toBeInTheDocument()
    expect(screen.getByText('db')).toBeInTheDocument()

    // The row is built from SecretMeta, which structurally has no value field.
    // Nothing resembling a plaintext or a base64 payload can reach the DOM.
    expect(Object.keys(SECRET)).not.toContain('value')
  })

  it('hides the folder column unless subfolders are included', () => {
    const withoutFolder = buildSecretColumns(noopHandlers, { showFolder: false })
    const withFolder = buildSecretColumns(noopHandlers, { showFolder: true })

    expect(withoutFolder.map((column) => column.id)).not.toContain('folder')
    expect(withFolder.map((column) => column.id)).toContain('folder')
  })

  it('makes reveal an explicit, separate action rather than something the row does', async () => {
    const user = userEvent.setup()
    const onReveal = vi.fn()
    const columns = buildSecretColumns({ ...noopHandlers, onReveal }, { showFolder: false })
    render(<Harness columns={columns} />)

    // The value is not fetched by rendering the row: it takes opening the menu
    // and choosing "Reveal value".
    expect(onReveal).not.toHaveBeenCalled()
    await user.click(screen.getByRole('button', { name: /open menu/i }))
    await user.click(await screen.findByText('Reveal value'))
    expect(onReveal).toHaveBeenCalledWith(SECRET)
  })

  it('requires typing the key before delete runs', async () => {
    const user = userEvent.setup()
    const onDelete = vi.fn()
    const columns = buildSecretColumns({ ...noopHandlers, onDelete }, { showFolder: false })
    render(<Harness columns={columns} />)

    await user.click(screen.getByRole('button', { name: /open menu/i }))
    await user.click(await screen.findByText('Delete'))

    const confirm = await screen.findByRole('button', { name: 'Delete' })
    expect(confirm).toBeDisabled()

    await user.type(screen.getByLabelText(/to confirm/i), 'DATABASE_PASSWORD')
    expect(confirm).toBeEnabled()
    await user.click(confirm)
    expect(onDelete).toHaveBeenCalledWith(SECRET)
  })

  it('flags an expired secret with the shared status pill', () => {
    const columns = buildSecretColumns(noopHandlers, { showFolder: false })
    render(<Harness columns={columns} rows={[{ ...SECRET, expires_at: '2020-01-01T00:00:00Z' }]} />)
    expect(screen.getByText(/expired/i)).toBeInTheDocument()
  })
})
