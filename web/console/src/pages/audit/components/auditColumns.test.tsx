import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import {
  flexRender,
  getCoreRowModel,
  useReactTable,
  type ColumnDef,
} from '@tanstack/react-table'
import { auditRowClassName, buildAuditColumns } from './auditColumns'
import type { AuditEntry } from '@/services/api/types'

function entry(overrides: Partial<AuditEntry> = {}): AuditEntry {
  return {
    event_uuid: 'e1',
    actor_subject: 'ops@example.com',
    actor_kind: 'user',
    action: 'secret.list',
    resource_mrn: 'mrn:secret:acme:secret/app/prod',
    outcome: 'success',
    created_at: '2026-02-01T10:00:00Z',
    ...overrides,
  }
}

function Harness({ rows, columns }: { rows: AuditEntry[]; columns: ColumnDef<AuditEntry>[] }) {
  const table = useReactTable({ data: rows, columns, getCoreRowModel: getCoreRowModel() })
  return (
    <table>
      <tbody>
        {table.getRowModel().rows.map((row) => (
          <tr key={row.id} className={auditRowClassName(row.original)}>
            {row.getVisibleCells().map((cell) => (
              <td key={cell.id}>{flexRender(cell.column.columnDef.cell, cell.getContext())}</td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  )
}

/**
 * The audit trail's whole point is that "who listed the secrets" and "who saw
 * the production database password" are different rows. A trail that renders
 * both identically throws that distinction away at the last step.
 */
describe('audit columns', () => {
  it.each(['secret.reveal', 'secret.reference'])(
    'marks %s as a value read, in text and not only in colour',
    (action) => {
      const { container } = render(
        <Harness rows={[entry({ action })]} columns={buildAuditColumns()} />,
      )

      expect(screen.getByText('(a value was read)')).toBeInTheDocument()
      expect(screen.getByText(action).className).toMatch(/font-semibold/)
      expect(container.querySelector('tr')?.className).toMatch(/amber/)
    },
  )

  it('leaves a metadata read unmarked', () => {
    const { container } = render(
      <Harness rows={[entry({ action: 'secret.list' })]} columns={buildAuditColumns()} />,
    )

    expect(screen.queryByText('(a value was read)')).not.toBeInTheDocument()
    expect(container.querySelector('tr')?.className ?? '').not.toMatch(/amber/)
  })

  it('tints a denial', () => {
    const { container } = render(
      <Harness
        rows={[entry({ outcome: 'denied', reason: 'missing secret:GetSecret' })]}
        columns={buildAuditColumns()}
      />,
    )

    expect(container.querySelector('tr')?.className).toMatch(/destructive/)
    expect(screen.getByText('denied')).toBeInTheDocument()
    expect(screen.getByText('missing secret:GetSecret')).toBeInTheDocument()
  })

  it('shows the version alongside the resource when the event has one', () => {
    render(<Harness rows={[entry({ version: 7 })]} columns={buildAuditColumns()} />)
    expect(screen.getByText(/· v7/)).toBeInTheDocument()
  })
})
