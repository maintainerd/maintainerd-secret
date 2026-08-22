import type { ColumnDef } from '@tanstack/react-table'
import { Eye } from 'lucide-react'
import { DataTableColumnHeader } from '@/components/data-table'
import { StatusBadge } from '@/components/badges'
import { cn } from '@/lib/utils'
import { formatDateTime } from '@/lib/formatDate'
import { SENSITIVE_AUDIT_ACTIONS, type AuditEntry } from '@/services/api/types'

/**
 * The audit trail's columns.
 *
 * REVEALS ARE VISUALLY DISTINCT because they are the sensitive event. Reading
 * metadata and reading a value are different grants in this service precisely so
 * an incident review can tell "who listed the secrets" from "who saw the
 * production database password" — a trail that renders both identically throws
 * that distinction away at the last step.
 *
 * `secret.reference` is marked the same way: a reference hop IS a decryption of
 * the target's value, and it is the row that answers "what did this caller
 * actually read" when they only ever revealed a pointer.
 *
 * The marker is an icon plus a bold label plus screen-reader text, never colour
 * alone — the row tint is a reinforcement, not the signal.
 */

/** Row classes that tint a sensitive read and a denial. */
export function auditRowClassName(entry: AuditEntry): string | undefined {
  return (
    cn(
      SENSITIVE_AUDIT_ACTIONS.has(entry.action) && 'bg-amber-50 dark:bg-amber-950/30',
      entry.outcome === 'denied' && 'bg-destructive/10',
    ) || undefined
  )
}

export function buildAuditColumns(): ColumnDef<AuditEntry>[] {
  return [
    {
      id: 'when',
      accessorKey: 'created_at',
      header: ({ column }) => <DataTableColumnHeader column={column} title="When" />,
      cell: ({ row }) => (
        <span className="whitespace-nowrap text-sm">
          {formatDateTime(row.original.created_at)}
        </span>
      ),
    },
    {
      id: 'action',
      accessorKey: 'action',
      header: ({ column }) => <DataTableColumnHeader column={column} title="Action" />,
      cell: ({ row }) => {
        const sensitive = SENSITIVE_AUDIT_ACTIONS.has(row.original.action)
        return (
          <span className="flex items-center gap-1.5">
            {sensitive && (
              <Eye className="size-3.5 text-amber-600 dark:text-amber-400" aria-hidden="true" />
            )}
            <span className={cn('font-mono text-xs', sensitive && 'font-semibold')}>
              {row.original.action}
            </span>
            {sensitive && <span className="sr-only">(a value was read)</span>}
          </span>
        )
      },
    },
    {
      id: 'actor',
      accessorKey: 'actor_subject',
      header: ({ column }) => <DataTableColumnHeader column={column} title="Actor" />,
      cell: ({ row }) => (
        <div className="min-w-0 max-w-56">
          <div className="truncate">{row.original.actor_subject || '—'}</div>
          <div className="text-xs text-muted-foreground">{row.original.actor_kind}</div>
        </div>
      ),
    },
    {
      id: 'resource',
      accessorKey: 'resource_mrn',
      header: ({ column }) => <DataTableColumnHeader column={column} title="Resource" />,
      cell: ({ row }) => (
        <span className="block max-w-96 truncate font-mono text-xs">
          {row.original.resource_mrn}
          {row.original.version ? ` · v${row.original.version}` : ''}
        </span>
      ),
    },
    {
      id: 'outcome',
      accessorKey: 'outcome',
      header: ({ column }) => <DataTableColumnHeader column={column} title="Outcome" />,
      cell: ({ row }) => (
        <div className="space-y-1">
          <StatusBadge
            status={
              row.original.outcome === 'success'
                ? 'active'
                : row.original.outcome === 'denied'
                  ? 'blocked'
                  : 'pending'
            }
            label={row.original.outcome}
          />
          {row.original.reason && (
            <div className="text-xs text-muted-foreground">{row.original.reason}</div>
          )}
        </div>
      ),
    },
  ]
}
