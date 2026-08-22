import type { ColumnDef } from '@tanstack/react-table'
import { ListChecks, Trash2 } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { DataTableColumnHeader, RowActions, type RowActionItem } from '@/components/data-table'
import { StatusBadge } from '@/components/badges'
import { formatRelative } from '@/lib/formatDate'
import type { WebhookEndpoint } from '@/services/api/types'

/** The webhook-endpoint listing, shaped like maintainerd-auth's `*Columns.tsx`. */

export interface WebhookColumnHandlers {
  onOpen: (endpoint: WebhookEndpoint) => void
  onDelete: (endpoint: WebhookEndpoint) => Promise<void> | void
}

export function buildWebhookColumns(
  handlers: WebhookColumnHandlers,
): ColumnDef<WebhookEndpoint>[] {
  return [
    {
      id: 'url',
      accessorKey: 'url',
      header: ({ column }) => <DataTableColumnHeader column={column} title="URL" />,
      cell: ({ row }) => (
        <div className="min-w-0 max-w-80">
          <div className="truncate font-mono text-sm font-medium">{row.original.url}</div>
          {row.original.description && (
            <div className="truncate text-xs text-muted-foreground">
              {row.original.description}
            </div>
          )}
        </div>
      ),
    },
    {
      id: 'events',
      accessorFn: (row) => row.events.join(', '),
      enableSorting: false,
      header: 'Events',
      cell: ({ row }) => (
        <div className="flex flex-wrap gap-1">
          {row.original.events.length === 0 ? (
            <Badge variant="outline" className="text-xs">
              all
            </Badge>
          ) : (
            row.original.events.map((event) => (
              <Badge key={event} variant="outline" className="text-xs">
                {event}
              </Badge>
            ))
          )}
        </div>
      ),
    },
    {
      id: 'status',
      accessorKey: 'status',
      header: ({ column }) => <DataTableColumnHeader column={column} title="Status" />,
      cell: ({ row }) => <StatusBadge status={row.original.status} />,
    },
    {
      id: 'last_triggered',
      accessorKey: 'last_triggered_at',
      header: ({ column }) => <DataTableColumnHeader column={column} title="Last triggered" />,
      cell: ({ row }) => (
        <span className="text-sm text-muted-foreground">
          {formatRelative(row.original.last_triggered_at)}
        </span>
      ),
    },
    {
      id: 'actions',
      enableHiding: false,
      enableSorting: false,
      header: () => <span className="sr-only">Actions</span>,
      cell: ({ row }) => {
        const endpoint = row.original
        const items: RowActionItem[] = [
          {
            key: 'deliveries',
            label: 'Deliveries',
            icon: ListChecks,
            onSelect: () => handlers.onOpen(endpoint),
          },
          {
            key: 'delete',
            label: 'Delete',
            icon: Trash2,
            destructive: true,
            separatorBefore: true,
            onSelect: () => handlers.onDelete(endpoint),
            confirm: {
              title: 'Delete this endpoint?',
              description:
                'Consumers stop being told when a secret in this project changes or rotates. They will keep using a stale value until they re-read on their own.',
              destructive: true,
              itemName: endpoint.url,
              confirmText: 'Delete endpoint',
            },
          },
        ]
        return <RowActions items={items} />
      },
    },
  ]
}
