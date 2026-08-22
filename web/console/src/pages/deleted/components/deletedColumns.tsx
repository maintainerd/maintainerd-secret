import type { ColumnDef } from '@tanstack/react-table'
import { RotateCcw, Trash2 } from 'lucide-react'
import { DataTableColumnHeader, RowActions, type RowActionItem } from '@/components/data-table'
import { formatDateTime, formatRelative } from '@/lib/formatDate'
import type { DeletedSecret } from '@/services/api/types'

/** The recovery-window listing, shaped like maintainerd-auth's `*Columns.tsx`. */

export interface DeletedColumnHandlers {
  onRestore: (secret: DeletedSecret) => Promise<void> | void
  onDestroy: (secret: DeletedSecret) => void
}

export function buildDeletedColumns(
  handlers: DeletedColumnHandlers,
): ColumnDef<DeletedSecret>[] {
  return [
    {
      id: 'key',
      accessorKey: 'key',
      header: ({ column }) => <DataTableColumnHeader column={column} title="Key" />,
      cell: ({ row }) => <span className="font-medium">{row.original.key}</span>,
    },
    {
      id: 'folder',
      accessorFn: (row) => row.folder_path || '/',
      header: ({ column }) => <DataTableColumnHeader column={column} title="Folder" />,
      cell: ({ row }) => (
        <span className="font-mono text-xs text-muted-foreground">
          {row.original.folder_path || '/'}
        </span>
      ),
    },
    {
      id: 'version',
      accessorKey: 'current_version',
      header: ({ column }) => <DataTableColumnHeader column={column} title="Version" />,
      cell: ({ row }) => <span className="tabular-nums">v{row.original.current_version}</span>,
    },
    {
      id: 'deleted',
      accessorKey: 'deleted_at',
      header: ({ column }) => <DataTableColumnHeader column={column} title="Deleted" />,
      cell: ({ row }) => (
        <span className="text-sm text-muted-foreground">
          {formatRelative(row.original.deleted_at)}
        </span>
      ),
    },
    {
      id: 'destroy_after',
      accessorKey: 'destroy_after',
      header: ({ column }) => <DataTableColumnHeader column={column} title="Destroy after" />,
      cell: ({ row }) => (
        <span className="text-sm">
          {row.original.destroy_after ? (
            formatDateTime(row.original.destroy_after)
          ) : (
            <span className="text-muted-foreground">—</span>
          )}
        </span>
      ),
    },
    {
      id: 'actions',
      enableHiding: false,
      enableSorting: false,
      header: () => <span className="sr-only">Actions</span>,
      cell: ({ row }) => {
        const secret = row.original
        const items: RowActionItem[] = [
          {
            key: 'restore',
            label: 'Restore',
            icon: RotateCcw,
            onSelect: () => handlers.onRestore(secret),
          },
          {
            key: 'destroy',
            label: 'Destroy permanently',
            icon: Trash2,
            destructive: true,
            separatorBefore: true,
            // Destroy is the one action in this console with no way back, so it
            // gets the page's own type-to-confirm dialog rather than the menu's
            // inline confirm — the copy has to spell out what "permanent" means.
            onSelect: () => handlers.onDestroy(secret),
          },
        ]
        return <RowActions items={items} />
      },
    },
  ]
}
