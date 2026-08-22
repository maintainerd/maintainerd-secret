import type { ColumnDef } from '@tanstack/react-table'
import { Eye, Info, Pencil, Plus, Trash2 } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { DataTableColumnHeader, RowActions, type RowActionItem } from '@/components/data-table'
import { StatusBadge } from '@/components/badges'
import { formatDateTime, formatRelative, isExpired } from '@/lib/formatDate'
import { normalizePath } from '@/lib/paths'
import type { SecretMeta } from '@/services/api/types'

/**
 * The browse table's columns.
 *
 * EVERY COLUMN HERE IS METADATA. `SecretMeta` — the type `GET /secrets` returns —
 * structurally has no value field, so this file could not render one even if a
 * future edit tried to. Revealing is an explicit row action that goes through a
 * different endpoint, a different grant and its own audit row.
 *
 * Shaped like maintainerd-auth's per-page column modules: a factory taking the
 * page's handlers, sortable headers via `DataTableColumnHeader`, and a
 * declarative `RowActions` menu in the trailing `actions` column.
 */

export interface SecretColumnHandlers {
  onReveal: (secret: SecretMeta) => void
  onDetails: (secret: SecretMeta) => void
  onNewVersion: (secret: SecretMeta) => void
  onEditMetadata: (secret: SecretMeta) => void
  onDelete: (secret: SecretMeta) => Promise<void> | void
}

export function buildSecretColumns(
  handlers: SecretColumnHandlers,
  { showFolder }: { showFolder: boolean },
): ColumnDef<SecretMeta>[] {
  const columns: ColumnDef<SecretMeta>[] = [
    {
      id: 'key',
      accessorKey: 'key',
      header: ({ column }) => <DataTableColumnHeader column={column} title="Key" />,
      cell: ({ row }) => (
        <div className="min-w-0 max-w-72">
          <div className="truncate font-medium">{row.original.key}</div>
          {row.original.description && (
            <div className="truncate text-xs text-muted-foreground">
              {row.original.description}
            </div>
          )}
        </div>
      ),
    },
  ]

  if (showFolder) {
    columns.push({
      id: 'folder',
      accessorFn: (row) => normalizePath(row.folder_path),
      header: ({ column }) => <DataTableColumnHeader column={column} title="Folder" />,
      cell: ({ row }) => (
        <span className="font-mono text-xs text-muted-foreground">
          {normalizePath(row.original.folder_path)}
        </span>
      ),
    })
  }

  columns.push(
    {
      id: 'tags',
      accessorFn: (row) => row.tags.join(', '),
      enableSorting: false,
      header: 'Tags',
      cell: ({ row }) =>
        row.original.tags.length > 0 ? (
          <div className="flex flex-wrap gap-1">
            {row.original.tags.map((tag) => (
              <Badge key={tag} variant="outline" className="text-xs">
                {tag}
              </Badge>
            ))}
          </div>
        ) : (
          <span className="text-muted-foreground">—</span>
        ),
    },
    {
      id: 'version',
      accessorKey: 'current_version',
      header: ({ column }) => <DataTableColumnHeader column={column} title="Version" />,
      cell: ({ row }) => <span className="tabular-nums">v{row.original.current_version}</span>,
    },
    {
      id: 'rotated',
      accessorKey: 'rotated_at',
      header: ({ column }) => <DataTableColumnHeader column={column} title="Rotated" />,
      cell: ({ row }) => (
        <span className="text-sm text-muted-foreground">
          {formatRelative(row.original.rotated_at)}
        </span>
      ),
    },
    {
      id: 'expires',
      accessorKey: 'expires_at',
      header: ({ column }) => <DataTableColumnHeader column={column} title="Expires" />,
      cell: ({ row }) => {
        const expiresAt = row.original.expires_at
        if (!expiresAt) return <span className="text-muted-foreground">—</span>
        // An expired secret gets the shared status pill rather than red text, so
        // "this stopped resolving" reads the same everywhere in the console.
        return isExpired(expiresAt) ? (
          <StatusBadge status="expired" label={`expired ${formatRelative(expiresAt)}`} />
        ) : (
          <span className="text-sm">{formatDateTime(expiresAt)}</span>
        )
      },
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
            key: 'reveal',
            label: 'Reveal value',
            icon: Eye,
            onSelect: () => handlers.onReveal(secret),
          },
          {
            key: 'details',
            label: 'Details',
            icon: Info,
            onSelect: () => handlers.onDetails(secret),
          },
          {
            key: 'new-version',
            label: 'New version',
            icon: Plus,
            separatorBefore: true,
            onSelect: () => handlers.onNewVersion(secret),
          },
          {
            key: 'edit',
            label: 'Edit metadata',
            icon: Pencil,
            onSelect: () => handlers.onEditMetadata(secret),
          },
          {
            key: 'delete',
            label: 'Delete',
            icon: Trash2,
            destructive: true,
            separatorBefore: true,
            onSelect: () => handlers.onDelete(secret),
            confirm: {
              title: `Delete ${secret.key}?`,
              description:
                'This is a soft delete. The secret stops resolving immediately — anything still reading it starts failing right away — but stays restorable from the Deleted page until its destroy date.',
              destructive: true,
              itemName: secret.key,
              confirmText: 'Delete',
            },
          },
        ]
        return <RowActions items={items} />
      },
    },
  )

  return columns
}
