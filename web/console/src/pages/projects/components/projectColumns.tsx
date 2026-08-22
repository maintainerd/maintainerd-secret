import type { ColumnDef } from '@tanstack/react-table'
import { FolderTree, Settings2, Trash2 } from 'lucide-react'
import { DataTableColumnHeader, RowActions, type RowActionItem } from '@/components/data-table'
import { StatusBadge } from '@/components/badges'
import { formatDateTime } from '@/lib/formatDate'
import type { Project } from '@/services/api/types'

/** The projects listing, shaped like maintainerd-auth's `*Columns.tsx` files. */

export interface ProjectColumnHandlers {
  onOpen: (project: Project) => void
  onBrowse: (project: Project) => void
  onDelete: (project: Project) => Promise<void> | void
}

export function buildProjectColumns(handlers: ProjectColumnHandlers): ColumnDef<Project>[] {
  return [
    {
      id: 'slug',
      accessorKey: 'slug',
      header: ({ column }) => <DataTableColumnHeader column={column} title="Slug" />,
      cell: ({ row }) => <span className="font-mono font-medium">{row.original.slug}</span>,
    },
    {
      id: 'name',
      accessorKey: 'name',
      header: ({ column }) => <DataTableColumnHeader column={column} title="Name" />,
      cell: ({ row }) => (
        <div className="min-w-0 max-w-72">
          <div className="truncate">{row.original.name || '—'}</div>
          {row.original.description && (
            <div className="truncate text-xs text-muted-foreground">
              {row.original.description}
            </div>
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
      id: 'created',
      accessorKey: 'created_at',
      header: ({ column }) => <DataTableColumnHeader column={column} title="Created" />,
      cell: ({ row }) => (
        <span className="text-sm text-muted-foreground">
          {formatDateTime(row.original.created_at)}
        </span>
      ),
    },
    {
      id: 'actions',
      enableHiding: false,
      enableSorting: false,
      header: () => <span className="sr-only">Actions</span>,
      cell: ({ row }) => {
        const project = row.original
        const items: RowActionItem[] = [
          {
            key: 'environments',
            label: 'Environments',
            icon: Settings2,
            onSelect: () => handlers.onOpen(project),
          },
          {
            key: 'browse',
            label: 'Browse secrets',
            icon: FolderTree,
            onSelect: () => handlers.onBrowse(project),
          },
          {
            key: 'delete',
            label: 'Delete',
            icon: Trash2,
            destructive: true,
            separatorBefore: true,
            onSelect: () => handlers.onDelete(project),
            confirm: {
              title: `Delete project ${project.slug}?`,
              description:
                'Everything addressed under this project stops resolving. Any grant written against its MRN becomes dead, and the slug stays reserved forever.',
              destructive: true,
              itemName: project.slug,
              confirmText: 'Delete project',
            },
          },
        ]
        return <RowActions items={items} />
      },
    },
  ]
}
