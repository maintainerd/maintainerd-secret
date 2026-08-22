import { Folder as FolderIcon, FolderOpen } from 'lucide-react'
import { cn } from '@/lib/utils'
import { ROOT_PATH, folderName, isDescendantOf, normalizePath } from '@/lib/paths'
import type { Folder } from '@/services/api/types'

/**
 * The environment's folder hierarchy.
 *
 * Rendered from the MATERIALIZED PATHS the service returns rather than from a
 * parent/child graph the client assembles: the path is the authoritative shape,
 * and rebuilding a tree from it client-side is one more place for the console's
 * idea of the hierarchy to drift from the vault's.
 *
 * Indentation comes from the path depth, and the list is a `tree` role so a
 * screen reader announces the nesting the indentation implies. The item styling
 * reuses maintainerd-auth's sidebar treatment (`NavMain`'s accent-on-active,
 * muted-on-idle, heavier icon stroke when active) so the tree reads as
 * navigation rather than as a widget of its own.
 */

const itemClass =
  'flex w-full items-center gap-2 rounded-md py-1.5 pr-2 text-left text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring'

const idleClass =
  'text-sidebar-foreground/75 hover:bg-sidebar-accent hover:text-sidebar-accent-foreground'

const activeClass = 'bg-sidebar-accent font-semibold text-sidebar-accent-foreground'

export function FolderTree({
  folders,
  selected,
  onSelect,
}: {
  folders: Folder[]
  selected: string
  onSelect: (path: string) => void
}) {
  const current = normalizePath(selected)
  const paths = [ROOT_PATH, ...folders.map((folder) => normalizePath(folder.path))]
  const unique = Array.from(new Set(paths)).sort((a, b) => a.localeCompare(b))

  return (
    <ul role="tree" aria-label="Folders" className="space-y-0.5">
      {unique.map((path) => {
        const depth = path === ROOT_PATH ? 0 : path.split('/').length - 1
        const active = path === current
        const onTrail = isDescendantOf(current, path)
        return (
          <li key={path} role="none">
            <button
              type="button"
              role="treeitem"
              aria-selected={active}
              aria-level={depth + 1}
              onClick={() => onSelect(path)}
              style={{ paddingLeft: `${depth * 12 + 8}px` }}
              className={cn(itemClass, active ? activeClass : idleClass)}
            >
              {onTrail ? (
                <FolderOpen
                  className="size-4 shrink-0"
                  strokeWidth={active ? 2.25 : 1.5}
                  aria-hidden="true"
                />
              ) : (
                <FolderIcon className="size-4 shrink-0" strokeWidth={1.5} aria-hidden="true" />
              )}
              <span className="truncate">{folderName(path)}</span>
            </button>
          </li>
        )
      })}
    </ul>
  )
}
