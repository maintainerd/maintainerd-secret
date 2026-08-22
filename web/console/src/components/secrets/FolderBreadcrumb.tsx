import { ChevronRight } from 'lucide-react'
import { breadcrumbTrail } from '@/lib/paths'
import { cn } from '@/lib/utils'

/**
 * Breadcrumb for the folder being browsed.
 *
 * The trail is state, not a URL. Putting a folder path in the address bar would
 * leak the shape of the vault into browser history, the referer header and every
 * proxy log in between — the same reason the service made reveal a POST — so
 * each crumb is a button rather than a link.
 */
export function FolderBreadcrumb({
  path,
  onNavigate,
  className,
}: {
  path: string
  onNavigate: (path: string) => void
  className?: string
}) {
  const trail = breadcrumbTrail(path)

  return (
    <nav aria-label="Folder path" className={cn('min-w-0', className)}>
      <ol className="flex flex-wrap items-center gap-1 text-sm">
        {trail.map((crumb, index) => {
          const last = index === trail.length - 1
          return (
            <li key={crumb.path} className="flex items-center gap-1">
              {index > 0 && (
                <ChevronRight className="size-3.5 text-muted-foreground" aria-hidden="true" />
              )}
              {last ? (
                <span aria-current="page" className="font-medium">
                  {crumb.label}
                </span>
              ) : (
                <button
                  type="button"
                  className="rounded-sm text-muted-foreground underline-offset-2 transition-colors hover:text-foreground hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                  onClick={() => onNavigate(crumb.path)}
                >
                  {crumb.label}
                </button>
              )}
            </li>
          )
        })}
      </ol>
    </nav>
  )
}
