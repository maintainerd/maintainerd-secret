import { ChevronRight } from 'lucide-react'
import { breadcrumbTrail } from '@/lib/paths'

/** Breadcrumb for the folder being browsed. */
export function FolderBreadcrumb({
  path,
  onNavigate,
}: {
  path: string
  onNavigate: (path: string) => void
}) {
  const trail = breadcrumbTrail(path)

  return (
    <nav aria-label="Folder path">
      <ol className="flex flex-wrap items-center gap-1 text-sm">
        {trail.map((crumb, index) => {
          const last = index === trail.length - 1
          return (
            <li key={crumb.path} className="flex items-center gap-1">
              {index > 0 ? (
                <ChevronRight className="size-3.5 text-muted-foreground" aria-hidden="true" />
              ) : null}
              {last ? (
                <span aria-current="page" className="font-medium">
                  {crumb.label}
                </span>
              ) : (
                <button
                  type="button"
                  className="text-muted-foreground underline-offset-2 hover:text-foreground hover:underline"
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
