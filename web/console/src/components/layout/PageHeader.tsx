import type { ReactNode } from 'react'
import type { LucideIcon } from 'lucide-react'

interface PageHeaderProps {
  title: string
  /** ReactNode rather than string: several pages inline the current scope. */
  description?: ReactNode
  /** Optional icon rendered to the left of the title. */
  icon?: LucideIcon
  /**
   * Page-level actions rendered on the right of the title row.
   *
   * Auth's PageHeader has no action slot because its listing pages put every
   * action in the ListingToolbar. Secret has page actions that are NOT about the
   * listing below them — "Imports" and "New folder" act on the folder being
   * browsed — so the slot exists here, matching FormPageHeader's `headerActions`.
   */
  actions?: ReactNode
}

export function PageHeader({ title, description, icon: Icon, actions }: PageHeaderProps) {
  return (
    <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
      <div className="flex min-w-0 flex-col gap-2">
        <div className="flex items-center gap-2">
          {Icon && <Icon className="size-5 shrink-0 text-foreground" />}
          <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
        </div>
        {description && <div className="text-sm text-muted-foreground">{description}</div>}
      </div>
      {actions && <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>}
    </div>
  )
}
