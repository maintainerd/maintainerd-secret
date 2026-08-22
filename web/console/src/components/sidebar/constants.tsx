import {
  FolderTree,
  Layers,
  ScrollText,
  Trash2,
  Webhook,
  type LucideIcon,
} from 'lucide-react'
import type { ComponentType } from 'react'
import type { NavSection } from './NavMain'

/**
 * The side navigation, in maintainerd-auth's shape.
 *
 * Sections group by what an operator is doing, not by what the API happens to
 * expose: the vault itself, the hierarchy that addresses it, and the operational
 * surfaces (deliveries, recovery, the trail). "Audit log" sits in its own
 * section rather than under Operations because in a vault it is the surface an
 * incident review opens first, and burying it one level down costs a click at
 * exactly the wrong moment.
 */

// Sidenav icons: lucide, wrapped so the active item renders a bolder stroke and
// inactive items a thinner one (mirroring the active/inactive weight used for
// the nav text). Icons inherit the nav item's text color.
const li =
  (IconCmp: LucideIcon): ComponentType<{ className?: string; active?: boolean }> =>
  ({ className, active }) => <IconCmp className={className} strokeWidth={active ? 2.25 : 1.5} />

export const data: { navSections: NavSection[] } = {
  navSections: [
    {
      label: 'Vault',
      items: [
        {
          title: 'Secrets',
          route: '/browse',
          icon: li(FolderTree),
        },
      ],
    },
    {
      label: 'Hierarchy',
      items: [
        {
          title: 'Projects',
          route: '/projects',
          icon: li(Layers),
        },
      ],
    },
    {
      label: 'Operations',
      items: [
        {
          title: 'Webhooks',
          route: '/webhooks',
          icon: li(Webhook),
        },
        {
          title: 'Deleted',
          route: '/deleted',
          icon: li(Trash2),
        },
      ],
    },
    {
      label: 'Compliance',
      items: [
        {
          title: 'Audit log',
          route: '/audit',
          icon: li(ScrollText),
        },
      ],
    },
  ],
}
