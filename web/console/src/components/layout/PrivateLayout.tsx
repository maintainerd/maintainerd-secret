import type { CSSProperties } from 'react'
import { Outlet } from 'react-router-dom'
import { ShieldAlert } from 'lucide-react'
import { AppSidebar } from '@/components/sidebar/AppSideBar'
import { AppTopNav } from '@/components/navigation/AppTopNav'
import { ScopeSwitcher } from '@/components/navigation/ScopeSwitcher'
import { SidebarProvider, SidebarInset } from '@/components/ui/sidebar'
import { useAuth } from '@/auth/authContext'
import { cn } from '@/lib/utils'

interface PrivateLayoutProps {
  fullWidth?: boolean
}

/**
 * The signed-in chrome: brand bar across the top, sidebar and content beneath.
 *
 * Copied from maintainerd-auth's `components/layout/PrivateLayout.tsx` — same
 * 17rem sidebar, same `pt-14` inset, same max-w-6xl content column — with one
 * addition that is not cosmetic:
 *
 * THE GUARD-OPEN BANNER IS PERMANENT AND NOT DISMISSIBLE. A vault whose API
 * serves unauthenticated callers as a blanket-granted principal is safe only as
 * a development convenience, and the one way that becomes dangerous is somebody
 * forgetting it is on. It renders inside the content inset (below the fixed bar)
 * so it cannot be scrolled away from either.
 *
 * Access gating (auth, setup completion, scope) is handled by the route tree in
 * App.tsx; this layout only renders chrome.
 */
export function PrivateLayout({ fullWidth = false }: PrivateLayoutProps) {
  const { mode } = useAuth()

  return (
    <div className="min-h-svh bg-background">
      <SidebarProvider style={{ '--sidebar-width': '17rem' } as CSSProperties}>
        <AppTopNav />
        <AppSidebar variant="sidebar" />
        <SidebarInset className="min-w-0 bg-background pt-14">
          {mode === 'guard-open' && (
            <div
              role="status"
              className="flex items-start gap-2 border-b border-destructive/40 bg-destructive/10 px-4 py-2 text-sm sm:px-6"
            >
              <ShieldAlert
                className="mt-0.5 size-4 shrink-0 text-destructive"
                aria-hidden="true"
              />
              <p>
                <span className="font-medium">No identity is configured.</span> This console is
                calling the API without a bearer token, which only works while the service runs in
                development-open mode — where it serves every caller as a blanket-granted
                principal. Never point this build at a production vault.
              </p>
            </div>
          )}

          {/* The scope switcher lives in the brand bar at md+; below that the bar
              is too narrow for two comboboxes, so it moves here rather than
              disappearing — "which environment is this" must never be unanswerable. */}
          <div className="border-b px-4 py-2 md:hidden">
            <ScopeSwitcher className="[&_button]:border-border [&_button]:bg-background [&_button]:text-foreground" />
          </div>

          <main
            className={cn(
              'flex-1 px-4 py-6 sm:px-6 sm:py-8',
              !fullWidth && 'mx-auto w-full max-w-6xl',
            )}
          >
            <Outlet />
          </main>
        </SidebarInset>
      </SidebarProvider>
    </div>
  )
}
