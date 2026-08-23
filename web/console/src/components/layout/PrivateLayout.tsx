import type { CSSProperties } from 'react'
import { Outlet } from 'react-router-dom'
import { ShieldAlert } from 'lucide-react'
import { AppSidebar } from '@/components/sidebar/AppSideBar'
import { AppTopNav } from '@/components/navigation/AppTopNav'
import { ScopeSwitcher } from '@/components/navigation/ScopeSwitcher'
import { SidebarProvider, SidebarInset } from '@/components/ui/sidebar'
import { useAuth } from '@/auth/authContext'

/**
 * The signed-in chrome: brand bar across the top, sidebar and content beneath.
 *
 * Copied from maintainerd-auth's `components/layout/PrivateLayout.tsx` — same
 * 17rem sidebar, same `pt-14` inset — with one addition that is not cosmetic:
 *
 * THE GUARD-OPEN BANNER IS PERMANENT AND NOT DISMISSIBLE. A vault whose API
 * serves unauthenticated callers as a blanket-granted principal is safe only as
 * a development convenience, and the one way that becomes dangerous is somebody
 * forgetting it is on. It renders inside the content inset (below the fixed bar)
 * so it cannot be scrolled away from either.
 *
 * IT NOW SAYS WHAT THE SERVICE REPORTED, not what this console guessed. The
 * banner used to be shown whenever the console had no identity configuration,
 * which conflated two opposite states — see `authContext.ts`. `identity-missing`
 * gets its own banner and its own text, because "no token is needed" and "a token
 * is required and I cannot get one" must not read the same.
 *
 * THERE IS NO `fullWidth` PROP, AND THIS MOUNTS EXACTLY ONCE. It used to take
 * one, and App.tsx declared the layout TWICE — `<PrivateLayout fullWidth/>` for
 * /browse and `<PrivateLayout/>` for everything else. Two `element=` positions in
 * the route tree are two component instances, so crossing between /browse and any
 * other route unmounted this whole subtree and mounted the other: the
 * `SidebarProvider` was recreated (a collapsed rail sprang back open), and the
 * sidebar container remounted mid-animation, replaying its 200ms
 * `transition-[left,right,width]` from scratch. That is the "sticking" — it looked
 * intermittent only because it happened on some navigations and not others.
 *
 * The width fix is auth's own: auth mounts this layout once and always
 * full-width, and its LISTING PAGES own `mx-auto max-w-6xl` (see
 * `pages/tenants/TenantsPage.tsx`). Capping here as well double-capped every page
 * that already capped itself, insetting secret's tables by the main element's
 * padding. Pages that want the centred column ask for it; /browse simply does not.
 *
 * Access gating (auth, setup completion, scope) is handled by the route tree in
 * App.tsx; this layout only renders chrome.
 */
export function PrivateLayout() {
  const { mode, capabilities } = useAuth()

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
                <span className="font-medium">
                  This vault reports its guard is development-open.
                </span>{' '}
                It serves every caller as a blanket-granted principal, so this console is calling
                the API without a bearer token — and so is anything else that can reach it. Never
                run a production vault in this mode.
              </p>
            </div>
          )}

          {mode === 'identity-missing' && (
            <div
              role="status"
              className="flex items-start gap-2 border-b border-destructive/40 bg-destructive/10 px-4 py-2 text-sm sm:px-6"
            >
              <ShieldAlert
                className="mt-0.5 size-4 shrink-0 text-destructive"
                aria-hidden="true"
              />
              <p>
                <span className="font-medium">
                  This vault enforces authentication and this console has no identity configured.
                </span>{' '}
                Every request will be refused until{' '}
                <code>SECRET_CONSOLE_CLIENT_ID</code>, <code>AUTH_ISSUER</code> and{' '}
                <code>SECRET_CONSOLE_TOKEN_URL</code> are set for this build.
                {capabilities?.auth ? (
                  <>
                    {' '}
                    The service expects tokens from <code>{capabilities.auth.issuer}</code> for
                    audience <code>{capabilities.auth.audience}</code>.
                  </>
                ) : null}
              </p>
            </div>
          )}

          {/* The scope switcher lives in the brand bar at md+; below that the bar
              is too narrow for two comboboxes, so it moves here rather than
              disappearing — "which environment is this" must never be unanswerable. */}
          <div className="border-b px-4 py-2 md:hidden">
            <ScopeSwitcher className="[&_button]:border-border [&_button]:bg-background [&_button]:text-foreground" />
          </div>

          <main className="flex-1 px-4 py-6 sm:px-6 sm:py-8">
            <Outlet />
          </main>
        </SidebarInset>
      </SidebarProvider>
    </div>
  )
}
