import { NavLink, Outlet } from 'react-router-dom'
import {
  FolderTree,
  KeyRound,
  LogOut,
  ScrollText,
  ShieldAlert,
  Trash2,
  Webhook,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { cn } from '@/lib/utils'
import { useAuth } from '@/auth/authContext'
import { ScopeSwitcher } from './ScopeSwitcher'

const NAV = [
  { to: '/browse', label: 'Secrets', icon: FolderTree },
  { to: '/projects', label: 'Projects', icon: KeyRound },
  { to: '/webhooks', label: 'Webhooks', icon: Webhook },
  { to: '/deleted', label: 'Deleted', icon: Trash2 },
  { to: '/audit', label: 'Audit log', icon: ScrollText },
]

/**
 * The signed-in shell.
 *
 * The guard-open banner is PERMANENT and not dismissible. A vault whose API
 * serves unauthenticated callers as a blanket-granted principal is safe only as
 * a development convenience, and the one way that becomes dangerous is somebody
 * forgetting it is on.
 */
export function AppShell() {
  const { mode, signOut, identity } = useAuth()

  return (
    <div className="flex min-h-screen bg-background">
      <aside className="hidden w-56 shrink-0 border-r bg-sidebar p-4 md:block">
        <div className="mb-6 flex items-center gap-2">
          <KeyRound className="size-5 text-primary" aria-hidden="true" />
          <div className="leading-tight">
            <p className="text-sm font-semibold">maintainerd</p>
            <p className="text-xs text-muted-foreground">secret</p>
          </div>
        </div>
        <nav aria-label="Main">
          <ul className="space-y-1">
            {NAV.map((item) => (
              <li key={item.to}>
                <NavLink
                  to={item.to}
                  className={({ isActive }) =>
                    cn(
                      'flex items-center gap-2 rounded-md px-3 py-2 text-sm transition-colors',
                      isActive
                        ? 'bg-sidebar-accent font-medium text-sidebar-accent-foreground'
                        : 'text-muted-foreground hover:bg-sidebar-accent/60 hover:text-foreground',
                    )
                  }
                >
                  <item.icon className="size-4" aria-hidden="true" />
                  {item.label}
                </NavLink>
              </li>
            ))}
          </ul>
        </nav>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex flex-wrap items-center justify-between gap-3 border-b px-6 py-3">
          <ScopeSwitcher />
          <div className="flex items-center gap-2">
            {mode === 'authenticated' && identity ? (
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="outline" size="sm">
                    Signed in
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                  <DropdownMenuLabel className="text-xs font-normal text-muted-foreground">
                    Session held in memory only
                  </DropdownMenuLabel>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem onSelect={() => signOut()}>
                    <LogOut className="size-4" aria-hidden="true" />
                    Sign out
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            ) : null}
          </div>
        </header>

        {mode === 'guard-open' ? (
          <div
            className="flex items-start gap-2 border-b border-destructive/40 bg-destructive/10 px-6 py-2 text-sm"
            role="status"
          >
            <ShieldAlert className="mt-0.5 size-4 shrink-0 text-destructive" aria-hidden="true" />
            <p>
              <span className="font-medium">No identity is configured.</span> This console is
              calling the API without a bearer token, which only works while the service runs in
              development-open mode — where it serves every caller as a blanket-granted principal.
              Never point this build at a production vault.
            </p>
          </div>
        ) : null}

        <main className="min-w-0 flex-1 p-6">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
