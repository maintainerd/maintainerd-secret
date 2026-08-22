import {
  BookOpen,
  ChevronDown,
  Code2,
  HelpCircle,
  LogOut,
  ShieldAlert,
  ShieldCheck,
  UserRound,
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
import { Avatar, AvatarFallback } from '@/components/ui/avatar'
import { SidebarTrigger } from '@/components/ui/sidebar'
import { BrandLockup } from '@/components/brand/BrandLockup'
import { ScopeSwitcher } from '@/components/navigation/ScopeSwitcher'
import { useAuth } from '@/auth/authContext'

const resourceLinks = [
  { title: 'Documentation', icon: BookOpen, href: 'https://maintainerd.github.io' },
  { title: 'API Reference', icon: Code2, href: 'https://maintainerd.github.io' },
]

/**
 * The fixed brand bar.
 *
 * This is maintainerd-auth's `components/navigation/AppTopNav.tsx`: the same
 * slate-950 bar, the same 14-unit height the sidebar offsets against, the same
 * ghost controls on `bg-white/5`. Three things differ, and each is a
 * secret-domain fact rather than a style choice:
 *
 *  - The tenant switcher becomes the project/environment scope switcher.
 *  - There is no user profile to fetch. The console holds an opaque access token
 *    in memory and never calls a userinfo endpoint, so the session menu says
 *    what it can honestly say — that a session is held, in memory only — rather
 *    than inventing a display name.
 *  - The guard mode is surfaced as a chip. A vault whose API answers anonymous
 *    callers is safe only as a development convenience, and the one way that
 *    becomes dangerous is somebody forgetting it is on.
 */
export function AppTopNav() {
  const { mode, signOut } = useAuth()
  const guardOpen = mode === 'guard-open'

  return (
    <header
      data-console-top-panel
      className="fixed inset-x-0 top-0 z-30 flex h-14 items-center border-b border-[#1e293b] bg-[#0f172a] px-4 text-white sm:px-6"
    >
      <div className="flex min-w-0 flex-1 items-center gap-3">
        <SidebarTrigger
          data-console-top-control
          className="size-10 bg-white/5 text-slate-300 hover:bg-white/10 hover:text-white active:!bg-white/15 active:!text-white"
        />
        {/* The transparent mark, not the plated app icon: the bar is slate-950,
            and a white icon plate would read as a sticker on it. The label drops
            below sm, leaving the mark alone — auth's collapsed treatment. */}
        <BrandLockup
          asset="mark"
          orientation="inline"
          iconSize={28}
          onDark
          className="gap-2"
          labelClassName="hidden sm:block"
        />
        <div className="ml-2 hidden items-center gap-2 md:flex lg:ml-6">
          <ScopeSwitcher />
        </div>
      </div>

      <div className="ml-3 flex shrink-0 items-center gap-1.5">
        <span
          data-console-top-control
          role="status"
          className={
            guardOpen
              ? 'hidden items-center gap-1.5 rounded-md border border-destructive/60 bg-destructive/20 px-2 py-1 text-xs font-medium text-red-200 sm:inline-flex'
              : 'hidden items-center gap-1.5 rounded-md border border-slate-700 bg-white/5 px-2 py-1 text-xs font-medium text-slate-300 sm:inline-flex'
          }
        >
          {guardOpen ? (
            <ShieldAlert className="size-3.5" aria-hidden="true" />
          ) : (
            <ShieldCheck className="size-3.5" aria-hidden="true" />
          )}
          {guardOpen ? 'Guard open' : 'Guarded'}
        </span>

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              data-console-top-control
              variant="ghost"
              size="icon"
              aria-label="Help & resources"
              className="bg-white/5 text-slate-300 hover:bg-white/10 hover:text-white active:!bg-white/15 active:!text-white data-[state=open]:!bg-white/15 data-[state=open]:!text-white"
            >
              <HelpCircle className="size-5" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent className="w-48" align="end">
            <DropdownMenuLabel className="font-normal text-muted-foreground">
              Resources
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            {resourceLinks.map((link) => (
              <DropdownMenuItem key={link.title} asChild className="cursor-pointer">
                <a href={link.href} target="_blank" rel="noopener noreferrer">
                  <link.icon className="mr-2 h-4 w-4" />
                  {link.title}
                </a>
              </DropdownMenuItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              data-console-top-profile-trigger
              variant="ghost"
              className="flex items-center gap-2 bg-white/5 px-2 text-white hover:bg-white/10 hover:text-white active:!bg-white/15 active:!text-white data-[state=open]:!bg-white/15 data-[state=open]:!text-white"
            >
              <Avatar className="h-8 w-8 shrink-0">
                <AvatarFallback className="bg-slate-700 text-white">
                  <UserRound className="size-4" aria-hidden="true" />
                </AvatarFallback>
              </Avatar>
              <span className="hidden max-w-40 truncate text-sm font-medium lg:inline">
                {guardOpen ? 'No identity' : 'Signed in'}
              </span>
              <ChevronDown className="hidden h-4 w-4 text-slate-400 sm:block" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent className="w-64" align="end">
            <DropdownMenuLabel className="font-normal">
              <div className="flex flex-col space-y-1">
                <p className="text-sm font-medium leading-none">
                  {guardOpen ? 'No identity configured' : 'Session held in memory only'}
                </p>
                <p className="text-xs leading-none text-muted-foreground">
                  {guardOpen
                    ? 'Calls are made without a bearer token.'
                    : 'Nothing is written to local or session storage.'}
                </p>
              </div>
            </DropdownMenuLabel>
            {!guardOpen && (
              <>
                <DropdownMenuSeparator />
                <DropdownMenuItem className="cursor-pointer" onSelect={() => signOut()}>
                  <LogOut className="mr-2 h-4 w-4" />
                  Sign out
                </DropdownMenuItem>
              </>
            )}
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  )
}
