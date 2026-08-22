import { Loader2 } from 'lucide-react'
import { BrandLockup } from '@/components/brand/BrandLockup'

/**
 * Full-screen splash shown while the app decides what it is allowed to show.
 *
 * Mirrors maintainerd-auth's `components/layout/AppLoadingScreen.tsx`: the same
 * brand lockup as the login page (via `BrandLockup`) plus a spinner, so the
 * loading state belongs to the same product instead of being a bare spinner on a
 * blank page.
 */
export function AppLoadingScreen({ message = 'Loading' }: { message?: string }) {
  return (
    <div
      data-console-auth-shell
      className="flex min-h-svh flex-col items-center justify-center bg-background px-4 text-foreground"
      role="status"
      aria-live="polite"
    >
      <div className="flex flex-col items-center gap-6 text-center">
        {/* The square app icon, whose light and dark variants track the
            operator's colour scheme — the splash paints before anything else. */}
        <BrandLockup asset="icon" iconSize={72} />
        <div className="flex items-center gap-2 text-muted-foreground">
          <Loader2 className="size-4 animate-spin" aria-hidden="true" />
          <span className="text-sm">{message}…</span>
        </div>
      </div>
    </div>
  )
}

export default AppLoadingScreen
