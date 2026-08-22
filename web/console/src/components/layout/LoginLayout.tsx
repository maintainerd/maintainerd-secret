import type { ReactNode } from 'react'
import { BrandLockup } from '@/components/brand/BrandLockup'
import { Card, CardContent } from '@/components/ui/card'
import { useConsoleBranding } from '@/components/theme/brandingContext'
import { cn } from '@/lib/utils'

/**
 * The unauthenticated shell: brand lockup, a single card, a footer.
 *
 * Copied from maintainerd-auth's `components/layout/LoginLayout.tsx`, minus the
 * tenant-supplied legal links (secret has no branding API to read them from).
 * Used by sign-in, the OAuth callback's failure state, and the first-run wizard,
 * so all three read as one product.
 */
export function LoginLayout({
  children,
  className,
  /** The wizard needs a wider column than a sign-in card. */
  width = 'md',
}: {
  children: ReactNode
  className?: string
  width?: 'md' | 'xl'
}) {
  const { branding } = useConsoleBranding()
  const year = new Date().getFullYear()

  return (
    <div
      data-console-auth-shell
      className="flex min-h-svh flex-col items-center justify-center bg-background px-4 py-12 text-foreground"
    >
      <div className={cn('w-full', width === 'xl' ? 'max-w-2xl' : 'max-w-md', className)}>
        {/* The front door gets the full official lockup — mark, wordmark and
            tagline — with the app name naming which maintainerd console this is. */}
        <div className="mb-8">
          <BrandLockup asset="logo" logoClassName="h-28 w-auto" />
        </div>

        <Card data-console-auth-card className="border-border shadow-sm">
          <CardContent className="p-7 sm:p-9">{children}</CardContent>
        </Card>

        <div className="mt-8 flex flex-col items-center gap-3 text-center">
          <span className="text-xs text-muted-foreground">
            © {year} {branding.appName}
          </span>
        </div>
      </div>
    </div>
  )
}

export default LoginLayout
