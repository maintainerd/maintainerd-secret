import { useEffect, useRef } from 'react'
import { Navigate, useLocation } from 'react-router-dom'
import { Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { LoginLayout } from '@/components/layout/LoginLayout'
import { useAuth } from '@/auth/authContext'
import { safeReturnTo } from '@/auth/oauthFlow'

/**
 * Sign-in.
 *
 * The redirect fires automatically — an administrative console has exactly one
 * way in, so making the operator click a button first is ceremony. The button is
 * still rendered as the fallback for a browser that blocked the navigation.
 *
 * The chrome is maintainerd-auth's `LoginLayout`: brand lockup above a single
 * card, so the first screen an operator sees belongs to the same product as the
 * rest of the suite.
 */
export default function LoginPage() {
  const { mode, signIn } = useAuth()
  const location = useLocation()
  const startedRef = useRef(false)

  const from = (location.state as { from?: string } | null)?.from
  const returnTo = safeReturnTo(from) ?? '/browse'

  useEffect(() => {
    if (mode !== 'anonymous' || startedRef.current) return
    startedRef.current = true
    signIn(returnTo)
  }, [mode, signIn, returnTo])

  if (mode !== 'anonymous') return <Navigate to={returnTo} replace />

  return (
    <LoginLayout>
      <div className="space-y-6 text-center">
        <div className="space-y-2">
          <h1 className="text-lg font-semibold tracking-tight">Sign in</h1>
          <p className="text-sm text-muted-foreground">
            Taking you to your identity provider. Nothing about your session is stored in this
            browser.
          </p>
        </div>
        <div
          className="flex items-center justify-center gap-2 text-muted-foreground"
          role="status"
          aria-live="polite"
        >
          <Loader2 className="size-4 animate-spin" aria-hidden="true" />
          <span className="text-sm">Redirecting…</span>
        </div>
        <Button className="w-full" onClick={() => signIn(returnTo)}>
          Continue to sign in
        </Button>
      </div>
    </LoginLayout>
  )
}
