import { useEffect, useRef } from 'react'
import { Navigate, useLocation } from 'react-router-dom'
import { KeyRound } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useAuth } from '@/auth/authContext'
import { safeReturnTo } from '@/auth/oauthFlow'

/**
 * Sign-in.
 *
 * The redirect fires automatically — an administrative console has exactly one
 * way in, so making the operator click a button first is ceremony. The button is
 * still rendered as the fallback for a browser that blocked the navigation.
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
    <div className="flex min-h-screen items-center justify-center p-6">
      <div className="w-full max-w-sm space-y-4 text-center">
        <KeyRound className="mx-auto size-8 text-primary" aria-hidden="true" />
        <div>
          <h1 className="text-lg font-semibold">maintainerd secret</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Taking you to your identity provider to sign in.
          </p>
        </div>
        <Button className="w-full" onClick={() => signIn(returnTo)}>
          Continue to sign in
        </Button>
      </div>
    </div>
  )
}
