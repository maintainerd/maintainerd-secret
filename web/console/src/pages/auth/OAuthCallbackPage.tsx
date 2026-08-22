import { useEffect, useRef, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { Button } from '@/components/ui/button'
import { AppLoadingScreen } from '@/components/layout/AppLoadingScreen'
import { useAuth } from '@/auth/authContext'
import { exchangeAuthorizationCode } from '@/auth/oauthClient'
import { consumePendingOAuthFlow, discardPendingOAuthFlow, safeReturnTo } from '@/auth/oauthFlow'

/**
 * The OAuth redirect target.
 *
 * The `state` comparison inside `consumePendingOAuthFlow` is the CSRF check: a
 * code that arrives without a matching pending flow is refused rather than
 * exchanged. The code and state are dropped from the URL by navigating away with
 * `replace`, so neither survives in history.
 */
export default function OAuthCallbackPage() {
  const [params] = useSearchParams()
  const navigate = useNavigate()
  const { identity } = useAuth()
  const [error, setError] = useState<string | null>(null)
  const startedRef = useRef(false)

  useEffect(() => {
    if (startedRef.current) return
    startedRef.current = true

    const run = async () => {
      const code = params.get('code')
      const state = params.get('state')
      const oauthError = params.get('error')

      if (oauthError) {
        if (state) discardPendingOAuthFlow(state)
        setError('Your identity provider refused the sign-in request.')
        return
      }
      if (!identity) {
        setError('This console has no identity configuration, so it cannot complete a sign-in.')
        return
      }
      if (!code || !state) {
        setError('The sign-in response was incomplete.')
        return
      }
      const flow = consumePendingOAuthFlow(state)
      if (!flow) {
        // Either the state did not match or the pending flow is gone (a reload of
        // the callback, or a second tab). Failing here is correct: exchanging a
        // code whose origin we cannot vouch for is the attack this check exists
        // to stop.
        setError('This sign-in link is no longer valid. Please sign in again.')
        return
      }
      try {
        await exchangeAuthorizationCode(identity, {
          code,
          redirectUri: flow.redirectUri,
          codeVerifier: flow.codeVerifier,
        })
        navigate(safeReturnTo(flow.returnTo) ?? '/browse', { replace: true })
      } catch {
        // The exchange response is never surfaced or logged — it carries a token.
        setError('Could not complete sign-in. Please try again.')
      }
    }

    void run()
  }, [identity, navigate, params])

  if (error) {
    return (
      <div className="flex min-h-screen items-center justify-center p-6">
        <div className="w-full max-w-sm space-y-4 text-center" role="alert">
          <h1 className="text-lg font-semibold">Sign-in failed</h1>
          <p className="text-sm text-muted-foreground">{error}</p>
          <Button className="w-full" onClick={() => navigate('/login', { replace: true })}>
            Try again
          </Button>
        </div>
      </div>
    )
  }

  return <AppLoadingScreen message="Completing sign-in" />
}
