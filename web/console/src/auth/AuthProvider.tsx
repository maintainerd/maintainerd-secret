import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { IDENTITY_CONFIG } from '@/services/api/config'
import { setUnauthenticatedHandler } from '@/services/api/client'
import { AuthContext, type AuthContextValue, type AuthMode } from './authContext'
import { clearAccessToken, getIdTokenHint, hasAccessToken, subscribeToToken } from './tokenStore'
import { endSessionUrl, startLogin, trySilentLogin } from './oauthClient'
import { OAUTH_CALLBACK_ROUTE, safeReturnTo } from './oauthFlow'
import { AppLoadingScreen } from '@/components/layout/AppLoadingScreen'

/**
 * The session gate.
 *
 * On boot it decides ONE thing and blocks rendering until it has: does this
 * console hold a credential, and if not, can it get one silently? Rendering the
 * app before that verdict is what produces the classic flicker — a protected
 * page paints, a 401 lands, and the app bounces mid-paint.
 *
 * Recovery from an expired token is a `prompt=none` re-authorization, not a
 * refresh-token call: the console deliberately holds no refresh token (see
 * `tokenStore.ts`). While the identity SSO session is alive the operator sees
 * nothing; once it is gone they land on a visible sign-in.
 */
export function AuthProvider({ children }: { children: ReactNode }) {
  const identity = IDENTITY_CONFIG
  const [ready, setReady] = useState(identity === null)
  const [tokenTick, setTokenTick] = useState(0)
  const startedRef = useRef(false)

  // Re-render whenever the in-memory token is set or cleared.
  useEffect(() => subscribeToToken(() => setTokenTick((tick) => tick + 1)), [])

  const signIn = useCallback(
    (returnTo?: string) => {
      if (!identity) return
      const target =
        safeReturnTo(returnTo) ??
        safeReturnTo(`${window.location.pathname}${window.location.search}`) ??
        '/'
      void startLogin(identity, target)
    },
    [identity],
  )

  const signOut = useCallback(() => {
    const hint = getIdTokenHint()
    clearAccessToken()
    if (!identity) return
    window.location.assign(endSessionUrl(identity, hint))
  }, [identity])

  // Boot: try to pick the session back up without showing anything.
  useEffect(() => {
    if (!identity || startedRef.current) return
    startedRef.current = true
    // The callback route is mid-exchange — attempting a second authorization
    // here would race the one already in flight and consume its pending state.
    if (window.location.pathname === OAUTH_CALLBACK_ROUTE) {
      setReady(true)
      return
    }
    if (hasAccessToken()) {
      setReady(true)
      return
    }
    trySilentLogin(identity, `${window.location.pathname}${window.location.search}`)
      .catch(() => false)
      .finally(() => setReady(true))
  }, [identity])

  // A 401 from any API call lands here. The token is already cleared by the
  // interceptor; this decides where the operator goes next.
  useEffect(() => {
    if (!identity) return undefined
    setUnauthenticatedHandler(() => {
      signIn(`${window.location.pathname}${window.location.search}`)
    })
    return () => setUnauthenticatedHandler(null)
  }, [identity, signIn])

  const value = useMemo<AuthContextValue>(() => {
    // tokenTick is read so the memo re-runs when the token store changes.
    void tokenTick
    let mode: AuthMode = 'anonymous'
    if (!identity) mode = 'guard-open'
    else if (hasAccessToken()) mode = 'authenticated'
    return { mode, ready, identity, signIn, signOut }
  }, [identity, ready, signIn, signOut, tokenTick])

  if (!ready) return <AppLoadingScreen message="Checking your session" />

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}
