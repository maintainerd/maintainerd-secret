import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import { IDENTITY_CONFIG } from '@/services/api/config'
import { setUnauthenticatedHandler } from '@/services/api/client'
import { getCapabilities } from '@/services/api/capabilities'
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
 * THE SERVER'S POSTURE IS ASKED FOR, NOT INFERRED. This used to decide "the
 * guard must be development-open" from `IDENTITY_CONFIG === null` — the absence
 * of identity settings in the CONSOLE's own configuration. That is a conclusion
 * about the server drawn from the client's config file, and it was wrong in both
 * directions: an ENFORCED vault whose console was handed no issuer rendered a
 * reassuring "no identity configured" banner and then 401'd every request, and an
 * actually-OPEN vault whose console did have an issuer sent the operator into an
 * OAuth flow nobody was listening for. `GET /capabilities` answers it directly,
 * unauthenticated — which it has to be, since obtaining a token is the thing
 * being worked out.
 *
 * WHEN THE PROBE FAILS the old inference is used as a fallback. An unreachable
 * service or an older build should degrade to previous behaviour rather than to a
 * blank screen; the fallback is marked below so it cannot be mistaken for the
 * primary path.
 *
 * Recovery from an expired token is a `prompt=none` re-authorization, not a
 * refresh-token call: the console deliberately holds no refresh token (see
 * `tokenStore.ts`). While the identity SSO session is alive the operator sees
 * nothing; once it is gone they land on a visible sign-in.
 */
export function AuthProvider({ children }: { children: ReactNode }) {
  const identity = IDENTITY_CONFIG
  const [loginSettled, setLoginSettled] = useState(false)
  const [tokenTick, setTokenTick] = useState(0)
  const startedRef = useRef(false)

  // The service's own posture. Fetched once per page load and never refetched:
  // the guard mode is fixed for the process's lifetime, and setup completion is
  // monotonic, so a stale answer cannot become wrong in the dangerous direction.
  // One retry, because this blocks first paint and a hung retry loop would be a
  // console that never renders.
  const capabilities = useQuery({
    queryKey: ['capabilities'] as const,
    queryFn: getCapabilities,
    staleTime: Number.POSITIVE_INFINITY,
    gcTime: Number.POSITIVE_INFINITY,
    retry: 1,
    refetchOnWindowFocus: false,
  })

  // guardEnforced is undefined until the probe settles, so no decision below acts
  // on a guess. Once it settles the SERVER decides; only a failed probe falls back
  // to the old client-side inference.
  const guardEnforced: boolean | undefined = capabilities.isPending
    ? undefined
    : capabilities.data
      ? capabilities.data.guard_mode !== 'dev-open'
      : identity !== null // fallback: probe failed, guess as this console used to

  /**
   * Starts a visible sign-in — AT MOST ONCE PER PAGE LOAD.
   *
   * The single-flight guard is not a micro-optimization; without it a 401 breaks
   * sign-in outright. Two independent callers react to the same expiry: the axios
   * interceptor invokes the unauthenticated handler below, and `clearAccessToken`
   * simultaneously flips `mode` to `anonymous`, which sends `RequireAuth` to
   * /login, whose own effect calls this too. Each call mints a fresh `state` +
   * `code_verifier` and writes them to the SINGLE pending-flow slot in
   * sessionStorage (`oauthFlow.ts`), then navigates. `startLogin` awaits the PKCE
   * digest before doing either, so the two interleave freely: the browser can
   * commit the first authorize URL while the second call has already overwritten
   * the stored flow. The callback then arrives bearing `state` A against stored
   * state B, `consumePendingOAuthFlow` correctly refuses it as a CSRF mismatch,
   * and the operator is told their sign-in link is no longer valid — on every
   * expiry.
   *
   * One flight, one stored flow, one navigation. The ref is never reset because
   * the page is leaving; a caller that wants a different destination has to win
   * the race, which is why the interceptor is registered as the LAST word on
   * where an expired session lands.
   */
  const redirectingRef = useRef(false)
  const signIn = useCallback(
    (returnTo?: string) => {
      if (!identity || redirectingRef.current) return
      redirectingRef.current = true
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
  //
  // It waits for the capability probe. Starting a silent authorization against a
  // vault whose guard turns out to be open is a redirect an operator watches for
  // no reason, and skipping one against a vault that turns out to be enforced is
  // a sign-in prompt they did not need.
  useEffect(() => {
    if (guardEnforced === undefined || startedRef.current) return
    startedRef.current = true
    if (!guardEnforced || !identity) {
      setLoginSettled(true)
      return
    }
    // The callback route is mid-exchange — attempting a second authorization
    // here would race the one already in flight and consume its pending state.
    if (window.location.pathname === OAUTH_CALLBACK_ROUTE) {
      setLoginSettled(true)
      return
    }
    if (hasAccessToken()) {
      setLoginSettled(true)
      return
    }
    trySilentLogin(identity, `${window.location.pathname}${window.location.search}`)
      .catch(() => false)
      .finally(() => setLoginSettled(true))
  }, [guardEnforced, identity])

  // Re-render whenever the in-memory token is set or cleared.
  useEffect(() => subscribeToToken(() => setTokenTick((tick) => tick + 1)), [])

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
    if (guardEnforced === false) {
      mode = 'guard-open'
    } else if (!identity) {
      // The service verifies tokens and this console cannot obtain one. Naming it
      // as its own mode is the whole point of asking the server: this state used
      // to be indistinguishable from "the guard is open", and it renders as a
      // banner telling the operator exactly which settings are missing rather
      // than as a reassurance that none are needed.
      mode = 'identity-missing'
    } else if (hasAccessToken()) {
      mode = 'authenticated'
    }
    return {
      mode,
      ready: loginSettled,
      identity,
      capabilities: capabilities.data ?? null,
      signIn,
      signOut,
    }
  }, [capabilities.data, guardEnforced, identity, loginSettled, signIn, signOut, tokenTick])

  if (!loginSettled) return <AppLoadingScreen message="Checking your session" />

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}
