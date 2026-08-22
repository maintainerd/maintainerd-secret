import { createContext, useContext } from 'react'
import type { IdentityConfig } from '@/services/api/config'
import type { Capabilities } from '@/services/api/types'

/**
 * How this console is authenticating against maintainerd-secret.
 *
 * THE SERVER DECIDES WHICH OF THESE IT IS, not this console. The mode is derived
 * from `GET /capabilities` (see `AuthProvider`), which is why `guard-open` and
 * `identity-missing` are separate: they used to be one state, because the console
 * inferred "the guard must be open" from its own missing settings and therefore
 * could not tell "no token is needed" from "a token is needed and I cannot get
 * one". Those are opposite situations and only one of them is safe.
 *
 *  - `guard-open`       The SERVICE reports its guard is development-open: it
 *                       serves every caller as a blanket-granted principal.
 *                       There is no token to hold and no sign-out to perform. The
 *                       shell says so permanently, because a vault that answers
 *                       anonymous callers is a fact an operator must not discover
 *                       by accident.
 *  - `identity-missing` The service ENFORCES tokens and this console has no
 *                       identity configuration, so it cannot obtain one. Every
 *                       API call will be refused; the shell names the settings to
 *                       set rather than letting the operator read it as "no auth
 *                       needed".
 *  - `authenticated`    A PKCE access token is held in memory and sent as a bearer.
 *  - `anonymous`        Identity is configured but no token is held yet.
 */
export type AuthMode = 'guard-open' | 'identity-missing' | 'authenticated' | 'anonymous'

export interface AuthContextValue {
  mode: AuthMode
  /** True once the boot-time capability probe and silent authorization have settled. */
  ready: boolean
  /** Present only when identity is configured. */
  identity: IdentityConfig | null
  /**
   * What the service reported about itself, or null when the probe failed (in
   * which case `mode` fell back to the old client-side inference).
   */
  capabilities: Capabilities | null
  /** Sends the browser to the identity app. No-op in `guard-open`. */
  signIn: (returnTo?: string) => void
  /** Drops the in-memory token and ends the identity session. */
  signOut: () => void
}

export const AuthContext = createContext<AuthContextValue | null>(null)

export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext)
  if (!value) throw new Error('useAuth must be used inside <AuthProvider>')
  return value
}
