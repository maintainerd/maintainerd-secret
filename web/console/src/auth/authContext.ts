import { createContext, useContext } from 'react'
import type { IdentityConfig } from '@/services/api/config'

/**
 * How this console is authenticating against maintainerd-secret.
 *
 *  - `guard-open`   No identity is configured. The service is expected to be
 *                   running in development-open mode, where its guard serves
 *                   every caller as a blanket-granted principal. There is no
 *                   token to hold and no sign-out to perform. The shell says so
 *                   permanently, because a vault that answers anonymous callers
 *                   is a fact an operator must not discover by accident.
 *  - `authenticated` A PKCE access token is held in memory and sent as a bearer.
 *  - `anonymous`     Identity is configured but no token is held yet.
 */
export type AuthMode = 'guard-open' | 'authenticated' | 'anonymous'

export interface AuthContextValue {
  mode: AuthMode
  /** True once the boot-time silent authorization attempt has settled. */
  ready: boolean
  /** Present only when identity is configured. */
  identity: IdentityConfig | null
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
