/**
 * OAuth2 authorization-code + PKCE plumbing.
 *
 * What is persisted here is the PENDING flow only — the `state` and the PKCE
 * `code_verifier`, in sessionStorage, for the seconds between leaving for the
 * identity app and coming back. Neither is a credential once the exchange has
 * happened, and the entry is consumed (removed) on the way back. The access
 * token itself is never persisted; see `auth/tokenStore.ts`.
 */

export const OAUTH_CALLBACK_ROUTE = '/auth/callback'

/**
 * Constrain a stored return-to to a same-origin path before it drives a
 * post-login redirect. Only an absolute local path (`/foo`) is allowed —
 * protocol-relative (`//host`), backslash tricks (`/\host`), and absolute URLs
 * are rejected so a crafted `returnTo` cannot become an open redirect. Returns
 * `null` when unsafe; callers fall back to the default post-auth route.
 */
export function safeReturnTo(value: string | null | undefined): string | null {
  if (!value || !value.startsWith('/')) return null
  if (value.startsWith('//') || value.startsWith('/\\')) return null
  return value
}

export interface PendingOAuthFlow {
  state: string
  codeVerifier: string
  clientId: string
  returnTo: string
  redirectUri: string
}

const PENDING_KEY = 'maintainerd.secret.console.oauth.pending'

function base64Url(bytes: Uint8Array): string {
  let binary = ''
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte)
  })
  return window.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function randomOAuthValue(byteLength = 32): string {
  const bytes = new Uint8Array(byteLength)
  window.crypto.getRandomValues(bytes)
  return base64Url(bytes)
}

export async function pkceChallenge(verifier: string): Promise<string> {
  const digest = await window.crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
  return base64Url(new Uint8Array(digest))
}

export function consoleRedirectUri(): string {
  return `${window.location.origin}${OAUTH_CALLBACK_ROUTE}`
}

export function savePendingOAuthFlow(flow: PendingOAuthFlow): void {
  window.sessionStorage.setItem(PENDING_KEY, JSON.stringify(flow))
}

/**
 * Reads back the pending flow for `state` and removes it. A mismatched state is
 * treated as no flow at all — that comparison is the CSRF check, so it fails
 * closed rather than falling back to whatever happens to be stored.
 */
export function consumePendingOAuthFlow(state: string): PendingOAuthFlow | null {
  try {
    const raw = window.sessionStorage.getItem(PENDING_KEY)
    if (!raw) return null
    const flow = JSON.parse(raw) as PendingOAuthFlow
    if (flow.state !== state) return null
    window.sessionStorage.removeItem(PENDING_KEY)
    return flow
  } catch {
    return null
  }
}

export function discardPendingOAuthFlow(state: string): void {
  try {
    const raw = window.sessionStorage.getItem(PENDING_KEY)
    if (!raw) return
    const flow = JSON.parse(raw) as PendingOAuthFlow
    if (flow.state === state) window.sessionStorage.removeItem(PENDING_KEY)
  } catch {
    window.sessionStorage.removeItem(PENDING_KEY)
  }
}
