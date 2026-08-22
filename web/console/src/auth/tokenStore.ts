/**
 * The access token store — IN MEMORY, for the lifetime of the page, only.
 *
 * NOTHING HERE IS EVER PERSISTED. Not localStorage, not sessionStorage, not a
 * cookie this app can read. A token minted for maintainerd-secret is a key to a
 * vault, so any XSS that can run in this console must not be able to walk away
 * with a credential that outlives the tab it stole it from.
 *
 * Session continuity across a reload therefore does NOT come from storage and
 * does NOT come from a refresh token (the console never requests one — it is an
 * administrative surface and must not hold a long-lived credential). It comes
 * from the hosted-identity SSO session: on boot the app re-authorizes with
 * `prompt=none` in a hidden iframe, which is silent while identity is still
 * signed in and falls back to a visible login when it is not. See
 * `auth/oauthClient.ts`.
 */

interface StoredToken {
  accessToken: string
  /** Epoch milliseconds. Undefined when the server did not send expires_in. */
  expiresAt?: number
}

let current: StoredToken | null = null

/**
 * The id_token, kept only as an OIDC `id_token_hint` for RP-initiated logout.
 * In memory for the lifetime of the page, like the access token.
 */
let idTokenHint: string | null = null

/** Subscribers notified whenever the token changes (set or cleared). */
const listeners = new Set<() => void>()

function notify(): void {
  listeners.forEach((listener) => listener())
}

export function subscribeToToken(listener: () => void): () => void {
  listeners.add(listener)
  return () => {
    listeners.delete(listener)
  }
}

export function setAccessToken(accessToken: string, expiresInSeconds?: number): void {
  current = {
    accessToken,
    // A 30s safety margin: a token that expires mid-flight produces a 401 the
    // user reads as a bug rather than as a session boundary.
    expiresAt:
      typeof expiresInSeconds === 'number' && Number.isFinite(expiresInSeconds)
        ? Date.now() + Math.max(0, expiresInSeconds - 30) * 1000
        : undefined,
  }
  notify()
}

export function setIdTokenHint(idToken: string | null | undefined): void {
  idTokenHint = idToken ?? null
}

export function getIdTokenHint(): string | null {
  return idTokenHint
}

/** The current access token, or null when there is none or it has expired. */
export function getAccessToken(): string | null {
  if (!current) return null
  if (current.expiresAt !== undefined && Date.now() >= current.expiresAt) {
    current = null
    notify()
    return null
  }
  return current.accessToken
}

export function hasAccessToken(): boolean {
  return getAccessToken() !== null
}

export function clearAccessToken(): void {
  current = null
  idTokenHint = null
  notify()
}
