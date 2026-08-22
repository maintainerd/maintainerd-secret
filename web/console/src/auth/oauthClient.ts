/**
 * The hosted-identity OAuth2 client.
 *
 * The console is a PUBLIC client: authorization code + PKCE, no client secret,
 * and deliberately NO refresh token (`offline_access` is never requested). An
 * administrative surface must not hold a long-lived credential, so continuity
 * across a reload comes from the identity SSO session via a `prompt=none`
 * re-authorization rather than from a stored refresh token.
 *
 * The resulting access token is used as a bearer against maintainerd-secret's
 * own `/api/v1`, which verifies it against Auth's JWKS + issuer + audience.
 */

import axios from 'axios'
import type { IdentityConfig } from '@/services/api/config'
import { setAccessToken, setIdTokenHint } from './tokenStore'
import {
  consumePendingOAuthFlow,
  consoleRedirectUri,
  discardPendingOAuthFlow,
  pkceChallenge,
  randomOAuthValue,
  savePendingOAuthFlow,
} from './oauthFlow'

interface OAuthTokenResponse {
  access_token: string
  id_token?: string
  token_type?: string
  expires_in?: number
  scope?: string
}

const BASE_SCOPE = 'openid profile email'

function scopeFor(identity: IdentityConfig): string {
  return identity.extraScope ? `${BASE_SCOPE} ${identity.extraScope}` : BASE_SCOPE
}

async function buildAuthorizeUrl(
  identity: IdentityConfig,
  returnTo: string,
  prompt?: 'none',
): Promise<string> {
  const state = randomOAuthValue()
  const codeVerifier = randomOAuthValue(48)
  const redirectUri = consoleRedirectUri()
  const codeChallenge = await pkceChallenge(codeVerifier)

  savePendingOAuthFlow({
    state,
    codeVerifier,
    clientId: identity.clientId,
    returnTo,
    redirectUri,
  })

  const query = new URLSearchParams({
    response_type: 'code',
    client_id: identity.clientId,
    redirect_uri: redirectUri,
    scope: scopeFor(identity),
    state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
  })
  // The audience names the resource API the token is FOR. Without it Auth may
  // mint a token for its own audience, which secret's verifier would reject —
  // an authenticated user who cannot call anything.
  if (identity.audience) query.set('audience', identity.audience)
  if (prompt) query.set('prompt', prompt)

  return `${identity.issuerUrl}/authorize?${query.toString()}`
}

/** Sends the browser to the identity app to sign in. */
export async function startLogin(identity: IdentityConfig, returnTo: string): Promise<void> {
  const url = await buildAuthorizeUrl(identity, returnTo)
  window.location.assign(url)
}

type SilentOAuthMessage = {
  type: 'maintainerd:oauth:silent'
  state: string
  redirect_uri?: string
  error?: string
}

/**
 * Non-interactive authorization in a hidden identity iframe.
 *
 * Succeeds when the identity SSO session is still live and consent was already
 * given; any login/consent requirement resolves `false` so the caller can fall
 * back to a visible redirect. This is what makes "no persisted token" cost the
 * operator nothing on a page reload.
 */
export async function trySilentLogin(identity: IdentityConfig, returnTo: string): Promise<boolean> {
  const authorizeUrl = await buildAuthorizeUrl(identity, returnTo, 'none')
  const expectedOrigin = new URL(identity.issuerUrl).origin
  const iframe = document.createElement('iframe')
  iframe.hidden = true
  iframe.setAttribute('aria-hidden', 'true')
  iframe.title = 'silent authorization'

  return new Promise<boolean>((resolve) => {
    let settled = false
    const finish = (value: boolean) => {
      if (settled) return
      settled = true
      window.clearTimeout(timeout)
      window.removeEventListener('message', onMessage)
      iframe.remove()
      resolve(value)
    }
    const onMessage = async (event: MessageEvent<SilentOAuthMessage>) => {
      // Origin AND source are both checked: any page can postMessage to this
      // window, and accepting an authorization result from an unverified sender
      // would be accepting a token address from an attacker.
      if (event.origin !== expectedOrigin || event.source !== iframe.contentWindow) return
      const message = event.data
      if (!message || message.type !== 'maintainerd:oauth:silent' || !message.state) return
      if (message.error || !message.redirect_uri) {
        discardPendingOAuthFlow(message.state)
        finish(false)
        return
      }
      const redirect = new URL(message.redirect_uri)
      const code = redirect.searchParams.get('code')
      const state = redirect.searchParams.get('state')
      if (!code || !state || state !== message.state) {
        discardPendingOAuthFlow(message.state)
        finish(false)
        return
      }
      const flow = consumePendingOAuthFlow(state)
      if (!flow) {
        finish(false)
        return
      }
      try {
        await exchangeAuthorizationCode(identity, {
          code,
          redirectUri: flow.redirectUri,
          codeVerifier: flow.codeVerifier,
        })
        finish(true)
      } catch {
        finish(false)
      }
    }
    const timeout = window.setTimeout(() => finish(false), 5000)
    window.addEventListener('message', onMessage)
    document.body.appendChild(iframe)
    iframe.src = authorizeUrl
  })
}

/**
 * Exchanges an authorization code for an access token and puts it in the
 * in-memory store. The response body is never logged and never persisted.
 */
export async function exchangeAuthorizationCode(
  identity: IdentityConfig,
  params: { code: string; redirectUri: string; codeVerifier: string },
): Promise<void> {
  const form = new URLSearchParams({
    grant_type: 'authorization_code',
    code: params.code,
    redirect_uri: params.redirectUri,
    code_verifier: params.codeVerifier,
    client_id: identity.clientId,
  })

  const response = await axios.post<OAuthTokenResponse>(identity.tokenUrl, form, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    // No-store on the way in as well: an access token must not sit in a disk or
    // proxy cache on the strength of a default heuristic.
    validateStatus: (status) => status >= 200 && status < 300,
  })

  setAccessToken(response.data.access_token, response.data.expires_in)
  setIdTokenHint(response.data.id_token)
}

/**
 * RP-initiated logout. The id_token hint is best effort — logout still works
 * without it, the hint just lets identity end the right session precisely.
 */
export function endSessionUrl(identity: IdentityConfig, idTokenHint: string | null): string {
  const query = new URLSearchParams({
    client_id: identity.clientId,
    post_logout_redirect_uri: window.location.origin,
  })
  if (idTokenHint) query.set('id_token_hint', idTokenHint)
  return `${identity.issuerUrl}/end-session?${query.toString()}`
}
