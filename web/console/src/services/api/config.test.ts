import { afterEach, describe, expect, it, vi } from 'vitest'

/**
 * The runtime-configuration contract.
 *
 * ONE BUILT IMAGE, ANY OPERATOR. Nothing about which Auth this console talks to
 * may be baked into the bundle, because the bundle is what ships in the image and
 * every operator's Auth is different. `public/config.js` writes `window.__ENV__`
 * before the app loads, and these tests hold the resolution rules that make that
 * work — including the one that matters for a standalone install: the console
 * signs in with `SECRET_CONSOLE_CLIENT_ID`, the same variable the service
 * validates at boot, so an operator sets one value and both halves agree.
 *
 * IDENTITY_CONFIG is computed at module load, so each case resets the module
 * registry and re-imports.
 */

type Env = Record<string, string | undefined>

async function loadConfig(runtime: Env) {
  vi.resetModules()
  window.__ENV__ = runtime
  return import('./config')
}

afterEach(() => {
  delete window.__ENV__
  vi.resetModules()
})

describe('identity configuration', () => {
  const complete = {
    AUTH_ISSUER: 'https://identity.auth.example',
    SECRET_CONSOLE_TOKEN_URL: 'https://identity-api.auth.example/api/v1/oauth/token',
    SECRET_CONSOLE_CLIENT_ID: 'secret-console',
    AUTH_AUDIENCE: 'maintainerd-secret',
  }

  it('reads the service-spelled variables at runtime', async () => {
    const { IDENTITY_CONFIG } = await loadConfig(complete)

    expect(IDENTITY_CONFIG).not.toBeNull()
    expect(IDENTITY_CONFIG?.clientId).toBe('secret-console')
    expect(IDENTITY_CONFIG?.issuerUrl).toBe('https://identity.auth.example')
    expect(IDENTITY_CONFIG?.audience).toBe('maintainerd-secret')
  })

  it('still honours the VITE_ build-time spellings', async () => {
    const { IDENTITY_CONFIG } = await loadConfig({
      VITE_OAUTH_ISSUER_URL: 'https://identity.auth.example',
      VITE_OAUTH_TOKEN_URL: 'https://identity-api.auth.example/api/v1/oauth/token',
      VITE_OAUTH_CLIENT_ID: 'legacy-console',
      VITE_OAUTH_AUDIENCE: 'maintainerd-secret',
    })

    expect(IDENTITY_CONFIG?.clientId).toBe('legacy-console')
  })

  it('prefers SECRET_CONSOLE_CLIENT_ID over the VITE_ alias', async () => {
    const { IDENTITY_CONFIG } = await loadConfig({
      ...complete,
      VITE_OAUTH_CLIENT_ID: 'stale-baked-in-client',
    })

    expect(IDENTITY_CONFIG?.clientId).toBe('secret-console')
  })

  it('trims a trailing slash off the issuer so /authorize is not built with a double slash', async () => {
    const { IDENTITY_CONFIG } = await loadConfig({
      ...complete,
      AUTH_ISSUER: 'https://identity.auth.example/',
    })

    expect(IDENTITY_CONFIG?.issuerUrl).toBe('https://identity.auth.example')
  })

  it('ignores the empty placeholders public/config.js ships', async () => {
    const { IDENTITY_CONFIG } = await loadConfig({
      AUTH_ISSUER: '',
      SECRET_CONSOLE_TOKEN_URL: '   ',
      SECRET_CONSOLE_CLIENT_ID: '',
    })

    expect(IDENTITY_CONFIG).toBeNull()
  })

  /**
   * A PARTIAL IDENTITY IS TREATED AS NONE. Configuring an issuer and a token URL
   * but no client id would send the operator to an authorize endpoint whose code
   * could never be exchanged — an error they cannot act on, in a place they are
   * not looking. Guard-open mode at least announces itself.
   */
  it.each([
    ['no client id', { AUTH_ISSUER: complete.AUTH_ISSUER, SECRET_CONSOLE_TOKEN_URL: complete.SECRET_CONSOLE_TOKEN_URL }],
    ['no issuer', { SECRET_CONSOLE_TOKEN_URL: complete.SECRET_CONSOLE_TOKEN_URL, SECRET_CONSOLE_CLIENT_ID: 'c' }],
    ['no token url', { AUTH_ISSUER: complete.AUTH_ISSUER, SECRET_CONSOLE_CLIENT_ID: 'c' }],
  ])('is null with %s', async (_name, runtime) => {
    const { IDENTITY_CONFIG } = await loadConfig(runtime)
    expect(IDENTITY_CONFIG).toBeNull()
  })
})

describe('api base url', () => {
  it('defaults to the same-origin /api/v1', async () => {
    const { API_CONFIG } = await loadConfig({})
    expect(API_CONFIG.BASE_URL).toBe('/api/v1')
  })
})
