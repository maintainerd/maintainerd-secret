/**
 * API + identity configuration.
 *
 * Every value can be supplied at BUILD time (import.meta.env) or at RUN time
 * (window.__ENV__, written by public/config.js), so one built image can target
 * several deployments. Nothing here is a secret: the console is a public OAuth
 * client (authorization code + PKCE), so it has no client secret to leak.
 */

// Runtime environment injected into window.__ENV__ before the app bundle loads.
declare global {
  interface Window {
    __ENV__?: Record<string, string | undefined>
  }
}

function runtimeEnv(key: string): string | undefined {
  if (typeof window === 'undefined') return undefined
  const value = window.__ENV__?.[key]
  // Ignore the empty placeholders public/config.js ships for local dev.
  return value && value.trim() !== '' ? value : undefined
}

function setting(key: string): string {
  return (runtimeEnv(key) ?? (import.meta.env[key] as string | undefined) ?? '').trim()
}

function trimSlash(value: string): string {
  return value.replace(/\/$/, '')
}

/**
 * Where secret's REST API lives.
 *
 * Same-origin `/api/v1` by default, in dev through the Vite proxy and in a
 * deployment through the edge proxy. Same-origin is the point rather than a
 * convenience: it keeps the bearer token off a cross-origin preflight and keeps
 * this console's requests out of another host's logs.
 */
const getBaseUrl = (): string => {
  if (import.meta.env.DEV) return '/api/v1'
  return setting('VITE_SECRET_API_BASE_URL') || '/api/v1'
}

/**
 * The identity configuration, or null when this deployment has none.
 *
 * NULL IS A REAL, SUPPORTED STATE and not an error. A development instance of
 * maintainerd-secret runs with APP_ENV=development and no AUTH_JWKS_URL /
 * AUTH_ISSUER / AUTH_AUDIENCE, which puts its guard in development-open mode:
 * it serves every caller as a blanket-granted principal and there is no token to
 * obtain. The console renders that state honestly (a persistent banner) instead
 * of bouncing the operator into an OAuth flow no one is listening for.
 *
 * All three fields are required together. A half-configured identity would send
 * the operator to an authorize endpoint whose code could never be exchanged.
 */
export interface IdentityConfig {
  /** Hosted identity origin — `/authorize` and `/end-session` hang off it. */
  issuerUrl: string
  /** Absolute URL of the OAuth token endpoint (maintainerd-auth public API). */
  tokenUrl: string
  /** This console's public OAuth client id. */
  clientId: string
  /** Resource-API audience secret enforces (its AUTH_AUDIENCE). */
  audience: string
  /** Space-separated scopes requested on top of `openid profile email`. */
  extraScope: string
}

function readIdentityConfig(): IdentityConfig | null {
  const issuerUrl = trimSlash(setting('VITE_OAUTH_ISSUER_URL'))
  const clientId = setting('VITE_OAUTH_CLIENT_ID')
  const tokenUrl = setting('VITE_OAUTH_TOKEN_URL')
  if (!issuerUrl || !clientId || !tokenUrl) return null
  return {
    issuerUrl,
    tokenUrl,
    clientId,
    audience: setting('VITE_OAUTH_AUDIENCE'),
    extraScope: setting('VITE_OAUTH_SCOPE'),
  }
}

export const IDENTITY_CONFIG: IdentityConfig | null = readIdentityConfig()

export const API_CONFIG = {
  BASE_URL: getBaseUrl(),
  TIMEOUT: 30000,
  HEADERS: {
    'Content-Type': 'application/json',
  },
} as const

/**
 * REST endpoints, relative to BASE_URL (= /api/v1).
 *
 * The shape is FLAT — /projects, /environments, /folders, /secrets, /bulk,
 * /imports, /webhooks, /audit, /setup — because that is what the service's
 * per-segment permission allowlist is built on. Reveal and batch-get are POSTs
 * despite being reads: a secret's address in a URL lands in access logs, proxy
 * logs and browser history, and a request body does not.
 */
export const API_ENDPOINTS = {
  SETUP: '/setup',
  SETUP_STATUS: '/setup/status',
  PROJECTS: '/projects',
  ENVIRONMENTS: '/environments',
  FOLDERS: '/folders',
  FOLDERS_MOVE: '/folders/move',
  IMPORTS: '/imports',
  SECRETS: '/secrets',
  SECRETS_DESCRIBE: '/secrets/describe',
  SECRETS_VERSIONS: '/secrets/versions',
  SECRETS_DELETED: '/secrets/deleted',
  SECRETS_REVEAL: '/secrets/reveal',
  SECRETS_ROLLBACK: '/secrets/rollback',
  SECRETS_ROTATE: '/secrets/rotate',
  SECRETS_ROTATION_POLICY: '/secrets/rotation-policy',
  SECRETS_DELETE: '/secrets/delete',
  SECRETS_RESTORE: '/secrets/restore',
  SECRETS_DESTROY: '/secrets/destroy',
  WEBHOOKS: '/webhooks',
  AUDIT: '/audit',
} as const

/** Header that selects which tenant a request addresses (never an authorization). */
export const TENANT_HEADER = 'X-Maintainerd-Tenant'

/** Header carrying the one-time bootstrap token on the setup wizard. */
export const SETUP_TOKEN_HEADER = 'X-Setup-Token'
