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

/**
 * Reads one setting, trying each key in order and taking the first that is set,
 * runtime before build time.
 *
 * TWO SPELLINGS ON PURPOSE. The first key is the name maintainerd-secret's own
 * process uses for the same fact — `SECRET_CONSOLE_CLIENT_ID`, `AUTH_ISSUER`,
 * `AUTH_AUDIENCE` — and the later ones are the `VITE_*` build-time names. An
 * operator following the standalone runbook creates a console SPA client in
 * Auth and is handed one client id; they then set `SECRET_CONSOLE_CLIENT_ID`
 * once, for the service (which validates it at boot) and for the console
 * (which signs in with it). A console whose variable were spelled differently
 * from the service's would be an invitation to set one and not the other, and
 * the symptom of that — an authorize request for a client id that does not
 * exist — surfaces in a browser, far from the operator reading the runbook.
 *
 * The `VITE_*` names keep working, unchanged, because they are what a local
 * `.env` and every existing deployment already use.
 */
function setting(...keys: string[]): string {
  for (const key of keys) {
    const value = runtimeEnv(key) ?? (import.meta.env[key] as string | undefined)
    if (value && value.trim() !== '') return value.trim()
  }
  return ''
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
  return setting('SECRET_API_BASE_URL', 'VITE_SECRET_API_BASE_URL') || '/api/v1'
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
  // Each line lists the SERVICE's spelling first and the build-time VITE_ name
  // second — see `setting`. The issuer is Auth's hosted identity origin, which is
  // the same value the service enforces as AUTH_ISSUER.
  const issuerUrl = trimSlash(setting('AUTH_ISSUER', 'VITE_OAUTH_ISSUER_URL'))
  const clientId = setting('SECRET_CONSOLE_CLIENT_ID', 'VITE_OAUTH_CLIENT_ID')
  const tokenUrl = setting('SECRET_CONSOLE_TOKEN_URL', 'VITE_OAUTH_TOKEN_URL')
  if (!issuerUrl || !clientId || !tokenUrl) return null
  return {
    issuerUrl,
    tokenUrl,
    clientId,
    audience: setting('AUTH_AUDIENCE', 'VITE_OAUTH_AUDIENCE'),
    extraScope: setting('SECRET_CONSOLE_SCOPE', 'VITE_OAUTH_SCOPE'),
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
  /** Unauthenticated: what this instance can tell an anonymous caller about itself. */
  CAPABILITIES: '/capabilities',
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
