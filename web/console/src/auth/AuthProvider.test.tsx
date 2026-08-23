import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { IdentityConfig } from '@/services/api/config'
import type { Capabilities } from '@/services/api/types'

const IDENTITY: IdentityConfig = {
  issuerUrl: 'https://identity.example.test',
  tokenUrl: 'https://identity.example.test/oauth/token',
  clientId: 'secret-console',
  audience: 'maintainerd-secret',
  extraScope: '',
}

const ENFORCED: Capabilities = {
  service: 'maintainerd-secret',
  version: 'test',
  guard_mode: 'enforced',
  setup_complete: true,
  run_mode: 'standalone',
  auth: { issuer: IDENTITY.issuerUrl, audience: IDENTITY.audience },
  console: true,
}

const startLogin = vi.fn(async () => {})
const trySilentLogin = vi.fn(async () => false)
const getCapabilities = vi.fn(async () => ENFORCED)

vi.mock('@/services/api/config', async () => {
  const actual = await vi.importActual<typeof import('@/services/api/config')>(
    '@/services/api/config',
  )
  return { ...actual, IDENTITY_CONFIG: IDENTITY }
})

vi.mock('./oauthClient', () => ({
  startLogin: (...args: unknown[]) => startLogin(...(args as [])),
  trySilentLogin: (...args: unknown[]) => trySilentLogin(...(args as [])),
  endSessionUrl: () => 'https://identity.example.test/end-session',
}))

vi.mock('@/services/api/capabilities', () => ({
  getCapabilities: () => getCapabilities(),
}))

const { AuthProvider } = await import('./AuthProvider')
const { useAuth } = await import('./authContext')

/**
 * Two independent callers, one sign-in — the double-tap that broke sign-in the
 * moment the API began refusing anonymous callers. See `AuthProvider.signIn`.
 */
function DoubleSignIn() {
  const { signIn } = useAuth()
  return (
    <button
      type="button"
      onClick={() => {
        // The interceptor's handler and RequireAuth → LoginPage both fire on the
        // same expiry, in whatever order React and axios happen to interleave.
        signIn('/projects')
        signIn('/browse')
      }}
    >
      expire
    </button>
  )
}

function renderProvider() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  })
  return render(
    <QueryClientProvider client={client}>
      <AuthProvider>
        <DoubleSignIn />
      </AuthProvider>
    </QueryClientProvider>,
  )
}

describe('AuthProvider sign-in single-flight', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getCapabilities.mockResolvedValue(ENFORCED)
    trySilentLogin.mockResolvedValue(false)
  })

  it('starts at most one authorization even when two callers ask at once', async () => {
    const user = userEvent.setup()
    renderProvider()

    await waitFor(() => expect(screen.getByRole('button', { name: 'expire' })).toBeInTheDocument())
    await user.click(screen.getByRole('button', { name: 'expire' }))

    // Each call would otherwise mint its own `state` + `code_verifier` and
    // overwrite the single pending-flow slot in sessionStorage before navigating,
    // so the callback could arrive bearing one state against the other's stored
    // flow — a CSRF mismatch the callback correctly refuses, leaving the operator
    // told their sign-in link is invalid on every single expiry.
    expect(startLogin).toHaveBeenCalledTimes(1)
  })

  it('honours the first caller\'s destination', async () => {
    const user = userEvent.setup()
    renderProvider()

    await waitFor(() => expect(screen.getByRole('button', { name: 'expire' })).toBeInTheDocument())
    await user.click(screen.getByRole('button', { name: 'expire' }))

    expect(startLogin).toHaveBeenCalledWith(IDENTITY, '/projects')
  })

  it('blocks first paint until the session verdict is in', async () => {
    let settle: (value: Capabilities) => void = () => {}
    getCapabilities.mockImplementation(
      () =>
        new Promise<Capabilities>((resolve) => {
          settle = resolve
        }),
    )

    renderProvider()

    // The splash, not the app: rendering a protected surface before the verdict is
    // what produces the paint-then-bounce flicker.
    expect(screen.getByRole('status')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'expire' })).not.toBeInTheDocument()

    settle(ENFORCED)
    await waitFor(() => expect(screen.getByRole('button', { name: 'expire' })).toBeInTheDocument())
  })
})
