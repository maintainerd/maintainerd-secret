import { beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { PrivateLayout } from './PrivateLayout'
import { AuthContext, type AuthContextValue } from '@/auth/authContext'
import { ScopeContext, type ScopeContextValue } from '@/context/scopeContext'
import { ConsoleBrandingProvider } from '@/components/theme/ConsoleBrandingProvider'
import type { Environment, Project } from '@/services/api/types'

const PROJECT: Project = {
  project_uuid: 'p1',
  name: 'Payments',
  slug: 'payments',
  description: '',
  status: 'active',
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
}

const ENVIRONMENT: Environment = {
  environment_uuid: 'e1',
  name: 'Production',
  slug: 'prod',
  description: '',
  position: 0,
  status: 'active',
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
}

function scope(): ScopeContextValue {
  return {
    projects: [PROJECT],
    environments: [ENVIRONMENT],
    project: 'payments',
    environment: 'prod',
    setProject: vi.fn(),
    setEnvironment: vi.fn(),
    loading: false,
    error: null,
  }
}

function auth(mode: AuthContextValue['mode']): AuthContextValue {
  return {
    mode,
    ready: true,
    identity: null,
    // Deliberately null. The shell must render each state from `mode` alone; if a
    // banner or chip ever needed the raw capability payload to decide what to say,
    // these tests would start passing for the wrong reason.
    capabilities: null,
    signIn: vi.fn(),
    signOut: vi.fn(),
  }
}

function renderShell(mode: AuthContextValue['mode'] = 'authenticated') {
  return render(
    <ConsoleBrandingProvider>
      <AuthContext.Provider value={auth(mode)}>
        <ScopeContext.Provider value={scope()}>
          <MemoryRouter initialEntries={['/projects']}>
            <Routes>
              <Route element={<PrivateLayout />}>
                <Route path="/projects" element={<p>page body</p>} />
              </Route>
            </Routes>
          </MemoryRouter>
        </ScopeContext.Provider>
      </AuthContext.Provider>
    </ConsoleBrandingProvider>,
  )
}

/**
 * The signed-in chrome, end to end: brand bar, sidebar, scope switcher, content.
 *
 * This is the smoke test for the design-system adoption — if a shared primitive
 * from maintainerd-auth is wired up wrong, the shell fails to mount here rather
 * than in somebody's browser.
 */
describe('PrivateLayout', () => {
  it('renders the brand bar, the nav and the page body', () => {
    renderShell()

    expect(screen.getByText('Maintainerd Secret')).toBeInTheDocument()
    expect(screen.getByText('page body')).toBeInTheDocument()

    for (const label of ['Secrets', 'Projects', 'Webhooks', 'Deleted', 'Audit log']) {
      expect(screen.getAllByText(label).length).toBeGreaterThan(0)
    }
  })

  it('marks the current route active in the sidebar', () => {
    renderShell()
    const projects = screen.getAllByRole('link', { name: 'Projects' })[0]
    expect(projects).toHaveAttribute('data-active', 'true')
  })

  it('shows the scope switcher with the selected project and environment', () => {
    renderShell()
    expect(screen.getAllByText('payments').length).toBeGreaterThan(0)
    expect(screen.getAllByText('prod').length).toBeGreaterThan(0)
  })

  it('offers sign-out while authenticated, and reports the guard as enforced', () => {
    renderShell('authenticated')
    expect(screen.getByText('Guarded')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /signed in/i })).toBeInTheDocument()
    expect(screen.queryByText(/development-open/)).not.toBeInTheDocument()
    expect(screen.queryByText(/no identity configured/)).not.toBeInTheDocument()
  })

  it('shows a permanent, non-dismissible banner in guard-open mode', () => {
    renderShell('guard-open')

    expect(screen.getByText(/reports its guard is development-open/)).toBeInTheDocument()
    expect(screen.getByText('Guard open')).toBeInTheDocument()
    // No close/dismiss affordance anywhere in the banner.
    expect(
      screen.queryByRole('button', { name: /dismiss|close banner/i }),
    ).not.toBeInTheDocument()
  })

  it('shows a different banner when the service enforces and no identity is configured', () => {
    renderShell('identity-missing')

    expect(
      screen.getByText(/enforces authentication and this console has no identity configured/),
    ).toBeInTheDocument()
    // It must name the settings to set, or the operator has nothing to act on.
    expect(screen.getByText('SECRET_CONSOLE_CLIENT_ID')).toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: /dismiss|close banner/i }),
    ).not.toBeInTheDocument()
  })

  // The regression that motivated splitting the two modes apart. They were one state,
  // so the console could not distinguish "no token is needed" from "a token is needed
  // and I cannot get one" — opposite situations where only one is safe. Asserting each
  // banner separately would still pass if both rendered the same words, so this asserts
  // the DISTINCTION directly, in both the banner and the chip.
  it('never describes the two enforcement states the same way', () => {
    renderShell('guard-open')
    expect(screen.getByText('Guard open')).toBeInTheDocument()
    expect(
      screen.queryByText(/enforces authentication and this console has no identity configured/),
    ).not.toBeInTheDocument()

    cleanup()

    renderShell('identity-missing')
    // Not "Guarded": the service IS enforcing, so that would be true and misleading —
    // the operator would read a reassuring chip while every request comes back 401.
    expect(screen.getByText('No credentials')).toBeInTheDocument()
    expect(screen.queryByText('Guarded')).not.toBeInTheDocument()
    expect(screen.queryByText(/reports its guard is development-open/)).not.toBeInTheDocument()
  })
})

/**
 * Mounts the layout the way App.tsx does: ONE layout element with every signed-in
 * route nested beneath it.
 *
 * That structure is the fix, and this is the shape it has to keep. It used to be
 * two sibling `<PrivateLayout>` elements — one full-width for /browse, one capped
 * for the rest — and two element positions in a route tree are two component
 * instances. Crossing between /browse and anything else therefore unmounted the
 * whole shell and mounted the other one: the `SidebarProvider` was rebuilt from
 * `defaultOpen`, so a collapsed rail sprang back open, and the sidebar container
 * remounted part-way through its 200ms `transition-[left,right,width]` and
 * replayed it. That is the "sticking", and it read as intermittent because it only
 * happened on the navigations that crossed between the two layouts.
 */
function renderRoutedShell(initial = '/projects') {
  return render(
    <ConsoleBrandingProvider>
      <AuthContext.Provider value={auth('authenticated')}>
        <ScopeContext.Provider value={scope()}>
          <MemoryRouter initialEntries={[initial]}>
            <Routes>
              <Route element={<PrivateLayout />}>
                <Route path="/browse" element={<p>secrets body</p>} />
                <Route path="/projects" element={<p>projects body</p>} />
              </Route>
            </Routes>
          </MemoryRouter>
        </ScopeContext.Provider>
      </AuthContext.Provider>
    </ConsoleBrandingProvider>,
  )
}

function railState(): string | null | undefined {
  return document.querySelector('[data-slot="sidebar"]')?.getAttribute('data-state')
}

describe('PrivateLayout sidebar stability across navigation', () => {
  beforeEach(() => {
    document.cookie = 'sidebar_state=; path=/; max-age=0'
  })

  it('keeps the rail collapsed when navigating between the browse and listing routes', async () => {
    const user = userEvent.setup()
    renderRoutedShell('/projects')

    await user.click(screen.getByRole('button', { name: /toggle sidebar/i }))
    expect(railState()).toBe('collapsed')

    // /browse and /projects are the two routes that used to live under DIFFERENT
    // layout elements, so this is exactly the navigation that lost the state.
    await user.click(screen.getAllByRole('link', { name: 'Secrets' })[0])
    expect(await screen.findByText('secrets body')).toBeInTheDocument()
    expect(railState()).toBe('collapsed')

    await user.click(screen.getAllByRole('link', { name: 'Projects' })[0])
    expect(await screen.findByText('projects body')).toBeInTheDocument()
    expect(railState()).toBe('collapsed')
  })

  it('keeps the brand bar and rail mounted across that navigation', async () => {
    const user = userEvent.setup()
    renderRoutedShell('/browse')

    const barBefore = document.querySelector('[data-console-sidebar]')
    await user.click(screen.getAllByRole('link', { name: 'Projects' })[0])
    expect(await screen.findByText('projects body')).toBeInTheDocument()

    // Same DOM node, not a replacement — a remounted rail is what replayed the
    // slide animation from scratch.
    expect(document.querySelector('[data-console-sidebar]')).toBe(barBefore)
  })

  it('leaves the content width to the page, capping nothing itself', async () => {
    renderRoutedShell('/browse')

    // Auth mounts this layout full-width and lets its listing pages own
    // `mx-auto max-w-6xl`. Capping here as well double-capped every page that
    // already capped itself, insetting the tables by the main element's padding.
    const main = document.querySelector('main[class*="flex-1"]')
    expect(main?.className).not.toMatch(/max-w-/)
  })
})
