import { beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { SetupGate } from './SetupGate'
import { AuthContext, type AuthContextValue } from '@/auth/authContext'
import type { Capabilities } from '@/services/api/types'

const status = vi.hoisted(() => ({ current: { data: { completed: false }, isLoading: false } }))

vi.mock('@/hooks/useSetup', () => ({
  useSetupStatus: () => status.current,
}))

function capabilities(runMode: string): Capabilities {
  return {
    service: 'secret',
    version: 'test',
    guard_mode: 'enforced',
    setup_complete: false,
    run_mode: runMode,
    console: true,
  }
}

function auth(caps: Capabilities | null): AuthContextValue {
  return {
    mode: 'authenticated',
    ready: true,
    identity: null,
    capabilities: caps,
    signIn: vi.fn(),
    signOut: vi.fn(),
  }
}

/** Renders the gate at `entry` and reports where it landed. */
function renderGate(entry: string, caps: Capabilities | null) {
  return render(
    <AuthContext.Provider value={auth(caps)}>
      <MemoryRouter initialEntries={[entry]}>
        <Routes>
          <Route
            path="/setup"
            element={
              <SetupGate>
                <p>set up this vault</p>
              </SetupGate>
            }
          />
          <Route
            path="/browse"
            element={
              <SetupGate>
                <p>the browser</p>
              </SetupGate>
            }
          />
        </Routes>
      </MemoryRouter>
    </AuthContext.Provider>,
  )
}

beforeEach(() => {
  cleanup()
  status.current = { data: { completed: false }, isLoading: false }
})

/**
 * Which first-run path this console offers — and it must never offer one the
 * service has already shut.
 */
describe('an unprovisioned vault', () => {
  it('sends a standalone install to the wizard', () => {
    renderGate('/browse', capabilities('standalone'))
    expect(screen.getByText('set up this vault')).toBeInTheDocument()
  })

  /**
   * `run_mode: "core"` means the service closed its REST wizard at boot because a
   * controller owns first-run over gRPC. Offering the wizard anyway is offering a
   * form the server refuses with `setup_orchestrated` — and it reads to the
   * operator as a second live bootstrap path, which is the race the mode exists to
   * close.
   */
  it('offers no wizard when a controller owns the vault', () => {
    renderGate('/browse', capabilities('core'))
    expect(screen.getByText('the browser')).toBeInTheDocument()
    expect(screen.queryByText('set up this vault')).not.toBeInTheDocument()
  })

  it('bounces a controller-owned install off /setup', () => {
    renderGate('/setup', capabilities('core'))
    expect(screen.getByText('the browser')).toBeInTheDocument()
  })

  // A probe that failed says nothing about who owns setup, so the gate keeps the
  // standalone behaviour — the direction AuthProvider also degrades in.
  it('keeps the wizard when the capability probe failed', () => {
    renderGate('/browse', null)
    expect(screen.getByText('set up this vault')).toBeInTheDocument()
  })
})

describe('a provisioned vault', () => {
  it('bounces /setup to the browser', () => {
    status.current = { data: { completed: true }, isLoading: false }
    renderGate('/setup', capabilities('standalone'))
    expect(screen.getByText('the browser')).toBeInTheDocument()
  })
})
