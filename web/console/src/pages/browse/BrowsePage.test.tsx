import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import BrowsePage from './BrowsePage'
import { ScopeContext, type ScopeContextValue } from '@/context/scopeContext'
import type { Folder, SecretMeta } from '@/services/api/types'

const SECRETS: SecretMeta[] = [
  {
    secret_uuid: 'a1',
    folder_path: '/',
    key: 'DATABASE_PASSWORD',
    description: 'Primary Postgres',
    tags: ['db'],
    current_version: 4,
    keep_versions: 10,
    rotation_policy: {},
    mrn_resource_path: 'secret/payments/prod/DATABASE_PASSWORD',
    mrn: 'mrn:secret:acme:secret/payments/prod/DATABASE_PASSWORD',
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
  },
  {
    secret_uuid: 'a2',
    folder_path: '/billing',
    key: 'STRIPE_KEY',
    description: '',
    tags: ['billing'],
    current_version: 1,
    keep_versions: 10,
    rotation_policy: {},
    mrn_resource_path: 'secret/payments/prod/billing/STRIPE_KEY',
    mrn: 'mrn:secret:acme:secret/payments/prod/billing/STRIPE_KEY',
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
  },
]

const FOLDERS: Folder[] = [
  {
    folder_uuid: 'f1',
    name: 'billing',
    path: '/billing',
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
  },
]

const revealSpy = vi.fn()

vi.mock('@/hooks/useFolders', () => ({
  useFolders: () => ({ data: FOLDERS, isLoading: false, isError: false, error: null, refetch: vi.fn() }),
  useCreateFolder: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useMoveFolder: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useDeleteFolder: () => ({ mutateAsync: vi.fn(), isPending: false }),
}))

vi.mock('@/hooks/useSecrets', () => ({
  useSecrets: () => ({
    data: { rows: SECRETS, meta: { page: 1, limit: 200, total: SECRETS.length } },
    isLoading: false,
    isError: false,
    error: null,
    refetch: vi.fn(),
  }),
  useDeleteSecret: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useSecretMeta: () => ({ data: undefined, isLoading: false, isError: false, refetch: vi.fn() }),
  useSecretVersions: () => ({ data: undefined, isLoading: false, isError: false, refetch: vi.fn() }),
  useRollbackSecret: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useRotateSecret: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useSetRotationPolicy: () => ({ mutateAsync: vi.fn(), isPending: false }),
  usePutSecret: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useUpdateSecretMeta: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useRevealSecret: () => ({
    mutateAsync: revealSpy,
    reset: vi.fn(),
    isPending: false,
    isError: false,
    error: null,
  }),
}))

vi.mock('@/hooks/useImports', () => ({
  useImports: () => ({ data: [], isLoading: false, isError: false, error: null, refetch: vi.fn() }),
  useCreateImport: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useSetImportEnabled: () => ({ mutate: vi.fn() }),
  useDeleteImport: () => ({ mutate: vi.fn() }),
}))

function scope(): ScopeContextValue {
  return {
    projects: [],
    environments: [],
    project: 'payments',
    environment: 'prod',
    setProject: vi.fn(),
    setEnvironment: vi.fn(),
    loading: false,
    error: null,
  }
}

function renderPage() {
  return render(
    <ScopeContext.Provider value={scope()}>
      <MemoryRouter initialEntries={['/browse']}>
        <BrowsePage />
      </MemoryRouter>
    </ScopeContext.Provider>,
  )
}

/**
 * The two guarantees the browse screen exists to keep, asserted rather than
 * described in a comment.
 */
describe('BrowsePage', () => {
  it('lists metadata for the current folder without revealing anything', () => {
    renderPage()

    expect(screen.getByRole('heading', { name: 'Secrets' })).toBeInTheDocument()
    expect(screen.getByText('DATABASE_PASSWORD')).toBeInTheDocument()
    expect(screen.getByText('Primary Postgres')).toBeInTheDocument()

    // Rendering the list must never have called the reveal endpoint.
    expect(revealSpy).not.toHaveBeenCalled()

    // A secret in a subfolder is out of scope until "Include subfolders" is on.
    expect(screen.queryByText('STRIPE_KEY')).not.toBeInTheDocument()
  })

  it('brings subfolder secrets in when asked, and shows which folder they are in', async () => {
    const user = userEvent.setup()
    renderPage()

    await user.click(screen.getByLabelText(/include subfolders/i))

    expect(await screen.findByText('STRIPE_KEY')).toBeInTheDocument()
    expect(screen.getByText('/billing')).toBeInTheDocument()
  })

  it('keeps the folder path and the search term out of the URL', async () => {
    const user = userEvent.setup()
    renderPage()

    // Navigating the tree changes what is listed but never the address bar: a
    // folder path (and a searched-for key name) would otherwise land in history.
    await user.click(screen.getByRole('treeitem', { name: 'billing' }))
    expect(await screen.findByText('STRIPE_KEY')).toBeInTheDocument()
    expect(window.location.search).toBe('')

    await user.type(screen.getByPlaceholderText(/filter by key/i), 'STRIPE')
    expect(window.location.search).toBe('')
  })

  it('exposes the folder tree as a keyboard-navigable tree', () => {
    renderPage()
    expect(screen.getByRole('tree', { name: 'Folders' })).toBeInTheDocument()
    expect(screen.getAllByRole('treeitem')).toHaveLength(2)
  })
})
