import { createContext, useContext } from 'react'
import type { Environment, Project } from '@/services/api/types'

/**
 * The project/environment the console is pointed at.
 *
 * Almost every call in this API is addressed by (project, environment, folder,
 * key), so the shell owns that pair once instead of every page re-deriving it —
 * and, more importantly, so the operator can SEE which environment they are
 * about to write to. "Which environment am I in" is the question behind most
 * accidental production writes.
 */
export interface ScopeContextValue {
  projects: Project[]
  environments: Environment[]
  project: string | null
  environment: string | null
  setProject: (slug: string) => void
  setEnvironment: (slug: string) => void
  /** True while the project or environment list is still loading. */
  loading: boolean
  /** Set when the scope could not be loaded (commonly a missing grant). */
  error: unknown
}

export const ScopeContext = createContext<ScopeContextValue | null>(null)

export function useScope(): ScopeContextValue {
  const value = useContext(ScopeContext)
  if (!value) throw new Error('useScope must be used inside <ScopeProvider>')
  return value
}

/**
 * The scope as a partial secret address, for pages that need to pass it on.
 * Returns null until both halves are known, so a caller cannot accidentally
 * address `project=""`.
 */
export function useScopeAddress(): { project: string; environment: string } | null {
  const { project, environment } = useScope()
  if (!project || !environment) return null
  return { project, environment }
}
