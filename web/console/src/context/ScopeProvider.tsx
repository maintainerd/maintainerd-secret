import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react'
import { useEnvironments } from '@/hooks/useEnvironments'
import { useProjects } from '@/hooks/useProjects'
import { ScopeContext, type ScopeContextValue } from './scopeContext'

/**
 * Remembers the last project/environment across reloads.
 *
 * Slugs only. They are not credentials — they are the same names that appear in
 * every MRN and in the URL bar — and remembering them is what stops an operator
 * from re-selecting "prod" on every visit. Nothing about a SECRET is persisted
 * here: no key names, no values, no addresses.
 */
const STORAGE_KEY = 'maintainerd.secret.console.scope'

interface StoredScope {
  project?: string
  environment?: string
}

function readStoredScope(): StoredScope {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY)
    return raw ? (JSON.parse(raw) as StoredScope) : {}
  } catch {
    return {}
  }
}

function writeStoredScope(scope: StoredScope): void {
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(scope))
  } catch {
    // A blocked localStorage (private mode, storage policy) costs the operator a
    // re-selection; it must never take the console down.
  }
}

export function ScopeProvider({ children }: { children: ReactNode }) {
  const stored = useMemo(readStoredScope, [])
  const [project, setProjectState] = useState<string | null>(stored.project ?? null)
  const [environment, setEnvironmentState] = useState<string | null>(stored.environment ?? null)

  const projectsQuery = useProjects({ page: 1, limit: 200 })
  const environmentsQuery = useEnvironments(project ?? undefined)

  const projects = useMemo(() => projectsQuery.data?.rows ?? [], [projectsQuery.data])
  const environments = useMemo(() => environmentsQuery.data ?? [], [environmentsQuery.data])

  // Pick a project as soon as one is known, and drop a remembered slug that no
  // longer exists — a stale selection would 404 every page in the shell.
  useEffect(() => {
    if (projects.length === 0) return
    const known = project && projects.some((candidate) => candidate.slug === project)
    if (known) return
    setProjectState(projects[0].slug)
    setEnvironmentState(null)
  }, [projects, project])

  // Same for the environment, within the selected project.
  useEffect(() => {
    if (environments.length === 0) return
    const known = environment && environments.some((candidate) => candidate.slug === environment)
    if (known) return
    setEnvironmentState(environments[0].slug)
  }, [environments, environment])

  useEffect(() => {
    writeStoredScope({ project: project ?? undefined, environment: environment ?? undefined })
  }, [project, environment])

  const setProject = useCallback((slug: string) => {
    setProjectState(slug)
    // Environments are per-project: carrying the old slug over would point at an
    // environment that may not exist here, or — worse — at a same-named one in a
    // different project.
    setEnvironmentState(null)
  }, [])

  const setEnvironment = useCallback((slug: string) => setEnvironmentState(slug), [])

  const value = useMemo<ScopeContextValue>(
    () => ({
      projects,
      environments,
      project,
      environment,
      setProject,
      setEnvironment,
      loading: projectsQuery.isLoading || environmentsQuery.isLoading,
      error: projectsQuery.error ?? environmentsQuery.error ?? null,
    }),
    [
      projects,
      environments,
      project,
      environment,
      setProject,
      setEnvironment,
      projectsQuery.isLoading,
      projectsQuery.error,
      environmentsQuery.isLoading,
      environmentsQuery.error,
    ],
  )

  return <ScopeContext.Provider value={value}>{children}</ScopeContext.Provider>
}
