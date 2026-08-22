import type { ReactNode } from 'react'
import { Navigate, useLocation } from 'react-router-dom'
import { AppLoadingScreen } from '@/components/layout/AppLoadingScreen'
import { useSetupStatus } from '@/hooks/useSetup'

/**
 * First-run gate.
 *
 * While the status loads, the splash. If the instance has not been provisioned,
 * everything redirects to /setup; once it has, /setup bounces to the browser.
 *
 * IT FAILS CLOSED. An unreadable status is treated as NOT set up, deliberately:
 * defaulting to "set up" on an error renders the full console against a vault
 * that may not exist yet, and every page then reports a confusing failure of its
 * own. The wizard is the safe landing surface, and it recovers by itself the
 * moment /setup/status answers.
 */
export function SetupGate({ children }: { children: ReactNode }) {
  const { data, isLoading } = useSetupStatus()
  const location = useLocation()

  if (isLoading) return <AppLoadingScreen message="Checking the vault" />

  const completed = data?.completed ?? false // fail closed on error/unknown
  const onSetup = location.pathname === '/setup'

  if (!completed && !onSetup) return <Navigate to="/setup" replace />
  if (completed && onSetup) return <Navigate to="/browse" replace />

  return <>{children}</>
}
