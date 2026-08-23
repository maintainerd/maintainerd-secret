import type { ReactNode } from 'react'
import { Navigate, useLocation } from 'react-router-dom'
import { useAuth } from '@/auth/authContext'
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
 *
 * EXCEPT WHEN THE VAULT HAS A CONTROLLER. `run_mode: "core"` from
 * `GET /capabilities` means the service shut its REST wizard at boot and a
 * controller owns first-run over gRPC. Offering the wizard then is offering a
 * form the server will refuse with `setup_orchestrated` — and, worse, it reads to
 * the operator as a second live bootstrap path, which is precisely the race the
 * mode exists to close. The mode is what `run_mode` is published for; this gate
 * is its only consumer.
 *
 * A FAILED PROBE IS NOT A CONTROLLER. `capabilities` is null when the probe
 * failed, and the fall-through is the standalone behaviour above — the same
 * direction AuthProvider degrades in.
 */
export function SetupGate({ children }: { children: ReactNode }) {
  const { capabilities } = useAuth()
  const { data, isLoading } = useSetupStatus()
  const location = useLocation()

  if (isLoading) return <AppLoadingScreen message="Checking the vault" />

  const controllerOwned = capabilities?.run_mode === 'core'
  const completed = data?.completed ?? false // fail closed on error/unknown
  const onSetup = location.pathname === '/setup'

  if (onSetup && (completed || controllerOwned)) return <Navigate to="/browse" replace />
  if (!completed && !controllerOwned && !onSetup) return <Navigate to="/setup" replace />

  return <>{children}</>
}
