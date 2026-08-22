import { Outlet } from 'react-router-dom'
import { RequireAuth } from '@/auth/RequireAuth'
import { SetupGate } from '@/components/SetupGate'
import { ScopeProvider } from '@/context/ScopeProvider'

/**
 * The gates every signed-in route passes through, in order.
 *
 *   RequireAuth    keeps unauthenticated visitors off the app
 *   SetupGate      keeps everyone off an unprovisioned vault, failing CLOSED
 *   ScopeProvider  owns the project/environment every address is relative to
 *
 * It exists as a layout route rendering `<Outlet/>` so the gates are declared
 * ONCE and the two content layouts (full-width for the browser, centred for
 * everything else) nest beneath it. Declaring them per layout would mount the
 * scope provider twice and re-run the setup check on every switch between the
 * two widths.
 */
export function ProtectedShell() {
  return (
    <RequireAuth>
      <SetupGate>
        <ScopeProvider>
          <Outlet />
        </ScopeProvider>
      </SetupGate>
    </RequireAuth>
  )
}
