import type { ReactNode } from 'react'
import { Navigate, useLocation } from 'react-router-dom'
import { useAuth } from './authContext'

/**
 * Gate for every protected route.
 *
 * An unauthenticated visit routes to /login rather than rendering a shell full
 * of failed requests. A 403 is NOT handled here on purpose: a forbidden call
 * means the caller IS authenticated and simply lacks that grant, so bouncing it
 * to sign-in would loop them through identity forever and still land on the same
 * refusal. Those surface in place, as a "not permitted" state (see
 * `components/layout/states.tsx`).
 */
export function RequireAuth({ children }: { children: ReactNode }) {
  const { mode } = useAuth()
  const location = useLocation()

  if (mode === 'anonymous') {
    return (
      <Navigate to="/login" replace state={{ from: `${location.pathname}${location.search}` }} />
    )
  }
  return <>{children}</>
}
