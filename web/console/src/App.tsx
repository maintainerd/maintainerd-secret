import { lazy, Suspense } from 'react'
import { Navigate, Route, Routes, useLocation } from 'react-router-dom'
import { QueryClientProvider } from '@tanstack/react-query'
import { ToastContainer } from 'react-toastify'
import 'react-toastify/dist/ReactToastify.css'
import { queryClient } from '@/lib/queryClient'
import { AuthProvider } from '@/auth/AuthProvider'
import { RequireAuth } from '@/auth/RequireAuth'
import { OAUTH_CALLBACK_ROUTE } from '@/auth/oauthFlow'
import { ScopeProvider } from '@/context/ScopeProvider'
import { SetupGate } from '@/components/SetupGate'
import ErrorBoundary from '@/components/ErrorBoundary'
import { AppShell } from '@/components/layout/AppShell'
import { AppLoadingScreen } from '@/components/layout/AppLoadingScreen'

// The shell stays eager; every page is code-split so the initial bundle carries
// only the shell plus the current route's chunk.
const BrowsePage = lazy(() => import('./pages/browse/BrowsePage'))
const ProjectsPage = lazy(() => import('./pages/projects/ProjectsPage'))
const WebhooksPage = lazy(() => import('./pages/webhooks/WebhooksPage'))
const DeletedPage = lazy(() => import('./pages/deleted/DeletedPage'))
const AuditPage = lazy(() => import('./pages/audit/AuditPage'))
const SetupPage = lazy(() => import('./pages/setup/SetupPage'))
const LoginPage = lazy(() => import('./pages/auth/LoginPage'))
const OAuthCallbackPage = lazy(() => import('./pages/auth/OAuthCallbackPage'))
const NotFoundPage = lazy(() => import('./pages/not-found/NotFoundPage'))

/**
 * Route layering, outermost first:
 *
 *   AuthProvider   decides whether a credential is held, before anything paints
 *   RequireAuth    keeps unauthenticated visitors off the app (protected tree)
 *   SetupGate      keeps everyone off an unprovisioned vault, failing CLOSED
 *   ScopeProvider  owns the project/environment every address is relative to
 *
 * /login and the OAuth callback sit OUTSIDE all of it — they exist precisely
 * because there is no session yet, and gating them would deadlock sign-in.
 * /setup is outside RequireAuth for the same reason: on a fresh install there is
 * no identity to authenticate against until the vault has been provisioned.
 */
function App() {
  const location = useLocation()

  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <ErrorBoundary resetKey={`${location.pathname}${location.search}`}>
          <Suspense fallback={<AppLoadingScreen />}>
            <Routes>
              <Route path="/login" element={<LoginPage />} />
              <Route path={OAUTH_CALLBACK_ROUTE} element={<OAuthCallbackPage />} />
              <Route
                path="/setup"
                element={
                  <SetupGate>
                    <SetupPage />
                  </SetupGate>
                }
              />
              <Route
                element={
                  <RequireAuth>
                    <SetupGate>
                      <ScopeProvider>
                        <AppShell />
                      </ScopeProvider>
                    </SetupGate>
                  </RequireAuth>
                }
              >
                <Route path="/" element={<Navigate to="/browse" replace />} />
                <Route path="/browse" element={<BrowsePage />} />
                <Route path="/projects" element={<ProjectsPage />} />
                <Route path="/webhooks" element={<WebhooksPage />} />
                <Route path="/deleted" element={<DeletedPage />} />
                <Route path="/audit" element={<AuditPage />} />
                <Route path="*" element={<NotFoundPage />} />
              </Route>
            </Routes>
          </Suspense>
        </ErrorBoundary>
      </AuthProvider>
      <ToastContainer
        position="bottom-right"
        autoClose={5000}
        hideProgressBar
        newestOnTop={false}
        closeOnClick
        pauseOnFocusLoss
        draggable
        pauseOnHover
        theme="light"
      />
    </QueryClientProvider>
  )
}

export default App
