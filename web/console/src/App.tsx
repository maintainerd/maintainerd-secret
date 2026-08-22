import { lazy, Suspense } from 'react'
import { Navigate, Route, Routes, useLocation } from 'react-router-dom'
import { QueryClientProvider } from '@tanstack/react-query'
import { ToastContainer } from 'react-toastify'
import 'react-toastify/dist/ReactToastify.css'
import '@/styles/toast.css'
import { queryClient } from '@/lib/queryClient'
import { AuthProvider } from '@/auth/AuthProvider'
import { OAUTH_CALLBACK_ROUTE } from '@/auth/oauthFlow'
import { SetupGate } from '@/components/SetupGate'
import ErrorBoundary from '@/components/ErrorBoundary'
import { ConsoleBrandingProvider } from '@/components/theme/ConsoleBrandingProvider'
import { PrivateLayout } from '@/components/layout/PrivateLayout'
import { ProtectedShell } from '@/components/layout/ProtectedShell'
import { AppLoadingScreen } from '@/components/layout/AppLoadingScreen'

// The shell stays eager; every page is code-split so the initial bundle carries
// only the shell plus the current route's chunk.
const BrowsePage = lazy(() => import('./pages/browse/BrowsePage'))
const ProjectsPage = lazy(() => import('./pages/projects/ProjectsPage'))
const ProjectDetailsPage = lazy(() => import('./pages/projects/details/ProjectDetailsPage'))
const WebhooksPage = lazy(() => import('./pages/webhooks/WebhooksPage'))
const WebhookDetailsPage = lazy(() => import('./pages/webhooks/details/WebhookDetailsPage'))
const DeletedPage = lazy(() => import('./pages/deleted/DeletedPage'))
const AuditPage = lazy(() => import('./pages/audit/AuditPage'))
const SetupPage = lazy(() => import('./pages/setup/SetupPage'))
const LoginPage = lazy(() => import('./pages/auth/LoginPage'))
const OAuthCallbackPage = lazy(() => import('./pages/auth/OAuthCallbackPage'))
const NotFoundPage = lazy(() => import('./pages/not-found/NotFoundPage'))

/**
 * Route layering, outermost first:
 *
 *   ConsoleBrandingProvider  puts the brand + colour scheme on the document
 *   AuthProvider             decides whether a credential is held, before painting
 *   ProtectedShell           RequireAuth → SetupGate → ScopeProvider
 *   PrivateLayout            the signed-in chrome (brand bar + sidebar + content)
 *
 * /login and the OAuth callback sit OUTSIDE all of it — they exist precisely
 * because there is no session yet, and gating them would deadlock sign-in.
 * /setup is outside the protected shell for the same reason: on a fresh install
 * there is no identity to authenticate against until the vault is provisioned.
 *
 * WHAT IS NOT A ROUTE, DELIBERATELY: a secret. Secret detail and reveal are
 * dialogs on /browse, because a route would put the secret's address in the URL —
 * and therefore in browser history, the referer header, and every proxy log in
 * between. Project slugs and webhook endpoint UUIDs DO get routes: they name a
 * container and a destination, not a credential.
 */
function App() {
  const location = useLocation()

  return (
    <QueryClientProvider client={queryClient}>
      <ConsoleBrandingProvider>
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

                <Route element={<ProtectedShell />}>
                  {/* The browser needs the full width for its folder column. */}
                  <Route element={<PrivateLayout fullWidth />}>
                    <Route path="/browse" element={<BrowsePage />} />
                  </Route>

                  {/* Everything else keeps auth's centred, width-capped column. */}
                  <Route element={<PrivateLayout />}>
                    <Route path="/" element={<Navigate to="/browse" replace />} />
                    <Route path="/projects" element={<ProjectsPage />} />
                    <Route path="/projects/:slug" element={<ProjectDetailsPage />} />
                    <Route path="/webhooks" element={<WebhooksPage />} />
                    <Route path="/webhooks/:endpointUuid" element={<WebhookDetailsPage />} />
                    <Route path="/deleted" element={<DeletedPage />} />
                    <Route path="/audit" element={<AuditPage />} />
                    <Route path="*" element={<NotFoundPage />} />
                  </Route>
                </Route>
              </Routes>
            </Suspense>
          </ErrorBoundary>
        </AuthProvider>
      </ConsoleBrandingProvider>
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
