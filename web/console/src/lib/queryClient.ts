/**
 * TanStack Query client.
 *
 * Two things are deliberate here for a vault console:
 *
 *  - `retry` never repeats a definitive client error. Retrying a 403 would turn
 *    one denied-access audit row into several, which is noise in exactly the
 *    table an incident review reads.
 *  - The error surface shows the SERVER'S message. Those messages are written to
 *    be value-free; nothing in this file ever stringifies a response body.
 */

import { MutationCache, QueryCache, QueryClient } from '@tanstack/react-query'
import { toast } from 'react-toastify'

const NON_RETRYABLE_STATUSES = new Set([400, 401, 403, 404, 409, 422, 503])

function statusOf(error: unknown): number | undefined {
  return (error as { status?: number } | null | undefined)?.status
}

function messageOf(error: unknown): string {
  if (error instanceof Error && error.message) return error.message
  if (typeof error === 'string' && error) return error
  return 'Something went wrong. Please try again.'
}

// Deduped by message so a burst of identical failures shows one toast.
function showError(error: unknown): void {
  const message = messageOf(error)
  toast.error(message, { toastId: message })
}

function shouldRetry(failureCount: number, error: unknown): boolean {
  const status = statusOf(error)
  if (status !== undefined && NON_RETRYABLE_STATUSES.has(status)) return false
  return failureCount < 1
}

export const queryClient = new QueryClient({
  queryCache: new QueryCache({ onError: (error) => showError(error) }),
  mutationCache: new MutationCache({ onError: (error) => showError(error) }),
  defaultOptions: {
    queries: {
      retry: shouldRetry,
      refetchOnWindowFocus: false,
      // Short by vault standards: rotation and expiry move underneath you, and a
      // stale "rotated 3 days ago" is a wrong answer, not an old one.
      staleTime: 30 * 1000,
    },
    mutations: { retry: shouldRetry },
  },
})
