import { AlertTriangle, Loader2, ShieldOff } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { EmptyState } from '@/components/details'
import { ApiError, isForbidden } from '@/services/api/client'

/**
 * The not-permitted and error states every surface in this console has to render.
 *
 * Two of what used to live here are now maintainerd-auth's, adopted verbatim:
 * the EMPTY state is `EmptyState` from `@/components/details` (for a panel) and
 * `DataTableEmpty` from `@/components/data-table` (for a table), and the LOADING
 * skeleton is `ListSkeleton`. What auth has no equivalent of — and what therefore
 * stays local — is the 403 treatment below.
 *
 * They live in one module because they must stay consistent: a page that renders
 * an empty table on a permission error teaches the operator to distrust what they
 * are looking at — which in a vault means distrusting "this secret does not exist".
 */

export function InlineLoading({ label = 'Loading' }: { label?: string }) {
  return (
    <div
      className="flex items-center gap-2 py-6 text-sm text-muted-foreground"
      role="status"
      aria-live="polite"
    >
      <Loader2 className="size-4 animate-spin" aria-hidden="true" />
      {label}…
    </div>
  )
}

/**
 * "You are authenticated but not granted this."
 *
 * IN PLACE, NEVER A REDIRECT. A 403 means the caller IS signed in and simply
 * lacks that grant, so bouncing it to the identity app would loop them through
 * sign-in forever and land on the same refusal. And it is never dressed up as
 * "nothing here": reading metadata and revealing a value are DIFFERENT grants in
 * this service, so "you may not do this" is a normal, expected answer the
 * operator has to be able to tell apart from "this is empty" — otherwise they go
 * hunting for a secret that is right there.
 */
export function NotPermitted({ message }: { message?: string }) {
  return (
    <div role="alert">
      <EmptyState
        icon={ShieldOff}
        title="Not permitted"
        description={
          message ??
          'You do not hold the grant this action requires. Metadata access and value access are separate grants in maintainerd-secret; holding one does not imply the other.'
        }
      />
    </div>
  )
}

/**
 * The error state, with the 403 case routed to `NotPermitted`.
 *
 * A retry is offered for everything EXCEPT a 403 — retrying a denial just writes
 * another denied-access row into the audit trail an incident review reads.
 */
export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  if (isForbidden(error)) {
    return <NotPermitted message={error instanceof ApiError ? error.message : undefined} />
  }

  const message =
    error instanceof ApiError || error instanceof Error
      ? error.message
      : 'Something went wrong. Please try again.'

  return (
    <div role="alert">
      <EmptyState
        icon={AlertTriangle}
        title="Could not load this"
        description={message}
        action={
          onRetry ? (
            <Button variant="outline" size="sm" onClick={onRetry}>
              Try again
            </Button>
          ) : undefined
        }
      />
    </div>
  )
}
