import type { ReactNode } from 'react'
import { AlertTriangle, Inbox, Loader2, ShieldOff } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { ApiError, isForbidden } from '@/services/api/client'

/**
 * The four states every list and detail surface in this console has to render.
 *
 * They are one module because they must stay consistent: a page that shows a
 * spinner where another shows a skeleton, or that renders an empty table on a
 * permission error, teaches the operator to distrust what they are looking at —
 * which in a vault means distrusting "this secret does not exist".
 */

export function LoadingRows({ rows = 5 }: { rows?: number }) {
  return (
    <div className="space-y-2" role="status" aria-live="polite" aria-label="Loading">
      {Array.from({ length: rows }).map((_, index) => (
        <Skeleton key={index} className="h-10 w-full" />
      ))}
    </div>
  )
}

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

export function EmptyState({
  title,
  description,
  action,
}: {
  title: string
  description?: string
  action?: ReactNode
}) {
  return (
    <div className="flex flex-col items-center gap-3 rounded-md border border-dashed p-10 text-center">
      <Inbox className="size-6 text-muted-foreground" aria-hidden="true" />
      <div>
        <p className="font-medium">{title}</p>
        {description ? <p className="mt-1 text-sm text-muted-foreground">{description}</p> : null}
      </div>
      {action}
    </div>
  )
}

/**
 * The error state.
 *
 * A 403 is called out separately and never dressed up as "nothing here". Reading
 * metadata and revealing a value are DIFFERENT grants in this service, so "you
 * may not do this" is a normal, expected answer that the operator has to be able
 * to tell apart from "this is empty" — otherwise they go hunting for a secret
 * that is right there.
 */
export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const forbidden = isForbidden(error)
  const message =
    error instanceof ApiError || error instanceof Error
      ? error.message
      : 'Something went wrong. Please try again.'

  return (
    <div
      className="flex flex-col items-center gap-3 rounded-md border border-destructive/40 bg-destructive/5 p-10 text-center"
      role="alert"
    >
      {forbidden ? (
        <ShieldOff className="size-6 text-destructive" aria-hidden="true" />
      ) : (
        <AlertTriangle className="size-6 text-destructive" aria-hidden="true" />
      )}
      <div>
        <p className="font-medium">{forbidden ? 'Not permitted' : 'Could not load this'}</p>
        <p className="mt-1 text-sm text-muted-foreground">{message}</p>
        {forbidden ? (
          <p className="mt-2 max-w-prose text-xs text-muted-foreground">
            Metadata access and value access are separate grants in maintainerd-secret. Holding one
            does not imply the other.
          </p>
        ) : null}
      </div>
      {onRetry && !forbidden ? (
        <Button variant="outline" size="sm" onClick={onRetry}>
          Try again
        </Button>
      ) : null}
    </div>
  )
}
