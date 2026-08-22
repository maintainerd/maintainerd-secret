import { Loader2 } from 'lucide-react'

/** Full-screen splash shown while the app decides what it is allowed to show. */
export function AppLoadingScreen({ message = 'Loading' }: { message?: string }) {
  return (
    <div
      className="flex min-h-screen items-center justify-center bg-background"
      role="status"
      aria-live="polite"
    >
      <div className="flex flex-col items-center gap-3 text-muted-foreground">
        <Loader2 className="size-6 animate-spin" aria-hidden="true" />
        <p className="text-sm">{message}…</p>
      </div>
    </div>
  )
}

export default AppLoadingScreen
