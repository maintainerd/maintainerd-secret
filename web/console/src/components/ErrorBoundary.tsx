import { Component, type ErrorInfo, type ReactNode } from 'react'

/**
 * Last-resort render guard.
 *
 * Laid out like maintainerd-auth's `components/ErrorBoundary.tsx` — the same
 * `data-console-auth-shell` full-height panel and plain `<button>` reload
 * control, so it renders correctly even if the component tree (and therefore the
 * Button primitive's providers) is what failed.
 *
 * It shows the error's MESSAGE and nothing else — no stack, no component tree,
 * no props. A crash inside a reveal or a put would otherwise be an excellent way
 * to print a plaintext value onto the page, and "it only happens when something
 * is already broken" is exactly when nobody is looking.
 */
interface Props {
  children: ReactNode
  /** Changing this remounts the subtree — pass the route so navigation recovers. */
  resetKey?: string
}

interface State {
  error: Error | null
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  componentDidUpdate(previous: Props): void {
    if (previous.resetKey !== this.props.resetKey && this.state.error) {
      this.setState({ error: null })
    }
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    // Deliberately minimal: the message and the component stack only. Never the
    // error object, whose `config`/`response` on an axios failure would carry a
    // request body — and a put body carries a plaintext value.
    console.error('[console] render error', error.message, info.componentStack)
  }

  render(): ReactNode {
    if (this.state.error) {
      return (
        <div
          role="alert"
          data-console-auth-shell
          className="flex min-h-svh flex-col items-center justify-center gap-6 bg-background px-4 text-center text-foreground"
        >
          <div className="flex flex-col items-center gap-3">
            <h1 className="text-2xl font-semibold tracking-tight">Something went wrong</h1>
            <p className="max-w-sm text-sm text-muted-foreground">{this.state.error.message}</p>
          </div>
          <button
            type="button"
            onClick={() => this.setState({ error: null })}
            className="inline-flex h-9 items-center justify-center rounded-md bg-primary px-4 text-sm font-medium text-primary-foreground shadow transition-colors hover:bg-primary/90"
          >
            Try again
          </button>
        </div>
      )
    }

    return this.props.children
  }
}

export default ErrorBoundary
