import { Component, type ErrorInfo, type ReactNode } from 'react'
import { Button } from '@/components/ui/button'

/**
 * Last-resort render guard.
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
    // request body.
    console.error('[console] render error', error.message, info.componentStack)
  }

  render() {
    if (this.state.error) {
      return (
        <div className="flex min-h-[60vh] flex-col items-center justify-center gap-4 p-6 text-center">
          <div>
            <h1 className="text-lg font-semibold">Something broke</h1>
            <p className="mt-1 text-sm text-muted-foreground">{this.state.error.message}</p>
          </div>
          <Button onClick={() => this.setState({ error: null })}>Try again</Button>
        </div>
      )
    }
    return this.props.children
  }
}

export default ErrorBoundary
