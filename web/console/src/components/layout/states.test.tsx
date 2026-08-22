import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ErrorState, NotPermitted } from './states'
import { ApiError } from '@/services/api/client'

/**
 * The 403 contract, asserted rather than described.
 *
 * Metadata access and value access are separate grants in this service, so a
 * refusal has to read as "you may not do this" and never as "there is nothing
 * here" — otherwise an operator goes hunting for a secret that is right there.
 * And it must never offer a retry, which would just write another denied-access
 * row into the trail an incident review reads.
 */
describe('ErrorState', () => {
  it('renders a 403 as an explicit "not permitted" state, not an empty one', () => {
    const error = new ApiError({ message: 'You lack secret:GetSecret', status: 403 })
    render(<ErrorState error={error} onRetry={vi.fn()} />)

    expect(screen.getByRole('alert')).toBeInTheDocument()
    expect(screen.getByText('Not permitted')).toBeInTheDocument()
    expect(screen.getByText(/You lack secret:GetSecret/)).toBeInTheDocument()
    expect(screen.queryByText(/nothing here/i)).not.toBeInTheDocument()
  })

  it('offers no retry on a 403', () => {
    const onRetry = vi.fn()
    render(<ErrorState error={new ApiError({ message: 'nope', status: 403 })} onRetry={onRetry} />)
    expect(screen.queryByRole('button', { name: /try again/i })).not.toBeInTheDocument()
  })

  it('offers a retry on a transport failure', async () => {
    const user = userEvent.setup()
    const onRetry = vi.fn()
    render(
      <ErrorState
        error={new ApiError({ message: 'Could not reach the vault.', status: 0 })}
        onRetry={onRetry}
      />,
    )

    expect(screen.getByText('Could not load this')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: /try again/i }))
    expect(onRetry).toHaveBeenCalledOnce()
  })

  it('falls back to a generic message for a non-Error value', () => {
    render(<ErrorState error={{ weird: true }} />)
    expect(screen.getByText(/something went wrong/i)).toBeInTheDocument()
  })
})

describe('NotPermitted', () => {
  it('explains that metadata and value are separate grants', () => {
    render(<NotPermitted />)
    expect(screen.getByText(/separate grants/i)).toBeInTheDocument()
  })
})
