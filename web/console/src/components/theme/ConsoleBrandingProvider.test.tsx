import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { ConsoleBrandingProvider } from './ConsoleBrandingProvider'
import { useConsoleBranding } from './brandingContext'
import { CONSOLE_BRANDING } from './consoleBranding'

function Probe() {
  const { colorScheme, iconUrl, branding } = useConsoleBranding()
  return (
    <div>
      <span data-testid="scheme">{colorScheme}</span>
      <span data-testid="icon">{iconUrl}</span>
      <span data-testid="name">{branding.appName}</span>
    </div>
  )
}

/** Drives `prefers-color-scheme` for one render. */
function mockScheme(dark: boolean) {
  window.matchMedia = vi.fn().mockImplementation((query: string) => ({
    matches: dark,
    media: query,
    onchange: null,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    addListener: vi.fn(),
    removeListener: vi.fn(),
    dispatchEvent: vi.fn(),
  })) as unknown as typeof window.matchMedia
}

describe('ConsoleBrandingProvider', () => {
  const originalMatchMedia = window.matchMedia

  beforeEach(() => {
    document.documentElement.className = ''
    document.documentElement.removeAttribute('data-console-theme')
  })

  afterEach(() => {
    window.matchMedia = originalMatchMedia
  })

  it('paints light and serves the light icon when the OS prefers light', () => {
    mockScheme(false)
    render(
      <ConsoleBrandingProvider>
        <Probe />
      </ConsoleBrandingProvider>,
    )

    expect(screen.getByTestId('scheme')).toHaveTextContent('light')
    expect(screen.getByTestId('icon')).toHaveTextContent(CONSOLE_BRANDING.iconUrl)
    expect(document.documentElement.classList.contains('dark')).toBe(false)
  })

  it('paints dark and serves the dark icon when the OS prefers dark', () => {
    mockScheme(true)
    render(
      <ConsoleBrandingProvider>
        <Probe />
      </ConsoleBrandingProvider>,
    )

    expect(screen.getByTestId('scheme')).toHaveTextContent('dark')
    expect(screen.getByTestId('icon')).toHaveTextContent(CONSOLE_BRANDING.iconDarkUrl)
    expect(document.documentElement.classList.contains('dark')).toBe(true)
  })

  it('marks the theme active so the shared primitives key off it', () => {
    mockScheme(false)
    render(
      <ConsoleBrandingProvider>
        <Probe />
      </ConsoleBrandingProvider>,
    )
    expect(document.documentElement.getAttribute('data-console-theme')).toBe('active')
  })

  it('names the app "Maintainerd Secret" and titles the document with it', () => {
    mockScheme(false)
    render(
      <ConsoleBrandingProvider>
        <Probe />
      </ConsoleBrandingProvider>,
    )

    expect(screen.getByTestId('name')).toHaveTextContent('Maintainerd Secret')
    expect(document.title).toBe('Maintainerd Secret')
  })

  it('serves the default brand outside the provider rather than throwing', () => {
    render(<Probe />)
    expect(screen.getByTestId('name')).toHaveTextContent('Maintainerd Secret')
  })
})
