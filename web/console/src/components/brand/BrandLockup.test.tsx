import { afterEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { BrandLockup } from './BrandLockup'
import { ConsoleBrandingProvider } from '@/components/theme/ConsoleBrandingProvider'
import { CONSOLE_BRANDING } from '@/components/theme/consoleBranding'

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

describe('BrandLockup', () => {
  const originalMatchMedia = window.matchMedia
  afterEach(() => {
    window.matchMedia = originalMatchMedia
  })

  it('renders the app name and qualifier from the console branding', () => {
    render(
      <ConsoleBrandingProvider>
        <BrandLockup />
      </ConsoleBrandingProvider>,
    )

    expect(screen.getByText('Maintainerd Secret')).toBeInTheDocument()
    expect(screen.getByText(CONSOLE_BRANDING.appDetail)).toBeInTheDocument()
  })

  it('draws the transparent mark inline for the dark brand bar', () => {
    const { container } = render(<BrandLockup asset="mark" />)
    const svg = container.querySelector('svg')

    expect(svg).toBeInTheDocument()
    // Decorative: the app name beside it is the accessible name.
    expect(svg).toHaveAttribute('aria-hidden', 'true')
    expect(container.querySelector('img')).toBeNull()
  })

  it('serves the official square icon, following the colour scheme', () => {
    mockScheme(false)
    const { container: light } = render(
      <ConsoleBrandingProvider>
        <BrandLockup asset="icon" />
      </ConsoleBrandingProvider>,
    )
    expect(light.querySelector('img')).toHaveAttribute('src', CONSOLE_BRANDING.iconUrl)

    mockScheme(true)
    const { container: dark } = render(
      <ConsoleBrandingProvider>
        <BrandLockup asset="icon" />
      </ConsoleBrandingProvider>,
    )
    expect(dark.querySelector('img')).toHaveAttribute('src', CONSOLE_BRANDING.iconDarkUrl)
  })

  it('serves the full official lockup for the front door', () => {
    const { container } = render(<BrandLockup asset="logo" />)
    expect(container.querySelector('img')).toHaveAttribute('src', CONSOLE_BRANDING.logoUrl)
  })

  it('gives each inline mark unique clip-path ids so two on a page do not collide', () => {
    const { container } = render(
      <>
        <BrandLockup asset="mark" />
        <BrandLockup asset="mark" />
      </>,
    )

    const ids = Array.from(container.querySelectorAll('clipPath')).map((node) => node.id)
    expect(ids).toHaveLength(4)
    expect(new Set(ids).size).toBe(4)
  })

  it('drops the label for a compact bar', () => {
    render(<BrandLockup asset="mark" showLabel={false} />)
    expect(screen.queryByText('Maintainerd Secret')).not.toBeInTheDocument()
  })

  it('suppresses the qualifier when asked', () => {
    render(<BrandLockup detail={null} />)
    expect(screen.getByText('Maintainerd Secret')).toBeInTheDocument()
    expect(screen.queryByText(CONSOLE_BRANDING.appDetail)).not.toBeInTheDocument()
  })
})
