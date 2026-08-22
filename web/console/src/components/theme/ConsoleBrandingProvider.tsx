import { useEffect, useLayoutEffect, useMemo, useState, type ReactNode } from 'react'
import { ConsoleBrandingContext, type ConsoleBrandingValue } from './brandingContext'
import {
  applyConsoleTheme,
  clearConsoleTheme,
  CONSOLE_BRANDING,
  type ConsoleColorScheme,
} from './consoleBranding'

const DARK_QUERY = '(prefers-color-scheme: dark)'

function preferredScheme(): ConsoleColorScheme {
  if (typeof window === 'undefined' || !window.matchMedia) return 'light'
  return window.matchMedia(DARK_QUERY).matches ? 'dark' : 'light'
}

/**
 * Owns the document-level brand state: the `dark` class, the colour scheme, the
 * favicon, and the brand record every surface reads.
 *
 * Mirrors maintainerd-auth's `components/theme/ConsoleBrandingProvider.tsx`,
 * including its `useLayoutEffect`: the theme has to reach the document BEFORE
 * the browser paints or the splash renders in the wrong scheme and then visibly
 * flips. The difference is the source — auth pulls a tenant's branding from
 * Redux, secret has one fixed brand and follows the operator's OS preference for
 * light/dark. There is no in-app toggle on purpose: a console that disagrees
 * with the rest of the operator's desktop is a papercut, and a persisted
 * preference is one more thing this app would be storing.
 */
export function ConsoleBrandingProvider({ children }: { children: ReactNode }) {
  const [colorScheme, setColorScheme] = useState<ConsoleColorScheme>(preferredScheme)

  useLayoutEffect(() => {
    applyConsoleTheme(colorScheme)
    return () => clearConsoleTheme()
  }, [colorScheme])

  useEffect(() => {
    if (!window.matchMedia) return undefined
    const media = window.matchMedia(DARK_QUERY)
    const onChange = (event: MediaQueryListEvent) => {
      setColorScheme(event.matches ? 'dark' : 'light')
    }
    media.addEventListener('change', onChange)
    return () => media.removeEventListener('change', onChange)
  }, [])

  useEffect(() => {
    document.title = CONSOLE_BRANDING.appName
  }, [])

  const value = useMemo<ConsoleBrandingValue>(
    () => ({
      branding: CONSOLE_BRANDING,
      colorScheme,
      iconUrl: colorScheme === 'dark' ? CONSOLE_BRANDING.iconDarkUrl : CONSOLE_BRANDING.iconUrl,
    }),
    [colorScheme],
  )

  return (
    <ConsoleBrandingContext.Provider value={value}>{children}</ConsoleBrandingContext.Provider>
  )
}
