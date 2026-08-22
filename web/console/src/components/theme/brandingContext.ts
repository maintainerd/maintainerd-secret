import { createContext, useContext } from 'react'
import { CONSOLE_BRANDING, type ConsoleBranding, type ConsoleColorScheme } from './consoleBranding'

export interface ConsoleBrandingValue {
  branding: ConsoleBranding
  /** The scheme currently painted, following the OS preference. */
  colorScheme: ConsoleColorScheme
  /** The icon asset matching `colorScheme`. */
  iconUrl: string
}

export const ConsoleBrandingContext = createContext<ConsoleBrandingValue>({
  branding: CONSOLE_BRANDING,
  colorScheme: 'light',
  iconUrl: CONSOLE_BRANDING.iconUrl,
})

/**
 * The console's brand + colour scheme.
 *
 * Defaults are supplied by the context rather than thrown for, so a component
 * rendered outside the provider (a test, an error-boundary fallback that ran
 * before the tree mounted) still shows the right mark instead of crashing.
 */
export function useConsoleBranding(): ConsoleBrandingValue {
  return useContext(ConsoleBrandingContext)
}
