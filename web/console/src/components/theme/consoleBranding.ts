/**
 * This console's brand, as constants.
 *
 * maintainerd-auth resolves its console branding from a TENANT — company name,
 * logo URL, palette — because auth is the white-label surface a customer skins.
 * maintainerd-secret has no branding API and no tenant-branding table, so the
 * equivalent here is a fixed record rather than a fetch. The shape is kept
 * deliberately close to auth's `BrandingPublic` so that if secret ever grows a
 * branding endpoint, `ConsoleBrandingProvider` is the only file that changes.
 *
 * The asset paths are the OFFICIAL maintainerd assets in `public/`.
 */

export interface ConsoleBranding {
  /** The product name, rendered wherever auth renders `company_name`. */
  appName: string
  /** Short qualifier under the app name in the brand lockup. */
  appDetail: string
  /** Square icon for a light background. */
  iconUrl: string
  /** Square icon for a dark background (the top nav, dark mode). */
  iconDarkUrl: string
  /** The full horizontal lockup. */
  logoUrl: string
  faviconUrl: string
}

export const CONSOLE_BRANDING: ConsoleBranding = {
  appName: 'Maintainerd Secret',
  appDetail: 'Secrets & configuration vault',
  iconUrl: '/maintainerd-icon.svg',
  iconDarkUrl: '/maintainerd-icon-dark.svg',
  logoUrl: '/maintainerd-logo.svg',
  faviconUrl: '/favicon.svg',
}

/** The colour scheme the console is painting in. */
export type ConsoleColorScheme = 'light' | 'dark'

/**
 * Applies (or clears) the document-level theme state auth's
 * `lib/branding/consoleTheme.ts` owns.
 *
 * Auth writes a whole palette of `--md-*` custom properties here because a
 * tenant can recolour its console. Secret has one palette — the one in
 * `index.css` — so the only document state worth owning is the `dark` class and
 * the favicon. `data-console-theme` is still set so the shared component
 * primitives (which key their themeable surfaces off it) behave identically.
 */
export function applyConsoleTheme(scheme: ConsoleColorScheme): void {
  const root = document.documentElement
  root.classList.toggle('dark', scheme === 'dark')
  root.style.colorScheme = scheme
  root.setAttribute('data-console-theme', 'active')

  const link = document.querySelector<HTMLLinkElement>("link[rel*='icon']")
  if (link && link.getAttribute('href') !== CONSOLE_BRANDING.faviconUrl) {
    link.href = CONSOLE_BRANDING.faviconUrl
  }
}

export function clearConsoleTheme(): void {
  const root = document.documentElement
  root.classList.remove('dark')
  root.style.colorScheme = ''
  root.removeAttribute('data-console-theme')
}
