/**
 * Input shape rules shared by the console's forms.
 *
 * Adapted from maintainerd-auth's `lib/validations/regex.ts` — only the rules
 * this console actually needs are carried over. A project or environment slug is
 * an MRN segment and is PERMANENT once created, so sanitizing it as it is typed
 * is not cosmetic: it stops an operator minting an address the service would
 * reject, or worse, one they cannot rename afterwards.
 */

/** A project / environment slug: lowercase alphanumerics, hyphens, colons. */
export const SLUG_REGEX = /^[a-z0-9:-]+$/

/** Live normalizer for a slug field. */
export function sanitizeSlug(raw: string): string {
  return raw.replace(/[^a-z0-9:-]/g, '').toLowerCase()
}

/**
 * Like `sanitizeSlug` but without the colon — for names that must be plain
 * lowercase/digit/hyphen tokens. Project and environment slugs use this: a colon
 * is the MRN's own separator, so one inside a segment makes the address
 * ambiguous.
 */
export function sanitizeName(raw: string): string {
  return raw.replace(/[^a-z0-9-]/g, '').toLowerCase()
}

/** A folder-path segment. The slash is the separator, so it is stripped. */
export function sanitizePathSegment(raw: string): string {
  return raw.replace(/[^A-Za-z0-9._-]/g, '')
}

/**
 * True only when `value` is a well-formed URL whose scheme is https, EXCEPT that
 * plain http is allowed on localhost / 127.0.0.1 for local development.
 *
 * A webhook delivery carries an MRN and a version number over the public
 * internet. That is not a credential, but it is a map of what this vault holds,
 * and shipping it over cleartext http is not a choice anyone makes deliberately.
 */
export function isHttpsUrl(value: string): boolean {
  let url: URL
  try {
    url = new URL(value.trim())
  } catch {
    return false
  }
  if (url.protocol === 'https:') return true
  if (url.protocol === 'http:') {
    return url.hostname === 'localhost' || url.hostname === '127.0.0.1'
  }
  return false
}
