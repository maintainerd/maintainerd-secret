import { format, formatDistanceToNowStrict, isValid, parseISO } from 'date-fns'

/** Absolute timestamp, for tables and detail rows. Empty input renders as "—". */
export function formatDateTime(value?: string | null): string {
  if (!value) return '—'
  const parsed = parseISO(value)
  if (!isValid(parsed)) return '—'
  return format(parsed, 'yyyy-MM-dd HH:mm:ss')
}

/** Relative age ("3 days ago"), for rotated-at / last-triggered columns. */
export function formatRelative(value?: string | null): string {
  if (!value) return '—'
  const parsed = parseISO(value)
  if (!isValid(parsed)) return '—'
  return `${formatDistanceToNowStrict(parsed)} ago`
}

/** True when an expiry is in the past. */
export function isExpired(value?: string | null): boolean {
  if (!value) return false
  const parsed = parseISO(value)
  return isValid(parsed) && parsed.getTime() < Date.now()
}

/** `datetime-local` input value (local time, no seconds) from an RFC3339 string. */
export function toDateTimeLocalInput(value?: string | null): string {
  if (!value) return ''
  const parsed = parseISO(value)
  if (!isValid(parsed)) return ''
  return format(parsed, "yyyy-MM-dd'T'HH:mm")
}

/** RFC3339 (UTC) from a `datetime-local` input value, or null when empty. */
export function fromDateTimeLocalInput(value: string): string | null {
  if (!value) return null
  const parsed = new Date(value)
  if (!isValid(parsed)) return null
  return parsed.toISOString()
}
