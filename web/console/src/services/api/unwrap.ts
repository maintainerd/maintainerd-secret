/**
 * Envelope helpers.
 *
 * Every REST response is `{ success, data?, message?, error?, code?, meta? }`.
 * These centralize "return the payload or throw" so no call site has to repeat
 * it — and so a `success: false` body with a 200 status (which the service does
 * not currently emit, but an intermediary might) still fails loudly.
 */

import { ApiError } from './client'
import type { ApiResponse, Paged, PageMeta } from './types'

/**
 * Returns `res.data` when the call succeeded, otherwise throws.
 * Uses `!= null` so legitimately falsy payloads (empty array, 0, false) pass.
 */
export function unwrap<T>(res: ApiResponse<T>, action: string): T {
  if (res.success && res.data != null) return res.data
  throw new ApiError({ message: res.error || res.message || `Failed to ${action}`, status: 0 })
}

/** Asserts success for calls with no meaningful payload (delete, destroy). */
export function assertSuccess(res: ApiResponse<unknown>, action: string): void {
  if (!res.success) {
    throw new ApiError({ message: res.error || res.message || `Failed to ${action}`, status: 0 })
  }
}

const EMPTY_META: PageMeta = { page: 1, limit: 0, total: 0 }

/**
 * Unwraps a paginated list. A list endpoint answers with `data` as the rows and
 * `meta` as the page block; an endpoint that returns no rows at all sends `data`
 * omitted rather than `[]`, so that case resolves to an empty page instead of
 * throwing.
 */
export function unwrapPaged<T>(res: ApiResponse<T[]>, action: string): Paged<T> {
  if (!res.success) {
    throw new ApiError({ message: res.error || res.message || `Failed to ${action}`, status: 0 })
  }
  const rows = res.data ?? []
  return { rows, meta: res.meta ?? { ...EMPTY_META, limit: rows.length, total: rows.length } }
}

/**
 * Unwraps a non-paginated list (environments, folders, imports, deleted
 * secrets), which the service returns as a bare array under `data`.
 */
export function unwrapList<T>(res: ApiResponse<T[]>, action: string): T[] {
  if (!res.success) {
    throw new ApiError({ message: res.error || res.message || `Failed to ${action}`, status: 0 })
  }
  return res.data ?? []
}

/** Builds a query string, dropping empty values so `?prefix=` is never sent. */
export function query(params: Record<string, string | number | undefined | null>): string {
  const search = new URLSearchParams()
  Object.entries(params).forEach(([key, value]) => {
    if (value === undefined || value === null) return
    const text = String(value)
    if (text === '') return
    search.set(key, text)
  })
  const rendered = search.toString()
  return rendered ? `?${rendered}` : ''
}
