import { describe, expect, it } from 'vitest'
import { safeReturnTo } from './oauthFlow'

/**
 * `safeReturnTo` is the open-redirect guard on the post-login hop. These cases
 * are the ones that actually get exploited, so they are pinned.
 */
describe('safeReturnTo', () => {
  it('accepts an absolute local path', () => {
    expect(safeReturnTo('/browse')).toBe('/browse')
    expect(safeReturnTo('/audit?page=2')).toBe('/audit?page=2')
  })

  it('rejects a protocol-relative URL', () => {
    expect(safeReturnTo('//evil.example')).toBeNull()
  })

  it('rejects a backslash-prefixed host', () => {
    expect(safeReturnTo('/\\evil.example')).toBeNull()
  })

  it('rejects an absolute URL', () => {
    expect(safeReturnTo('https://evil.example/browse')).toBeNull()
  })

  it('rejects empty and relative values', () => {
    expect(safeReturnTo('')).toBeNull()
    expect(safeReturnTo(null)).toBeNull()
    expect(safeReturnTo(undefined)).toBeNull()
    expect(safeReturnTo('browse')).toBeNull()
  })
})
