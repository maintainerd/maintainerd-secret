import { describe, expect, it } from 'vitest'
import {
  breadcrumbTrail,
  folderName,
  isDescendantOf,
  isDirectChildOf,
  joinPath,
  normalizePath,
  parentPath,
} from './paths'

describe('normalizePath', () => {
  it('treats empty, undefined and "/" as the root', () => {
    expect(normalizePath('')).toBe('/')
    expect(normalizePath(undefined)).toBe('/')
    expect(normalizePath('/')).toBe('/')
  })

  it('collapses duplicate slashes and strips a trailing one', () => {
    expect(normalizePath('//db//primary/')).toBe('/db/primary')
  })

  it('makes a relative path absolute', () => {
    expect(normalizePath('db/primary')).toBe('/db/primary')
  })
})

describe('folder arithmetic', () => {
  it('names the last segment', () => {
    expect(folderName('/db/primary')).toBe('primary')
    expect(folderName('/')).toBe('/')
  })

  it('walks up to the parent', () => {
    expect(parentPath('/db/primary')).toBe('/db')
    expect(parentPath('/db')).toBe('/')
    expect(parentPath('/')).toBeNull()
  })

  it('joins a child onto a parent', () => {
    expect(joinPath('/', 'db')).toBe('/db')
    expect(joinPath('/db', '/primary/')).toBe('/db/primary')
  })

  it('distinguishes a descendant from a direct child', () => {
    expect(isDescendantOf('/db/primary/replica', '/db')).toBe(true)
    expect(isDirectChildOf('/db/primary/replica', '/db')).toBe(false)
    expect(isDirectChildOf('/db/primary', '/db')).toBe(true)
    // A prefix match on the STRING is not a match on the TREE: /database is not
    // inside /db, and treating it as such would list another folder's secrets.
    expect(isDescendantOf('/database', '/db')).toBe(false)
  })

  it('builds a breadcrumb trail from the root', () => {
    expect(breadcrumbTrail('/db/primary')).toEqual([
      { label: 'root', path: '/' },
      { label: 'db', path: '/db' },
      { label: 'primary', path: '/db/primary' },
    ])
  })
})
