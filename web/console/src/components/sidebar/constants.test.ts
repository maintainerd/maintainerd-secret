import { describe, expect, it } from 'vitest'
import { data } from './constants'

/**
 * The nav is a map of the app, so it has to stay in step with the router. A
 * route that 404s from the sidebar is the kind of bug nobody files and everybody
 * works around.
 */
const ROUTES = ['/browse', '/projects', '/webhooks', '/deleted', '/audit']

describe('sidebar navigation', () => {
  it('points at every top-level route the router serves, and nothing else', () => {
    const routes = data.navSections.flatMap((section) => section.items.map((item) => item.route))
    expect(routes.sort()).toEqual([...ROUTES].sort())
  })

  it('labels every section', () => {
    for (const section of data.navSections) {
      expect(section.label).toBeTruthy()
      expect(section.items.length).toBeGreaterThan(0)
    }
  })

  it('gives every item an icon and a title', () => {
    for (const section of data.navSections) {
      for (const item of section.items) {
        expect(item.title).toBeTruthy()
        expect(item.icon).toBeTypeOf('function')
      }
    }
  })

  it('uses absolute routes so NavMain does not have to guess', () => {
    for (const section of data.navSections) {
      for (const item of section.items) {
        expect(item.route.startsWith('/')).toBe(true)
      }
    }
  })
})
