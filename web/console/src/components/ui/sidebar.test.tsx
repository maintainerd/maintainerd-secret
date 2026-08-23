import { beforeEach, describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Sidebar, SidebarProvider, SidebarTrigger } from './sidebar'

const COOKIE = 'sidebar_state'

function setStateCookie(value: string) {
  document.cookie = `${COOKIE}=${value}; path=/`
}

function readStateCookie(): string | undefined {
  return document.cookie
    .split(';')
    .map((entry) => entry.trim())
    .find((entry) => entry.startsWith(`${COOKIE}=`))
    ?.slice(COOKIE.length + 1)
}

/** The `data-state` the rail exposes for styling — "expanded" or "collapsed". */
function railState(): string | null | undefined {
  return document.querySelector('[data-slot="sidebar"]')?.getAttribute('data-state')
}

function renderRail() {
  return render(
    <SidebarProvider>
      <SidebarTrigger />
      <Sidebar collapsible="offcanvas" />
    </SidebarProvider>,
  )
}

/**
 * The nav rail's collapsed state has to OUTLIVE the provider that holds it.
 *
 * `SidebarProvider` always wrote a `sidebar_state` cookie and nothing ever read it
 * back — upstream shadcn reads it during a server render, which this console does
 * not have. So collapsing the rail lasted exactly as long as the React tree did:
 * every reload snapped it open again, and so did anything that remounted the
 * provider. That remount is no longer possible (the layout is a single route
 * element now — see `layout/PrivateLayout.tsx`), but the persistence is the part
 * that has to keep working regardless, because a reload will always be a remount.
 */
describe('SidebarProvider collapsed-state persistence', () => {
  beforeEach(() => {
    // Cookies are shared across a file's tests in jsdom; each case states its own.
    document.cookie = `${COOKIE}=; path=/; max-age=0`
  })

  it('defaults to expanded when nothing has been persisted', () => {
    renderRail()
    expect(readStateCookie()).toBeUndefined()
    expect(railState()).toBe('expanded')
  })

  it('starts collapsed when the persisted state says collapsed', () => {
    setStateCookie('false')
    renderRail()
    // Asserted on the FIRST paint, not after an effect: the state is seeded in the
    // useState initializer precisely so there is no expanded-then-collapsed flash.
    expect(railState()).toBe('collapsed')
  })

  it('starts expanded when the persisted state says expanded', () => {
    setStateCookie('true')
    renderRail()
    expect(railState()).toBe('expanded')
  })

  it('persists a collapse, and then restores it on a fresh mount', async () => {
    const user = userEvent.setup()
    const first = renderRail()

    await user.click(screen.getByRole('button', { name: /toggle sidebar/i }))
    expect(railState()).toBe('collapsed')
    expect(readStateCookie()).toBe('false')

    // A fresh mount is what a reload is. This is the assertion the old code failed.
    first.unmount()
    renderRail()
    expect(railState()).toBe('collapsed')
  })

  it('persists re-expanding too, so the rail is not stuck closed', async () => {
    const user = userEvent.setup()
    setStateCookie('false')
    const first = renderRail()
    expect(railState()).toBe('collapsed')

    await user.click(screen.getByRole('button', { name: /toggle sidebar/i }))
    expect(readStateCookie()).toBe('true')

    first.unmount()
    renderRail()
    expect(railState()).toBe('expanded')
  })

  it('ignores an unparseable persisted value rather than collapsing on it', () => {
    setStateCookie('yes-please')
    renderRail()
    expect(railState()).toBe('expanded')
  })

  it('stores only the open flag — never a token, scope or address', async () => {
    const user = userEvent.setup()
    renderRail()
    await user.click(screen.getByRole('button', { name: /toggle sidebar/i }))

    // The whole cookie is the literal word "false". If this ever grows a payload,
    // the console has started persisting state it promised not to.
    expect(readStateCookie()).toBe('false')
  })
})
