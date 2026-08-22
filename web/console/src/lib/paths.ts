/**
 * Folder-path arithmetic for the materialized-path hierarchy.
 *
 * The service stores absolute paths ('/' for the root, '/db/primary' below it)
 * and every address is expressed against one. These helpers keep the browser's
 * navigation and the API's addressing agreeing on what a path is, so a trailing
 * slash typed in a form never becomes a different folder than the one clicked.
 */

export const ROOT_PATH = '/'

/** Normalizes any user- or URL-supplied path to the service's canonical form. */
export function normalizePath(raw: string | null | undefined): string {
  if (!raw) return ROOT_PATH
  const collapsed = `/${raw}`.replace(/\/+/g, '/')
  if (collapsed === ROOT_PATH) return ROOT_PATH
  return collapsed.replace(/\/$/, '')
}

export function isRoot(path: string): boolean {
  return normalizePath(path) === ROOT_PATH
}

/** The last segment, which is what a tree row shows. */
export function folderName(path: string): string {
  const normalized = normalizePath(path)
  if (normalized === ROOT_PATH) return ROOT_PATH
  return normalized.slice(normalized.lastIndexOf('/') + 1)
}

/** The parent path, or null at the root. */
export function parentPath(path: string): string | null {
  const normalized = normalizePath(path)
  if (normalized === ROOT_PATH) return null
  const cut = normalized.lastIndexOf('/')
  return cut <= 0 ? ROOT_PATH : normalized.slice(0, cut)
}

/** Appends a child segment to a parent path. */
export function joinPath(parent: string, segment: string): string {
  const base = normalizePath(parent)
  const child = segment.replace(/^\/+|\/+$/g, '')
  if (!child) return base
  return base === ROOT_PATH ? `/${child}` : `${base}/${child}`
}

/** True when `path` is `ancestor` or lives beneath it. */
export function isDescendantOf(path: string, ancestor: string): boolean {
  const target = normalizePath(path)
  const root = normalizePath(ancestor)
  if (root === ROOT_PATH) return true
  return target === root || target.startsWith(`${root}/`)
}

/** True when `path` is a DIRECT child of `parent`. */
export function isDirectChildOf(path: string, parent: string): boolean {
  const target = normalizePath(path)
  const base = normalizePath(parent)
  if (target === base) return false
  if (!isDescendantOf(target, base)) return false
  const rest = base === ROOT_PATH ? target.slice(1) : target.slice(base.length + 1)
  return !rest.includes('/')
}

/** Breadcrumb trail from the root down to `path`, inclusive. */
export function breadcrumbTrail(path: string): { label: string; path: string }[] {
  const normalized = normalizePath(path)
  const trail = [{ label: 'root', path: ROOT_PATH }]
  if (normalized === ROOT_PATH) return trail
  let current = ''
  normalized
    .split('/')
    .filter(Boolean)
    .forEach((segment) => {
      current = `${current}/${segment}`
      trail.push({ label: segment, path: current })
    })
  return trail
}

/**
 * The API sends `folder_path: ''` for the root on some shapes and `'/'` on
 * others; both mean the same folder. This makes them one value.
 */
export function displayFolderPath(path: string | null | undefined): string {
  return normalizePath(path)
}
