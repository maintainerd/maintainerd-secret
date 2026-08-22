/**
 * The maintainerd mark, inline.
 *
 * Auth's console ships this as `components/icon/MaintainedAuthIcon.tsx` — an
 * inline SVG rather than an `<img src>` so the brand still renders when the
 * network is gone and so it inherits the surrounding text colour context. The
 * geometry here is the OFFICIAL asset from `public/maintainerd-mark.svg`, split
 * left/right by two clip paths and filled with the two blues of the palette
 * (blue-800 / blue-600), which is where `--primary` comes from.
 *
 * The ids are suffixed per instance: several marks can be on one page (sidebar
 * rail + splash), and duplicate SVG ids inside one document silently make every
 * copy after the first reference the wrong clip path.
 */

import { useId } from 'react'

interface MaintainerdMarkProps {
  width?: number | string
  height?: number | string
  className?: string
  /** Accessible name. Set to "" to mark the SVG decorative. */
  title?: string
}

export function MaintainerdMark({
  width = 24,
  height = 24,
  className = '',
  title = 'maintainerd',
}: MaintainerdMarkProps) {
  const uid = useId().replace(/[^a-zA-Z0-9]/g, '')
  const left = `mdL-${uid}`
  const right = `mdR-${uid}`
  const cloud = `mdC-${uid}`
  const decorative = title === ''

  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 24 24"
      width={width}
      height={height}
      className={className}
      role={decorative ? undefined : 'img'}
      aria-hidden={decorative ? true : undefined}
      aria-label={decorative ? undefined : title}
    >
      <defs>
        <clipPath id={left}>
          <rect x="0" y="0" width="12" height="24" />
        </clipPath>
        <clipPath id={right}>
          <rect x="12" y="0" width="12" height="24" />
        </clipPath>
        <path
          id={cloud}
          d="M19.35 10.04C18.67 6.59 15.64 4 12 4C9.11 4 6.6 5.64 5.35 8.04C2.34 8.36 0 10.91 0 14C0 17.31 2.69 20 6 20H19C21.76 20 24 17.76 24 15C24 12.36 21.95 10.22 19.35 10.04Z"
        />
      </defs>
      <g clipPath={`url(#${left})`}>
        <use href={`#${cloud}`} fill="#1E40AF" />
      </g>
      <g clipPath={`url(#${right})`}>
        <use href={`#${cloud}`} fill="#2563EB" />
      </g>
    </svg>
  )
}

export default MaintainerdMark
