import { MaintainerdMark } from '@/components/icon/MaintainerdMark'
import { useConsoleBranding } from '@/components/theme/brandingContext'
import { cn } from '@/lib/utils'

/**
 * Which official asset the lockup draws.
 *
 *  - `logo`  `public/maintainerd-logo.svg` — the full horizontal lockup with the
 *            wordmark, on its own card. The front door: sign-in and the first-run
 *            wizard.
 *  - `icon`  `public/maintainerd-icon{,-dark}.svg` — the square app icon. It
 *            ships in a light and a dark variant, and the provider picks the one
 *            matching the operator's colour scheme.
 *  - `mark`  `public/maintainerd-mark.svg`, inlined by `MaintainerdMark` — the
 *            transparent mark with no plate, for placing on a coloured surface
 *            such as the slate brand bar.
 */
export type BrandAsset = 'logo' | 'icon' | 'mark'

type BrandLockupProps = {
  asset?: BrandAsset
  /** Overrides the app name from branding (rarely needed). */
  appName?: string
  /** Qualifier under the name. Pass `null` to suppress it. */
  detail?: string | null
  /** Hide the text entirely — a compact bar renders the mark alone. */
  showLabel?: boolean
  /** Classes on the text block, e.g. to drop it below a breakpoint. */
  labelClassName?: string
  /** Pixel size of the `mark`/`icon` asset. `logo` is sized by `logoClassName`. */
  iconSize?: number
  logoClassName?: string
  /** `stacked` (login/splash) or `inline` (top nav). */
  orientation?: 'stacked' | 'inline'
  className?: string
  /** Renders the name in the top nav's light-on-dark treatment. */
  onDark?: boolean
}

/**
 * The canonical console brand mark: a maintainerd asset above (or beside) the app
 * name and its qualifier.
 *
 * This is maintainerd-auth's `components/brand/BrandLockup.tsx` with the
 * tenant-logo branch replaced by the official maintainerd assets — secret has no
 * per-tenant logo to resolve. Every brand surface (sign-in, the wizard, the
 * bootstrap splash, the brand bar) renders through here so none of them
 * re-implements the pairing and drifts.
 */
export function BrandLockup({
  asset = 'icon',
  appName,
  detail,
  showLabel = true,
  labelClassName,
  iconSize = 48,
  logoClassName = 'h-24 w-auto',
  orientation = 'stacked',
  className,
  onDark = false,
}: BrandLockupProps) {
  const { branding, iconUrl } = useConsoleBranding()
  const label = appName ?? branding.appName
  const qualifier = detail === null ? undefined : (detail ?? branding.appDetail)
  const inline = orientation === 'inline'

  return (
    <div
      className={cn(
        'flex gap-3',
        inline ? 'min-w-0 flex-row items-center' : 'flex-col items-center text-center',
        className,
      )}
    >
      {asset === 'mark' && (
        <MaintainerdMark width={iconSize} height={iconSize} className="shrink-0" title="" />
      )}
      {asset === 'icon' && (
        <img
          src={iconUrl}
          alt=""
          aria-hidden="true"
          width={iconSize}
          height={iconSize}
          className="shrink-0 rounded-md object-contain"
        />
      )}
      {asset === 'logo' && (
        <img
          src={branding.logoUrl}
          alt=""
          aria-hidden="true"
          className={cn('shrink-0 object-contain', logoClassName)}
        />
      )}

      {showLabel && (
        <span className={cn('min-w-0', inline ? 'block' : 'text-center', labelClassName)}>
          <span
            className={cn(
              'block truncate font-semibold tracking-tight',
              qualifier ? 'text-sm' : 'text-lg',
              onDark ? 'text-white' : 'text-foreground',
            )}
          >
            {label}
          </span>
          {qualifier && (
            <span
              className={cn(
                'mt-0.5 block truncate text-xs',
                onDark ? 'text-slate-400' : 'text-muted-foreground',
              )}
            >
              {qualifier}
            </span>
          )}
        </span>
      )}
    </div>
  )
}
