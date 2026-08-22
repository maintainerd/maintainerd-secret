import { useCallback, useEffect, useRef, useState } from 'react'
import { useLocation } from 'react-router-dom'
import { Check, Copy, Eye, EyeOff, ShieldAlert } from 'lucide-react'
import { toast } from 'react-toastify'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { InlineLoading, ErrorState } from '@/components/layout/states'
import { useRevealSecret } from '@/hooks/useSecrets'
import { base64ByteLength, decodeBase64ToUtf8, isPrintableUtf8 } from '@/lib/base64'
import type { SecretAddress } from '@/services/api/types'

/**
 * Reveals one secret value.
 *
 * ==========================================================================
 * THE VALUE LIVES IN MEMORY ONLY, FOR AS LONG AS THIS DIALOG IS OPEN.
 * ==========================================================================
 * It is held in component state and NOTHING ELSE. It is never written to
 * localStorage or sessionStorage, never put in a URL, never logged, never
 * handed to TanStack Query's cache (the reveal is a mutation with `gcTime: 0`
 * precisely so react-query does not retain it), and never stored on a ref that
 * outlives the dialog. `clear()` drops it on close, on Escape, on an overlay
 * click and on any route change — see the navigation effect below.
 *
 * That is not paranoia about a specific attack; it is the only way "the value
 * was on screen for eleven seconds" stays true. Anything cached turns a single
 * audited read into an unbounded number of unaudited ones.
 *
 * EVERY OPEN IS ONE AUDITED READ. The server records `secret.reveal` against
 * this MRN, with the actor, and a reference chain records `secret.reference`
 * per hop. The dialog says so before the value appears, because an operator who
 * does not know the read is logged cannot make an informed decision about
 * whether to make it.
 */
export function RevealDialog({
  address,
  version,
  open,
  onOpenChange,
}: {
  address: SecretAddress | null
  version?: number
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const reveal = useRevealSecret()
  const [value, setValue] = useState<string | null>(null)
  const [mrn, setMrn] = useState<string | null>(null)
  const [valueType, setValueType] = useState<string | null>(null)
  const [revealedVersion, setRevealedVersion] = useState<number | null>(null)
  const [hops, setHops] = useState<string[]>([])
  const [visible, setVisible] = useState(false)
  const [copied, setCopied] = useState(false)
  const requestedRef = useRef<string | null>(null)
  const location = useLocation()

  const clear = useCallback(() => {
    setValue(null)
    setMrn(null)
    setValueType(null)
    setRevealedVersion(null)
    setHops([])
    setVisible(false)
    setCopied(false)
    requestedRef.current = null
    reveal.reset()
  }, [reveal])

  // Fetch once per (address, version) while open. The guard is a ref rather
  // than a dependency list because a reveal has a side effect — an audit row —
  // and a re-render must never quietly produce a second one.
  useEffect(() => {
    if (!open || !address) return
    const signature = `${address.project}/${address.environment}/${address.folder_path ?? ''}/${address.key}#${version ?? 'current'}`
    if (requestedRef.current === signature) return
    requestedRef.current = signature

    reveal
      .mutateAsync({ address, version })
      .then((response) => {
        setValue(response.value)
        setMrn(response.mrn)
        setValueType(response.value_type)
        setRevealedVersion(response.version)
        setHops(response.reference_hops ?? [])
      })
      .catch(() => {
        // The error is surfaced from the mutation's own state; nothing about the
        // failed request is logged, because the request body is an address.
      })
    // `reveal` is intentionally omitted: including the mutation object would
    // re-run this effect on every mutation state change, i.e. reveal in a loop.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, address, version])

  // Navigating away drops the value even if the dialog is somehow still mounted.
  // The previous pathname is tracked in a ref so this fires on a CHANGE only —
  // reacting to the first render would close the dialog the instant it opened.
  const pathnameRef = useRef(location.pathname)
  useEffect(() => {
    if (pathnameRef.current === location.pathname) return
    pathnameRef.current = location.pathname
    if (!open) return
    clear()
    onOpenChange(false)
    // `clear` and `onOpenChange` change identity on every render; depending on
    // them would make this an every-render effect rather than a navigation one.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [location.pathname, open])

  const handleOpenChange = (next: boolean) => {
    if (!next) clear()
    onOpenChange(next)
  }

  const printable = value !== null && isPrintableUtf8(value)
  const text = printable && value !== null ? decodeBase64ToUtf8(value) : null

  const copy = async () => {
    if (value === null) return
    try {
      await navigator.clipboard.writeText(printable && text !== null ? text : value)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 2000)
    } catch {
      toast.error('Your browser blocked clipboard access.')
    }
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Reveal {address?.key ?? 'secret'}</DialogTitle>
          <DialogDescription>
            {revealedVersion !== null
              ? `Version ${revealedVersion}`
              : version
                ? `Version ${version}`
                : 'Current version'}
          </DialogDescription>
        </DialogHeader>

        <Alert>
          <ShieldAlert className="size-4" aria-hidden="true" />
          <AlertTitle>This read is recorded</AlertTitle>
          <AlertDescription>
            Opening this dialog wrote an audit row naming you, this secret and the time. The value
            is held in this page’s memory only and is discarded when the dialog closes.
          </AlertDescription>
        </Alert>

        {reveal.isPending ? <InlineLoading label="Decrypting" /> : null}
        {reveal.isError ? <ErrorState error={reveal.error} /> : null}

        {value !== null ? (
          <div className="space-y-3">
            <div className="flex flex-wrap items-center gap-2">
              {valueType ? <Badge variant="secondary">{valueType}</Badge> : null}
              {!printable ? (
                <Badge variant="outline">binary · {base64ByteLength(value)} bytes</Badge>
              ) : null}
            </div>

            <div className="rounded-md border bg-muted/40 p-3">
              <pre
                className="max-h-48 overflow-auto text-sm break-all whitespace-pre-wrap"
                aria-label={visible ? 'Secret value' : 'Secret value, hidden'}
              >
                {visible ? (printable && text !== null ? text : value) : '••••••••••••••••'}
              </pre>
            </div>

            <div className="flex flex-wrap gap-2">
              <Button variant="outline" size="sm" onClick={() => setVisible((shown) => !shown)}>
                {visible ? (
                  <EyeOff className="size-4" aria-hidden="true" />
                ) : (
                  <Eye className="size-4" aria-hidden="true" />
                )}
                {visible ? 'Hide value' : 'Show value'}
              </Button>
              <Button variant="outline" size="sm" onClick={() => void copy()}>
                {copied ? (
                  <Check className="size-4" aria-hidden="true" />
                ) : (
                  <Copy className="size-4" aria-hidden="true" />
                )}
                {copied ? 'Copied' : 'Copy'}
              </Button>
            </div>

            {!printable ? (
              <p className="text-xs text-muted-foreground">
                This value is not UTF-8 text, so it is shown and copied as base64.
              </p>
            ) : null}

            {hops.length > 0 ? (
              <div className="rounded-md border p-3">
                <p className="text-sm font-medium">Resolved through references</p>
                <p className="mt-1 text-xs text-muted-foreground">
                  This secret is a pointer. The value came from the chain below, and reading each
                  hop required your own grant on that hop and was audited separately.
                </p>
                <ol className="mt-2 space-y-1">
                  {hops.map((hop, index) => (
                    <li key={hop} className="font-mono text-xs break-all">
                      {index + 1}. {hop}
                    </li>
                  ))}
                </ol>
              </div>
            ) : null}

            {mrn ? (
              <p className="font-mono text-xs break-all text-muted-foreground">{mrn}</p>
            ) : null}
          </div>
        ) : null}

        <DialogFooter>
          <Button variant="outline" onClick={() => handleOpenChange(false)}>
            Close and discard
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
