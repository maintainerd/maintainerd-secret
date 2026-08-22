import { useMemo, useState } from 'react'
import {
  CalendarClock,
  Eye,
  FileText,
  History,
  Layers,
  Link2,
  RotateCw,
  Tag,
  Undo2,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import {
  DetailTabs,
  EmptyState,
  ListingItemCard,
  ListingItemMeta,
  ListSkeleton,
} from '@/components/details'
import { StatusBadge } from '@/components/badges'
import { CopyableCode } from '@/components/inputs'
import { ConfirmDialog } from '@/components/ConfirmDialog'
import { ErrorState } from '@/components/layout/states'
import { RevealDialog } from './RevealDialog'
import { RotationPanel } from './RotationPanel'
import { useRollbackSecret, useSecretMeta, useSecretVersions } from '@/hooks/useSecrets'
import { formatDateTime, formatRelative, isExpired } from '@/lib/formatDate'
import { VALUE_TYPE_REFERENCE, type SecretAddress } from '@/services/api/types'

/**
 * Everything about one secret except its value.
 *
 * IT IS A DIALOG, NOT A ROUTE, and that is a security decision rather than a
 * layout preference: a route would put the secret's address in the URL, and an
 * address in a URL lands in browser history, the referer header, and every proxy
 * and access log between here and the vault. The same reasoning is why the
 * service made reveal a POST.
 *
 * Inside, it is composed exactly like one of maintainerd-auth's detail pages —
 * an attribute grid, `DetailTabs`, and `ListingItemCard` rows — just hosted in a
 * dialog instead of a route. `DetailHeaderCard` itself is not used: it renders
 * its own `<h1>`, which would be a second top-level heading inside a dialog that
 * already has a `DialogTitle`.
 */

interface Attribute {
  icon: typeof Layers
  label: string
  value: React.ReactNode
}

function AttributeGrid({ attributes }: { attributes: Attribute[] }) {
  return (
    <div className="grid grid-cols-1 gap-x-8 gap-y-4 sm:grid-cols-2 lg:grid-cols-3">
      {attributes.map(({ icon: Icon, label, value }) => (
        <div key={label} className="flex flex-col gap-1">
          <div className="flex items-center gap-1.5 text-xs font-medium uppercase tracking-wide text-muted-foreground">
            <Icon className="size-3.5" aria-hidden="true" />
            {label}
          </div>
          <div className="text-sm text-foreground">{value}</div>
        </div>
      ))}
    </div>
  )
}

export function SecretDetailDialog({
  address,
  open,
  onOpenChange,
}: {
  address: SecretAddress | null
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const metaQuery = useSecretMeta(open ? address : null)
  const versionsQuery = useSecretVersions(open ? address : null, { limit: 50 })
  const rollback = useRollbackSecret()

  const [revealVersion, setRevealVersion] = useState<number | undefined>(undefined)
  const [revealOpen, setRevealOpen] = useState(false)
  const [rollbackTarget, setRollbackTarget] = useState<number | null>(null)

  const meta = metaQuery.data
  const versions = useMemo(() => versionsQuery.data?.rows ?? [], [versionsQuery.data])

  // The metadata type carries no value_type, so "is this a reference" is read
  // from the CURRENT version's row — the only place the API exposes it.
  const currentVersion = versions.find((version) => version.version === meta?.current_version)
  const isReference = currentVersion?.value_type === VALUE_TYPE_REFERENCE

  const openReveal = (version?: number) => {
    setRevealVersion(version)
    setRevealOpen(true)
  }

  const confirmRollback = async () => {
    if (!address || rollbackTarget === null) return
    await rollback.mutateAsync({ address, version: rollbackTarget })
    setRollbackTarget(null)
    await versionsQuery.refetch()
    await metaQuery.refetch()
  }

  const attributes: Attribute[] = meta
    ? [
        { icon: Layers, label: 'Current version', value: `v${meta.current_version}` },
        { icon: History, label: 'Versions retained', value: meta.keep_versions },
        { icon: RotateCw, label: 'Rotated', value: formatRelative(meta.rotated_at) },
        {
          icon: CalendarClock,
          label: 'Expires',
          value: meta.expires_at ? (
            isExpired(meta.expires_at) ? (
              <StatusBadge status="expired" label={`expired ${formatRelative(meta.expires_at)}`} />
            ) : (
              formatDateTime(meta.expires_at)
            )
          ) : (
            '—'
          ),
        },
        {
          icon: FileText,
          label: 'Description',
          value: meta.description || <span className="text-muted-foreground">—</span>,
        },
        {
          icon: Tag,
          label: 'Tags',
          value:
            meta.tags.length > 0 ? (
              <div className="flex flex-wrap gap-1">
                {meta.tags.map((tag) => (
                  <Badge key={tag} variant="outline" className="text-xs">
                    {tag}
                  </Badge>
                ))}
              </div>
            ) : (
              <span className="text-muted-foreground">—</span>
            ),
        },
      ]
    : []

  return (
    <>
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle className="flex flex-wrap items-center gap-2.5">
              {address?.key ?? 'Secret'}
              {isReference && (
                <Badge variant="secondary" className="gap-1">
                  <Link2 className="size-3" aria-hidden="true" />
                  reference
                </Badge>
              )}
            </DialogTitle>
            <DialogDescription className="text-left">
              {address
                ? `${address.project} / ${address.environment} · ${address.folder_path || '/'}`
                : null}
            </DialogDescription>
          </DialogHeader>

          <DetailTabs defaultValue="overview">
            <TabsList>
              <TabsTrigger value="overview">Overview</TabsTrigger>
              <TabsTrigger value="versions">Versions</TabsTrigger>
              <TabsTrigger value="rotation">Rotation</TabsTrigger>
            </TabsList>

            <TabsContent value="overview" className="space-y-5">
              {metaQuery.isLoading && <ListSkeleton rows={2} />}
              {metaQuery.isError && (
                <ErrorState error={metaQuery.error} onRetry={() => void metaQuery.refetch()} />
              )}
              {meta && (
                <>
                  <AttributeGrid attributes={attributes} />

                  <div className="space-y-1.5">
                    <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                      MRN
                    </p>
                    <CopyableCode value={meta.mrn} label="MRN" variant="block" />
                  </div>

                  {isReference && (
                    <Alert>
                      <Link2 className="size-4" aria-hidden="true" />
                      <AlertTitle>This secret is a reference</AlertTitle>
                      <AlertDescription>
                        Its stored value is a pointer of the form{' '}
                        <code>{'${project/environment/folder/KEY}'}</code>, not a credential.
                        Revealing it resolves the chain, re-checking your reveal grant against each
                        target and auditing every hop — so a reference can never widen what you can
                        read. Reveal it to see the chain it traversed.
                      </AlertDescription>
                    </Alert>
                  )}

                  <Button size="sm" onClick={() => openReveal(undefined)}>
                    <Eye className="size-4" aria-hidden="true" />
                    Reveal current value
                  </Button>
                </>
              )}
            </TabsContent>

            <TabsContent value="versions" className="space-y-3">
              {versionsQuery.isLoading && <ListSkeleton rows={3} />}
              {versionsQuery.isError && (
                <ErrorState
                  error={versionsQuery.error}
                  onRetry={() => void versionsQuery.refetch()}
                />
              )}
              {!versionsQuery.isLoading && !versionsQuery.isError && versions.length === 0 && (
                <EmptyState
                  icon={History}
                  title="No versions"
                  description="This secret has no readable version history."
                />
              )}

              {versions.length > 0 && (
                <div className="max-h-80 space-y-2 overflow-y-auto pr-1">
                  {versions.map((version) => {
                    const current = version.version === meta?.current_version
                    return (
                      <ListingItemCard
                        key={version.version}
                        icon={History}
                        action={
                          <div className="flex gap-1">
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => openReveal(version.version)}
                            >
                              <Eye className="size-4" aria-hidden="true" />
                              Reveal
                            </Button>
                            {!current && (
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => setRollbackTarget(version.version)}
                              >
                                <Undo2 className="size-4" aria-hidden="true" />
                                Roll back
                              </Button>
                            )}
                          </div>
                        }
                      >
                        <div className="flex flex-wrap items-center gap-2">
                          <p className="text-sm font-medium">Version {version.version}</p>
                          {current && <StatusBadge status="active" label="current" />}
                        </div>
                        <ListingItemMeta>
                          <span>{version.value_type}</span>
                          <span>{formatDateTime(version.created_at)}</span>
                        </ListingItemMeta>
                      </ListingItemCard>
                    )
                  })}
                </div>
              )}

              <p className="flex items-start gap-2 text-xs text-muted-foreground">
                <History className="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />
                History is append-only. Retention prunes the oldest versions beyond the retained
                count and never touches the current one.
              </p>
            </TabsContent>

            <TabsContent value="rotation">
              {address && <RotationPanel address={address} meta={meta} />}
            </TabsContent>
          </DetailTabs>
        </DialogContent>
      </Dialog>

      <RevealDialog
        address={address}
        version={revealVersion}
        open={revealOpen}
        onOpenChange={setRevealOpen}
      />

      <ConfirmDialog
        open={rollbackTarget !== null}
        onOpenChange={(next) => {
          if (!next) setRollbackTarget(null)
        }}
        title={`Roll back to version ${rollbackTarget ?? ''}?`}
        confirmLabel="Roll back"
        pending={rollback.isPending}
        onConfirm={() => void confirmRollback()}
        description={
          <>
            <p>
              This does <strong>not</strong> rewrite history. It writes a NEW version carrying that
              version’s value, so the current version number moves forward, not back.
            </p>
            <p>
              That is deliberate: version history is append-only, and a version number that moved
              backwards would mean a consumer pinned to “version 5” silently got something else.
            </p>
          </>
        }
      />
    </>
  )
}
