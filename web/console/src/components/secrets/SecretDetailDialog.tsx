import { useMemo, useState } from 'react'
import { Eye, History, Link2, Undo2 } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { ConfirmDialog } from '@/components/ConfirmDialog'
import { ErrorState, InlineLoading } from '@/components/layout/states'
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
 * address in a URL lands in browser history, the referer header, and every
 * proxy and access log between here and the vault. The same reasoning is why the
 * service made reveal a POST.
 */
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

  return (
    <>
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent className="sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              {address?.key ?? 'Secret'}
              {isReference ? (
                <Badge variant="secondary" className="gap-1">
                  <Link2 className="size-3" aria-hidden="true" />
                  reference
                </Badge>
              ) : null}
            </DialogTitle>
            <DialogDescription>
              {address ? `${address.project} / ${address.environment} · ${address.folder_path || '/'}` : null}
            </DialogDescription>
          </DialogHeader>

          <Tabs defaultValue="overview">
            <TabsList>
              <TabsTrigger value="overview">Overview</TabsTrigger>
              <TabsTrigger value="versions">Versions</TabsTrigger>
              <TabsTrigger value="rotation">Rotation</TabsTrigger>
            </TabsList>

            <TabsContent value="overview" className="space-y-4 pt-4">
              {metaQuery.isLoading ? <InlineLoading /> : null}
              {metaQuery.isError ? (
                <ErrorState error={metaQuery.error} onRetry={() => void metaQuery.refetch()} />
              ) : null}
              {meta ? (
                <>
                  <dl className="grid gap-3 text-sm sm:grid-cols-2">
                    <div>
                      <dt className="text-xs text-muted-foreground">Current version</dt>
                      <dd>{meta.current_version}</dd>
                    </div>
                    <div>
                      <dt className="text-xs text-muted-foreground">Versions retained</dt>
                      <dd>{meta.keep_versions}</dd>
                    </div>
                    <div>
                      <dt className="text-xs text-muted-foreground">Rotated</dt>
                      <dd>{formatRelative(meta.rotated_at)}</dd>
                    </div>
                    <div>
                      <dt className="text-xs text-muted-foreground">Expires</dt>
                      <dd>
                        {meta.expires_at ? (
                          <span className={isExpired(meta.expires_at) ? 'text-destructive' : ''}>
                            {formatDateTime(meta.expires_at)}
                            {isExpired(meta.expires_at) ? ' (expired)' : ''}
                          </span>
                        ) : (
                          '—'
                        )}
                      </dd>
                    </div>
                    <div className="sm:col-span-2">
                      <dt className="text-xs text-muted-foreground">Description</dt>
                      <dd>{meta.description || '—'}</dd>
                    </div>
                    <div className="sm:col-span-2">
                      <dt className="text-xs text-muted-foreground">Tags</dt>
                      <dd className="flex flex-wrap gap-1">
                        {meta.tags.length > 0
                          ? meta.tags.map((tag) => (
                              <Badge key={tag} variant="outline">
                                {tag}
                              </Badge>
                            ))
                          : '—'}
                      </dd>
                    </div>
                    <div className="sm:col-span-2">
                      <dt className="text-xs text-muted-foreground">MRN</dt>
                      <dd className="font-mono text-xs break-all">{meta.mrn}</dd>
                    </div>
                  </dl>

                  {isReference ? (
                    <div className="rounded-md border p-3 text-sm">
                      <p className="font-medium">This secret is a reference</p>
                      <p className="mt-1 text-xs text-muted-foreground">
                        Its stored value is a pointer of the form{' '}
                        <code>{'${project/environment/folder/KEY}'}</code>, not a credential.
                        Revealing it resolves the chain, re-checking your reveal grant against each
                        target and auditing every hop — so a reference can never widen what you can
                        read. Reveal it to see the chain it traversed.
                      </p>
                    </div>
                  ) : null}

                  <Button size="sm" onClick={() => openReveal(undefined)}>
                    <Eye className="size-4" aria-hidden="true" />
                    Reveal current value
                  </Button>
                </>
              ) : null}
            </TabsContent>

            <TabsContent value="versions" className="space-y-3 pt-4">
              {versionsQuery.isLoading ? <InlineLoading /> : null}
              {versionsQuery.isError ? (
                <ErrorState
                  error={versionsQuery.error}
                  onRetry={() => void versionsQuery.refetch()}
                />
              ) : null}
              {versions.length > 0 ? (
                <div className="max-h-80 overflow-auto">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Version</TableHead>
                        <TableHead>Type</TableHead>
                        <TableHead>Created</TableHead>
                        <TableHead className="text-right">Actions</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {versions.map((version) => (
                        <TableRow key={version.version}>
                          <TableCell>
                            {version.version}
                            {version.version === meta?.current_version ? (
                              <Badge variant="secondary" className="ml-2">
                                current
                              </Badge>
                            ) : null}
                          </TableCell>
                          <TableCell>{version.value_type}</TableCell>
                          <TableCell>{formatDateTime(version.created_at)}</TableCell>
                          <TableCell className="text-right">
                            <div className="flex justify-end gap-1">
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => openReveal(version.version)}
                              >
                                <Eye className="size-4" aria-hidden="true" />
                                Reveal
                              </Button>
                              {version.version !== meta?.current_version ? (
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  onClick={() => setRollbackTarget(version.version)}
                                >
                                  <Undo2 className="size-4" aria-hidden="true" />
                                  Roll back
                                </Button>
                              ) : null}
                            </div>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              ) : null}
              <p className="flex items-start gap-2 text-xs text-muted-foreground">
                <History className="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />
                History is append-only. Retention prunes the oldest versions beyond the retained
                count and never touches the current one.
              </p>
            </TabsContent>

            <TabsContent value="rotation" className="pt-4">
              {address ? <RotationPanel address={address} meta={meta} /> : null}
            </TabsContent>
          </Tabs>
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
