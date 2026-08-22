import { useMemo, useState } from 'react'
import { FolderPlus, FolderTree as FolderTreeIcon, MoveRight, Plus } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { PageHeader } from '@/components/layout/PageHeader'
import { ErrorState } from '@/components/layout/states'
import { EmptyState, ListSkeleton } from '@/components/details'
import { ResourceListing } from '@/components/data-table'
import { ConfirmDialog } from '@/components/ConfirmDialog'
import { FolderBreadcrumb } from '@/components/secrets/FolderBreadcrumb'
import { FolderTree } from '@/components/secrets/FolderTree'
import { CreateFolderDialog, MoveFolderDialog } from '@/components/secrets/FolderDialogs'
import { ImportsDialog } from '@/components/secrets/ImportsDialog'
import { RevealDialog } from '@/components/secrets/RevealDialog'
import { SecretDetailDialog } from '@/components/secrets/SecretDetailDialog'
import { SecretFormDialog, type SecretFormMode } from '@/components/secrets/SecretFormDialog'
import { buildSecretColumns } from './components/secretColumns'
import { useFolders } from '@/hooks/useFolders'
import { useDeleteSecret, useSecrets } from '@/hooks/useSecrets'
import { useScope } from '@/context/scopeContext'
import { ROOT_PATH, normalizePath } from '@/lib/paths'
import type { SecretAddress, SecretMeta } from '@/services/api/types'

/**
 * The secret browser: folder tree on the left, the folder's secrets on the right.
 *
 * TWO THINGS THIS PAGE WILL NOT DO.
 *
 *  1. IT NEVER FETCHES A VALUE. Everything on this screen comes from
 *     `GET /secrets`, which returns a type with no value field. Revealing is an
 *     explicit, per-secret action behind its own grant and its own audit row.
 *  2. IT KEEPS THE FOLDER PATH AND THE SELECTED KEY OUT OF THE URL. Browsing
 *     state lives in component state, so a secret's address never reaches
 *     browser history or a referer header. That is the same reason the service
 *     made reveal a POST — and the reason `ResourceListing` here is given no
 *     `urlKey`, so it does not mirror its search term into the query string
 *     either (an operator searching for "STRIPE_LIVE_KEY" would otherwise put
 *     that in history).
 *
 * Everything else is maintainerd-auth's listing shape: a `PageHeader`, a
 * `ResourceListing` (toolbar → table → pagination) and the shared row-actions
 * menu, laid out full-width because the tree needs a column of its own.
 */
export default function BrowsePage() {
  const { project, environment, loading: scopeLoading, error: scopeError } = useScope()
  const [folderPath, setFolderPath] = useState<string>(ROOT_PATH)
  const [includeSubfolders, setIncludeSubfolders] = useState(false)

  const [formMode, setFormMode] = useState<SecretFormMode>('create')
  const [formSecret, setFormSecret] = useState<SecretMeta | null>(null)
  const [formOpen, setFormOpen] = useState(false)

  const [revealAddress, setRevealAddress] = useState<SecretAddress | null>(null)
  const [detailAddress, setDetailAddress] = useState<SecretAddress | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<SecretMeta | null>(null)

  const [createFolderOpen, setCreateFolderOpen] = useState(false)
  const [moveFolderOpen, setMoveFolderOpen] = useState(false)
  const [importsOpen, setImportsOpen] = useState(false)

  const folders = useFolders(project ?? undefined, environment ?? undefined)
  const secrets = useSecrets(
    {
      project: project ?? '',
      environment: environment ?? '',
      prefix: folderPath,
      limit: 200,
    },
    Boolean(project && environment),
  )
  const deleteSecret = useDeleteSecret()
  // `mutateAsync` is stable across renders; the mutation object is not. Depending
  // on the object below would rebuild the column defs on every render.
  const deleteSecretAsync = deleteSecret.mutateAsync

  const addressOf = (secret: SecretMeta): SecretAddress => ({
    project: project ?? '',
    environment: environment ?? '',
    folder_path: normalizePath(secret.folder_path),
    key: secret.key,
  })

  const rows = useMemo(() => {
    const all = secrets.data?.rows ?? []
    if (includeSubfolders) return all
    return all.filter((row) => normalizePath(row.folder_path) === normalizePath(folderPath))
  }, [secrets.data, includeSubfolders, folderPath])

  const columns = useMemo(
    () =>
      buildSecretColumns(
        {
          onReveal: (secret) => setRevealAddress(addressOf(secret)),
          onDetails: (secret) => setDetailAddress(addressOf(secret)),
          onNewVersion: (secret) => {
            setFormMode('new-version')
            setFormSecret(secret)
            setFormOpen(true)
          },
          onEditMetadata: (secret) => {
            setFormMode('edit-metadata')
            setFormSecret(secret)
            setFormOpen(true)
          },
          onDelete: async (secret) => {
            await deleteSecretAsync({ address: addressOf(secret) })
          },
        },
        { showFolder: includeSubfolders },
      ),
    // `addressOf` closes over the scope, which is what actually has to be fresh.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [includeSubfolders, project, environment, deleteSecretAsync],
  )

  if (scopeError) {
    return <ErrorState error={scopeError} />
  }

  if (!scopeLoading && (!project || !environment)) {
    return (
      <EmptyState
        icon={FolderTreeIcon}
        title="No project or environment"
        description="Create a project and an environment before storing secrets."
      />
    )
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Secrets"
        icon={FolderTreeIcon}
        description={
          project && environment ? (
            <span>
              Browsing <span className="font-mono">{project}</span> /{' '}
              <span className="font-mono">{environment}</span>. Values are never loaded for a list —
              revealing one is a separate, audited action.
            </span>
          ) : null
        }
        actions={
          <>
            <Button
              data-md-action-button
              variant="outline"
              size="sm"
              onClick={() => setImportsOpen(true)}
            >
              <MoveRight className="size-4" aria-hidden="true" />
              Imports
            </Button>
            <Button
              data-md-action-button
              variant="outline"
              size="sm"
              onClick={() => setCreateFolderOpen(true)}
            >
              <FolderPlus className="size-4" aria-hidden="true" />
              New folder
            </Button>
            <Button
              size="sm"
              onClick={() => {
                setFormMode('create')
                setFormSecret(null)
                setFormOpen(true)
              }}
            >
              <Plus className="size-4" aria-hidden="true" />
              New secret
            </Button>
          </>
        }
      />

      <div className="grid gap-6 lg:grid-cols-[260px_minmax(0,1fr)]">
        <Card className="h-fit py-4">
          <CardHeader className="px-4">
            <div className="flex items-center justify-between gap-2">
              <CardTitle className="text-base">Folders</CardTitle>
              {folderPath !== ROOT_PATH && (
                <Button variant="ghost" size="sm" onClick={() => setMoveFolderOpen(true)}>
                  Move
                </Button>
              )}
            </div>
          </CardHeader>
          <CardContent className="px-2">
            {folders.isLoading && <ListSkeleton rows={3} />}
            {folders.isError && (
              <ErrorState error={folders.error} onRetry={() => void folders.refetch()} />
            )}
            {folders.data && (
              <FolderTree folders={folders.data} selected={folderPath} onSelect={setFolderPath} />
            )}
          </CardContent>
        </Card>

        <Card className="min-w-0 py-6">
          <CardContent className="flex min-w-0 flex-col gap-4 px-6">
            <FolderBreadcrumb path={folderPath} onNavigate={setFolderPath} />

            <ResourceListing<SecretMeta>
              rows={rows}
              columns={columns}
              defaultSort={[{ id: 'key', desc: false }]}
              searchFields={(row) => [row.key, row.description, row.tags.join(' ')]}
              searchPlaceholder="Filter by key, description or tag"
              isLoading={secrets.isLoading}
              error={secrets.error}
              onRowClick={(secret) => setDetailAddress(addressOf(secret))}
              emptyTitle="No secrets here"
              emptyDescription="This folder is empty. Create a secret to get started."
              onCreate={() => {
                setFormMode('create')
                setFormSecret(null)
                setFormOpen(true)
              }}
              createLabel="New secret"
              extraActions={
                <div className="flex items-center gap-2">
                  <Switch
                    id="include-subfolders"
                    checked={includeSubfolders}
                    onCheckedChange={setIncludeSubfolders}
                  />
                  <Label htmlFor="include-subfolders" className="text-sm whitespace-nowrap">
                    Include subfolders
                  </Label>
                </div>
              }
            />
          </CardContent>
        </Card>
      </div>

      {project && environment && (
        <>
          <SecretFormDialog
            mode={formMode}
            project={project}
            environment={environment}
            folderPath={formSecret ? normalizePath(formSecret.folder_path) : folderPath}
            secret={formSecret}
            open={formOpen}
            onOpenChange={setFormOpen}
          />
          <CreateFolderDialog
            project={project}
            environment={environment}
            parentPath={folderPath}
            open={createFolderOpen}
            onOpenChange={setCreateFolderOpen}
            onCreated={setFolderPath}
          />
          <MoveFolderDialog
            project={project}
            environment={environment}
            path={folderPath}
            open={moveFolderOpen}
            onOpenChange={setMoveFolderOpen}
            onMoved={setFolderPath}
          />
          <ImportsDialog
            project={project}
            environment={environment}
            folderPath={folderPath}
            open={importsOpen}
            onOpenChange={setImportsOpen}
          />
        </>
      )}

      <RevealDialog
        address={revealAddress}
        open={revealAddress !== null}
        onOpenChange={(open) => {
          if (!open) setRevealAddress(null)
        }}
      />

      <SecretDetailDialog
        address={detailAddress}
        open={detailAddress !== null}
        onOpenChange={(open) => {
          if (!open) setDetailAddress(null)
        }}
      />

      <ConfirmDialog
        open={deleteTarget !== null}
        onOpenChange={(open) => {
          if (!open) setDeleteTarget(null)
        }}
        title={`Delete ${deleteTarget?.key ?? ''}?`}
        confirmLabel="Delete"
        destructive
        pending={deleteSecret.isPending}
        onConfirm={async () => {
          if (!deleteTarget) return
          await deleteSecret.mutateAsync({ address: addressOf(deleteTarget) })
          setDeleteTarget(null)
        }}
        description={
          <>
            <p>
              This is a soft delete. The secret stops resolving immediately but stays restorable
              from the Deleted page until its destroy date.
            </p>
            <p>Anything still reading this secret will start failing right away.</p>
          </>
        }
      />
    </div>
  )
}
