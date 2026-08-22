import { useMemo, useState } from 'react'
import { Eye, FolderPlus, Info, MoveRight, Plus, Trash2 } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { PageHeader } from '@/components/layout/PageHeader'
import { EmptyState, ErrorState, LoadingRows } from '@/components/layout/states'
import { ConfirmDialog } from '@/components/ConfirmDialog'
import { FolderBreadcrumb } from '@/components/secrets/FolderBreadcrumb'
import { FolderTree } from '@/components/secrets/FolderTree'
import { CreateFolderDialog, MoveFolderDialog } from '@/components/secrets/FolderDialogs'
import { ImportsDialog } from '@/components/secrets/ImportsDialog'
import { RevealDialog } from '@/components/secrets/RevealDialog'
import { SecretDetailDialog } from '@/components/secrets/SecretDetailDialog'
import { SecretFormDialog, type SecretFormMode } from '@/components/secrets/SecretFormDialog'
import { useFolders } from '@/hooks/useFolders'
import { useDeleteSecret, useSecrets } from '@/hooks/useSecrets'
import { useScope } from '@/context/scopeContext'
import { formatDateTime, formatRelative, isExpired } from '@/lib/formatDate'
import { ROOT_PATH, isDirectChildOf, normalizePath } from '@/lib/paths'
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
 *     made reveal a POST.
 */
export default function BrowsePage() {
  const { project, environment, loading: scopeLoading, error: scopeError } = useScope()
  const [folderPath, setFolderPath] = useState<string>(ROOT_PATH)
  const [includeSubfolders, setIncludeSubfolders] = useState(false)
  const [search, setSearch] = useState('')

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

  const rows = useMemo(() => {
    const all = secrets.data?.rows ?? []
    const scoped = includeSubfolders
      ? all
      : all.filter((row) => normalizePath(row.folder_path) === normalizePath(folderPath))
    const needle = search.trim().toLowerCase()
    if (!needle) return scoped
    return scoped.filter(
      (row) =>
        row.key.toLowerCase().includes(needle) ||
        row.description.toLowerCase().includes(needle) ||
        row.tags.some((tag) => tag.toLowerCase().includes(needle)),
    )
  }, [secrets.data, includeSubfolders, folderPath, search])

  const childFolders = useMemo(
    () => (folders.data ?? []).filter((folder) => isDirectChildOf(folder.path, folderPath)),
    [folders.data, folderPath],
  )

  const addressOf = (secret: SecretMeta): SecretAddress => ({
    project: project ?? '',
    environment: environment ?? '',
    folder_path: normalizePath(secret.folder_path),
    key: secret.key,
  })

  if (scopeError) {
    return <ErrorState error={scopeError} />
  }

  if (!scopeLoading && (!project || !environment)) {
    return (
      <EmptyState
        title="No project or environment"
        description="Create a project and an environment before storing secrets."
      />
    )
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Secrets"
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
            <Button variant="outline" size="sm" onClick={() => setImportsOpen(true)}>
              <MoveRight className="size-4" aria-hidden="true" />
              Imports
            </Button>
            <Button variant="outline" size="sm" onClick={() => setCreateFolderOpen(true)}>
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

      <div className="grid gap-6 lg:grid-cols-[240px_minmax(0,1fr)]">
        <aside className="space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-medium">Folders</h2>
            {folderPath !== ROOT_PATH ? (
              <Button variant="ghost" size="sm" onClick={() => setMoveFolderOpen(true)}>
                Move
              </Button>
            ) : null}
          </div>
          {folders.isLoading ? <LoadingRows rows={4} /> : null}
          {folders.isError ? (
            <ErrorState error={folders.error} onRetry={() => void folders.refetch()} />
          ) : null}
          {folders.data ? (
            <FolderTree
              folders={folders.data}
              selected={folderPath}
              onSelect={setFolderPath}
            />
          ) : null}
        </aside>

        <section className="min-w-0 space-y-4">
          <FolderBreadcrumb path={folderPath} onNavigate={setFolderPath} />

          <div className="flex flex-wrap items-center gap-4">
            <div className="min-w-48 flex-1">
              <Label htmlFor="secret-search" className="sr-only">
                Filter secrets
              </Label>
              <Input
                id="secret-search"
                placeholder="Filter by key, description or tag"
                value={search}
                onChange={(event) => setSearch(event.target.value)}
              />
            </div>
            <div className="flex items-center gap-2">
              <Switch
                id="include-subfolders"
                checked={includeSubfolders}
                onCheckedChange={setIncludeSubfolders}
              />
              <Label htmlFor="include-subfolders" className="text-sm">
                Include subfolders
              </Label>
            </div>
          </div>

          {childFolders.length > 0 && !includeSubfolders ? (
            <div className="flex flex-wrap gap-2">
              {childFolders.map((folder) => (
                <Button
                  key={folder.folder_uuid}
                  variant="outline"
                  size="sm"
                  onClick={() => setFolderPath(folder.path)}
                >
                  {folder.name}
                </Button>
              ))}
            </div>
          ) : null}

          {secrets.isLoading ? <LoadingRows /> : null}
          {secrets.isError ? (
            <ErrorState error={secrets.error} onRetry={() => void secrets.refetch()} />
          ) : null}

          {!secrets.isLoading && !secrets.isError && rows.length === 0 ? (
            <EmptyState
              title="No secrets here"
              description={
                search
                  ? 'Nothing in this folder matches that filter.'
                  : 'This folder is empty. Create a secret to get started.'
              }
            />
          ) : null}

          {rows.length > 0 ? (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Key</TableHead>
                    {includeSubfolders ? <TableHead>Folder</TableHead> : null}
                    <TableHead>Tags</TableHead>
                    <TableHead>Version</TableHead>
                    <TableHead>Rotated</TableHead>
                    <TableHead>Expires</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rows.map((secret) => (
                    <TableRow key={secret.secret_uuid}>
                      <TableCell className="max-w-56">
                        <div className="truncate font-medium">{secret.key}</div>
                        {secret.description ? (
                          <div className="truncate text-xs text-muted-foreground">
                            {secret.description}
                          </div>
                        ) : null}
                      </TableCell>
                      {includeSubfolders ? (
                        <TableCell className="font-mono text-xs">
                          {normalizePath(secret.folder_path)}
                        </TableCell>
                      ) : null}
                      <TableCell>
                        <div className="flex flex-wrap gap-1">
                          {secret.tags.map((tag) => (
                            <Badge key={tag} variant="outline">
                              {tag}
                            </Badge>
                          ))}
                        </div>
                      </TableCell>
                      <TableCell>{secret.current_version}</TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {formatRelative(secret.rotated_at)}
                      </TableCell>
                      <TableCell className="text-sm">
                        {secret.expires_at ? (
                          <span className={isExpired(secret.expires_at) ? 'text-destructive' : ''}>
                            {formatDateTime(secret.expires_at)}
                          </span>
                        ) : (
                          <span className="text-muted-foreground">—</span>
                        )}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex justify-end gap-1">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => setRevealAddress(addressOf(secret))}
                          >
                            <Eye className="size-4" aria-hidden="true" />
                            Reveal
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => setDetailAddress(addressOf(secret))}
                          >
                            <Info className="size-4" aria-hidden="true" />
                            Details
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => {
                              setFormMode('new-version')
                              setFormSecret(secret)
                              setFormOpen(true)
                            }}
                          >
                            New version
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => {
                              setFormMode('edit-metadata')
                              setFormSecret(secret)
                              setFormOpen(true)
                            }}
                          >
                            Edit
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon-sm"
                            aria-label={`Delete ${secret.key}`}
                            onClick={() => setDeleteTarget(secret)}
                          >
                            <Trash2 className="size-4" aria-hidden="true" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          ) : null}
        </section>
      </div>

      {project && environment ? (
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
      ) : null}

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
