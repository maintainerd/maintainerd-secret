import { useState } from 'react'
import { RotateCcw, Trash2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
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
import { useDeletedSecrets, useDestroySecret, useRestoreSecret } from '@/hooks/useSecrets'
import { useScope } from '@/context/scopeContext'
import { formatDateTime, formatRelative } from '@/lib/formatDate'
import type { DeletedSecret } from '@/services/api/types'

/**
 * The recovery window.
 *
 * A deleted secret stops resolving immediately but stays restorable until its
 * destroy date. DESTROY IS THE ONE ACTION IN THIS CONSOLE WITH NO WAY BACK, so
 * it gets its own confirmation that says exactly that instead of the usual
 * "are you sure".
 */
export default function DeletedPage() {
  const { project, environment } = useScope()
  const deleted = useDeletedSecrets(project ?? undefined, environment ?? undefined)
  const restore = useRestoreSecret()
  const destroy = useDestroySecret()
  const [toDestroy, setToDestroy] = useState<DeletedSecret | null>(null)

  const rows = deleted.data ?? []

  return (
    <div className="space-y-6">
      <PageHeader
        title="Deleted secrets"
        description="Soft-deleted secrets in this environment, restorable until their destroy date."
      />

      {!project || !environment ? <EmptyState title="Select a project and environment" /> : null}

      {project && environment ? (
        <>
          {deleted.isLoading ? <LoadingRows /> : null}
          {deleted.isError ? (
            <ErrorState error={deleted.error} onRetry={() => void deleted.refetch()} />
          ) : null}
          {!deleted.isLoading && !deleted.isError && rows.length === 0 ? (
            <EmptyState
              title="Nothing deleted"
              description="No secret in this environment is inside its recovery window."
            />
          ) : null}

          {rows.length > 0 ? (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Key</TableHead>
                    <TableHead>Folder</TableHead>
                    <TableHead>Version</TableHead>
                    <TableHead>Deleted</TableHead>
                    <TableHead>Destroy after</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rows.map((row) => (
                    <TableRow key={row.secret_uuid}>
                      <TableCell className="font-medium">{row.key}</TableCell>
                      <TableCell className="font-mono text-xs">{row.folder_path || '/'}</TableCell>
                      <TableCell>{row.current_version}</TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {formatRelative(row.deleted_at)}
                      </TableCell>
                      <TableCell className="text-sm">
                        {row.destroy_after ? formatDateTime(row.destroy_after) : '—'}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex justify-end gap-1">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => restore.mutate(row.secret_uuid)}
                            disabled={restore.isPending}
                          >
                            <RotateCcw className="size-4" aria-hidden="true" />
                            Restore
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => setToDestroy(row)}
                          >
                            <Trash2 className="size-4" aria-hidden="true" />
                            Destroy
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          ) : null}
        </>
      ) : null}

      <ConfirmDialog
        open={toDestroy !== null}
        onOpenChange={(open) => {
          if (!open) setToDestroy(null)
        }}
        title={`Destroy ${toDestroy?.key ?? ''} permanently?`}
        confirmLabel="Destroy permanently"
        destructive
        pending={destroy.isPending}
        onConfirm={async () => {
          if (!toDestroy) return
          await destroy.mutateAsync(toDestroy.secret_uuid)
          setToDestroy(null)
        }}
        description={
          <>
            <p>
              This removes the secret and every version of it. There is no restore afterwards and no
              backup inside the vault.
            </p>
            <p>Leaving it alone destroys it on its destroy date anyway.</p>
          </>
        }
      />
    </div>
  )
}
