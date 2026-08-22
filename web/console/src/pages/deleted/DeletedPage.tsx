import { useMemo, useState } from 'react'
import { Layers, Trash2 } from 'lucide-react'
import { PageContainer } from '@/components/layout/PageContainer'
import { PageHeader } from '@/components/layout/PageHeader'
import { ResourceListing } from '@/components/data-table'
import { EmptyState } from '@/components/details'
import { DeleteConfirmationDialog } from '@/components/dialog'
import { buildDeletedColumns } from './components/deletedColumns'
import { useDeletedSecrets, useDestroySecret, useRestoreSecret } from '@/hooks/useSecrets'
import { useScope } from '@/context/scopeContext'
import type { DeletedSecret } from '@/services/api/types'

/**
 * The recovery window.
 *
 * A deleted secret stops resolving immediately but stays restorable until its
 * destroy date. DESTROY IS THE ONE ACTION IN THIS CONSOLE WITH NO WAY BACK, so
 * it uses auth's type-to-confirm `DeleteConfirmationDialog` — the operator has to
 * type the key — instead of a one-click confirm.
 */
export default function DeletedPage() {
  const { project, environment } = useScope()
  const deleted = useDeletedSecrets(project ?? undefined, environment ?? undefined)
  const restore = useRestoreSecret()
  const destroy = useDestroySecret()
  const [toDestroy, setToDestroy] = useState<DeletedSecret | null>(null)

  // `mutateAsync` is stable across renders; the mutation object is not.
  const restoreAsync = restore.mutateAsync

  const columns = useMemo(
    () =>
      buildDeletedColumns({
        onRestore: async (secret) => {
          await restoreAsync(secret.secret_uuid)
        },
        onDestroy: (secret) => setToDestroy(secret),
      }),
    [restoreAsync],
  )

  return (
    <PageContainer>
      <PageHeader
        title="Deleted secrets"
        icon={Trash2}
        description="Soft-deleted secrets in this environment, restorable until their destroy date."
      />

      {!project || !environment ? (
        <EmptyState
          icon={Layers}
          title="Select a project and environment"
          description="The recovery window is per environment. Pick one from the scope switcher."
        />
      ) : (
        <ResourceListing<DeletedSecret>
          rows={deleted.data ?? []}
          columns={columns}
          defaultSort={[{ id: 'deleted', desc: true }]}
          searchFields={(row) => [row.key, row.folder_path]}
          searchPlaceholder="Search deleted secrets"
          isLoading={deleted.isLoading}
          error={deleted.error}
          emptyTitle="Nothing deleted"
          emptyDescription="No secret in this environment is inside its recovery window."
        />
      )}

      <DeleteConfirmationDialog
        open={toDestroy !== null}
        onOpenChange={(open) => {
          if (!open) setToDestroy(null)
        }}
        onConfirm={async () => {
          if (!toDestroy) return
          await destroy.mutateAsync(toDestroy.secret_uuid)
          setToDestroy(null)
        }}
        title={`Destroy ${toDestroy?.key ?? ''} permanently?`}
        description="This removes the secret and every version of it. There is no restore afterwards and no backup inside the vault."
        confirmationText="Leaving it alone destroys it on its destroy date anyway — there is no reason to do this early unless you need the key name freed now."
        itemName={toDestroy?.key ?? ''}
        isDeleting={destroy.isPending}
        confirmLabel="Destroy permanently"
      />
    </PageContainer>
  )
}
