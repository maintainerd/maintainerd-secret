import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Layers, Webhook } from 'lucide-react'
import type { SortingState } from '@tanstack/react-table'
import { PageHeader } from '@/components/layout/PageHeader'
import { ResourceListing, type FilterGroup } from '@/components/data-table'
import { EmptyState } from '@/components/details'
import { WebhookFormDialog } from './components/WebhookFormDialog'
import { buildWebhookColumns } from './components/webhookColumns'
import { useDeleteWebhook, useWebhooks } from '@/hooks/useWebhooks'
import { useScope } from '@/context/scopeContext'
import type { WebhookEndpoint } from '@/services/api/types'

const DEFAULT_SORT: SortingState = [{ id: 'url', desc: false }]
const FILTER_GROUPS: readonly FilterGroup[] = [
  { key: 'status', label: 'Status', options: ['active', 'suspended', 'disabled'] },
]
// Stable identity: secret's engine filters client-side and re-runs its memo
// whenever this changes. See ProjectsPage for the full note.
const SEARCH_FIELDS = (row: WebhookEndpoint) => [
  row.url,
  row.description,
  row.events.join(' '),
]

/**
 * Webhook endpoints for the selected project.
 *
 * maintainerd-auth's standard listing page: a centred `max-w-6xl` column →
 * `PageHeader` → `ResourceListing tableInCard`, matching
 * `pages/webhooks/WebhooksPage.tsx` in auth (which passes `tableInCard` too).
 *
 * Deliveries live on the endpoint's detail route, the way auth puts a webhook's
 * deliveries on its detail page — an endpoint UUID in the URL is safe, since it
 * names a destination and not a secret.
 */
export default function WebhooksPage() {
  const navigate = useNavigate()
  const { project } = useScope()
  const webhooks = useWebhooks(project ?? undefined)
  const deleteWebhook = useDeleteWebhook()
  const [createOpen, setCreateOpen] = useState(false)

  // `mutateAsync` is stable across renders; the mutation object is not.
  const deleteWebhookAsync = deleteWebhook.mutateAsync

  const columns = useMemo(
    () =>
      buildWebhookColumns({
        onOpen: (endpoint) => navigate(`/webhooks/${encodeURIComponent(endpoint.endpoint_uuid)}`),
        onDelete: async (endpoint) => {
          if (!project) return
          await deleteWebhookAsync({ endpointUuid: endpoint.endpoint_uuid, project })
        },
      }),
    [navigate, project, deleteWebhookAsync],
  )

  return (
    <div className="mx-auto flex w-full max-w-6xl flex-col gap-4">
      <PageHeader
        title="Webhooks"
        icon={Webhook}
        description="Deliveries carry the MRN and the new version — never a value. A consumer learns it should re-read."
      />

      {!project ? (
        <EmptyState
          icon={Layers}
          title="Select a project"
          description="Webhook endpoints are scoped to a project. Pick one from the scope switcher."
        />
      ) : (
        <ResourceListing<WebhookEndpoint>
          tableInCard
          rows={webhooks.data?.rows ?? []}
          columns={columns}
          defaultSort={DEFAULT_SORT}
          searchFields={SEARCH_FIELDS}
          searchPlaceholder="Search endpoints"
          isLoading={webhooks.isLoading}
          error={webhooks.error}
          filterGroups={FILTER_GROUPS}
          onRowClick={(endpoint) =>
            navigate(`/webhooks/${encodeURIComponent(endpoint.endpoint_uuid)}`)
          }
          onCreate={() => setCreateOpen(true)}
          createLabel="New endpoint"
          emptyTitle="No endpoints"
          emptyDescription="Add one to be told when a secret in this project changes or rotates."
          urlKey="webhooks"
        />
      )}

      {project && (
        <WebhookFormDialog project={project} open={createOpen} onOpenChange={setCreateOpen} />
      )}
    </div>
  )
}
