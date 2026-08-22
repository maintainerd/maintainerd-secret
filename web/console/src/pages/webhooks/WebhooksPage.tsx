import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Layers, Webhook } from 'lucide-react'
import { PageContainer } from '@/components/layout/PageContainer'
import { PageHeader } from '@/components/layout/PageHeader'
import { ResourceListing } from '@/components/data-table'
import { EmptyState } from '@/components/details'
import { WebhookFormDialog } from './components/WebhookFormDialog'
import { buildWebhookColumns } from './components/webhookColumns'
import { useDeleteWebhook, useWebhooks } from '@/hooks/useWebhooks'
import { useScope } from '@/context/scopeContext'
import type { WebhookEndpoint } from '@/services/api/types'

/**
 * Webhook endpoints for the selected project.
 *
 * The standard maintainerd-auth listing: `PageContainer` → `PageHeader` →
 * `ResourceListing`. Deliveries live on the endpoint's detail route, the way
 * auth puts a webhook's deliveries on its detail page — an endpoint UUID in the
 * URL is safe, since it names a destination and not a secret.
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
    <PageContainer>
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
          rows={webhooks.data?.rows ?? []}
          columns={columns}
          defaultSort={[{ id: 'url', desc: false }]}
          searchFields={(row) => [row.url, row.description, row.events.join(' ')]}
          searchPlaceholder="Search endpoints"
          isLoading={webhooks.isLoading}
          error={webhooks.error}
          filterGroups={STATUS_FILTERS}
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
    </PageContainer>
  )
}

const STATUS_FILTERS = [
  { key: 'status', label: 'Status', options: ['active', 'suspended', 'disabled'] },
] as const
