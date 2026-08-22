import { useMemo, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { Clock, ListChecks, Repeat, Send, Webhook } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  DetailHeaderCard,
  DetailLayout,
  DetailTabs,
  EmptyState,
  ListingItemCard,
  ListingItemMeta,
  ListSkeleton,
  type DetailAttribute,
} from '@/components/details'
import { StatusBadge } from '@/components/badges'
import { InformationCard } from '@/components/card'
import { CopyableCode } from '@/components/inputs'
import { DataTablePagination, usePaginationTable } from '@/components/data-table'
import { ErrorState } from '@/components/layout/states'
import { useWebhookDeliveries, useWebhooks } from '@/hooks/useWebhooks'
import { useScope } from '@/context/scopeContext'
import { formatDateTime, formatRelative } from '@/lib/formatDate'

const PAGE_SIZE = 25

/**
 * One webhook endpoint and its recent deliveries.
 *
 * A maintainerd-auth detail page: `DetailLayout` → `DetailHeaderCard` →
 * `DetailTabs`, with the delivery list paginated through the shared
 * `usePaginationTable` + `DataTablePagination` pair auth uses for every
 * server-paginated detail tab.
 *
 * A delivery row shows the MRN and the version, because that is all a delivery
 * carries. It has never carried a value: a consumer is TOLD to re-read rather
 * than handed the credential over whatever transport the endpoint happens to use.
 */
export default function WebhookDetailsPage() {
  const { endpointUuid = '' } = useParams()
  const navigate = useNavigate()
  const { project } = useScope()

  const [pagination, setPagination] = useState({ pageIndex: 0, pageSize: PAGE_SIZE })

  // The API has no "get one endpoint" route, so the endpoint is picked out of
  // the project's list — which the shell has usually already cached.
  const webhooks = useWebhooks(project ?? undefined, { limit: 200 })
  const endpoint = useMemo(
    () => webhooks.data?.rows.find((row) => row.endpoint_uuid === endpointUuid),
    [webhooks.data, endpointUuid],
  )

  const deliveries = useWebhookDeliveries(endpointUuid, project ?? undefined, {
    page: pagination.pageIndex + 1,
    limit: pagination.pageSize,
  })

  const total = deliveries.data?.meta.total ?? 0
  const table = usePaginationTable({
    pagination,
    onPaginationChange: setPagination,
    pageCount: Math.ceil(total / pagination.pageSize) || 0,
  })

  const attributes: DetailAttribute[] = endpoint
    ? [
        { icon: Clock, label: 'Timeout', value: `${endpoint.timeout_seconds}s` },
        { icon: Repeat, label: 'Max attempts', value: endpoint.max_attempts },
        {
          icon: Send,
          label: 'Last triggered',
          value: formatRelative(endpoint.last_triggered_at),
        },
      ]
    : []

  return (
    <DetailLayout
      backLabel="Back to webhooks"
      onBack={() => navigate('/webhooks')}
      isLoading={webhooks.isLoading}
      isError={webhooks.isError || (!webhooks.isLoading && !endpoint)}
      notFoundTitle="Endpoint not found"
      notFoundDescription="This endpoint does not exist in the selected project, or you do not hold a grant that can see it."
    >
      {endpoint && (
        <>
          <DetailHeaderCard
            leading={
              <div className="flex size-14 shrink-0 items-center justify-center rounded-lg bg-muted text-muted-foreground">
                <Webhook className="size-6" aria-hidden="true" />
              </div>
            }
            title={<span className="font-mono text-base break-all">{endpoint.url}</span>}
            badge={<StatusBadge status={endpoint.status} />}
            subtitle={
              <div className="flex flex-wrap items-center gap-1">
                {endpoint.events.length === 0 ? (
                  <Badge variant="outline" className="text-xs">
                    all events
                  </Badge>
                ) : (
                  endpoint.events.map((event) => (
                    <Badge key={event} variant="outline" className="text-xs">
                      {event}
                    </Badge>
                  ))
                )}
              </div>
            }
            attributes={attributes}
          />

          <DetailTabs defaultValue="deliveries">
            <TabsList>
              <TabsTrigger value="deliveries">Deliveries</TabsTrigger>
            </TabsList>

            <TabsContent value="deliveries" className="space-y-4">
              <InformationCard
                title="Recent deliveries"
                icon={ListChecks}
                description="Each delivery names the secret's MRN and its new version. A value is never sent."
              >
                {deliveries.isLoading && <ListSkeleton rows={3} />}
                {deliveries.isError && (
                  <ErrorState
                    error={deliveries.error}
                    onRetry={() => void deliveries.refetch()}
                  />
                )}
                {!deliveries.isLoading &&
                  !deliveries.isError &&
                  deliveries.data?.rows.length === 0 && (
                    <EmptyState
                      icon={Send}
                      title="No deliveries yet"
                      description="Nothing in this project has changed or rotated since the endpoint was created."
                    />
                  )}
                {deliveries.data && deliveries.data.rows.length > 0 && (
                  <ul className="space-y-2">
                    {deliveries.data.rows.map((delivery) => (
                      <li key={delivery.delivery_uuid}>
                        <ListingItemCard icon={Send}>
                          <div className="flex flex-wrap items-center gap-2">
                            <p className="text-sm font-medium">{delivery.event_type}</p>
                            <StatusBadge
                              status={delivery.status === 'delivered' ? 'active' : 'blocked'}
                              label={
                                delivery.response_status
                                  ? `${delivery.status} · ${delivery.response_status}`
                                  : delivery.status
                              }
                            />
                          </div>
                          <div className="mt-1.5">
                            <CopyableCode
                              value={
                                delivery.version
                                  ? `${delivery.resource_mrn} · v${delivery.version}`
                                  : delivery.resource_mrn
                              }
                              label="Resource MRN"
                              variant="block"
                            />
                          </div>
                          <ListingItemMeta>
                            <span>{formatDateTime(delivery.created_at)}</span>
                            <span>
                              {delivery.attempt_count}{' '}
                              {delivery.attempt_count === 1 ? 'attempt' : 'attempts'}
                            </span>
                            {delivery.error && (
                              <span className="text-destructive">{delivery.error}</span>
                            )}
                          </ListingItemMeta>
                        </ListingItemCard>
                      </li>
                    ))}
                  </ul>
                )}
              </InformationCard>

              <DataTablePagination table={table} rowCount={total} />
            </TabsContent>
          </DetailTabs>
        </>
      )}
    </DetailLayout>
  )
}
