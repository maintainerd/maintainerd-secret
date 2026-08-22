import { useState } from 'react'
import { Check, Copy, Plus, Trash2 } from 'lucide-react'
import { toast } from 'react-toastify'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { PageHeader } from '@/components/layout/PageHeader'
import { EmptyState, ErrorState, InlineLoading, LoadingRows } from '@/components/layout/states'
import { ConfirmDialog } from '@/components/ConfirmDialog'
import {
  useCreateWebhook,
  useDeleteWebhook,
  useWebhookDeliveries,
  useWebhooks,
} from '@/hooks/useWebhooks'
import { useScope } from '@/context/scopeContext'
import { formatDateTime, formatRelative } from '@/lib/formatDate'
import { WEBHOOK_EVENTS, type WebhookEndpoint } from '@/services/api/types'

/**
 * Webhook endpoints for the selected project, and their recent deliveries.
 *
 * THE SIGNING KEY IS SHOWN ONCE. There is no endpoint that returns it again —
 * an HMAC key that can be fetched is a forgery primitive — so the create dialog
 * holds the key on screen until the operator explicitly dismisses it, and says
 * plainly that closing it loses the key for good.
 */
export default function WebhooksPage() {
  const { project } = useScope()
  const webhooks = useWebhooks(project ?? undefined)
  const createWebhook = useCreateWebhook()
  const deleteWebhook = useDeleteWebhook()

  const [dialogOpen, setDialogOpen] = useState(false)
  const [signingKey, setSigningKey] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)
  const [toDelete, setToDelete] = useState<WebhookEndpoint | null>(null)
  const [expanded, setExpanded] = useState<string | null>(null)

  const [form, setForm] = useState({
    url: '',
    description: '',
    events: [] as string[],
    timeoutSeconds: '',
    maxAttempts: '',
  })

  const deliveries = useWebhookDeliveries(expanded, project ?? undefined)

  const rows = webhooks.data?.rows ?? []

  const copyKey = async () => {
    if (!signingKey) return
    try {
      await navigator.clipboard.writeText(signingKey)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 2000)
    } catch {
      toast.error('Your browser blocked clipboard access.')
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Webhooks"
        description="Deliveries carry the MRN and the new version — never a value. A consumer learns it should re-read."
        actions={
          <Button size="sm" disabled={!project} onClick={() => setDialogOpen(true)}>
            <Plus className="size-4" aria-hidden="true" />
            New endpoint
          </Button>
        }
      />

      {!project ? <EmptyState title="Select a project" /> : null}

      {project ? (
        <>
          {webhooks.isLoading ? <LoadingRows /> : null}
          {webhooks.isError ? (
            <ErrorState error={webhooks.error} onRetry={() => void webhooks.refetch()} />
          ) : null}
          {!webhooks.isLoading && !webhooks.isError && rows.length === 0 ? (
            <EmptyState
              title="No endpoints"
              description="Add one to be told when a secret in this project changes or rotates."
            />
          ) : null}

          {rows.length > 0 ? (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>URL</TableHead>
                    <TableHead>Events</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Last triggered</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rows.map((endpoint) => (
                    <TableRow key={endpoint.endpoint_uuid}>
                      <TableCell className="max-w-72">
                        <div className="truncate font-mono text-sm">{endpoint.url}</div>
                        {endpoint.description ? (
                          <div className="truncate text-xs text-muted-foreground">
                            {endpoint.description}
                          </div>
                        ) : null}
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-wrap gap-1">
                          {endpoint.events.length === 0 ? (
                            <Badge variant="outline">all</Badge>
                          ) : (
                            endpoint.events.map((event) => (
                              <Badge key={event} variant="outline">
                                {event}
                              </Badge>
                            ))
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge variant={endpoint.status === 'active' ? 'secondary' : 'outline'}>
                          {endpoint.status}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {formatRelative(endpoint.last_triggered_at)}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex justify-end gap-1">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() =>
                              setExpanded((current) =>
                                current === endpoint.endpoint_uuid ? null : endpoint.endpoint_uuid,
                              )
                            }
                          >
                            {expanded === endpoint.endpoint_uuid ? 'Hide' : 'Deliveries'}
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon-sm"
                            aria-label="Delete this endpoint"
                            onClick={() => setToDelete(endpoint)}
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

          {expanded ? (
            <section className="space-y-3 border-t pt-6">
              <h2 className="text-lg font-semibold">Recent deliveries</h2>
              {deliveries.isLoading ? <InlineLoading /> : null}
              {deliveries.isError ? (
                <ErrorState error={deliveries.error} onRetry={() => void deliveries.refetch()} />
              ) : null}
              {deliveries.data && deliveries.data.rows.length === 0 ? (
                <EmptyState title="No deliveries yet" />
              ) : null}
              {deliveries.data && deliveries.data.rows.length > 0 ? (
                <div className="overflow-x-auto">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>When</TableHead>
                        <TableHead>Event</TableHead>
                        <TableHead>Resource</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead>Attempts</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {deliveries.data.rows.map((delivery) => (
                        <TableRow key={delivery.delivery_uuid}>
                          <TableCell className="text-sm">
                            {formatDateTime(delivery.created_at)}
                          </TableCell>
                          <TableCell>{delivery.event_type}</TableCell>
                          <TableCell className="max-w-72 truncate font-mono text-xs">
                            {delivery.resource_mrn}
                          </TableCell>
                          <TableCell>
                            <Badge
                              variant={delivery.status === 'delivered' ? 'secondary' : 'destructive'}
                            >
                              {delivery.status}
                              {delivery.response_status ? ` · ${delivery.response_status}` : ''}
                            </Badge>
                          </TableCell>
                          <TableCell>{delivery.attempt_count}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              ) : null}
            </section>
          ) : null}
        </>
      ) : null}

      <Dialog
        open={dialogOpen}
        onOpenChange={(open) => {
          setDialogOpen(open)
          if (!open) setSigningKey(null)
        }}
      >
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>{signingKey ? 'Copy the signing key' : 'New webhook endpoint'}</DialogTitle>
            <DialogDescription>
              {signingKey
                ? 'This is the only time it will ever be shown.'
                : 'Deliveries are signed with an HMAC key generated now.'}
            </DialogDescription>
          </DialogHeader>

          {signingKey ? (
            <div className="space-y-3">
              <Alert>
                <AlertTitle>Copy this now</AlertTitle>
                <AlertDescription>
                  There is no endpoint that returns a signing key. Closing this dialog without
                  copying it means deleting the endpoint and creating a new one.
                </AlertDescription>
              </Alert>
              <pre className="overflow-auto rounded-md border bg-muted/40 p-3 text-xs break-all">
                {signingKey}
              </pre>
              <Button variant="outline" size="sm" onClick={() => void copyKey()}>
                {copied ? (
                  <Check className="size-4" aria-hidden="true" />
                ) : (
                  <Copy className="size-4" aria-hidden="true" />
                )}
                {copied ? 'Copied' : 'Copy signing key'}
              </Button>
            </div>
          ) : (
            <div className="space-y-4">
              <div className="space-y-1.5">
                <Label htmlFor="webhook-url">URL</Label>
                <Input
                  id="webhook-url"
                  type="url"
                  value={form.url}
                  autoComplete="off"
                  onChange={(event) =>
                    setForm((current) => ({ ...current, url: event.target.value }))
                  }
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="webhook-description">Description</Label>
                <Input
                  id="webhook-description"
                  value={form.description}
                  onChange={(event) =>
                    setForm((current) => ({ ...current, description: event.target.value }))
                  }
                />
              </div>
              <fieldset className="space-y-2">
                <legend className="text-sm font-medium">Events</legend>
                {WEBHOOK_EVENTS.map((event) => (
                  <div key={event} className="flex items-center gap-2">
                    <Checkbox
                      id={`event-${event}`}
                      checked={form.events.includes(event)}
                      onCheckedChange={(checked) =>
                        setForm((current) => ({
                          ...current,
                          events: checked
                            ? [...current.events, event]
                            : current.events.filter((candidate) => candidate !== event),
                        }))
                      }
                    />
                    <Label htmlFor={`event-${event}`} className="font-normal">
                      {event}
                    </Label>
                  </div>
                ))}
                <p className="text-xs text-muted-foreground">
                  Selecting none subscribes the endpoint to every event.
                </p>
              </fieldset>
              <div className="grid gap-4 sm:grid-cols-2">
                <div className="space-y-1.5">
                  <Label htmlFor="webhook-timeout">Timeout (seconds)</Label>
                  <Input
                    id="webhook-timeout"
                    type="number"
                    min={1}
                    value={form.timeoutSeconds}
                    onChange={(event) =>
                      setForm((current) => ({ ...current, timeoutSeconds: event.target.value }))
                    }
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="webhook-attempts">Max attempts</Label>
                  <Input
                    id="webhook-attempts"
                    type="number"
                    min={1}
                    value={form.maxAttempts}
                    onChange={(event) =>
                      setForm((current) => ({ ...current, maxAttempts: event.target.value }))
                    }
                  />
                </div>
              </div>
            </div>
          )}

          <DialogFooter>
            {signingKey ? (
              <Button
                onClick={() => {
                  setSigningKey(null)
                  setDialogOpen(false)
                }}
              >
                I have copied it
              </Button>
            ) : (
              <>
                <Button variant="outline" onClick={() => setDialogOpen(false)}>
                  Cancel
                </Button>
                <Button
                  disabled={!project || !form.url.trim() || createWebhook.isPending}
                  onClick={async () => {
                    if (!project) return
                    const created = await createWebhook.mutateAsync({
                      project,
                      url: form.url.trim(),
                      description: form.description.trim(),
                      events: form.events,
                      ...(form.timeoutSeconds
                        ? { timeout_seconds: Number(form.timeoutSeconds) }
                        : {}),
                      ...(form.maxAttempts ? { max_attempts: Number(form.maxAttempts) } : {}),
                    })
                    setForm({
                      url: '',
                      description: '',
                      events: [],
                      timeoutSeconds: '',
                      maxAttempts: '',
                    })
                    setSigningKey(created.signing_key)
                  }}
                >
                  {createWebhook.isPending ? 'Creating…' : 'Create'}
                </Button>
              </>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        open={toDelete !== null}
        onOpenChange={(open) => {
          if (!open) setToDelete(null)
        }}
        title="Delete this endpoint?"
        confirmLabel="Delete"
        destructive
        pending={deleteWebhook.isPending}
        onConfirm={async () => {
          if (!toDelete || !project) return
          await deleteWebhook.mutateAsync({ endpointUuid: toDelete.endpoint_uuid, project })
          setToDelete(null)
        }}
        description={
          <p>
            Consumers stop being told when a secret in this project changes or rotates. They will
            keep using a stale value until they re-read on their own.
          </p>
        }
      />
    </div>
  )
}
