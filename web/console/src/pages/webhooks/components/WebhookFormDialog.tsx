import { useEffect, useState } from 'react'
import { KeyRound, Webhook } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { FieldShell, FormInputField, FormSubmitButton } from '@/components/form'
import { CopyableCode, FormCheckboxSubContainer, FormUrlField } from '@/components/inputs'
import { useCreateWebhook } from '@/hooks/useWebhooks'
import { isHttpsUrl } from '@/lib/validations/regex'
import { WEBHOOK_EVENTS } from '@/services/api/types'

/**
 * Create a webhook endpoint, then show its signing key exactly once.
 *
 * THE SIGNING KEY IS SHOWN ONCE. There is no endpoint that returns it again —
 * an HMAC key that can be fetched is a forgery primitive — so the dialog swaps
 * to a key panel on success and holds it there until the operator explicitly
 * acknowledges, saying plainly that closing loses the key for good.
 *
 * The key panel uses auth's `CopyableCode`, which is exactly right here and
 * wrong for a revealed secret: a signing key is a value the operator MUST copy
 * to be able to use the endpoint at all, whereas a revealed credential must stay
 * masked until asked for.
 */

const EVENT_OPTIONS = WEBHOOK_EVENTS.map((event) => ({
  value: event,
  title: event,
  description:
    event === 'secret.changed'
      ? 'A new version was written for a secret in this project.'
      : 'A secret in this project was rotated.',
}))

export function WebhookFormDialog({
  project,
  open,
  onOpenChange,
}: {
  project: string
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const createWebhook = useCreateWebhook()
  const [signingKey, setSigningKey] = useState<string | null>(null)
  const [form, setForm] = useState({
    url: '',
    description: '',
    events: [] as string[],
    timeoutSeconds: '',
    maxAttempts: '',
  })

  useEffect(() => {
    if (open) return
    setSigningKey(null)
    setForm({ url: '', description: '', events: [], timeoutSeconds: '', maxAttempts: '' })
  }, [open])

  const urlError =
    form.url.trim() !== '' && !isHttpsUrl(form.url)
      ? 'Use https (http is allowed only on localhost). A delivery names the secrets this vault holds.'
      : undefined

  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    const created = await createWebhook.mutateAsync({
      project,
      url: form.url.trim(),
      description: form.description.trim(),
      events: form.events,
      ...(form.timeoutSeconds ? { timeout_seconds: Number(form.timeoutSeconds) } : {}),
      ...(form.maxAttempts ? { max_attempts: Number(form.maxAttempts) } : {}),
    })
    setSigningKey(created.signing_key)
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-lg">
        <DialogHeader>
          <div className="flex items-center gap-3">
            <div
              className={
                signingKey
                  ? 'flex size-9 shrink-0 items-center justify-center rounded-full bg-destructive/10 text-destructive'
                  : 'flex size-9 shrink-0 items-center justify-center rounded-md bg-muted text-muted-foreground'
              }
            >
              {signingKey ? (
                <KeyRound className="size-5" aria-hidden="true" />
              ) : (
                <Webhook className="size-5" aria-hidden="true" />
              )}
            </div>
            <DialogTitle>{signingKey ? 'Copy the signing key' : 'New webhook endpoint'}</DialogTitle>
          </div>
          <DialogDescription className="pt-1 text-left">
            {signingKey
              ? 'This is the only time it will ever be shown.'
              : 'Deliveries are signed with an HMAC key generated now. They carry the MRN and the new version — never a value.'}
          </DialogDescription>
        </DialogHeader>

        {signingKey ? (
          <div className="space-y-4">
            <Alert variant="destructive">
              <AlertTitle>Copy this now</AlertTitle>
              <AlertDescription>
                There is no endpoint that returns a signing key. Closing this dialog without copying
                it means deleting the endpoint and creating a new one.
              </AlertDescription>
            </Alert>
            <CopyableCode value={signingKey} label="Signing key" variant="block" />
          </div>
        ) : (
          <form id="webhook-form" onSubmit={submit} className="space-y-5" noValidate>
            <fieldset className="space-y-5" disabled={createWebhook.isPending}>
              <FormUrlField
                id="webhook-url"
                label="URL"
                required
                value={form.url}
                error={urlError}
                onChange={(event) =>
                  setForm((current) => ({ ...current, url: event.target.value }))
                }
              />
              <FormInputField
                id="webhook-description"
                label="Description"
                value={form.description}
                onChange={(event) =>
                  setForm((current) => ({ ...current, description: event.target.value }))
                }
              />
              <FieldShell
                fieldId="webhook-events"
                label="Events"
                description="Selecting none subscribes the endpoint to every event."
              >
                <FormCheckboxSubContainer
                  options={EVENT_OPTIONS}
                  selected={form.events}
                  onToggle={(value) =>
                    setForm((current) => ({
                      ...current,
                      events: current.events.includes(value)
                        ? current.events.filter((candidate) => candidate !== value)
                        : [...current.events, value],
                    }))
                  }
                />
              </FieldShell>
              <div className="grid gap-5 sm:grid-cols-2">
                <FormInputField
                  id="webhook-timeout"
                  label="Timeout (seconds)"
                  type="number"
                  min={1}
                  value={form.timeoutSeconds}
                  onChange={(event) =>
                    setForm((current) => ({ ...current, timeoutSeconds: event.target.value }))
                  }
                />
                <FormInputField
                  id="webhook-attempts"
                  label="Max attempts"
                  type="number"
                  min={1}
                  value={form.maxAttempts}
                  onChange={(event) =>
                    setForm((current) => ({ ...current, maxAttempts: event.target.value }))
                  }
                />
              </div>
            </fieldset>
          </form>
        )}

        <DialogFooter>
          {signingKey ? (
            <Button onClick={() => onOpenChange(false)}>I have copied it</Button>
          ) : (
            <>
              <Button variant="outline" onClick={() => onOpenChange(false)}>
                Cancel
              </Button>
              <FormSubmitButton
                form="webhook-form"
                isSubmitting={createWebhook.isPending}
                disabled={!form.url.trim() || Boolean(urlError)}
                submitText="Create"
              />
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
