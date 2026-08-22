import { useEffect, useState } from 'react'
import { Server } from 'lucide-react'
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
import { FormInputField, FormSubmitButton, FormTextareaField } from '@/components/form'
import { FormSlugField } from '@/components/inputs'
import { useCreateEnvironment } from '@/hooks/useEnvironments'
import { sanitizeName } from '@/lib/validations/regex'

/** Create an environment inside a project. The slug is permanent, like a project's. */
export function EnvironmentFormDialog({
  project,
  open,
  onOpenChange,
}: {
  project: string
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const createEnvironment = useCreateEnvironment()
  const [form, setForm] = useState({ slug: '', name: '', description: '', position: '0' })

  useEffect(() => {
    if (!open) setForm({ slug: '', name: '', description: '', position: '0' })
  }, [open])

  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    await createEnvironment.mutateAsync({
      project,
      slug: form.slug.trim(),
      name: form.name.trim(),
      description: form.description.trim(),
      position: Number(form.position) || 0,
    })
    onOpenChange(false)
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <div className="flex items-center gap-3">
            <div className="flex size-9 shrink-0 items-center justify-center rounded-md bg-muted text-muted-foreground">
              <Server className="size-5" aria-hidden="true" />
            </div>
            <DialogTitle>New environment</DialogTitle>
          </div>
          <DialogDescription className="pt-1 text-left">
            In <span className="font-mono">{project}</span>.
          </DialogDescription>
        </DialogHeader>

        <Alert>
          <AlertTitle>The slug is permanent</AlertTitle>
          <AlertDescription>
            It is quoted in every MRN, grant and consumer configuration underneath it.
          </AlertDescription>
        </Alert>

        <form id="environment-form" onSubmit={submit} className="space-y-5" noValidate>
          <FormSlugField
            id="environment-slug"
            label="Slug"
            required
            sanitize={sanitizeName}
            value={form.slug}
            onChange={(event) => setForm((current) => ({ ...current, slug: event.target.value }))}
            placeholder="production"
          />
          <FormInputField
            id="environment-name"
            label="Name"
            value={form.name}
            onChange={(event) => setForm((current) => ({ ...current, name: event.target.value }))}
          />
          <FormTextareaField
            id="environment-description"
            label="Description"
            rows={2}
            value={form.description}
            onChange={(event) =>
              setForm((current) => ({ ...current, description: event.target.value }))
            }
          />
          <FormInputField
            id="environment-position"
            label="Position"
            type="number"
            value={form.position}
            onChange={(event) =>
              setForm((current) => ({ ...current, position: event.target.value }))
            }
            description="Environments are listed in this order — lowest first."
          />
        </form>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <FormSubmitButton
            form="environment-form"
            isSubmitting={createEnvironment.isPending}
            disabled={!form.slug.trim()}
            submitText="Create"
          />
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
