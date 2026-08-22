import { useEffect, useState } from 'react'
import { Layers } from 'lucide-react'
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
import { useCreateProject } from '@/hooks/useProjects'
import { sanitizeName } from '@/lib/validations/regex'

/**
 * Create a project.
 *
 * THE SLUG IS PERMANENT and the dialog says so where the operator would go
 * looking for a rename. A project slug is an MRN segment, so renaming it would
 * silently repoint every grant written against the old name; the service
 * reserves it forever and this console does not pretend otherwise.
 *
 * `FormSlugField` is auth's, with `sanitizeName` rather than the default
 * `sanitizeSlug`: a colon is the MRN's own separator, so one inside a segment
 * makes the address ambiguous.
 */
export function ProjectFormDialog({
  open,
  onOpenChange,
  onCreated,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  onCreated?: (slug: string) => void
}) {
  const createProject = useCreateProject()
  const [form, setForm] = useState({ slug: '', name: '', description: '' })

  useEffect(() => {
    if (!open) setForm({ slug: '', name: '', description: '' })
  }, [open])

  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    const project = await createProject.mutateAsync({
      slug: form.slug.trim(),
      name: form.name.trim(),
      description: form.description.trim(),
    })
    onCreated?.(project.slug)
    onOpenChange(false)
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <div className="flex items-center gap-3">
            <div className="flex size-9 shrink-0 items-center justify-center rounded-md bg-muted text-muted-foreground">
              <Layers className="size-5" aria-hidden="true" />
            </div>
            <DialogTitle>New project</DialogTitle>
          </div>
          <DialogDescription className="pt-1 text-left">
            A project groups a tenant’s secrets.
          </DialogDescription>
        </DialogHeader>

        <Alert>
          <AlertTitle>The slug is permanent</AlertTitle>
          <AlertDescription>
            It is an MRN segment, so it cannot be renamed later without breaking every grant
            written against it.
          </AlertDescription>
        </Alert>

        <form id="project-form" onSubmit={submit} className="space-y-5" noValidate>
          <FormSlugField
            id="project-slug"
            label="Slug"
            required
            sanitize={sanitizeName}
            value={form.slug}
            onChange={(event) =>
              setForm((current) => ({ ...current, slug: event.target.value }))
            }
            placeholder="payments"
          />
          <FormInputField
            id="project-name"
            label="Name"
            value={form.name}
            onChange={(event) => setForm((current) => ({ ...current, name: event.target.value }))}
            description="A human-readable label. Unlike the slug, this can change."
          />
          <FormTextareaField
            id="project-description"
            label="Description"
            rows={2}
            value={form.description}
            onChange={(event) =>
              setForm((current) => ({ ...current, description: event.target.value }))
            }
          />
        </form>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <FormSubmitButton
            form="project-form"
            isSubmitting={createProject.isPending}
            disabled={!form.slug.trim()}
            submitText="Create"
          />
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
