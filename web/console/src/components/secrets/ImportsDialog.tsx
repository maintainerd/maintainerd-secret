import { useState } from 'react'
import { MoveRight, Trash2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Switch } from '@/components/ui/switch'
import { Label } from '@/components/ui/label'
import { Separator } from '@/components/ui/separator'
import {
  EmptyState,
  ListingItemCard,
  ListingItemMeta,
  ListSkeleton,
} from '@/components/details'
import { FormInputField, FormSubmitButton } from '@/components/form'
import { ErrorState } from '@/components/layout/states'
import { useCreateImport, useDeleteImport, useImports, useSetImportEnabled } from '@/hooks/useImports'
import { normalizePath } from '@/lib/paths'
import { sanitizeName } from '@/lib/validations/regex'

/**
 * Scope imports for one folder.
 *
 * An import makes another scope's secrets resolve here. It is a property of the
 * IMPORTING folder, so it is edited from the folder being browsed rather than
 * from some global settings page.
 *
 * Two limits are the service's and are stated in the UI because they are
 * surprising otherwise: an import may not cross a TENANT boundary (that would be
 * a supported cross-tenant read path), and an edge that would create a cycle is
 * refused at insert time inside the same transaction.
 *
 * Each edge renders as maintainerd-auth's `ListingItemCard`, the same row shape
 * its detail tabs use for linked clients and assigned roles.
 */
export function ImportsDialog({
  project,
  environment,
  folderPath,
  open,
  onOpenChange,
}: {
  project: string
  environment: string
  folderPath: string
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const path = normalizePath(folderPath)
  const importsQuery = useImports(open ? project : undefined, open ? environment : undefined, path)
  const createImport = useCreateImport()
  const setEnabled = useSetImportEnabled()
  const removeImport = useDeleteImport()

  const [sourceProject, setSourceProject] = useState('')
  const [sourceEnvironment, setSourceEnvironment] = useState('')
  const [sourceFolder, setSourceFolder] = useState('/')

  const add = async (event: React.FormEvent) => {
    event.preventDefault()
    await createImport.mutateAsync({
      project,
      environment,
      folder_path: path,
      source_project: sourceProject.trim(),
      source_environment: sourceEnvironment.trim(),
      source_folder_path: normalizePath(sourceFolder),
    })
    setSourceProject('')
    setSourceEnvironment('')
    setSourceFolder('/')
  }

  const rows = importsQuery.data ?? []

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-xl">
        <DialogHeader>
          <div className="flex items-center gap-3">
            <div className="flex size-9 shrink-0 items-center justify-center rounded-md bg-muted text-muted-foreground">
              <MoveRight className="size-5" aria-hidden="true" />
            </div>
            <DialogTitle>Imports for {path}</DialogTitle>
          </div>
          <DialogDescription className="pt-1 text-left">
            Secrets from an imported scope resolve here as if they were local. Resolution order
            follows the position of each edge.
          </DialogDescription>
        </DialogHeader>

        {importsQuery.isLoading && <ListSkeleton rows={2} />}
        {importsQuery.isError && (
          <ErrorState error={importsQuery.error} onRetry={() => void importsQuery.refetch()} />
        )}

        {!importsQuery.isLoading && !importsQuery.isError && rows.length === 0 && (
          <EmptyState
            icon={MoveRight}
            title="No imports"
            description="This folder resolves only its own secrets."
          />
        )}

        {rows.length > 0 && (
          <ul className="space-y-2">
            {rows.map((edge) => (
              <li key={edge.import_uuid}>
                <ListingItemCard
                  icon={MoveRight}
                  action={
                    <div className="flex items-center gap-3">
                      <div className="flex items-center gap-2">
                        <Switch
                          id={`import-${edge.import_uuid}`}
                          checked={edge.enabled}
                          onCheckedChange={(next) =>
                            setEnabled.mutate({
                              importUuid: edge.import_uuid,
                              enabled: next,
                              position: edge.position,
                            })
                          }
                          aria-label={edge.enabled ? 'Disable this import' : 'Enable this import'}
                        />
                        <Label htmlFor={`import-${edge.import_uuid}`} className="text-xs">
                          {edge.enabled ? 'Enabled' : 'Disabled'}
                        </Label>
                      </div>
                      <Button
                        variant="ghost"
                        size="icon-sm"
                        aria-label="Remove this import"
                        onClick={() => removeImport.mutate(edge.import_uuid)}
                      >
                        <Trash2 className="size-4" aria-hidden="true" />
                      </Button>
                    </div>
                  }
                >
                  <p className="truncate font-mono text-sm font-medium">
                    {edge.source_project}/{edge.source_environment}
                    {edge.source_folder_path}
                  </p>
                  <ListingItemMeta>
                    <span>position {edge.position}</span>
                  </ListingItemMeta>
                </ListingItemCard>
              </li>
            ))}
          </ul>
        )}

        <Separator />

        <form onSubmit={add} className="space-y-4" noValidate>
          <h3 className="text-sm font-semibold">Add an import</h3>
          <div className="grid gap-5 sm:grid-cols-3">
            <FormInputField
              id="import-source-project"
              label="Source project"
              required
              value={sourceProject}
              autoComplete="off"
              onChange={(event) => setSourceProject(sanitizeName(event.target.value))}
            />
            <FormInputField
              id="import-source-environment"
              label="Source environment"
              required
              value={sourceEnvironment}
              autoComplete="off"
              onChange={(event) => setSourceEnvironment(sanitizeName(event.target.value))}
            />
            <FormInputField
              id="import-source-folder"
              label="Source folder"
              value={sourceFolder}
              autoComplete="off"
              className="font-mono"
              onChange={(event) => setSourceFolder(event.target.value)}
            />
          </div>
          <p className="text-xs text-muted-foreground">
            The source must live in this tenant. An edge that would create a cycle is refused.
          </p>
          <FormSubmitButton
            isSubmitting={createImport.isPending}
            disabled={!sourceProject.trim() || !sourceEnvironment.trim()}
            submitText="Add import"
            submittingText="Adding…"
          />
        </form>
      </DialogContent>
    </Dialog>
  )
}
