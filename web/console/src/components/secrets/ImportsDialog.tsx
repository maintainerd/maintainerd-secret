import { useState } from 'react'
import { Trash2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { EmptyState, ErrorState, InlineLoading } from '@/components/layout/states'
import { useCreateImport, useDeleteImport, useImports, useSetImportEnabled } from '@/hooks/useImports'
import { normalizePath } from '@/lib/paths'

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

  const add = async () => {
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
      <DialogContent className="sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>Imports for {path}</DialogTitle>
          <DialogDescription>
            Secrets from an imported scope resolve here as if they were local. Resolution order
            follows the position of each edge.
          </DialogDescription>
        </DialogHeader>

        {importsQuery.isLoading ? <InlineLoading /> : null}
        {importsQuery.isError ? (
          <ErrorState error={importsQuery.error} onRetry={() => void importsQuery.refetch()} />
        ) : null}

        {!importsQuery.isLoading && !importsQuery.isError && rows.length === 0 ? (
          <EmptyState
            title="No imports"
            description="This folder resolves only its own secrets."
          />
        ) : null}

        {rows.length > 0 ? (
          <ul className="space-y-2">
            {rows.map((edge) => (
              <li
                key={edge.import_uuid}
                className="flex flex-wrap items-center justify-between gap-3 rounded-md border p-3"
              >
                <div className="min-w-0">
                  <p className="truncate font-mono text-sm">
                    {edge.source_project}/{edge.source_environment}
                    {edge.source_folder_path}
                  </p>
                  <p className="text-xs text-muted-foreground">position {edge.position}</p>
                </div>
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
              </li>
            ))}
          </ul>
        ) : null}

        <div className="space-y-3 border-t pt-4">
          <h3 className="text-sm font-medium">Add an import</h3>
          <div className="grid gap-3 sm:grid-cols-3">
            <div className="space-y-1.5">
              <Label htmlFor="import-source-project">Source project</Label>
              <Input
                id="import-source-project"
                value={sourceProject}
                autoComplete="off"
                onChange={(event) => setSourceProject(event.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="import-source-environment">Source environment</Label>
              <Input
                id="import-source-environment"
                value={sourceEnvironment}
                autoComplete="off"
                onChange={(event) => setSourceEnvironment(event.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="import-source-folder">Source folder</Label>
              <Input
                id="import-source-folder"
                value={sourceFolder}
                autoComplete="off"
                onChange={(event) => setSourceFolder(event.target.value)}
              />
            </div>
          </div>
          <p className="text-xs text-muted-foreground">
            The source must live in this tenant. An edge that would create a cycle is refused.
          </p>
          <Button
            size="sm"
            onClick={() => void add()}
            disabled={createImport.isPending || !sourceProject.trim() || !sourceEnvironment.trim()}
          >
            {createImport.isPending ? 'Adding…' : 'Add import'}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  )
}
