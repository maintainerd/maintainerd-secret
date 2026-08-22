import { useEffect, useState } from 'react'
import { FolderPlus, MoveRight } from 'lucide-react'
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
import { FormInputField, FormSubmitButton } from '@/components/form'
import { useCreateFolder, useMoveFolder } from '@/hooks/useFolders'
import { joinPath, normalizePath } from '@/lib/paths'
import { sanitizePathSegment } from '@/lib/validations/regex'

/**
 * Folder create + move.
 *
 * Both are composed from maintainerd-auth's field components
 * (`FormInputField` + `FormSubmitButton`) inside the shared `Dialog` primitive,
 * so label spacing, error colour and aria wiring match every other form in the
 * suite instead of being hand-rolled per dialog.
 */

/** Creates a folder beneath the folder currently being browsed. */
export function CreateFolderDialog({
  project,
  environment,
  parentPath,
  open,
  onOpenChange,
  onCreated,
}: {
  project: string
  environment: string
  parentPath: string
  open: boolean
  onOpenChange: (open: boolean) => void
  onCreated?: (path: string) => void
}) {
  const [name, setName] = useState('')
  const createFolder = useCreateFolder()
  const parent = normalizePath(parentPath)

  useEffect(() => {
    if (!open) setName('')
  }, [open])

  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    const path = joinPath(parent, name)
    await createFolder.mutateAsync({ project, environment, path })
    onCreated?.(path)
    onOpenChange(false)
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <div className="flex items-center gap-3">
            <div className="flex size-9 shrink-0 items-center justify-center rounded-md bg-muted text-muted-foreground">
              <FolderPlus className="size-5" aria-hidden="true" />
            </div>
            <DialogTitle>New folder</DialogTitle>
          </div>
          <DialogDescription className="pt-1 text-left">
            Created inside <span className="font-mono">{parent}</span>.
          </DialogDescription>
        </DialogHeader>

        <form id="create-folder-form" onSubmit={submit} noValidate>
          <FormInputField
            id="folder-name"
            label="Name"
            required
            value={name}
            autoComplete="off"
            spellCheck={false}
            // A slash would silently create a nested path the operator did not
            // ask for, so it is stripped as they type rather than at submit.
            onChange={(event) => setName(sanitizePathSegment(event.target.value))}
            description="One segment. Nest by creating folders one level at a time."
          />
        </form>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <FormSubmitButton
            form="create-folder-form"
            isSubmitting={createFolder.isPending}
            disabled={!name.trim()}
            submitText="Create"
          />
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/**
 * Moves a folder, and with it every secret beneath it.
 *
 * The warning is not decoration: a folder path is part of a secret's MRN, so
 * moving one CHANGES THE ADDRESS every grant and every consumer refers to. A
 * grant written against the old path stops matching. It is rendered as a
 * destructive `Alert` rather than helper text for exactly that reason.
 */
export function MoveFolderDialog({
  project,
  environment,
  path,
  open,
  onOpenChange,
  onMoved,
}: {
  project: string
  environment: string
  path: string
  open: boolean
  onOpenChange: (open: boolean) => void
  onMoved?: (path: string) => void
}) {
  const [target, setTarget] = useState(path)
  const moveFolder = useMoveFolder()
  const from = normalizePath(path)
  const unchanged = normalizePath(target) === from

  useEffect(() => {
    if (open) setTarget(from)
  }, [open, from])

  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    const to = normalizePath(target)
    await moveFolder.mutateAsync({ project, environment, from, to })
    onMoved?.(to)
    onOpenChange(false)
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <div className="flex items-center gap-3">
            <div className="flex size-9 shrink-0 items-center justify-center rounded-md bg-muted text-muted-foreground">
              <MoveRight className="size-5" aria-hidden="true" />
            </div>
            <DialogTitle>Move {from}</DialogTitle>
          </div>
          <DialogDescription className="pt-1 text-left">
            The subtree moves with it, and every secret underneath gets a new address.
          </DialogDescription>
        </DialogHeader>

        <Alert variant="destructive">
          <AlertTitle>Addresses change</AlertTitle>
          <AlertDescription>
            A folder path is part of every MRN beneath it. Grants and consumers written against the
            old path will no longer match.
          </AlertDescription>
        </Alert>

        <form id="move-folder-form" onSubmit={submit} noValidate>
          <FormInputField
            id="folder-target"
            label="New path"
            required
            value={target}
            autoComplete="off"
            spellCheck={false}
            className="font-mono"
            onChange={(event) => setTarget(event.target.value)}
            description="An absolute path, e.g. /db/primary."
          />
        </form>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <FormSubmitButton
            form="move-folder-form"
            isSubmitting={moveFolder.isPending}
            disabled={unchanged}
            submitText="Move"
            submittingText="Moving…"
          />
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
