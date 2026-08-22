import { useEffect, useState } from 'react'
import { Button } from '@/components/ui/button'
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
import { useCreateFolder, useMoveFolder } from '@/hooks/useFolders'
import { joinPath, normalizePath } from '@/lib/paths'

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

  useEffect(() => {
    if (!open) setName('')
  }, [open])

  const submit = async () => {
    const path = joinPath(parentPath, name)
    await createFolder.mutateAsync({ project, environment, path })
    onCreated?.(path)
    onOpenChange(false)
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>New folder</DialogTitle>
          <DialogDescription>
            Created inside {normalizePath(parentPath)}.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-1.5">
          <Label htmlFor="folder-name">Name</Label>
          <Input
            id="folder-name"
            value={name}
            autoComplete="off"
            spellCheck={false}
            onChange={(event) => setName(event.target.value)}
          />
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={() => void submit()} disabled={!name.trim() || createFolder.isPending}>
            {createFolder.isPending ? 'Creating…' : 'Create'}
          </Button>
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
 * grant written against the old path stops matching.
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

  useEffect(() => {
    if (open) setTarget(normalizePath(path))
  }, [open, path])

  const submit = async () => {
    const to = normalizePath(target)
    await moveFolder.mutateAsync({ project, environment, from: normalizePath(path), to })
    onMoved?.(to)
    onOpenChange(false)
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Move {normalizePath(path)}</DialogTitle>
          <DialogDescription>
            The subtree moves with it, and every secret underneath gets a new address.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-1.5">
          <Label htmlFor="folder-target">New path</Label>
          <Input
            id="folder-target"
            value={target}
            autoComplete="off"
            spellCheck={false}
            onChange={(event) => setTarget(event.target.value)}
          />
          <p className="text-xs text-muted-foreground">
            A folder path is part of every MRN beneath it, so grants and consumers written against
            the old path will no longer match.
          </p>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            onClick={() => void submit()}
            disabled={moveFolder.isPending || normalizePath(target) === normalizePath(path)}
          >
            {moveFolder.isPending ? 'Moving…' : 'Move'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
