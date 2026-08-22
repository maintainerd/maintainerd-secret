import { useEffect, useState } from 'react'
import { Plus } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
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
import { Textarea } from '@/components/ui/textarea'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { PageHeader } from '@/components/layout/PageHeader'
import { EmptyState, ErrorState, LoadingRows } from '@/components/layout/states'
import { ConfirmDialog } from '@/components/ConfirmDialog'
import { useCreateProject, useDeleteProject, useProjects } from '@/hooks/useProjects'
import { useCreateEnvironment, useDeleteEnvironment, useEnvironments } from '@/hooks/useEnvironments'
import { useScope } from '@/context/scopeContext'
import { formatDateTime } from '@/lib/formatDate'
import type { Environment, Project } from '@/services/api/types'

/**
 * Projects and their environments.
 *
 * NEITHER SLUG CAN BE RENAMED, and the page says so where the operator would go
 * looking for it. A project or environment slug is quoted in every MRN beneath
 * it, so a rename would silently repoint every grant written against the old
 * name — the service reserves both forever and this console does not pretend
 * otherwise.
 */
export default function ProjectsPage() {
  const { project: activeProject, setProject } = useScope()
  const projects = useProjects({ page: 1, limit: 200 })
  const [selected, setSelected] = useState<string | null>(activeProject)

  const environments = useEnvironments(selected ?? undefined)
  const createProject = useCreateProject()
  const deleteProject = useDeleteProject()
  const createEnvironment = useCreateEnvironment()
  const deleteEnvironment = useDeleteEnvironment(selected ?? '')

  const [projectDialogOpen, setProjectDialogOpen] = useState(false)
  const [environmentDialogOpen, setEnvironmentDialogOpen] = useState(false)
  const [projectToDelete, setProjectToDelete] = useState<Project | null>(null)
  const [environmentToDelete, setEnvironmentToDelete] = useState<Environment | null>(null)

  const [newProject, setNewProject] = useState({ slug: '', name: '', description: '' })
  const [newEnvironment, setNewEnvironment] = useState({
    slug: '',
    name: '',
    description: '',
    position: '0',
  })

  useEffect(() => {
    if (!selected && projects.data?.rows.length) setSelected(projects.data.rows[0].slug)
  }, [projects.data, selected])

  const rows = projects.data?.rows ?? []

  return (
    <div className="space-y-6">
      <PageHeader
        title="Projects"
        description="A project groups a tenant's secrets; an environment is a deployment stage inside it."
        actions={
          <Button size="sm" onClick={() => setProjectDialogOpen(true)}>
            <Plus className="size-4" aria-hidden="true" />
            New project
          </Button>
        }
      />

      {projects.isLoading ? <LoadingRows /> : null}
      {projects.isError ? (
        <ErrorState error={projects.error} onRetry={() => void projects.refetch()} />
      ) : null}
      {!projects.isLoading && !projects.isError && rows.length === 0 ? (
        <EmptyState title="No projects" description="Create one to start storing secrets." />
      ) : null}

      {rows.length > 0 ? (
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Slug</TableHead>
                <TableHead>Name</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Created</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((row) => (
                <TableRow key={row.project_uuid} data-state={row.slug === selected ? 'selected' : undefined}>
                  <TableCell className="font-mono">{row.slug}</TableCell>
                  <TableCell>{row.name || '—'}</TableCell>
                  <TableCell>
                    <Badge variant={row.status === 'active' ? 'secondary' : 'outline'}>
                      {row.status}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {formatDateTime(row.created_at)}
                  </TableCell>
                  <TableCell className="text-right">
                    <div className="flex justify-end gap-1">
                      <Button variant="ghost" size="sm" onClick={() => setSelected(row.slug)}>
                        Environments
                      </Button>
                      <Button variant="ghost" size="sm" onClick={() => setProject(row.slug)}>
                        Browse
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => setProjectToDelete(row)}
                      >
                        Delete
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      ) : null}

      {selected ? (
        <section className="space-y-4 border-t pt-6">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h2 className="text-lg font-semibold">
                Environments in <span className="font-mono">{selected}</span>
              </h2>
              <p className="text-sm text-muted-foreground">
                Ordered by position. A slug is fixed once created — it is part of every MRN
                underneath it.
              </p>
            </div>
            <Button size="sm" variant="outline" onClick={() => setEnvironmentDialogOpen(true)}>
              <Plus className="size-4" aria-hidden="true" />
              New environment
            </Button>
          </div>

          {environments.isLoading ? <LoadingRows rows={3} /> : null}
          {environments.isError ? (
            <ErrorState error={environments.error} onRetry={() => void environments.refetch()} />
          ) : null}
          {environments.data && environments.data.length === 0 ? (
            <EmptyState
              title="No environments"
              description="Add one — secrets are addressed per environment."
            />
          ) : null}

          {environments.data && environments.data.length > 0 ? (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Slug</TableHead>
                    <TableHead>Name</TableHead>
                    <TableHead>Position</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {environments.data.map((environment) => (
                    <TableRow key={environment.environment_uuid}>
                      <TableCell className="font-mono">{environment.slug}</TableCell>
                      <TableCell>{environment.name || '—'}</TableCell>
                      <TableCell>{environment.position}</TableCell>
                      <TableCell>
                        <Badge variant={environment.status === 'active' ? 'secondary' : 'outline'}>
                          {environment.status}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-right">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setEnvironmentToDelete(environment)}
                        >
                          Delete
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          ) : null}
        </section>
      ) : null}

      <Dialog open={projectDialogOpen} onOpenChange={setProjectDialogOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>New project</DialogTitle>
            <DialogDescription>
              The slug is permanent — it is an MRN segment, so it cannot be renamed later.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="project-slug">Slug</Label>
              <Input
                id="project-slug"
                value={newProject.slug}
                autoComplete="off"
                spellCheck={false}
                onChange={(event) =>
                  setNewProject((current) => ({ ...current, slug: event.target.value }))
                }
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="project-name">Name</Label>
              <Input
                id="project-name"
                value={newProject.name}
                onChange={(event) =>
                  setNewProject((current) => ({ ...current, name: event.target.value }))
                }
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="project-description">Description</Label>
              <Textarea
                id="project-description"
                rows={2}
                value={newProject.description}
                onChange={(event) =>
                  setNewProject((current) => ({ ...current, description: event.target.value }))
                }
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setProjectDialogOpen(false)}>
              Cancel
            </Button>
            <Button
              disabled={!newProject.slug.trim() || createProject.isPending}
              onClick={async () => {
                await createProject.mutateAsync({
                  slug: newProject.slug.trim(),
                  name: newProject.name.trim(),
                  description: newProject.description.trim(),
                })
                setNewProject({ slug: '', name: '', description: '' })
                setProjectDialogOpen(false)
              }}
            >
              {createProject.isPending ? 'Creating…' : 'Create'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={environmentDialogOpen} onOpenChange={setEnvironmentDialogOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>New environment</DialogTitle>
            <DialogDescription>
              In <span className="font-mono">{selected}</span>. The slug is permanent.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="environment-slug">Slug</Label>
              <Input
                id="environment-slug"
                value={newEnvironment.slug}
                autoComplete="off"
                spellCheck={false}
                onChange={(event) =>
                  setNewEnvironment((current) => ({ ...current, slug: event.target.value }))
                }
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="environment-name">Name</Label>
              <Input
                id="environment-name"
                value={newEnvironment.name}
                onChange={(event) =>
                  setNewEnvironment((current) => ({ ...current, name: event.target.value }))
                }
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="environment-position">Position</Label>
              <Input
                id="environment-position"
                type="number"
                value={newEnvironment.position}
                onChange={(event) =>
                  setNewEnvironment((current) => ({ ...current, position: event.target.value }))
                }
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEnvironmentDialogOpen(false)}>
              Cancel
            </Button>
            <Button
              disabled={!selected || !newEnvironment.slug.trim() || createEnvironment.isPending}
              onClick={async () => {
                if (!selected) return
                await createEnvironment.mutateAsync({
                  project: selected,
                  slug: newEnvironment.slug.trim(),
                  name: newEnvironment.name.trim(),
                  description: newEnvironment.description.trim(),
                  position: Number(newEnvironment.position) || 0,
                })
                setNewEnvironment({ slug: '', name: '', description: '', position: '0' })
                setEnvironmentDialogOpen(false)
              }}
            >
              {createEnvironment.isPending ? 'Creating…' : 'Create'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        open={projectToDelete !== null}
        onOpenChange={(open) => {
          if (!open) setProjectToDelete(null)
        }}
        title={`Delete project ${projectToDelete?.slug ?? ''}?`}
        confirmLabel="Delete project"
        destructive
        pending={deleteProject.isPending}
        onConfirm={async () => {
          if (!projectToDelete) return
          await deleteProject.mutateAsync(projectToDelete.slug)
          setProjectToDelete(null)
        }}
        description={
          <p>
            Everything addressed under this project stops resolving. Any grant written against its
            MRN becomes dead, and the slug stays reserved.
          </p>
        }
      />

      <ConfirmDialog
        open={environmentToDelete !== null}
        onOpenChange={(open) => {
          if (!open) setEnvironmentToDelete(null)
        }}
        title={`Delete environment ${environmentToDelete?.slug ?? ''}?`}
        confirmLabel="Delete environment"
        destructive
        pending={deleteEnvironment.isPending}
        onConfirm={async () => {
          if (!environmentToDelete) return
          await deleteEnvironment.mutateAsync(environmentToDelete.slug)
          setEnvironmentToDelete(null)
        }}
        description={
          <p>
            Every secret addressed in this environment stops resolving. Consumers reading it will
            start failing immediately.
          </p>
        }
      />
    </div>
  )
}
