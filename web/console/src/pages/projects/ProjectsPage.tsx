import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Layers } from 'lucide-react'
import { PageContainer } from '@/components/layout/PageContainer'
import { PageHeader } from '@/components/layout/PageHeader'
import { ResourceListing } from '@/components/data-table'
import { ProjectFormDialog } from './components/ProjectFormDialog'
import { buildProjectColumns } from './components/projectColumns'
import { useDeleteProject, useProjects } from '@/hooks/useProjects'
import { useScope } from '@/context/scopeContext'
import type { Project } from '@/services/api/types'

/**
 * Projects.
 *
 * The standard maintainerd-auth listing page: a `PageContainer` card wrapping a
 * `PageHeader` and a `ResourceListing`, with the row-actions menu and the
 * type-to-confirm delete dialog coming from the shared components.
 *
 * A project's ENVIRONMENTS live on its detail route rather than in a second
 * table below this one — the same shape auth uses for a client's APIs or a
 * role's permissions. Putting a project slug in the URL is safe: it is a public
 * name that appears in every MRN, not a secret address.
 */
export default function ProjectsPage() {
  const navigate = useNavigate()
  const { setProject } = useScope()
  const projects = useProjects({ page: 1, limit: 200 })
  const deleteProject = useDeleteProject()
  const [createOpen, setCreateOpen] = useState(false)

  // `mutateAsync` is stable across renders; the mutation object is not.
  const deleteProjectAsync = deleteProject.mutateAsync

  const columns = useMemo(
    () =>
      buildProjectColumns({
        onOpen: (project) => navigate(`/projects/${encodeURIComponent(project.slug)}`),
        onBrowse: (project) => {
          setProject(project.slug)
          navigate('/browse')
        },
        onDelete: async (project) => {
          await deleteProjectAsync(project.slug)
        },
      }),
    [navigate, setProject, deleteProjectAsync],
  )

  return (
    <PageContainer>
      <PageHeader
        title="Projects"
        icon={Layers}
        description="A project groups a tenant's secrets; an environment is a deployment stage inside it. Both slugs are permanent — they are MRN segments."
      />

      <ResourceListing<Project>
        rows={projects.data?.rows ?? []}
        columns={columns}
        defaultSort={[{ id: 'slug', desc: false }]}
        searchFields={(row) => [row.slug, row.name, row.description]}
        searchPlaceholder="Search projects"
        isLoading={projects.isLoading}
        error={projects.error}
        filterGroups={STATUS_FILTERS}
        onRowClick={(project) => navigate(`/projects/${encodeURIComponent(project.slug)}`)}
        onCreate={() => setCreateOpen(true)}
        createLabel="New project"
        emptyTitle="No projects"
        emptyDescription="Create one to start storing secrets."
        urlKey="projects"
      />

      <ProjectFormDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        onCreated={(slug) => navigate(`/projects/${encodeURIComponent(slug)}`)}
      />
    </PageContainer>
  )
}

const STATUS_FILTERS = [
  { key: 'status', label: 'Status', options: ['active', 'suspended', 'archived'] },
] as const
