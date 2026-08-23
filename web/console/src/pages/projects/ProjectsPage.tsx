import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Layers } from 'lucide-react'
import type { SortingState } from '@tanstack/react-table'
import { PageHeader } from '@/components/layout/PageHeader'
import { ResourceListing, type FilterGroup } from '@/components/data-table'
import { ProjectFormDialog } from './components/ProjectFormDialog'
import { buildProjectColumns } from './components/projectColumns'
import { useDeleteProject, useProjects } from '@/hooks/useProjects'
import { useScope } from '@/context/scopeContext'
import type { Project } from '@/services/api/types'

const DEFAULT_SORT: SortingState = [{ id: 'slug', desc: false }]
const FILTER_GROUPS: readonly FilterGroup[] = [
  { key: 'status', label: 'Status', options: ['active', 'suspended', 'archived'] },
]

// Module-level, like auth's `*Listing.tsx` config constants — and load-bearing
// here in a way it is not in auth. Secret's listing engine filters in the browser
// and takes `searchFields` as a FUNCTION, so an inline arrow would be a new
// identity on every render and re-run the filter memo every time.
const SEARCH_FIELDS = (row: Project) => [row.slug, row.name, row.description]

/**
 * Projects.
 *
 * maintainerd-auth's standard listing page, matched shape for shape against
 * `pages/tenants/TenantsPage.tsx`: a centred `max-w-6xl` column holding a
 * `PageHeader` and a `ResourceListing tableInCard`, with the row-actions menu and
 * the delete dialog coming from the shared components.
 *
 * `tableInCard` IS THE STANDARD, not decoration. Auth passes it from every one of
 * its listing pages: the table gets its own bordered card while the toolbar and
 * pagination sit outside it on the page background. This page used to wrap the
 * whole thing in a single `PageContainer` card instead, which put the toolbar and
 * pagination inside the table's card and left the table itself unbordered — the
 * biggest single reason secret's listings did not read as auth's.
 *
 * A project's ENVIRONMENTS live on its detail route rather than in a second table
 * below this one — the same shape auth uses for a client's APIs or a role's
 * permissions. Putting a project slug in the URL is safe: it is a public name that
 * appears in every MRN, not a secret address.
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
    <div className="mx-auto flex w-full max-w-6xl flex-col gap-4">
      <PageHeader
        title="Projects"
        icon={Layers}
        description="A project groups a tenant's secrets; an environment is a deployment stage inside it. Both slugs are permanent — they are MRN segments."
      />

      <ResourceListing<Project>
        tableInCard
        rows={projects.data?.rows ?? []}
        columns={columns}
        defaultSort={DEFAULT_SORT}
        searchFields={SEARCH_FIELDS}
        searchPlaceholder="Search projects"
        isLoading={projects.isLoading}
        error={projects.error}
        filterGroups={FILTER_GROUPS}
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
    </div>
  )
}
