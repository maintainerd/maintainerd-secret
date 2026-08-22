import { useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { CalendarClock, FolderTree, Hash, Layers, Plus, Server, Trash2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  DetailHeaderCard,
  DetailLayout,
  DetailTabs,
  EmptyState,
  ListingItemCard,
  ListingItemMeta,
  ListSkeleton,
  type DetailAttribute,
} from '@/components/details'
import { StatusBadge } from '@/components/badges'
import { InformationCard } from '@/components/card'
import { DeleteConfirmationDialog } from '@/components/dialog'
import { ErrorState } from '@/components/layout/states'
import { EnvironmentFormDialog } from './components/EnvironmentFormDialog'
import { useDeleteEnvironment, useEnvironments } from '@/hooks/useEnvironments'
import { useProject } from '@/hooks/useProjects'
import { useScope } from '@/context/scopeContext'
import { formatDateTime } from '@/lib/formatDate'
import type { Environment } from '@/services/api/types'

/**
 * One project, and the environments inside it.
 *
 * Composed exactly like a maintainerd-auth detail page: `DetailLayout` supplies
 * the back link plus the loading and not-found states, `DetailHeaderCard` the
 * summary and attribute grid, and `DetailTabs` the tab bar. Each environment is
 * a `ListingItemCard` row, the same shape auth uses for a role's users or a
 * client's APIs.
 */
export default function ProjectDetailsPage() {
  const { slug = '' } = useParams()
  const navigate = useNavigate()
  const { setProject } = useScope()

  const projectQuery = useProject(slug)
  const environments = useEnvironments(slug)
  const deleteEnvironment = useDeleteEnvironment(slug)

  const [createOpen, setCreateOpen] = useState(false)
  const [toDelete, setToDelete] = useState<Environment | null>(null)

  const project = projectQuery.data
  const attributes: DetailAttribute[] = project
    ? [
        { icon: Hash, label: 'Slug', value: <span className="font-mono">{project.slug}</span> },
        {
          icon: Server,
          label: 'Environments',
          value: environments.data?.length ?? '—',
        },
        {
          icon: CalendarClock,
          label: 'Created',
          value: formatDateTime(project.created_at),
        },
      ]
    : []

  return (
    <DetailLayout
      backLabel="Back to projects"
      onBack={() => navigate('/projects')}
      isLoading={projectQuery.isLoading}
      isError={projectQuery.isError}
      notFoundTitle="Project not found"
      notFoundDescription="This project does not exist, or you do not hold a grant that can see it."
    >
      {project && (
        <>
          <DetailHeaderCard
            leading={
              <div className="flex size-14 shrink-0 items-center justify-center rounded-lg bg-muted text-muted-foreground">
                <Layers className="size-6" aria-hidden="true" />
              </div>
            }
            title={project.name || project.slug}
            badge={<StatusBadge status={project.status} />}
            subtitle={project.description || <span className="font-mono">{project.slug}</span>}
            attributes={attributes}
            actions={
              <Button
                data-md-action-button
                variant="outline"
                size="sm"
                onClick={() => {
                  setProject(project.slug)
                  navigate('/browse')
                }}
              >
                <FolderTree className="size-4" aria-hidden="true" />
                Browse secrets
              </Button>
            }
          />

          <DetailTabs defaultValue="environments">
            <TabsList>
              <TabsTrigger value="environments">Environments</TabsTrigger>
            </TabsList>

            <TabsContent value="environments">
              <InformationCard
                title="Environments"
                icon={Server}
                description="Deployment stages inside this project, ordered by position. A slug is fixed once created — it is part of every MRN underneath it."
                action={
                  <Button
                    data-md-action-button
                    variant="outline"
                    size="sm"
                    onClick={() => setCreateOpen(true)}
                  >
                    <Plus className="size-4" aria-hidden="true" />
                    New environment
                  </Button>
                }
              >
                {environments.isLoading && <ListSkeleton rows={3} />}
                {environments.isError && (
                  <ErrorState
                    error={environments.error}
                    onRetry={() => void environments.refetch()}
                  />
                )}
                {environments.data?.length === 0 && (
                  <EmptyState
                    icon={Server}
                    title="No environments"
                    description="Add one — secrets are addressed per environment."
                    action={
                      <Button size="sm" onClick={() => setCreateOpen(true)}>
                        <Plus className="size-4" aria-hidden="true" />
                        New environment
                      </Button>
                    }
                  />
                )}
                {environments.data && environments.data.length > 0 && (
                  <ul className="space-y-2">
                    {environments.data.map((environment) => (
                      <li key={environment.environment_uuid}>
                        <ListingItemCard
                          icon={Server}
                          action={
                            <Button
                              variant="ghost"
                              size="icon-sm"
                              aria-label={`Delete environment ${environment.slug}`}
                              onClick={() => setToDelete(environment)}
                            >
                              <Trash2 className="size-4" aria-hidden="true" />
                            </Button>
                          }
                        >
                          <div className="flex flex-wrap items-center gap-2">
                            <p className="font-mono text-sm font-medium">{environment.slug}</p>
                            <StatusBadge status={environment.status} />
                          </div>
                          <ListingItemMeta>
                            {environment.name && <span>{environment.name}</span>}
                            <span>position {environment.position}</span>
                          </ListingItemMeta>
                        </ListingItemCard>
                      </li>
                    ))}
                  </ul>
                )}
              </InformationCard>
            </TabsContent>
          </DetailTabs>

          <EnvironmentFormDialog
            project={project.slug}
            open={createOpen}
            onOpenChange={setCreateOpen}
          />

          <DeleteConfirmationDialog
            open={toDelete !== null}
            onOpenChange={(open) => {
              if (!open) setToDelete(null)
            }}
            onConfirm={async () => {
              if (!toDelete) return
              await deleteEnvironment.mutateAsync(toDelete.slug)
              setToDelete(null)
            }}
            title={`Delete environment ${toDelete?.slug ?? ''}?`}
            description="Every secret addressed in this environment stops resolving."
            confirmationText="Consumers reading a secret in this environment will start failing immediately, and the slug stays reserved."
            itemName={toDelete?.slug ?? ''}
            isDeleting={deleteEnvironment.isPending}
            confirmLabel="Delete environment"
          />
        </>
      )}
    </DetailLayout>
  )
}
