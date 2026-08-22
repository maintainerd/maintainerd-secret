import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { toast } from 'react-toastify'
import {
  createProject,
  deleteProject,
  getProject,
  listProjects,
  updateProject,
  type CreateProjectInput,
  type UpdateProjectInput,
} from '@/services/api/projects'
import type { PageRequest } from '@/services/api/types'

export const projectKeys = {
  all: ['projects'] as const,
  list: (page: PageRequest) => [...projectKeys.all, 'list', page] as const,
  detail: (slug: string) => [...projectKeys.all, 'detail', slug] as const,
}

export function useProjects(page: PageRequest = { page: 1, limit: 100 }) {
  return useQuery({
    queryKey: projectKeys.list(page),
    queryFn: () => listProjects(page),
  })
}

export function useProject(slug: string | undefined) {
  return useQuery({
    queryKey: projectKeys.detail(slug ?? ''),
    queryFn: () => getProject(slug as string),
    enabled: Boolean(slug),
  })
}

export function useCreateProject() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (input: CreateProjectInput) => createProject(input),
    onSuccess: (project) => {
      toast.success(`Project ${project.slug} created`)
      void queryClient.invalidateQueries({ queryKey: projectKeys.all })
    },
  })
}

export function useUpdateProject(slug: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (input: UpdateProjectInput) => updateProject(slug, input),
    onSuccess: () => {
      toast.success('Project updated')
      void queryClient.invalidateQueries({ queryKey: projectKeys.all })
    },
  })
}

export function useDeleteProject() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (slug: string) => deleteProject(slug),
    onSuccess: () => {
      toast.success('Project deleted')
      void queryClient.invalidateQueries({ queryKey: projectKeys.all })
    },
  })
}
