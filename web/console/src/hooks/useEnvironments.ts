import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { toast } from 'react-toastify'
import {
  createEnvironment,
  deleteEnvironment,
  listEnvironments,
  updateEnvironment,
  type CreateEnvironmentInput,
  type UpdateEnvironmentInput,
} from '@/services/api/environments'

export const environmentKeys = {
  all: ['environments'] as const,
  list: (project: string) => [...environmentKeys.all, 'list', project] as const,
}

export function useEnvironments(project: string | undefined) {
  return useQuery({
    queryKey: environmentKeys.list(project ?? ''),
    queryFn: () => listEnvironments(project as string),
    enabled: Boolean(project),
  })
}

export function useCreateEnvironment() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (input: CreateEnvironmentInput) => createEnvironment(input),
    onSuccess: (environment) => {
      toast.success(`Environment ${environment.slug} created`)
      void queryClient.invalidateQueries({ queryKey: environmentKeys.all })
    },
  })
}

export function useUpdateEnvironment(project: string, slug: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (input: UpdateEnvironmentInput) => updateEnvironment(project, slug, input),
    onSuccess: () => {
      toast.success('Environment updated')
      void queryClient.invalidateQueries({ queryKey: environmentKeys.all })
    },
  })
}

export function useDeleteEnvironment(project: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (slug: string) => deleteEnvironment(project, slug),
    onSuccess: () => {
      toast.success('Environment deleted')
      void queryClient.invalidateQueries({ queryKey: environmentKeys.all })
    },
  })
}
