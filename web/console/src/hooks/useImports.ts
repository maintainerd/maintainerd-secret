import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { toast } from 'react-toastify'
import {
  createImport,
  deleteImport,
  listImports,
  setImportEnabled,
  type CreateImportInput,
} from '@/services/api/imports'
import { secretKeys } from './useSecrets'

export const importKeys = {
  all: ['imports'] as const,
  list: (project: string, environment: string, folderPath: string) =>
    [...importKeys.all, 'list', project, environment, folderPath] as const,
}

export function useImports(
  project: string | undefined,
  environment: string | undefined,
  folderPath: string,
) {
  return useQuery({
    queryKey: importKeys.list(project ?? '', environment ?? '', folderPath),
    queryFn: () => listImports(project as string, environment as string, folderPath),
    enabled: Boolean(project && environment),
  })
}

export function useCreateImport() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (input: CreateImportInput) => createImport(input),
    onSuccess: () => {
      toast.success('Import added')
      void queryClient.invalidateQueries({ queryKey: importKeys.all })
      // What resolves in this scope changed, so listed secrets are stale.
      void queryClient.invalidateQueries({ queryKey: secretKeys.all })
    },
  })
}

export function useSetImportEnabled() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (input: { importUuid: string; enabled: boolean; position?: number }) =>
      setImportEnabled(input.importUuid, input.enabled, input.position),
    onSuccess: (edge) => {
      toast.success(edge.enabled ? 'Import enabled' : 'Import disabled')
      void queryClient.invalidateQueries({ queryKey: importKeys.all })
      void queryClient.invalidateQueries({ queryKey: secretKeys.all })
    },
  })
}

export function useDeleteImport() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (importUuid: string) => deleteImport(importUuid),
    onSuccess: () => {
      toast.success('Import removed')
      void queryClient.invalidateQueries({ queryKey: importKeys.all })
      void queryClient.invalidateQueries({ queryKey: secretKeys.all })
    },
  })
}
