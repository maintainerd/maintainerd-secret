import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { toast } from 'react-toastify'
import {
  createFolder,
  deleteFolder,
  listFolders,
  moveFolder,
  type CreateFolderInput,
  type MoveFolderInput,
} from '@/services/api/folders'
import { secretKeys } from './useSecrets'

export const folderKeys = {
  all: ['folders'] as const,
  list: (project: string, environment: string) =>
    [...folderKeys.all, 'list', project, environment] as const,
}

export function useFolders(project: string | undefined, environment: string | undefined) {
  return useQuery({
    queryKey: folderKeys.list(project ?? '', environment ?? ''),
    queryFn: () => listFolders(project as string, environment as string),
    enabled: Boolean(project && environment),
  })
}

export function useCreateFolder() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (input: CreateFolderInput) => createFolder(input),
    onSuccess: (folder) => {
      toast.success(`Folder ${folder.path} created`)
      void queryClient.invalidateQueries({ queryKey: folderKeys.all })
    },
  })
}

/**
 * Moving a folder rewrites the paths of everything beneath it server-side, so
 * the secret cache is invalidated too — every listed address under the old path
 * is now wrong.
 */
export function useMoveFolder() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (input: MoveFolderInput) => moveFolder(input),
    onSuccess: (folder) => {
      toast.success(`Folder moved to ${folder.path}`)
      void queryClient.invalidateQueries({ queryKey: folderKeys.all })
      void queryClient.invalidateQueries({ queryKey: secretKeys.all })
    },
  })
}

export function useDeleteFolder() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (input: {
      project: string
      environment: string
      path: string
      recoveryWindow?: string
    }) => deleteFolder(input.project, input.environment, input.path, input.recoveryWindow),
    onSuccess: (deleted) => {
      toast.success(
        deleted === 1
          ? 'Folder deleted; 1 secret is now recoverable until its destroy date'
          : `Folder deleted; ${deleted} secrets are now recoverable until their destroy date`,
      )
      void queryClient.invalidateQueries({ queryKey: folderKeys.all })
      void queryClient.invalidateQueries({ queryKey: secretKeys.all })
    },
  })
}
