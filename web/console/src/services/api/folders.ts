import { apiClient } from './client'
import { API_ENDPOINTS } from './config'
import { query, unwrap, unwrapList } from './unwrap'
import type { ApiResponse, Folder } from './types'

/**
 * Folders — nodes in an environment's materialized-path hierarchy.
 *
 * `path` is the absolute path ('/' or '/db/primary'), and it is what the browser
 * navigates. Moving a folder rewrites the subtree's paths server-side; there is
 * no client-side reparenting to keep in sync.
 */

export interface CreateFolderInput {
  project: string
  environment: string
  path: string
}

export interface MoveFolderInput {
  project: string
  environment: string
  from: string
  to: string
}

export async function listFolders(
  project: string,
  environment: string,
  prefix?: string,
): Promise<Folder[]> {
  const res = await apiClient.get<ApiResponse<Folder[]>>(
    `${API_ENDPOINTS.FOLDERS}${query({ project, environment, prefix })}`,
  )
  return unwrapList(res, 'list folders').sort((a, b) => a.path.localeCompare(b.path))
}

export async function createFolder(input: CreateFolderInput): Promise<Folder> {
  const res = await apiClient.post<ApiResponse<Folder>>(API_ENDPOINTS.FOLDERS, input)
  return unwrap(res, 'create the folder')
}

export async function moveFolder(input: MoveFolderInput): Promise<Folder> {
  const res = await apiClient.post<ApiResponse<Folder>>(API_ENDPOINTS.FOLDERS_MOVE, input)
  return unwrap(res, 'move the folder')
}

/**
 * Deletes a folder and soft-deletes the secrets beneath it, returning how many
 * were deleted. `recoveryWindow` is a Go duration string such as "168h"; omitted
 * means the service default.
 */
export async function deleteFolder(
  project: string,
  environment: string,
  path: string,
  recoveryWindow?: string,
): Promise<number> {
  const res = await apiClient.delete<ApiResponse<{ secrets_deleted: number }>>(
    `${API_ENDPOINTS.FOLDERS}${query({ project, environment, path, recovery_window: recoveryWindow })}`,
  )
  return unwrap(res, 'delete the folder').secrets_deleted
}
