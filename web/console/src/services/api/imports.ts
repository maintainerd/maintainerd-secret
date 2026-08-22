import { apiClient } from './client'
import { API_ENDPOINTS } from './config'
import { query, unwrap, unwrapList } from './unwrap'
import type { ApiResponse, ScopeImport } from './types'

/**
 * Scope imports — a folder can inherit another scope's secrets.
 *
 * An import edge is a property of the importing FOLDER, which is why it is
 * governed by the same permission folders are. The source may live in another
 * project or environment of the same tenant (the "shared" folder pattern) but
 * never in another tenant, and the service refuses an edge that would create a
 * cycle.
 */

export interface CreateImportInput {
  project: string
  environment: string
  folder_path?: string
  source_project: string
  source_environment: string
  source_folder_path?: string
  position?: number
}

export async function listImports(
  project: string,
  environment: string,
  folderPath?: string,
): Promise<ScopeImport[]> {
  const res = await apiClient.get<ApiResponse<ScopeImport[]>>(
    `${API_ENDPOINTS.IMPORTS}${query({ project, environment, folder_path: folderPath })}`,
  )
  return unwrapList(res, 'list imports').sort((a, b) => a.position - b.position)
}

export async function createImport(input: CreateImportInput): Promise<ScopeImport> {
  const res = await apiClient.post<ApiResponse<ScopeImport>>(API_ENDPOINTS.IMPORTS, input)
  return unwrap(res, 'create the import')
}

export async function setImportEnabled(
  importUuid: string,
  enabled: boolean,
  position?: number,
): Promise<ScopeImport> {
  const res = await apiClient.patch<ApiResponse<ScopeImport>>(
    `${API_ENDPOINTS.IMPORTS}/${encodeURIComponent(importUuid)}`,
    { enabled, position: position ?? 0 },
  )
  return unwrap(res, 'update the import')
}

export async function deleteImport(importUuid: string): Promise<void> {
  await apiClient.delete<void>(`${API_ENDPOINTS.IMPORTS}/${encodeURIComponent(importUuid)}`)
}
