import { apiClient } from './client'
import { API_ENDPOINTS } from './config'
import { query, unwrap, unwrapList } from './unwrap'
import type { ApiResponse, Environment } from './types'

/**
 * Environments — a project's deployment stages, ordered by `position`.
 *
 * Like a project slug, an environment slug is quoted in MRNs, grants and every
 * consumer's configuration, so it is fixed at creation.
 */

export interface CreateEnvironmentInput {
  project: string
  slug: string
  name?: string
  description?: string
  position?: number
}

export interface UpdateEnvironmentInput {
  name?: string
  description?: string
  position?: number
  status?: string
}

/** Lists a project's environments. Not paginated: the list is small by nature. */
export async function listEnvironments(project: string): Promise<Environment[]> {
  const res = await apiClient.get<ApiResponse<Environment[]>>(
    `${API_ENDPOINTS.ENVIRONMENTS}${query({ project })}`,
  )
  const rows = unwrapList(res, 'list environments')
  return [...rows].sort((a, b) => a.position - b.position || a.slug.localeCompare(b.slug))
}

export async function getEnvironment(project: string, slug: string): Promise<Environment> {
  const res = await apiClient.get<ApiResponse<Environment>>(
    `${API_ENDPOINTS.ENVIRONMENTS}/${encodeURIComponent(project)}/${encodeURIComponent(slug)}`,
  )
  return unwrap(res, 'read the environment')
}

export async function createEnvironment(input: CreateEnvironmentInput): Promise<Environment> {
  const res = await apiClient.post<ApiResponse<Environment>>(API_ENDPOINTS.ENVIRONMENTS, input)
  return unwrap(res, 'create the environment')
}

export async function updateEnvironment(
  project: string,
  slug: string,
  input: UpdateEnvironmentInput,
): Promise<Environment> {
  const res = await apiClient.patch<ApiResponse<Environment>>(
    `${API_ENDPOINTS.ENVIRONMENTS}/${encodeURIComponent(project)}/${encodeURIComponent(slug)}`,
    input,
  )
  return unwrap(res, 'update the environment')
}

export async function deleteEnvironment(project: string, slug: string): Promise<void> {
  await apiClient.delete<void>(
    `${API_ENDPOINTS.ENVIRONMENTS}/${encodeURIComponent(project)}/${encodeURIComponent(slug)}`,
  )
}
