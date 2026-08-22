import { apiClient } from './client'
import { API_ENDPOINTS } from './config'
import { query, unwrap, unwrapPaged } from './unwrap'
import type { ApiResponse, Paged, PageRequest, Project } from './types'

/**
 * Projects — the top of the hierarchy under a tenant.
 *
 * A project SLUG is an MRN segment, which is why there is no rename: changing it
 * would silently repoint every grant written against the old name. The service
 * refuses it, and this module does not offer it.
 */

export interface CreateProjectInput {
  slug: string
  name?: string
  description?: string
}

export interface UpdateProjectInput {
  name?: string
  description?: string
  status?: string
}

export async function listProjects(page: PageRequest = {}): Promise<Paged<Project>> {
  const res = await apiClient.get<ApiResponse<Project[]>>(
    `${API_ENDPOINTS.PROJECTS}${query({ page: page.page, limit: page.limit })}`,
  )
  return unwrapPaged(res, 'list projects')
}

export async function getProject(slug: string): Promise<Project> {
  const res = await apiClient.get<ApiResponse<Project>>(
    `${API_ENDPOINTS.PROJECTS}/${encodeURIComponent(slug)}`,
  )
  return unwrap(res, 'read the project')
}

export async function createProject(input: CreateProjectInput): Promise<Project> {
  const res = await apiClient.post<ApiResponse<Project>>(API_ENDPOINTS.PROJECTS, input)
  return unwrap(res, 'create the project')
}

export async function updateProject(slug: string, input: UpdateProjectInput): Promise<Project> {
  const res = await apiClient.patch<ApiResponse<Project>>(
    `${API_ENDPOINTS.PROJECTS}/${encodeURIComponent(slug)}`,
    input,
  )
  return unwrap(res, 'update the project')
}

/** Deletes a project. Answers 204 with no body, so there is nothing to unwrap. */
export async function deleteProject(slug: string): Promise<void> {
  await apiClient.delete<void>(`${API_ENDPOINTS.PROJECTS}/${encodeURIComponent(slug)}`)
}
