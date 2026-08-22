import { apiClient } from './client'
import { API_ENDPOINTS } from './config'
import { unwrap } from './unwrap'
import type { ApiResponse, Capabilities } from './types'

/**
 * What this instance can tell an ANONYMOUS caller about itself.
 *
 * THE CONSOLE USED TO GUESS THIS. With no capability endpoint, "is the guard
 * enforced or dev-open" was inferred from whether this console's own runtime
 * config carried identity settings — a conclusion about the SERVER drawn from the
 * CLIENT's config file, and wrong in both directions. An enforced service whose
 * console was handed no issuer rendered as "no identity configured, calling
 * without a token" and then 401'd every request; an actually-open service whose
 * console WAS given an issuer sent the operator into an OAuth flow nobody was
 * listening for. Now the server answers.
 *
 * It is fetched WITHOUT a bearer token, and it has to be: obtaining one is the
 * thing this call is trying to find out how to do.
 */
export async function getCapabilities(): Promise<Capabilities> {
  const res = await apiClient.get<ApiResponse<Capabilities>>(API_ENDPOINTS.CAPABILITIES)
  return unwrap(res, 'read the service capabilities')
}
