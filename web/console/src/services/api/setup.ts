import { apiClient } from './client'
import { API_ENDPOINTS, SETUP_TOKEN_HEADER } from './config'
import { unwrap } from './unwrap'
import type { ApiResponse, SetupRequest, SetupResult, SetupStatus } from './types'

/**
 * The standalone first-run wizard.
 *
 * This is the one surface the token guard does not cover, and it has to be:
 * provisioning is what makes tokens mintable at all. It is self-guarded by the
 * service's `SETUP_BOOTSTRAP_TOKEN`, sent in `X-Setup-Token`.
 *
 * An ANONYMOUS status read returns exactly one bit — `completed` — because
 * everything else (controller identity, tenant, permission list) is
 * reconnaissance about an unprovisioned vault. The wizard therefore renders from
 * `completed` alone until a token is supplied.
 */

export async function getSetupStatus(setupToken?: string): Promise<SetupStatus> {
  const res = await apiClient.get<ApiResponse<SetupStatus>>(API_ENDPOINTS.SETUP_STATUS, {
    headers: setupToken ? { [SETUP_TOKEN_HEADER]: setupToken } : undefined,
  })
  return unwrap(res, 'read the setup status')
}

/**
 * Provisions the instance and closes the setup window, in that order.
 *
 * It refuses with `setup_orchestrated` when a controller (Core) already owns
 * this instance — that is not an error to retry past, it means bootstrap belongs
 * on the gRPC SetupService instead.
 */
export async function completeSetup(
  input: SetupRequest,
  setupToken: string,
): Promise<SetupResult> {
  const res = await apiClient.post<ApiResponse<SetupResult>>(API_ENDPOINTS.SETUP, input, {
    headers: { [SETUP_TOKEN_HEADER]: setupToken },
  })
  return unwrap(res, 'complete setup')
}
