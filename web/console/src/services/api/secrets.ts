import { apiClient } from './client'
import { API_ENDPOINTS } from './config'
import { query, unwrap, unwrapList, unwrapPaged } from './unwrap'
import type {
  ApiResponse,
  DeletedSecret,
  Paged,
  PageRequest,
  PutResult,
  RevealResponse,
  RotationPolicy,
  RotationSpec,
  SecretAddress,
  SecretMeta,
  VersionMeta,
} from './types'

/**
 * Secrets.
 *
 * TWO RULES GOVERN THIS MODULE, and they are the service's rules, not this
 * console's inventions:
 *
 *  1. A LIST NEVER CARRIES A VALUE. `listSecrets` returns `SecretMeta`, a type
 *     with no value field. Revealing is a separate call, a separate grant
 *     (`secret:GetSecret` vs `secret:ReadMetadata`) and a separate audit row.
 *  2. AN ADDRESS BELONGS IN A BODY, NOT A URL, for the calls that carry the
 *     sensitive intent. Reveal is a POST for exactly that reason: a URL lands in
 *     access logs, proxy logs, browser history and referer headers.
 *
 * Values on the wire are base64 of the raw plaintext bytes (see lib/base64.ts).
 */

/** Strips an empty folder_path so the service reads it as "the root". */
function address(addr: SecretAddress): SecretAddress {
  return {
    project: addr.project,
    environment: addr.environment,
    ...(addr.folder_path ? { folder_path: addr.folder_path } : {}),
    key: addr.key,
  }
}

export interface ListSecretsInput extends PageRequest {
  project: string
  environment: string
  /** Path prefix to scope the listing to a folder subtree. */
  prefix?: string
}

/** Metadata only, always. */
export async function listSecrets(input: ListSecretsInput): Promise<Paged<SecretMeta>> {
  const res = await apiClient.get<ApiResponse<SecretMeta[]>>(
    `${API_ENDPOINTS.SECRETS}${query({
      project: input.project,
      environment: input.environment,
      prefix: input.prefix,
      page: input.page,
      limit: input.limit,
    })}`,
  )
  return unwrapPaged(res, 'list secrets')
}

export async function describeSecret(addr: SecretAddress): Promise<SecretMeta> {
  const res = await apiClient.get<ApiResponse<SecretMeta>>(
    `${API_ENDPOINTS.SECRETS_DESCRIBE}${query({ ...address(addr) })}`,
  )
  return unwrap(res, 'describe the secret')
}

export async function listVersions(
  addr: SecretAddress,
  page: PageRequest = {},
): Promise<Paged<VersionMeta>> {
  const res = await apiClient.get<ApiResponse<VersionMeta[]>>(
    `${API_ENDPOINTS.SECRETS_VERSIONS}${query({
      ...address(addr),
      page: page.page,
      limit: page.limit,
    })}`,
  )
  return unwrapPaged(res, 'list versions')
}

export async function listDeletedSecrets(
  project: string,
  environment: string,
  page: PageRequest = {},
): Promise<DeletedSecret[]> {
  const res = await apiClient.get<ApiResponse<DeletedSecret[]>>(
    `${API_ENDPOINTS.SECRETS_DELETED}${query({
      project,
      environment,
      page: page.page,
      limit: page.limit,
    })}`,
  )
  return unwrapList(res, 'list deleted secrets')
}

/**
 * REVEALS A VALUE. Every call is audited server-side, individually, and a
 * reference chain re-checks the grant and audits at every hop.
 *
 * The response is NOT the standard envelope — the reveal handler encodes its own
 * body so that "which responses can contain a value" stays answerable by grep.
 * The caller owns the returned value's lifetime: hold it in memory, show it on
 * demand, and drop it. Never persist it.
 */
export async function revealSecret(
  addr: SecretAddress,
  version?: number,
): Promise<RevealResponse> {
  return apiClient.post<RevealResponse>(API_ENDPOINTS.SECRETS_REVEAL, {
    ...address(addr),
    ...(version ? { version } : {}),
  })
}

export interface PutSecretInput extends SecretAddress {
  /** Base64 of the raw plaintext bytes. */
  value: string
  value_type?: string
  description?: string
  tags?: string[]
  keep_versions?: number
  rotation_policy?: RotationPolicy
  /** RFC3339. */
  expires_at?: string | null
  /** Create any missing folders on the path rather than failing. */
  create_folders?: boolean
}

/** Writes a value: creates the secret, or appends a version to it. */
export async function putSecret(input: PutSecretInput): Promise<PutResult> {
  const res = await apiClient.post<ApiResponse<PutResult>>(API_ENDPOINTS.SECRETS, input)
  return unwrap(res, 'write the secret')
}

export interface UpdateSecretMetaInput extends SecretAddress {
  description?: string
  tags?: string[]
  keep_versions?: number
  rotation_policy?: RotationPolicy
  expires_at?: string | null
}

/** Updates metadata only — this call cannot change a value. */
export async function updateSecretMeta(input: UpdateSecretMetaInput): Promise<SecretMeta> {
  const res = await apiClient.patch<ApiResponse<SecretMeta>>(API_ENDPOINTS.SECRETS, input)
  return unwrap(res, 'update the secret metadata')
}

/**
 * Rolls a secret back to an earlier version by writing a NEW version carrying
 * that version's value. History is never rewritten — see the confirm copy in
 * `pages/secrets/VersionHistory.tsx`.
 */
export async function rollbackSecret(addr: SecretAddress, version: number): Promise<PutResult> {
  const res = await apiClient.post<ApiResponse<PutResult>>(API_ENDPOINTS.SECRETS_ROLLBACK, {
    ...address(addr),
    version,
  })
  return unwrap(res, 'roll the secret back')
}

/**
 * Rotates now. The rotated value is NOT in the response: reading it is a reveal,
 * with its own grant and its own audit row.
 */
export async function rotateSecret(
  addr: SecretAddress,
  generator: RotationSpec,
): Promise<PutResult> {
  const res = await apiClient.post<ApiResponse<PutResult>>(API_ENDPOINTS.SECRETS_ROTATE, {
    ...address(addr),
    generator,
  })
  return unwrap(res, 'rotate the secret')
}

/**
 * Sets the stored rotation policy.
 *
 * The generator here must NOT carry a value: a policy is stored as readable
 * metadata, so a value in it would be a credential in a metadata field. The
 * service refuses one; this signature makes it unrepresentable.
 */
export async function setRotationPolicy(
  addr: SecretAddress,
  policy: { enabled: boolean; interval?: string; generator?: Omit<RotationSpec, 'value'> },
): Promise<SecretMeta> {
  const res = await apiClient.post<ApiResponse<SecretMeta>>(API_ENDPOINTS.SECRETS_ROTATION_POLICY, {
    ...address(addr),
    enabled: policy.enabled,
    ...(policy.interval ? { interval: policy.interval } : {}),
    ...(policy.generator ? { generator: policy.generator } : {}),
  })
  return unwrap(res, 'set the rotation policy')
}

/** Soft-deletes. The secret stays restorable until `destroy_after`. */
export async function deleteSecret(
  addr: SecretAddress,
  recoveryWindow?: string,
): Promise<DeletedSecret> {
  const res = await apiClient.post<ApiResponse<DeletedSecret>>(API_ENDPOINTS.SECRETS_DELETE, {
    ...address(addr),
    ...(recoveryWindow ? { recovery_window: recoveryWindow } : {}),
  })
  return unwrap(res, 'delete the secret')
}

export async function restoreSecret(secretUuid: string): Promise<SecretMeta> {
  const res = await apiClient.post<ApiResponse<SecretMeta>>(API_ENDPOINTS.SECRETS_RESTORE, {
    secret_uuid: secretUuid,
  })
  return unwrap(res, 'restore the secret')
}

/** Permanent. There is no recovery after this. */
export async function destroySecret(secretUuid: string): Promise<void> {
  const res = await apiClient.post<ApiResponse<{ destroyed: boolean }>>(
    API_ENDPOINTS.SECRETS_DESTROY,
    { secret_uuid: secretUuid },
  )
  unwrap(res, 'destroy the secret')
}
