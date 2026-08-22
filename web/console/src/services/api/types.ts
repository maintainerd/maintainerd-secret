/**
 * Wire types for maintainerd-secret's REST API.
 *
 * These mirror the Go domain types in `internal/store` and `internal/api`
 * field-for-field. NOTHING HERE CARRIES A SECRET VALUE except `RevealResponse`
 * and `BatchGetItem`, which is the same guarantee the server side makes: the
 * listing and describe types structurally cannot hold one.
 */

/** The envelope every REST response takes (internal/platform/response). */
export interface ApiResponse<T = undefined> {
  success: boolean
  data?: T
  message?: string
  error?: string
  code?: string
  meta?: PageMeta
}

/** Pagination block on a list response. */
export interface PageMeta {
  page: number
  limit: number
  total: number
}

/** A page of rows plus its meta, as the hooks consume it. */
export interface Paged<T> {
  rows: T[]
  meta: PageMeta
}

export interface PageRequest {
  page?: number
  limit?: number
}

// ---------------------------------------------------------------------------
// Hierarchy
// ---------------------------------------------------------------------------

export type ResourceStatus = 'active' | 'suspended' | 'archived'

export interface Project {
  project_uuid: string
  name: string
  slug: string
  description: string
  status: string
  created_at: string
  updated_at: string
}

export interface Environment {
  environment_uuid: string
  name: string
  slug: string
  description: string
  position: number
  status: string
  created_at: string
  updated_at: string
}

export interface Folder {
  folder_uuid: string
  name: string
  /** Materialized absolute path: '/' or '/db/primary'. */
  path: string
  created_at: string
  updated_at: string
}

export interface ScopeImport {
  import_uuid: string
  folder_path?: string
  source_project: string
  source_environment: string
  source_folder_path: string
  position: number
  enabled: boolean
  created_at: string
  updated_at: string
}

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

/** Value types the service accepts. `reference` is a POINTER, not a credential. */
export const VALUE_TYPE_OPAQUE = 'opaque'
export const VALUE_TYPE_JSON = 'json'
export const VALUE_TYPE_REFERENCE = 'reference'
export type ValueType =
  | typeof VALUE_TYPE_OPAQUE
  | typeof VALUE_TYPE_JSON
  | typeof VALUE_TYPE_REFERENCE

/** A secret's address. The primary way to name a secret on this API. */
export interface SecretAddress {
  project: string
  environment: string
  /** Absolute folder path; omitted or empty means the environment root. */
  folder_path?: string
  key: string
}

/**
 * Everything about a secret EXCEPT its value — what a list renders.
 *
 * `value_type` IS metadata and is carried here. It is the current version's
 * declared type, projected up by the service (it lives on `secret_versions` in
 * the schema), and it is the one field that distinguishes a `reference` — a
 * POINTER of the form `${project/environment/KEY}` — from a literal credential.
 * Before it existed the console had to fetch each row's version history to find
 * out, one extra call per row, so the reference indicator only appeared in the
 * detail dialog: the one place an operator has already stopped scanning the list.
 *
 * Empty string when the secret has no version yet.
 */
export interface SecretMeta {
  secret_uuid: string
  folder_path: string
  key: string
  description: string
  tags: string[]
  current_version: number
  keep_versions: number
  rotation_policy: RotationPolicy | Record<string, never>
  /** `opaque`, `json` or `reference` — the CURRENT version's type. */
  value_type: string
  mrn_resource_path: string
  mrn: string
  rotated_at?: string
  expires_at?: string
  created_at: string
  updated_at: string
}

/** One version's metadata. `checksum` is base64 of the raw digest bytes. */
export interface VersionMeta {
  version: number
  kek_id: string
  value_type: string
  checksum: string
  created_at: string
}

export interface DeletedSecret {
  secret_uuid: string
  folder_path: string
  key: string
  current_version: number
  deleted_at: string
  destroy_after?: string
}

/** What a write reports. */
export interface PutResult {
  secret_uuid: string
  version: number
  created: boolean
  /** True when the submitted value matched the current version's checksum. */
  unchanged: boolean
  pruned: number
}

/**
 * The ONE response shape on this API that carries a value.
 *
 * `value` is base64 of the raw plaintext bytes — values are arbitrary bytes and
 * JSON strings cannot carry those losslessly. It is never persisted anywhere in
 * this console; see `components/secrets/RevealDialog.tsx`.
 */
export interface RevealResponse {
  success: boolean
  key: string
  version: number
  value_type: string
  value: string
  mrn: string
  /** MRNs a reference chain traversed, so the operator sees where it came from. */
  reference_hops?: string[]
}

// ---------------------------------------------------------------------------
// Rotation
// ---------------------------------------------------------------------------

export const GENERATOR_RANDOM = 'random'
export const GENERATOR_SUPPLIED = 'supplied'
export type GeneratorType = typeof GENERATOR_RANDOM | typeof GENERATOR_SUPPLIED

/** A rotation generator spec. `value` is base64, and only on `rotate now`. */
export interface RotationSpec {
  type?: string
  length?: number
  charset?: string
  value?: string
}

/**
 * A stored rotation policy. It lives in READABLE METADATA, which is exactly why
 * the service refuses a policy carrying a generator value.
 */
export interface RotationPolicy {
  enabled?: boolean
  /** Go duration string, e.g. "720h". */
  interval?: string
  generator?: RotationSpec
  [key: string]: unknown
}

// ---------------------------------------------------------------------------
// Webhooks
// ---------------------------------------------------------------------------

export const WEBHOOK_EVENTS = ['secret.changed', 'secret.rotated'] as const

export interface WebhookEndpoint {
  endpoint_uuid: string
  url: string
  description: string
  events: string[]
  status: string
  timeout_seconds: number
  max_attempts: number
  last_triggered_at?: string
  created_at: string
  updated_at: string
}

/**
 * The create response, and the only time the signing key is ever disclosed —
 * there is no read-it-back endpoint, because an HMAC key that can be fetched is
 * a forgery primitive.
 */
export interface CreatedWebhookEndpoint extends WebhookEndpoint {
  signing_key: string
}

export interface WebhookDelivery {
  delivery_uuid: string
  event_type: string
  resource_mrn: string
  version?: number
  attempt_count: number
  status: string
  response_status?: number
  error?: string
  payload: Record<string, unknown>
  created_at: string
  updated_at: string
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

/** Audited actions, as the service records them (internal/store/audit.go). */
export const AUDIT_ACTIONS = [
  'secret.read',
  'secret.reveal',
  'secret.write',
  'secret.rotate',
  'secret.delete',
  'secret.restore',
  'secret.destroy',
  'secret.list',
  'secret.rollback',
  'secret.reference',
  'secret.metadata',
  'project.create',
  'project.update',
  'project.delete',
  'environment.create',
  'environment.update',
  'environment.delete',
  'folder.create',
  'folder.move',
  'folder.delete',
  'import.create',
  'import.update',
  'import.delete',
  'webhook.create',
  'webhook.update',
  'webhook.delete',
  'webhook.deliver',
  'audit.read',
  'rootkey.rotate',
  'setup.provision',
  'setup.complete',
  'setup.status',
  'rotation.policy',
  'rotation.scheduled',
] as const

/** `secret.reveal` and `secret.reference` are the sensitive rows. */
export const SENSITIVE_AUDIT_ACTIONS: ReadonlySet<string> = new Set([
  'secret.reveal',
  'secret.reference',
])

export type AuditOutcome = 'success' | 'denied' | 'error'

export interface AuditEntry {
  event_uuid: string
  actor_subject: string
  actor_kind: string
  action: string
  resource_mrn: string
  version?: number
  outcome: string
  reason?: string
  ip_address?: string
  user_agent?: string
  request_id?: string
  metadata?: Record<string, unknown>
  created_at: string
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

/**
 * Setup status.
 *
 * An anonymous caller sees ONE BIT (`completed`); the rest requires the setup
 * token or a `secret:Admin` grant. That is why every field but `completed` is
 * optional here.
 */
export interface SetupStatus {
  completed: boolean
  controller?: string
  controller_kind?: string
  mode?: 'standalone' | 'controlled' | string
  completed_at?: string
  tenant?: string
  auth_tenant_uuid?: string
  project?: string
  environment?: string
  permissions?: string[]
  rest_wizard_open: boolean
}

// ---------------------------------------------------------------------------
// Capabilities
// ---------------------------------------------------------------------------

/** The guard postures the service reports. */
export type GuardMode = 'enforced' | 'dev-open' | 'unavailable'

/**
 * What `GET /capabilities` reports — UNAUTHENTICATED, because it answers the
 * questions a client has to settle before it can hold a token.
 *
 * IT REPLACES AN INFERENCE. The console used to conclude "the guard must be
 * dev-open" from the absence of identity settings in its OWN configuration,
 * which is a guess about the server made from the client's config file — wrong
 * in both directions. Now the server says.
 *
 * Nothing here is sensitive: the service name is a constant, the version is
 * already public as an image tag, the guard mode is determinable in one
 * unauthenticated request anyway, `setup_complete` is the same single bit
 * `/setup/status` returns anonymously, and `auth` is present only when the guard
 * is enforced and carries only values that appear in the clear in every token
 * the service verifies.
 */
export interface Capabilities {
  service: string
  version: string
  guard_mode: GuardMode | string
  setup_complete: boolean
  run_mode: 'standalone' | 'core' | string
  /** Present only when `guard_mode` is `enforced`. */
  auth?: {
    issuer: string
    audience: string
  }
  /** True when the service is serving this console itself. */
  console: boolean
}

export interface SetupRequest {
  tenant?: string
  tenant_display_name?: string
  project?: string
  environment?: string
  auth_tenant_uuid?: string
  controller: string
}

export interface ProvisionResult {
  tenant_uuid: string
  tenant: string
  project: string
  environment: string
  already_existed: boolean
  permissions: string[]
}

export interface SetupResult {
  provisioned: ProvisionResult
  status: SetupStatus
}
