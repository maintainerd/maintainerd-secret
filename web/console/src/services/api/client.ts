/**
 * The HTTP client for maintainerd-secret's REST API.
 *
 * It attaches the in-memory bearer token, normalizes every failure into an
 * `ApiError`, and turns an expired session into a re-authentication rather than
 * a page full of empty tables.
 *
 * IT NEVER LOGS A REQUEST OR RESPONSE BODY. A put body carries a plaintext value
 * and a reveal response carries one; `console.log(error.response)` would put a
 * production credential in the browser console and in any error-reporting SDK
 * that hooks it. Only status codes and the server's own (value-free) message
 * ever reach a log line here.
 */

import axios, { type AxiosError, type AxiosRequestConfig } from 'axios'
import { API_CONFIG } from './config'
import { clearAccessToken, getAccessToken } from '@/auth/tokenStore'

export class ApiError extends Error {
  public status: number
  public code?: string
  public retryAfter?: number

  constructor({
    message,
    status,
    code,
    retryAfter,
  }: {
    message: string
    status: number
    code?: string
    retryAfter?: number
  }) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.retryAfter = retryAfter
  }
}

/** True when the failure is "you are authenticated but not granted this". */
export function isForbidden(error: unknown): boolean {
  return error instanceof ApiError && error.status === 403
}

/** True when the service has no auth configuration and refuses the whole API. */
export function isAuthUnavailable(error: unknown): boolean {
  return error instanceof ApiError && error.status === 503 && error.code === 'auth_unavailable'
}

/** True when the resource does not exist — or exists in a tenant you cannot see. */
export function isNotFound(error: unknown): boolean {
  return error instanceof ApiError && error.status === 404
}

// Maps an HTTP status to a distinct, user-facing message. Never surface the raw
// `HTTP <status>` string — it reads like a bug and tells the operator nothing.
function friendlyMessageForStatus(status: number): string {
  switch (status) {
    case 400:
      return 'The request was invalid. Please check your input and try again.'
    case 401:
      return 'Your session has expired. Please sign in again.'
    case 403:
      return 'You do not have permission to perform this action.'
    case 404:
      return 'The requested resource could not be found.'
    case 409:
      return 'This action conflicts with the current state. Please refresh and try again.'
    case 422:
      return 'Some of the information provided was invalid. Please review and try again.'
    case 429:
      return 'Too many requests. Please wait a moment and try again.'
    case 503:
      return 'The vault is not accepting API requests right now.'
    default:
      if (status >= 500) return 'The server ran into a problem. Please try again in a moment.'
      return 'Something went wrong. Please try again.'
  }
}

function parseRetryAfter(value: unknown): number | undefined {
  if (typeof value !== 'string' || value.trim() === '') return undefined
  const seconds = Number(value)
  if (Number.isFinite(seconds) && seconds >= 0) return Math.ceil(seconds)
  const dateMs = Date.parse(value)
  if (!Number.isNaN(dateMs)) {
    const delta = Math.ceil((dateMs - Date.now()) / 1000)
    return delta > 0 ? delta : 0
  }
  return undefined
}

/**
 * What to do when the session is gone.
 *
 * Registered by `AuthProvider` so the router — not this module — decides where
 * an unauthenticated user belongs. Until it is registered (during boot) a 401 is
 * simply reported: bootstrap owns routing at that point, and redirecting on a
 * verdict that is still being determined is the classic reload loop.
 */
type UnauthenticatedHandler = () => void
let onUnauthenticated: UnauthenticatedHandler | null = null
// Fire once per page. A dashboard fans out and several requests can 401
// together; without this each would trigger its own navigation and they'd race.
let reauthStarted = false

export function setUnauthenticatedHandler(handler: UnauthenticatedHandler | null): void {
  onUnauthenticated = handler
  reauthStarted = false
}

const axiosInstance = axios.create({
  baseURL: API_CONFIG.BASE_URL,
  timeout: API_CONFIG.TIMEOUT,
  headers: API_CONFIG.HEADERS,
})

// Attach the bearer token. It is read fresh on every request rather than baked
// into the instance's defaults, because it lives only in memory and can be
// replaced by a silent re-authorization at any moment.
axiosInstance.interceptors.request.use((config) => {
  const token = getAccessToken()
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

axiosInstance.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    if (error.response) {
      const status = error.response.status
      const data = error.response.data as
        | { error?: string; message?: string; success?: boolean; code?: string }
        | undefined

      // A 401 means the token is gone or expired. The console holds no refresh
      // token by design, so recovery is a hosted-identity re-authorization —
      // handled by AuthProvider, which can do it silently when the SSO session
      // is still alive.
      if (status === 401) {
        clearAccessToken()
        if (onUnauthenticated && !reauthStarted) {
          reauthStarted = true
          onUnauthenticated()
        }
      }

      const retryAfter =
        status === 429 ? parseRetryAfter(error.response.headers?.['retry-after']) : undefined

      const backendMessage =
        typeof data?.error === 'string' && data.error.trim() !== '' ? data.error : undefined
      let message = backendMessage || friendlyMessageForStatus(status)
      if (status === 429 && !backendMessage && retryAfter && retryAfter > 0) {
        message = `Too many requests. Please try again in ${retryAfter} second${retryAfter === 1 ? '' : 's'}.`
      }

      throw new ApiError({ message, status, code: data?.code, retryAfter })
    }
    if (error.code === 'ECONNABORTED') {
      throw new ApiError({ message: 'The request timed out.', status: 408, code: 'TIMEOUT' })
    }
    if (error.request) {
      throw new ApiError({
        message: 'Could not reach the vault. Check that the service is running.',
        status: 0,
        code: 'NETWORK_ERROR',
      })
    }
    throw new ApiError({
      message: error.message || 'Something went wrong.',
      status: 0,
      code: 'UNKNOWN_ERROR',
    })
  },
)

export async function get<T>(endpoint: string, config?: AxiosRequestConfig): Promise<T> {
  const response = await axiosInstance.get<T>(endpoint, config)
  return response.data
}

/**
 * POST — the body defaults to `{}` so axios keeps the JSON Content-Type header
 * (it strips it when there is no body), which the service's decoder requires.
 */
export async function post<T>(
  endpoint: string,
  data?: unknown,
  config?: AxiosRequestConfig,
): Promise<T> {
  const response = await axiosInstance.post<T>(endpoint, data ?? {}, config)
  return response.data
}

export async function patch<T>(
  endpoint: string,
  data?: unknown,
  config?: AxiosRequestConfig,
): Promise<T> {
  const response = await axiosInstance.patch<T>(endpoint, data ?? {}, config)
  return response.data
}

export async function deleteRequest<T>(endpoint: string, config?: AxiosRequestConfig): Promise<T> {
  const response = await axiosInstance.delete<T>(endpoint, config)
  return response.data
}

export const apiClient = {
  get,
  post,
  patch,
  delete: deleteRequest,
}
