import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { toast } from 'react-toastify'
import {
  deleteSecret,
  describeSecret,
  destroySecret,
  listDeletedSecrets,
  listSecrets,
  listVersions,
  putSecret,
  restoreSecret,
  revealSecret,
  rollbackSecret,
  rotateSecret,
  setRotationPolicy,
  updateSecretMeta,
  type ListSecretsInput,
  type PutSecretInput,
  type UpdateSecretMetaInput,
} from '@/services/api/secrets'
import type { PageRequest, RotationSpec, SecretAddress } from '@/services/api/types'

/**
 * Secret queries and mutations.
 *
 * NOTE WHAT IS NOT HERE: there is no `useReveal` query. A reveal is a mutation
 * on purpose — it has a side effect (an audit row), and TanStack Query's job is
 * to CACHE what it fetches, which is the one thing a decrypted value must never
 * be. `revealOnce` below performs the call and hands the value straight back to
 * the caller, which holds it in component state and drops it.
 */

export const secretKeys = {
  all: ['secrets'] as const,
  list: (input: ListSecretsInput) => [...secretKeys.all, 'list', input] as const,
  describe: (addr: SecretAddress) => [...secretKeys.all, 'describe', addr] as const,
  versions: (addr: SecretAddress, page: PageRequest) =>
    [...secretKeys.all, 'versions', addr, page] as const,
  deleted: (project: string, environment: string) =>
    [...secretKeys.all, 'deleted', project, environment] as const,
}

export function useSecrets(input: ListSecretsInput, enabled = true) {
  return useQuery({
    queryKey: secretKeys.list(input),
    queryFn: () => listSecrets(input),
    enabled: enabled && Boolean(input.project && input.environment),
  })
}

export function useSecretMeta(addr: SecretAddress | null) {
  return useQuery({
    queryKey: secretKeys.describe(addr ?? { project: '', environment: '', key: '' }),
    queryFn: () => describeSecret(addr as SecretAddress),
    enabled: Boolean(addr?.project && addr?.environment && addr?.key),
  })
}

export function useSecretVersions(addr: SecretAddress | null, page: PageRequest = { limit: 50 }) {
  return useQuery({
    queryKey: secretKeys.versions(addr ?? { project: '', environment: '', key: '' }, page),
    queryFn: () => listVersions(addr as SecretAddress, page),
    enabled: Boolean(addr?.project && addr?.environment && addr?.key),
  })
}

export function useDeletedSecrets(project: string | undefined, environment: string | undefined) {
  return useQuery({
    queryKey: secretKeys.deleted(project ?? '', environment ?? ''),
    queryFn: () => listDeletedSecrets(project as string, environment as string),
    enabled: Boolean(project && environment),
  })
}

/**
 * Performs one reveal.
 *
 * Deliberately NOT a query and deliberately not memoized: each call is a
 * separate, individually audited read of a decrypted value.
 */
export function useRevealSecret() {
  return useMutation({
    mutationFn: (input: { address: SecretAddress; version?: number }) =>
      revealSecret(input.address, input.version),
    // gcTime 0: react-query keeps a mutation's `data` around for its cache
    // window, and that data is a plaintext value. Zero means it is dropped as
    // soon as the mutation is no longer mounted.
    gcTime: 0,
  })
}

export function usePutSecret() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (input: PutSecretInput) => putSecret(input),
    onSuccess: (result) => {
      if (result.unchanged) {
        toast.info('The value was identical, so no new version was written')
      } else if (result.created) {
        toast.success('Secret created')
      } else {
        toast.success(`Secret updated — now at version ${result.version}`)
      }
      void queryClient.invalidateQueries({ queryKey: secretKeys.all })
    },
  })
}

export function useUpdateSecretMeta() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (input: UpdateSecretMetaInput) => updateSecretMeta(input),
    onSuccess: () => {
      toast.success('Secret metadata updated')
      void queryClient.invalidateQueries({ queryKey: secretKeys.all })
    },
  })
}

export function useRollbackSecret() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (input: { address: SecretAddress; version: number }) =>
      rollbackSecret(input.address, input.version),
    onSuccess: (result) => {
      toast.success(
        result.unchanged
          ? 'That version is already the current one'
          : `Rolled back — the value is now version ${result.version}`,
      )
      void queryClient.invalidateQueries({ queryKey: secretKeys.all })
    },
  })
}

export function useRotateSecret() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (input: { address: SecretAddress; generator: RotationSpec }) =>
      rotateSecret(input.address, input.generator),
    onSuccess: (result) => {
      // The rotated value is NOT in the response, and that is by design: reading
      // it is a reveal, with its own grant and its own audit row.
      toast.success(`Rotated — now at version ${result.version}. Reveal it to read the new value.`)
      void queryClient.invalidateQueries({ queryKey: secretKeys.all })
    },
  })
}

export function useSetRotationPolicy() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (input: {
      address: SecretAddress
      enabled: boolean
      interval?: string
      generator?: Omit<RotationSpec, 'value'>
    }) =>
      setRotationPolicy(input.address, {
        enabled: input.enabled,
        interval: input.interval,
        generator: input.generator,
      }),
    onSuccess: () => {
      toast.success('Rotation policy saved')
      void queryClient.invalidateQueries({ queryKey: secretKeys.all })
    },
  })
}

export function useDeleteSecret() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (input: { address: SecretAddress; recoveryWindow?: string }) =>
      deleteSecret(input.address, input.recoveryWindow),
    onSuccess: () => {
      toast.success('Secret deleted; it can be restored until its destroy date')
      void queryClient.invalidateQueries({ queryKey: secretKeys.all })
    },
  })
}

export function useRestoreSecret() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (secretUuid: string) => restoreSecret(secretUuid),
    onSuccess: () => {
      toast.success('Secret restored')
      void queryClient.invalidateQueries({ queryKey: secretKeys.all })
    },
  })
}

export function useDestroySecret() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (secretUuid: string) => destroySecret(secretUuid),
    onSuccess: () => {
      toast.success('Secret destroyed permanently')
      void queryClient.invalidateQueries({ queryKey: secretKeys.all })
    },
  })
}
