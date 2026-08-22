import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { toast } from 'react-toastify'
import {
  createWebhook,
  deleteWebhook,
  listWebhookDeliveries,
  listWebhooks,
  updateWebhook,
  type CreateWebhookInput,
  type UpdateWebhookInput,
} from '@/services/api/webhooks'
import type { PageRequest } from '@/services/api/types'

export const webhookKeys = {
  all: ['webhooks'] as const,
  list: (project: string, page: PageRequest) =>
    [...webhookKeys.all, 'list', project, page] as const,
  deliveries: (endpointUuid: string, project: string, page: PageRequest) =>
    [...webhookKeys.all, 'deliveries', endpointUuid, project, page] as const,
}

export function useWebhooks(project: string | undefined, page: PageRequest = { limit: 50 }) {
  return useQuery({
    queryKey: webhookKeys.list(project ?? '', page),
    queryFn: () => listWebhooks(project as string, page),
    enabled: Boolean(project),
  })
}

export function useWebhookDeliveries(
  endpointUuid: string | null,
  project: string | undefined,
  page: PageRequest = { limit: 25 },
) {
  return useQuery({
    queryKey: webhookKeys.deliveries(endpointUuid ?? '', project ?? '', page),
    queryFn: () => listWebhookDeliveries(endpointUuid as string, project as string, page),
    enabled: Boolean(endpointUuid && project),
  })
}

/**
 * Creates an endpoint. The caller MUST show the returned `signing_key` to the
 * operator immediately — it is disclosed once and cannot be fetched again.
 */
export function useCreateWebhook() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (input: CreateWebhookInput) => createWebhook(input),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: webhookKeys.all })
    },
  })
}

export function useUpdateWebhook() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (input: { endpointUuid: string; body: UpdateWebhookInput }) =>
      updateWebhook(input.endpointUuid, input.body),
    onSuccess: () => {
      toast.success('Webhook endpoint updated')
      void queryClient.invalidateQueries({ queryKey: webhookKeys.all })
    },
  })
}

export function useDeleteWebhook() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (input: { endpointUuid: string; project: string }) =>
      deleteWebhook(input.endpointUuid, input.project),
    onSuccess: () => {
      toast.success('Webhook endpoint deleted')
      void queryClient.invalidateQueries({ queryKey: webhookKeys.all })
    },
  })
}
