import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { completeSetup, getSetupStatus } from '@/services/api/setup'
import type { SetupRequest } from '@/services/api/types'

export const setupKeys = {
  all: ['setup'] as const,
  status: (withToken: boolean) => [...setupKeys.all, 'status', withToken] as const,
}

/**
 * The instance's setup state.
 *
 * `retry: false` and a short staleTime on purpose: this query gates the whole
 * app, so a failure has to surface immediately rather than after a retry the
 * operator waits through. The gate treats an unreadable status as NOT set up —
 * see `components/SetupGate.tsx`.
 */
export function useSetupStatus(setupToken?: string) {
  return useQuery({
    queryKey: setupKeys.status(Boolean(setupToken)),
    queryFn: () => getSetupStatus(setupToken),
    retry: false,
    staleTime: 0,
  })
}

export function useCompleteSetup() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (input: { body: SetupRequest; setupToken: string }) =>
      completeSetup(input.body, input.setupToken),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: setupKeys.all })
    },
  })
}
