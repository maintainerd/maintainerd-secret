import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { LoginLayout } from '@/components/layout/LoginLayout'
import { FormInputField, FormPasswordField, FormSubmitButton } from '@/components/form'
import { useCompleteSetup, useSetupStatus } from '@/hooks/useSetup'
import { ApiError } from '@/services/api/client'

/**
 * The standalone first-run wizard.
 *
 * It provisions the first tenant plus a default project and environment, then
 * closes the setup window permanently. Two things it deliberately does not do:
 *
 *  - It does not pretend the window can be reopened. Completion is a durable,
 *    one-shot database lock, not a process flag, so the copy says "permanently".
 *  - It does not treat `setup_orchestrated` as a retryable failure. That code
 *    means a controller (Core) already owns this instance, and the answer is to
 *    bootstrap through the gRPC SetupService — not to try the wizard again.
 *
 * Laid out in maintainerd-auth's `LoginLayout` (brand lockup over a single card)
 * for the same reason auth's own setup pages are: this is the FIRST screen
 * anybody sees on a new install, and it should look like the product.
 *
 * The bootstrap token uses `FormPasswordField` — auth's, complete with its
 * show/hide toggle and its "new-password" autocomplete default, so no password
 * manager offers to remember a provisioning credential.
 */

const schema = z.object({
  setupToken: z.string().min(1, 'The bootstrap token is required'),
  controller: z
    .string()
    .min(1, 'Name who is provisioning this vault — it is recorded on the durable lock'),
  tenant: z.string().optional(),
  tenantDisplayName: z.string().optional(),
  project: z.string().optional(),
  environment: z.string().optional(),
  authTenantUuid: z
    .string()
    .optional()
    .refine(
      (value) =>
        !value ||
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value.trim()),
      'Must be a UUID',
    ),
})

type SetupForm = z.infer<typeof schema>

export default function SetupPage() {
  const navigate = useNavigate()
  const [failure, setFailure] = useState<{ message: string; orchestrated: boolean } | null>(null)
  const status = useSetupStatus()
  const complete = useCompleteSetup()

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<SetupForm>({
    resolver: zodResolver(schema),
    defaultValues: {
      setupToken: '',
      controller: '',
      tenant: '',
      tenantDisplayName: '',
      project: '',
      environment: '',
      authTenantUuid: '',
    },
  })

  const onSubmit = handleSubmit(async (values) => {
    setFailure(null)
    try {
      await complete.mutateAsync({
        setupToken: values.setupToken,
        body: {
          controller: values.controller.trim(),
          ...(values.tenant?.trim() ? { tenant: values.tenant.trim() } : {}),
          ...(values.tenantDisplayName?.trim()
            ? { tenant_display_name: values.tenantDisplayName.trim() }
            : {}),
          ...(values.project?.trim() ? { project: values.project.trim() } : {}),
          ...(values.environment?.trim() ? { environment: values.environment.trim() } : {}),
          ...(values.authTenantUuid?.trim()
            ? { auth_tenant_uuid: values.authTenantUuid.trim() }
            : {}),
        },
      })
      navigate('/browse', { replace: true })
    } catch (error) {
      const apiError = error instanceof ApiError ? error : null
      setFailure({
        message: apiError?.message ?? 'Setup could not be completed.',
        orchestrated: apiError?.code === 'setup_orchestrated',
      })
    }
  })

  return (
    <LoginLayout width="xl">
      <div className="space-y-6">
        <div className="space-y-2">
          <h1 className="text-lg font-semibold tracking-tight">Set up this vault</h1>
          <p className="text-sm text-muted-foreground">
            Creates the first tenant, a default project and a default environment, then closes the
            setup window permanently.
          </p>
        </div>

        {status.isError && (
          <Alert variant="destructive">
            <AlertTitle>Could not read the setup status</AlertTitle>
            <AlertDescription>
              The wizard is shown because the status is unknown, which is treated as “not set up”.
              If the service is still starting, this page recovers on its own once it answers.
            </AlertDescription>
          </Alert>
        )}

        {failure && (
          <Alert variant="destructive">
            <AlertTitle>
              {failure.orchestrated ? 'This vault has a controller' : 'Setup refused'}
            </AlertTitle>
            <AlertDescription>
              {failure.orchestrated
                ? 'A controller already provisioned this instance. Bootstrap it through the gRPC SetupService with its setup token — the standalone wizard is closed on purpose, so that two paths cannot race to own the vault.'
                : failure.message}
            </AlertDescription>
          </Alert>
        )}

        <form onSubmit={onSubmit} className="space-y-6" noValidate>
          <fieldset className="space-y-6" disabled={isSubmitting}>
            <FormPasswordField
              id="setupToken"
              label="Bootstrap token"
              required
              spellCheck={false}
              error={errors.setupToken?.message}
              description="The service’s SETUP_BOOTSTRAP_TOKEN. It is compared in constant time and never stored by this console."
              {...register('setupToken')}
            />

            <FormInputField
              id="controller"
              label="Controller"
              required
              autoComplete="off"
              placeholder="ops@example.com"
              error={errors.controller?.message}
              description="Who is closing the setup window. Recorded on the durable lock and in the audit trail."
              {...register('controller')}
            />

            <div className="grid gap-6 sm:grid-cols-2">
              <FormInputField
                id="tenant"
                label="Tenant slug"
                placeholder="default"
                autoComplete="off"
                error={errors.tenant?.message}
                {...register('tenant')}
              />
              <FormInputField
                id="tenantDisplayName"
                label="Tenant display name"
                autoComplete="off"
                error={errors.tenantDisplayName?.message}
                {...register('tenantDisplayName')}
              />
              <FormInputField
                id="project"
                label="Default project"
                placeholder="default"
                autoComplete="off"
                error={errors.project?.message}
                {...register('project')}
              />
              <FormInputField
                id="environment"
                label="Default environment"
                placeholder="default"
                autoComplete="off"
                error={errors.environment?.message}
                {...register('environment')}
              />
            </div>

            <FormInputField
              id="authTenantUuid"
              label="Auth tenant UUID"
              autoComplete="off"
              spellCheck={false}
              error={errors.authTenantUuid?.message}
              description="Optional. Links this tenant to a maintainerd-auth tenant. Leave empty for a standalone install, which owns its own tenant names."
              {...register('authTenantUuid')}
            />
          </fieldset>

          <FormSubmitButton
            isSubmitting={isSubmitting}
            submitText="Provision and close setup"
            submittingText="Provisioning…"
            className="w-full"
          />
        </form>
      </div>
    </LoginLayout>
  )
}
