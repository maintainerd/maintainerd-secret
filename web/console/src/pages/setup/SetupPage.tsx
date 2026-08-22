import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { Eye, EyeOff, KeyRound } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
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
  const [showToken, setShowToken] = useState(false)
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
    <div className="mx-auto flex min-h-screen max-w-2xl flex-col justify-center p-6">
      <div className="mb-6 flex items-center gap-3">
        <KeyRound className="size-6 text-primary" aria-hidden="true" />
        <div>
          <h1 className="text-xl font-semibold">Set up this vault</h1>
          <p className="text-sm text-muted-foreground">
            Creates the first tenant, a default project and a default environment, then closes the
            setup window permanently.
          </p>
        </div>
      </div>

      {status.isError ? (
        <Alert variant="destructive" className="mb-4">
          <AlertTitle>Could not read the setup status</AlertTitle>
          <AlertDescription>
            The wizard is shown because the status is unknown, which is treated as “not set up”. If
            the service is still starting, this page recovers on its own once it answers.
          </AlertDescription>
        </Alert>
      ) : null}

      {failure ? (
        <Alert variant="destructive" className="mb-4">
          <AlertTitle>{failure.orchestrated ? 'This vault has a controller' : 'Setup refused'}</AlertTitle>
          <AlertDescription>
            {failure.orchestrated
              ? 'A controller already provisioned this instance. Bootstrap it through the gRPC SetupService with its setup token — the standalone wizard is closed on purpose, so that two paths cannot race to own the vault.'
              : failure.message}
          </AlertDescription>
        </Alert>
      ) : null}

      <form onSubmit={onSubmit} className="space-y-5" noValidate>
        <fieldset className="space-y-4" disabled={isSubmitting}>
          <div className="space-y-1.5">
            <Label htmlFor="setupToken">Bootstrap token</Label>
            <div className="flex gap-2">
              <Input
                id="setupToken"
                type={showToken ? 'text' : 'password'}
                autoComplete="off"
                spellCheck={false}
                aria-invalid={Boolean(errors.setupToken)}
                aria-describedby="setupToken-help"
                {...register('setupToken')}
              />
              <Button
                type="button"
                variant="outline"
                size="icon"
                aria-label={showToken ? 'Hide the token' : 'Show the token'}
                onClick={() => setShowToken((shown) => !shown)}
              >
                {showToken ? (
                  <EyeOff className="size-4" aria-hidden="true" />
                ) : (
                  <Eye className="size-4" aria-hidden="true" />
                )}
              </Button>
            </div>
            <p id="setupToken-help" className="text-xs text-muted-foreground">
              The service’s <code>SETUP_BOOTSTRAP_TOKEN</code>. It is compared in constant time and
              never stored by this console.
            </p>
            {errors.setupToken ? (
              <p className="text-xs text-destructive">{errors.setupToken.message}</p>
            ) : null}
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="controller">Controller</Label>
            <Input
              id="controller"
              autoComplete="off"
              placeholder="ops@example.com"
              aria-invalid={Boolean(errors.controller)}
              {...register('controller')}
            />
            <p className="text-xs text-muted-foreground">
              Who is closing the setup window. Recorded on the durable lock and in the audit trail.
            </p>
            {errors.controller ? (
              <p className="text-xs text-destructive">{errors.controller.message}</p>
            ) : null}
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="tenant">Tenant slug</Label>
              <Input id="tenant" placeholder="default" autoComplete="off" {...register('tenant')} />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="tenantDisplayName">Tenant display name</Label>
              <Input id="tenantDisplayName" autoComplete="off" {...register('tenantDisplayName')} />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="project">Default project</Label>
              <Input
                id="project"
                placeholder="default"
                autoComplete="off"
                {...register('project')}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="environment">Default environment</Label>
              <Input
                id="environment"
                placeholder="default"
                autoComplete="off"
                {...register('environment')}
              />
            </div>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="authTenantUuid">Auth tenant UUID (optional)</Label>
            <Input
              id="authTenantUuid"
              autoComplete="off"
              spellCheck={false}
              aria-invalid={Boolean(errors.authTenantUuid)}
              {...register('authTenantUuid')}
            />
            <p className="text-xs text-muted-foreground">
              Links this tenant to a maintainerd-auth tenant. Leave empty for a standalone install,
              which owns its own tenant names.
            </p>
            {errors.authTenantUuid ? (
              <p className="text-xs text-destructive">{errors.authTenantUuid.message}</p>
            ) : null}
          </div>
        </fieldset>

        <Button type="submit" disabled={isSubmitting}>
          {isSubmitting ? 'Provisioning…' : 'Provision and close setup'}
        </Button>
      </form>
    </div>
  )
}
