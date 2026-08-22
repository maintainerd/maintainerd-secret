import { useEffect } from 'react'
import { useForm, Controller } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { KeyRound } from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import {
  FormInputField,
  FormPasswordField,
  FormSelectField,
  FormSubmitButton,
  FormTextareaField,
} from '@/components/form'
import { usePutSecret, useUpdateSecretMeta } from '@/hooks/useSecrets'
import { encodeUtf8ToBase64 } from '@/lib/base64'
import { fromDateTimeLocalInput, toDateTimeLocalInput } from '@/lib/formatDate'
import { normalizePath } from '@/lib/paths'
import {
  VALUE_TYPE_JSON,
  VALUE_TYPE_OPAQUE,
  VALUE_TYPE_REFERENCE,
  type SecretMeta,
} from '@/services/api/types'

/**
 * Create a secret, write a new version, or edit metadata.
 *
 * THE VALUE FIELD IS A PASSWORD FIELD WITH AN EXPLICIT SHOW TOGGLE — auth's
 * `FormPasswordField`, which defaults `autoComplete` to "new-password" for
 * precisely this reason: a password manager offering to save a production
 * database credential typed into an admin console is not a feature. The typed
 * value is base64-encoded on submit and the form is reset the moment the dialog
 * closes, so it is not left sitting in React state behind a closed dialog.
 *
 * Metadata edits go through a DIFFERENT endpoint (`PATCH /secrets`) that cannot
 * change a value at all — which is why "edit metadata" here does not ask for one
 * and cannot accidentally write an empty version.
 */

export type SecretFormMode = 'create' | 'new-version' | 'edit-metadata'

const schema = z.object({
  key: z.string().optional(),
  value: z.string().optional(),
  valueType: z.string(),
  description: z.string().optional(),
  tags: z.string().optional(),
  expiresAt: z.string().optional(),
  keepVersions: z.string().optional(),
})

type SecretForm = z.infer<typeof schema>

const VALUE_TYPE_OPTIONS = [
  { value: VALUE_TYPE_OPAQUE, label: 'opaque' },
  { value: VALUE_TYPE_JSON, label: 'json' },
  { value: VALUE_TYPE_REFERENCE, label: 'reference' },
]

function parseTags(raw: string | undefined): string[] {
  if (!raw) return []
  return raw
    .split(',')
    .map((tag) => tag.trim())
    .filter(Boolean)
}

export function SecretFormDialog({
  mode,
  project,
  environment,
  folderPath,
  secret,
  open,
  onOpenChange,
}: {
  mode: SecretFormMode
  project: string
  environment: string
  folderPath: string
  /** The secret being edited. Required for every mode but `create`. */
  secret?: SecretMeta | null
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const put = usePutSecret()
  const updateMeta = useUpdateSecretMeta()

  const {
    register,
    handleSubmit,
    reset,
    control,
    watch,
    formState: { errors, isSubmitting },
  } = useForm<SecretForm>({
    resolver: zodResolver(schema),
    defaultValues: { valueType: VALUE_TYPE_OPAQUE },
  })

  const valueType = watch('valueType')

  useEffect(() => {
    if (!open) {
      // Drop the typed plaintext as soon as the dialog closes.
      reset({ valueType: VALUE_TYPE_OPAQUE })
      return
    }
    reset({
      key: secret?.key ?? '',
      value: '',
      valueType: VALUE_TYPE_OPAQUE,
      description: secret?.description ?? '',
      tags: (secret?.tags ?? []).join(', '),
      expiresAt: toDateTimeLocalInput(secret?.expires_at),
      keepVersions: secret?.keep_versions ? String(secret.keep_versions) : '',
    })
  }, [open, secret, reset])

  const onSubmit = handleSubmit(async (values) => {
    const key = mode === 'create' ? (values.key ?? '').trim() : (secret?.key ?? '')
    const address = {
      project,
      environment,
      folder_path: normalizePath(folderPath),
      key,
    }

    if (mode === 'edit-metadata') {
      await updateMeta.mutateAsync({
        ...address,
        description: values.description ?? '',
        tags: parseTags(values.tags),
        expires_at: fromDateTimeLocalInput(values.expiresAt ?? ''),
        ...(values.keepVersions ? { keep_versions: Number(values.keepVersions) } : {}),
      })
      onOpenChange(false)
      return
    }

    await put.mutateAsync({
      ...address,
      value: encodeUtf8ToBase64(values.value ?? ''),
      value_type: values.valueType,
      description: values.description ?? '',
      tags: parseTags(values.tags),
      expires_at: fromDateTimeLocalInput(values.expiresAt ?? ''),
      ...(values.keepVersions ? { keep_versions: Number(values.keepVersions) } : {}),
      // Creating a secret in a folder that does not exist yet is a normal first
      // move; the service will not invent the folders unless asked.
      create_folders: mode === 'create',
    })
    onOpenChange(false)
  })

  const needsValue = mode !== 'edit-metadata'
  const title =
    mode === 'create'
      ? 'New secret'
      : mode === 'new-version'
        ? `New version of ${secret?.key ?? ''}`
        : `Edit ${secret?.key ?? ''}`

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-lg">
        <DialogHeader>
          <div className="flex items-center gap-3">
            <div className="flex size-9 shrink-0 items-center justify-center rounded-md bg-muted text-muted-foreground">
              <KeyRound className="size-5" aria-hidden="true" />
            </div>
            <DialogTitle>{title}</DialogTitle>
          </div>
          <DialogDescription className="pt-1 text-left">
            {mode === 'edit-metadata' ? (
              'Metadata only. This cannot change the value.'
            ) : (
              <>
                In <span className="font-mono">{project}</span> /{' '}
                <span className="font-mono">{environment}</span> at{' '}
                <span className="font-mono">{normalizePath(folderPath)}</span>
              </>
            )}
          </DialogDescription>
        </DialogHeader>

        <form id="secret-form" onSubmit={onSubmit} className="space-y-5" noValidate>
          <fieldset className="space-y-5" disabled={isSubmitting}>
            {mode === 'create' && (
              <FormInputField
                id="secret-key"
                label="Key"
                required
                autoComplete="off"
                spellCheck={false}
                placeholder="DATABASE_PASSWORD"
                error={errors.key?.message}
                {...register('key', { required: true })}
              />
            )}

            {needsValue && (
              <>
                <FormPasswordField
                  id="secret-value"
                  label="Value"
                  required
                  spellCheck={false}
                  error={errors.value?.message}
                  description={
                    valueType === VALUE_TYPE_REFERENCE
                      ? 'A reference points at another secret: ${project/environment/folder/KEY}. Reading it re-checks your grant on the target, at every hop.'
                      : 'Writing the same value again is a no-op — the service compares checksums and does not create a duplicate version.'
                  }
                  {...register('value')}
                />

                <Controller
                  control={control}
                  name="valueType"
                  render={({ field }) => (
                    <FormSelectField
                      id="secret-value-type"
                      label="Value type"
                      options={VALUE_TYPE_OPTIONS}
                      value={field.value}
                      onValueChange={field.onChange}
                      error={errors.valueType?.message}
                    />
                  )}
                />
              </>
            )}

            <FormTextareaField
              id="secret-description"
              label="Description"
              rows={2}
              error={errors.description?.message}
              {...register('description')}
            />

            <FormInputField
              id="secret-tags"
              label="Tags"
              placeholder="database, prod"
              autoComplete="off"
              description="Comma-separated."
              error={errors.tags?.message}
              {...register('tags')}
            />

            <div className="grid gap-5 sm:grid-cols-2">
              <FormInputField
                id="secret-expires"
                label="Expires at"
                type="datetime-local"
                error={errors.expiresAt?.message}
                {...register('expiresAt')}
              />
              <FormInputField
                id="secret-keep"
                label="Versions to keep"
                type="number"
                min={1}
                description="Retention prunes the oldest beyond this, never the current one."
                error={errors.keepVersions?.message}
                {...register('keepVersions')}
              />
            </div>
          </fieldset>
        </form>

        <DialogFooter>
          <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <FormSubmitButton form="secret-form" isSubmitting={isSubmitting} submitText="Save" />
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
