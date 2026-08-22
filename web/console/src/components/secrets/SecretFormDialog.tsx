import { useEffect, useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { Eye, EyeOff } from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
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
 * THE VALUE FIELD IS `type=password` WITH AN EXPLICIT SHOW TOGGLE, and it is
 * never given an autocomplete hint the browser could act on: a password manager
 * offering to save a production database credential typed into an admin console
 * is not a feature. The typed value is base64-encoded on submit and the form is
 * reset the moment the dialog closes, so it is not left sitting in React state
 * behind a closed dialog.
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
  const [showValue, setShowValue] = useState(false)

  const {
    register,
    handleSubmit,
    reset,
    setValue: setField,
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
      setShowValue(false)
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
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>
            {mode === 'edit-metadata'
              ? 'Metadata only. This cannot change the value.'
              : `In ${project} / ${environment} at ${normalizePath(folderPath)}`}
          </DialogDescription>
        </DialogHeader>

        <form id="secret-form" onSubmit={onSubmit} className="space-y-4" noValidate>
          <fieldset className="space-y-4" disabled={isSubmitting}>
            {mode === 'create' ? (
              <div className="space-y-1.5">
                <Label htmlFor="secret-key">Key</Label>
                <Input
                  id="secret-key"
                  autoComplete="off"
                  spellCheck={false}
                  placeholder="DATABASE_PASSWORD"
                  aria-invalid={Boolean(errors.key)}
                  {...register('key', { required: true })}
                />
              </div>
            ) : null}

            {needsValue ? (
              <>
                <div className="space-y-1.5">
                  <Label htmlFor="secret-value">Value</Label>
                  <div className="flex gap-2">
                    <Input
                      id="secret-value"
                      type={showValue ? 'text' : 'password'}
                      autoComplete="off"
                      spellCheck={false}
                      aria-describedby="secret-value-help"
                      {...register('value')}
                    />
                    <Button
                      type="button"
                      variant="outline"
                      size="icon"
                      aria-label={showValue ? 'Hide the value' : 'Show the value'}
                      onClick={() => setShowValue((shown) => !shown)}
                    >
                      {showValue ? (
                        <EyeOff className="size-4" aria-hidden="true" />
                      ) : (
                        <Eye className="size-4" aria-hidden="true" />
                      )}
                    </Button>
                  </div>
                  <p id="secret-value-help" className="text-xs text-muted-foreground">
                    {valueType === VALUE_TYPE_REFERENCE
                      ? 'A reference points at another secret: ${project/environment/folder/KEY}. Reading it re-checks your grant on the target, at every hop.'
                      : 'Writing the same value again is a no-op — the service compares checksums and does not create a duplicate version.'}
                  </p>
                </div>

                <div className="space-y-1.5">
                  <Label htmlFor="secret-value-type">Value type</Label>
                  <Select
                    value={valueType}
                    onValueChange={(next) => setField('valueType', next)}
                  >
                    <SelectTrigger id="secret-value-type" className="w-full">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value={VALUE_TYPE_OPAQUE}>opaque</SelectItem>
                      <SelectItem value={VALUE_TYPE_JSON}>json</SelectItem>
                      <SelectItem value={VALUE_TYPE_REFERENCE}>reference</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </>
            ) : null}

            <div className="space-y-1.5">
              <Label htmlFor="secret-description">Description</Label>
              <Textarea id="secret-description" rows={2} {...register('description')} />
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="secret-tags">Tags</Label>
              <Input
                id="secret-tags"
                placeholder="database, prod"
                autoComplete="off"
                {...register('tags')}
              />
              <p className="text-xs text-muted-foreground">Comma-separated.</p>
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label htmlFor="secret-expires">Expires at</Label>
                <Input id="secret-expires" type="datetime-local" {...register('expiresAt')} />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="secret-keep">Versions to keep</Label>
                <Input id="secret-keep" type="number" min={1} {...register('keepVersions')} />
              </div>
            </div>
          </fieldset>
        </form>

        <DialogFooter>
          <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button type="submit" form="secret-form" disabled={isSubmitting}>
            {isSubmitting ? 'Saving…' : 'Save'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
