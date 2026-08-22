import { useEffect, useState } from 'react'
import { RefreshCw, Timer } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { InformationCard } from '@/components/card'
import {
  FormInputField,
  FormPasswordField,
  FormSelectField,
  FormSwitchField,
} from '@/components/form'
import { ConfirmDialog } from '@/components/ConfirmDialog'
import { useRotateSecret, useSetRotationPolicy } from '@/hooks/useSecrets'
import { encodeUtf8ToBase64 } from '@/lib/base64'
import { formatRelative } from '@/lib/formatDate'
import {
  GENERATOR_RANDOM,
  GENERATOR_SUPPLIED,
  type RotationPolicy,
  type SecretAddress,
  type SecretMeta,
} from '@/services/api/types'

/**
 * Rotation: the stored policy, and rotate-now.
 *
 * Composed from maintainerd-auth's `InformationCard` plus its field components,
 * so this reads like auth's own configuration surfaces (MFA config, token
 * config) rather than a bespoke panel.
 *
 * TWO THINGS THE UI HAS TO KEEP STRAIGHT, because the service enforces both:
 *
 *  1. A STORED POLICY MUST NOT CARRY A VALUE. The policy lives in readable
 *     metadata, so a supplied value in it would be a credential sitting in a
 *     field anyone with metadata access can read. The service refuses it; the
 *     form therefore offers `supplied` only on rotate-now, never on the policy.
 *  2. THE ROTATED VALUE IS NOT IN THE RESPONSE. Reading it after a rotation is a
 *     reveal, with its own grant and its own audit row — so this panel points at
 *     the reveal action instead of quietly showing what it just wrote.
 */

const DEFAULT_CHARSET = ''

const GENERATOR_OPTIONS = [
  { value: GENERATOR_RANDOM, label: 'random' },
  { value: GENERATOR_SUPPLIED, label: 'supplied' },
]

function readPolicy(meta: SecretMeta | undefined): RotationPolicy {
  const raw = meta?.rotation_policy
  if (!raw || typeof raw !== 'object') return {}
  return raw as RotationPolicy
}

export function RotationPanel({
  address,
  meta,
}: {
  address: SecretAddress
  meta: SecretMeta | undefined
}) {
  const stored = readPolicy(meta)
  const storedGenerator = stored.generator ?? {}

  const [enabled, setEnabled] = useState<boolean>(Boolean(stored.enabled))
  const [interval, setIntervalValue] = useState<string>(stored.interval ?? '720h')
  const [length, setLength] = useState<string>(
    storedGenerator.length ? String(storedGenerator.length) : '32',
  )
  const [charset, setCharset] = useState<string>(storedGenerator.charset ?? DEFAULT_CHARSET)

  const [rotateOpen, setRotateOpen] = useState(false)
  const [rotateType, setRotateType] = useState<string>(GENERATOR_RANDOM)
  const [suppliedValue, setSuppliedValue] = useState('')

  const setPolicy = useSetRotationPolicy()
  const rotate = useRotateSecret()

  useEffect(() => {
    const next = readPolicy(meta)
    setEnabled(Boolean(next.enabled))
    setIntervalValue(next.interval ?? '720h')
    setLength(next.generator?.length ? String(next.generator.length) : '32')
    setCharset(next.generator?.charset ?? DEFAULT_CHARSET)
  }, [meta])

  const savePolicy = async () => {
    await setPolicy.mutateAsync({
      address,
      enabled,
      interval: interval.trim() || undefined,
      generator: {
        type: GENERATOR_RANDOM,
        ...(length ? { length: Number(length) } : {}),
        ...(charset ? { charset } : {}),
      },
    })
  }

  const runRotation = async () => {
    await rotate.mutateAsync({
      address,
      generator:
        rotateType === GENERATOR_SUPPLIED
          ? { type: GENERATOR_SUPPLIED, value: encodeUtf8ToBase64(suppliedValue) }
          : {
              type: GENERATOR_RANDOM,
              ...(length ? { length: Number(length) } : {}),
              ...(charset ? { charset } : {}),
            },
    })
    setSuppliedValue('')
    setRotateOpen(false)
  }

  return (
    <div className="space-y-6">
      <InformationCard
        title="Rotation policy"
        icon={Timer}
        description={`Last rotated ${formatRelative(meta?.rotated_at)}.`}
      >
        <div className="space-y-5">
          <FormSwitchField
            id="rotation-enabled"
            label="Scheduled rotation"
            description="When on, the service rotates this secret on the interval below."
            checked={enabled}
            onCheckedChange={setEnabled}
          />

          <div className="grid gap-5 sm:grid-cols-3">
            <FormInputField
              id="rotation-interval"
              label="Interval"
              value={interval}
              onChange={(event) => setIntervalValue(event.target.value)}
              placeholder="720h"
              autoComplete="off"
              description="A duration, e.g. 720h for 30 days."
            />
            <FormInputField
              id="rotation-length"
              label="Generated length"
              type="number"
              min={1}
              value={length}
              onChange={(event) => setLength(event.target.value)}
            />
            <FormInputField
              id="rotation-charset"
              label="Charset"
              value={charset}
              onChange={(event) => setCharset(event.target.value)}
              placeholder="service default"
              autoComplete="off"
            />
          </div>

          <p className="text-xs text-muted-foreground">
            A stored policy generates a new random value. It cannot carry a supplied value — the
            policy is readable metadata, and a value in it would be a credential in a metadata
            field.
          </p>

          <Button size="sm" onClick={() => void savePolicy()} disabled={setPolicy.isPending}>
            {setPolicy.isPending ? 'Saving…' : 'Save policy'}
          </Button>
        </div>
      </InformationCard>

      <InformationCard
        title="Rotate now"
        icon={RefreshCw}
        description="Writes a new version immediately. The new value is not returned — reading it is a separate, audited reveal."
      >
        <div className="space-y-5">
          <div className="grid gap-5 sm:grid-cols-2">
            <FormSelectField
              id="rotate-generator"
              label="Generator"
              options={GENERATOR_OPTIONS}
              value={rotateType}
              onValueChange={setRotateType}
            />
            {rotateType === GENERATOR_SUPPLIED && (
              <FormPasswordField
                id="rotate-supplied"
                label="New value"
                spellCheck={false}
                value={suppliedValue}
                onChange={(event) => setSuppliedValue(event.target.value)}
              />
            )}
          </div>
          <Button variant="outline" size="sm" onClick={() => setRotateOpen(true)}>
            <RefreshCw className="size-4" aria-hidden="true" />
            Rotate now
          </Button>
        </div>
      </InformationCard>

      <ConfirmDialog
        open={rotateOpen}
        onOpenChange={setRotateOpen}
        title={`Rotate ${address.key}?`}
        confirmLabel="Rotate"
        pending={rotate.isPending}
        onConfirm={() => void runRotation()}
        description={
          <>
            <p>
              This writes a new version immediately. Anything still using the current value will
              keep working only until it re-reads.
            </p>
            <p>The new value is not returned here — reading it is a separate, audited reveal.</p>
          </>
        }
      />
    </div>
  )
}
