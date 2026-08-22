import { useEffect, useState } from 'react'
import { RefreshCw } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
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
      <section className="space-y-4">
        <div className="flex items-center justify-between gap-4">
          <div>
            <h3 className="text-sm font-medium">Rotation policy</h3>
            <p className="text-xs text-muted-foreground">
              Last rotated {formatRelative(meta?.rotated_at)}.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Switch
              id="rotation-enabled"
              checked={enabled}
              onCheckedChange={setEnabled}
              aria-label="Enable scheduled rotation"
            />
            <Label htmlFor="rotation-enabled" className="text-sm">
              {enabled ? 'Enabled' : 'Disabled'}
            </Label>
          </div>
        </div>

        <div className="grid gap-4 sm:grid-cols-3">
          <div className="space-y-1.5">
            <Label htmlFor="rotation-interval">Interval</Label>
            <Input
              id="rotation-interval"
              value={interval}
              onChange={(event) => setIntervalValue(event.target.value)}
              placeholder="720h"
              autoComplete="off"
            />
            <p className="text-xs text-muted-foreground">A duration, e.g. 720h for 30 days.</p>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="rotation-length">Generated length</Label>
            <Input
              id="rotation-length"
              type="number"
              min={1}
              value={length}
              onChange={(event) => setLength(event.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="rotation-charset">Charset</Label>
            <Input
              id="rotation-charset"
              value={charset}
              onChange={(event) => setCharset(event.target.value)}
              placeholder="service default"
              autoComplete="off"
            />
          </div>
        </div>

        <p className="text-xs text-muted-foreground">
          A stored policy generates a new random value. It cannot carry a supplied value — the
          policy is readable metadata, and a value in it would be a credential in a metadata field.
        </p>

        <Button size="sm" onClick={() => void savePolicy()} disabled={setPolicy.isPending}>
          {setPolicy.isPending ? 'Saving…' : 'Save policy'}
        </Button>
      </section>

      <section className="space-y-3 border-t pt-6">
        <h3 className="text-sm font-medium">Rotate now</h3>
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-1.5">
            <Label htmlFor="rotate-generator">Generator</Label>
            <Select value={rotateType} onValueChange={setRotateType}>
              <SelectTrigger id="rotate-generator" className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={GENERATOR_RANDOM}>random</SelectItem>
                <SelectItem value={GENERATOR_SUPPLIED}>supplied</SelectItem>
              </SelectContent>
            </Select>
          </div>
          {rotateType === GENERATOR_SUPPLIED ? (
            <div className="space-y-1.5">
              <Label htmlFor="rotate-supplied">New value</Label>
              <Input
                id="rotate-supplied"
                type="password"
                autoComplete="off"
                spellCheck={false}
                value={suppliedValue}
                onChange={(event) => setSuppliedValue(event.target.value)}
              />
            </div>
          ) : null}
        </div>
        <Button variant="outline" size="sm" onClick={() => setRotateOpen(true)}>
          <RefreshCw className="size-4" aria-hidden="true" />
          Rotate now
        </Button>
      </section>

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
            <p>
              The new value is not returned here — reading it is a separate, audited reveal.
            </p>
          </>
        }
      />
    </div>
  )
}
