import { useState } from 'react'
import { Eye, Info } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { PageHeader } from '@/components/layout/PageHeader'
import { EmptyState, ErrorState, LoadingRows } from '@/components/layout/states'
import { EMPTY_AUDIT_FILTERS, useAudit, type AuditFilters } from '@/hooks/useAudit'
import { formatDateTime } from '@/lib/formatDate'
import { cn } from '@/lib/utils'
import { AUDIT_ACTIONS, SENSITIVE_AUDIT_ACTIONS } from '@/services/api/types'

const ANY = '__any__'
const PAGE_SIZE = 100

/**
 * The access trail.
 *
 * REVEALS ARE VISUALLY DISTINCT because they are the sensitive event. Reading
 * metadata and reading a value are different grants in this service precisely so
 * an incident review can tell "who listed the secrets" from "who saw the
 * production database password" — a trail that renders both identically throws
 * that distinction away at the last step.
 *
 * `secret.reference` is marked the same way: a reference hop IS a decryption of
 * the target's value, and it is the row that answers "what did this caller
 * actually read" when they only ever revealed a pointer.
 */
export default function AuditPage() {
  const [page, setPage] = useState(1)
  const [filters, setFilters] = useState<AuditFilters>(EMPTY_AUDIT_FILTERS)
  const audit = useAudit({ page, limit: PAGE_SIZE }, filters)

  const update = (patch: Partial<AuditFilters>) =>
    setFilters((current) => ({ ...current, ...patch }))

  const lastPage = Math.max(1, Math.ceil(audit.total / PAGE_SIZE))

  return (
    <div className="space-y-6">
      <PageHeader
        title="Audit log"
        description="Every read, write, rotation and denial. Reading this page is itself audited."
      />

      <div className="flex items-start gap-2 rounded-md border bg-muted/40 p-3 text-xs text-muted-foreground">
        <Info className="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />
        <p>
          The API pages the trail but does not search it: filters below narrow the{' '}
          <strong>{audit.fetchedCount}</strong> {audit.fetchedCount === 1 ? 'row' : 'rows'} on this
          page, not all {audit.total}. Page through to widen the window.
        </p>
      </div>

      <div className="grid gap-3 md:grid-cols-3 lg:grid-cols-6">
        <div className="space-y-1.5">
          <Label htmlFor="filter-action">Action</Label>
          <Select
            value={filters.action || ANY}
            onValueChange={(value) => update({ action: value === ANY ? '' : value })}
          >
            <SelectTrigger id="filter-action" size="sm" className="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={ANY}>Any action</SelectItem>
              {AUDIT_ACTIONS.map((action) => (
                <SelectItem key={action} value={action}>
                  {action}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <div className="space-y-1.5">
          <Label htmlFor="filter-outcome">Outcome</Label>
          <Select
            value={filters.outcome || ANY}
            onValueChange={(value) => update({ outcome: value === ANY ? '' : value })}
          >
            <SelectTrigger id="filter-outcome" size="sm" className="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={ANY}>Any outcome</SelectItem>
              <SelectItem value="success">success</SelectItem>
              <SelectItem value="denied">denied</SelectItem>
              <SelectItem value="error">error</SelectItem>
            </SelectContent>
          </Select>
        </div>

        <div className="space-y-1.5">
          <Label htmlFor="filter-actor">Actor</Label>
          <Input
            id="filter-actor"
            value={filters.actor}
            onChange={(event) => update({ actor: event.target.value })}
          />
        </div>

        <div className="space-y-1.5">
          <Label htmlFor="filter-resource">Secret / MRN</Label>
          <Input
            id="filter-resource"
            value={filters.resource}
            onChange={(event) => update({ resource: event.target.value })}
          />
        </div>

        <div className="space-y-1.5">
          <Label htmlFor="filter-from">From</Label>
          <Input
            id="filter-from"
            type="date"
            value={filters.from}
            onChange={(event) => update({ from: event.target.value })}
          />
        </div>

        <div className="space-y-1.5">
          <Label htmlFor="filter-to">To</Label>
          <Input
            id="filter-to"
            type="date"
            value={filters.to}
            onChange={(event) => update({ to: event.target.value })}
          />
        </div>
      </div>

      {audit.isLoading ? <LoadingRows rows={8} /> : null}
      {audit.isError ? <ErrorState error={audit.error} onRetry={() => void audit.refetch()} /> : null}
      {!audit.isLoading && !audit.isError && audit.entries.length === 0 ? (
        <EmptyState
          title="No matching events"
          description="Nothing on this page matches. Try another page or clear the filters."
          action={
            <Button variant="outline" size="sm" onClick={() => setFilters(EMPTY_AUDIT_FILTERS)}>
              Clear filters
            </Button>
          }
        />
      ) : null}

      {audit.entries.length > 0 ? (
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>When</TableHead>
                <TableHead>Action</TableHead>
                <TableHead>Actor</TableHead>
                <TableHead>Resource</TableHead>
                <TableHead>Outcome</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {audit.entries.map((entry) => {
                const sensitive = SENSITIVE_AUDIT_ACTIONS.has(entry.action)
                return (
                  <TableRow
                    key={entry.event_uuid}
                    className={cn(
                      sensitive && 'bg-amber-50 dark:bg-amber-950/30',
                      entry.outcome === 'denied' && 'bg-destructive/10',
                    )}
                  >
                    <TableCell className="whitespace-nowrap text-sm">
                      {formatDateTime(entry.created_at)}
                    </TableCell>
                    <TableCell>
                      <span className="flex items-center gap-1.5">
                        {sensitive ? (
                          <Eye className="size-3.5 text-amber-600" aria-hidden="true" />
                        ) : null}
                        <span className={cn(sensitive && 'font-medium')}>{entry.action}</span>
                        {sensitive ? <span className="sr-only">(value was read)</span> : null}
                      </span>
                    </TableCell>
                    <TableCell className="max-w-48">
                      <div className="truncate">{entry.actor_subject || '—'}</div>
                      <div className="text-xs text-muted-foreground">{entry.actor_kind}</div>
                    </TableCell>
                    <TableCell className="max-w-96 truncate font-mono text-xs">
                      {entry.resource_mrn}
                      {entry.version ? ` · v${entry.version}` : ''}
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={
                          entry.outcome === 'success'
                            ? 'secondary'
                            : entry.outcome === 'denied'
                              ? 'destructive'
                              : 'outline'
                        }
                      >
                        {entry.outcome}
                      </Badge>
                      {entry.reason ? (
                        <div className="mt-1 text-xs text-muted-foreground">{entry.reason}</div>
                      ) : null}
                    </TableCell>
                  </TableRow>
                )
              })}
            </TableBody>
          </Table>
        </div>
      ) : null}

      <div className="flex items-center justify-between gap-3">
        <p className="text-xs text-muted-foreground">
          Page {page} of {lastPage} · {audit.total} events
        </p>
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            disabled={page <= 1}
            onClick={() => setPage((current) => Math.max(1, current - 1))}
          >
            Previous
          </Button>
          <Button
            variant="outline"
            size="sm"
            disabled={page >= lastPage}
            onClick={() => setPage((current) => current + 1)}
          >
            Next
          </Button>
        </div>
      </div>
    </div>
  )
}
