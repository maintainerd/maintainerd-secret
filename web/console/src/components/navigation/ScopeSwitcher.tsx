import { useState } from 'react'
import { Check, ChevronsUpDown } from 'lucide-react'

import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from '@/components/ui/command'
import { useScope } from '@/context/scopeContext'

/**
 * The project + environment switcher, in the top bar.
 *
 * Structurally this is maintainerd-auth's `components/navigation/TenantSwitcher`
 * — a ghost combobox on the dark brand bar opening a searchable command list —
 * applied twice, because secret's scope is a PAIR rather than a single tenant.
 *
 * It lives in the shell rather than on each page for the same reason auth's
 * tenant switcher does: every address in this console is relative to it, and
 * "which environment am I about to write to" must be answerable without
 * scrolling. Unlike auth, switching does NOT re-authenticate — the scope is a
 * view over one tenant's hierarchy, not a different session.
 */

interface ScopeComboboxProps {
  label: string
  value: string | null
  options: { id: string; slug: string; name?: string }[]
  onSelect: (slug: string) => void
  loading: boolean
  emptyLabel: string
  searchPlaceholder: string
  disabled?: boolean
}

function ScopeCombobox({
  label,
  value,
  options,
  onSelect,
  loading,
  emptyLabel,
  searchPlaceholder,
  disabled = false,
}: ScopeComboboxProps) {
  const [open, setOpen] = useState(false)

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          data-console-top-dropdown-trigger
          variant="ghost"
          role="combobox"
          aria-expanded={open}
          aria-label={`Switch ${label.toLowerCase()}`}
          disabled={disabled}
          className="h-9 w-44 gap-1.5 border border-slate-700 bg-white/5 px-2 text-xs text-slate-300 hover:bg-white/10 hover:text-white active:!bg-white/15 active:!text-white data-[state=open]:!bg-white/15 data-[state=open]:!text-white"
        >
          <span className="shrink-0 text-[10px] font-normal uppercase tracking-wide text-slate-500">
            {label}
          </span>
          {loading && !value ? (
            <Skeleton className="h-3.5 w-16" />
          ) : (
            <span className="min-w-0 flex-1 truncate text-left font-medium">
              {value ?? emptyLabel}
            </span>
          )}
          <ChevronsUpDown className="ml-auto size-3.5 shrink-0 text-slate-400" />
        </Button>
      </PopoverTrigger>

      <PopoverContent className="w-64 p-0" align="start">
        <Command>
          <CommandInput placeholder={searchPlaceholder} />
          <CommandList>
            {loading ? (
              <div className="space-y-2 p-2">
                {Array.from({ length: 3 }).map((_, index) => (
                  <Skeleton key={index} className="h-4 w-32" />
                ))}
              </div>
            ) : (
              <>
                <CommandEmpty>{emptyLabel}</CommandEmpty>
                <CommandGroup heading={label}>
                  {options.map((option) => (
                    <CommandItem
                      key={option.id}
                      value={option.slug}
                      onSelect={() => {
                        onSelect(option.slug)
                        setOpen(false)
                      }}
                      className="cursor-pointer gap-2"
                    >
                      <div className="flex min-w-0 flex-col">
                        <span className="truncate font-mono font-medium">{option.slug}</span>
                        {option.name && option.name !== option.slug && (
                          <span className="truncate text-xs text-muted-foreground">
                            {option.name}
                          </span>
                        )}
                      </div>
                      <Check
                        className={cn(
                          'ml-auto size-4 text-primary',
                          option.slug === value ? 'opacity-100' : 'opacity-0',
                        )}
                      />
                    </CommandItem>
                  ))}
                </CommandGroup>
              </>
            )}
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  )
}

export function ScopeSwitcher({ className }: { className?: string }) {
  const { projects, environments, project, environment, setProject, setEnvironment, loading } =
    useScope()

  return (
    <div className={cn('flex min-w-0 items-center gap-2', className)}>
      <ScopeCombobox
        label="Project"
        value={project}
        options={projects.map((candidate) => ({
          id: candidate.project_uuid,
          slug: candidate.slug,
          name: candidate.name,
        }))}
        onSelect={setProject}
        loading={loading}
        emptyLabel="No projects"
        searchPlaceholder="Search projects…"
      />
      <ScopeCombobox
        label="Env"
        value={environment}
        options={environments.map((candidate) => ({
          id: candidate.environment_uuid,
          slug: candidate.slug,
          name: candidate.name,
        }))}
        onSelect={setEnvironment}
        loading={loading}
        emptyLabel="No environments"
        searchPlaceholder="Search environments…"
        disabled={environments.length === 0}
      />
    </div>
  )
}
