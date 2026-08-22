import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useScope } from '@/context/scopeContext'

/**
 * The project + environment switcher.
 *
 * It lives in the shell rather than on each page because it is the single most
 * important piece of context in this console: every address is relative to it,
 * and "which environment is this" must be answerable without scrolling.
 */
export function ScopeSwitcher() {
  const { projects, environments, project, environment, setProject, setEnvironment, loading } =
    useScope()

  return (
    <div className="flex flex-wrap items-center gap-3">
      <div className="flex items-center gap-2">
        <Label htmlFor="scope-project" className="text-xs text-muted-foreground">
          Project
        </Label>
        <Select value={project ?? ''} onValueChange={setProject} disabled={loading}>
          <SelectTrigger id="scope-project" className="w-44" size="sm">
            <SelectValue placeholder={loading ? 'Loading…' : 'No projects'} />
          </SelectTrigger>
          <SelectContent>
            {projects.map((candidate) => (
              <SelectItem key={candidate.project_uuid} value={candidate.slug}>
                {candidate.slug}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <div className="flex items-center gap-2">
        <Label htmlFor="scope-environment" className="text-xs text-muted-foreground">
          Environment
        </Label>
        <Select
          value={environment ?? ''}
          onValueChange={setEnvironment}
          disabled={loading || environments.length === 0}
        >
          <SelectTrigger id="scope-environment" className="w-44" size="sm">
            <SelectValue placeholder={loading ? 'Loading…' : 'No environments'} />
          </SelectTrigger>
          <SelectContent>
            {environments.map((candidate) => (
              <SelectItem key={candidate.environment_uuid} value={candidate.slug}>
                {candidate.slug}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
    </div>
  )
}
