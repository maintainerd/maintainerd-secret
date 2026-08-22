package api

import (
	"context"

	"github.com/maintainerd/secret/internal/audit"
	"github.com/maintainerd/secret/internal/platform/apperror"
	"github.com/maintainerd/secret/internal/platform/authz"
	"github.com/maintainerd/secret/internal/store"
)

// Hierarchy operations: projects, environments and folders.
//
// Each is authorized against the MRN of the thing being acted on — a project
// against `project`, an environment against `environment/<slug>`, a folder against
// `folder/<env>/<path>` — so a grant can be written for one environment's structure
// without carrying the next one's. A create is checked against the MRN the created
// thing WILL have, which is the only MRN that exists to check.

// ---------------------------------------------------------------------------
// Projects
// ---------------------------------------------------------------------------

// CreateProjectInput describes a new project.
type CreateProjectInput struct {
	Slug        string
	Name        string
	Description string
}

// CreateProject adds a project to the caller's tenant.
func (s *Service) CreateProject(ctx context.Context, c Caller, in CreateProjectInput) (*store.Project, error) {
	if err := validate(in); err != nil {
		return nil, err
	}
	resourceMRN := c.mrn(in.Slug, store.ResourceProject)
	if err := s.guard(ctx, c, authz.PermManageProject, store.ActionProjectCreate, resourceMRN); err != nil {
		return nil, err
	}
	project, err := s.store.CreateProject(ctx, store.CreateProjectInput{
		TenantUUID:  c.TenantUUID,
		Slug:        in.Slug,
		Name:        in.Name,
		Description: in.Description,
	})
	if err != nil {
		s.recordFailure(ctx, c, store.ActionProjectCreate, resourceMRN, err)
		return nil, err
	}
	if err := s.recordSuccess(ctx, c, audit.Event{
		Action:      store.ActionProjectCreate,
		ResourceMRN: resourceMRN,
	}); err != nil {
		return nil, err
	}
	return project, nil
}

// ListProjects pages the caller's tenant's projects.
//
// It is authorized against the TENANT-scoped project MRN (an empty project segment),
// which is the scope boundary in MRN semantics: a grant written for one project does
// not carry the ability to enumerate the tenant's others.
func (s *Service) ListProjects(ctx context.Context, c Caller, in ListProjectsInput) ([]store.Project, int64, error) {
	if err := validate(in); err != nil {
		return nil, 0, err
	}
	page, limit := in.Pagination.resolved()
	resourceMRN := c.mrn("", store.ResourceProject)
	if err := s.guard(ctx, c, authz.PermReadMetadata, store.ActionRead, resourceMRN); err != nil {
		return nil, 0, err
	}
	projects, total, err := s.store.ListProjects(ctx, c.TenantUUID, page, limit)
	if err != nil {
		s.recordFailure(ctx, c, store.ActionRead, resourceMRN, err)
		return nil, 0, err
	}
	if err := s.recordSuccess(ctx, c, audit.Event{
		Action:      store.ActionRead,
		ResourceMRN: resourceMRN,
		Metadata:    map[string]any{"projects": len(projects), "total": total},
	}); err != nil {
		return nil, 0, err
	}
	return projects, total, nil
}

// GetProject reads one project.
func (s *Service) GetProject(ctx context.Context, c Caller, slug string) (*store.Project, error) {
	if err := validate(ProjectRef{Slug: slug}); err != nil {
		return nil, err
	}
	resourceMRN := c.mrn(slug, store.ResourceProject)
	if err := s.guard(ctx, c, authz.PermReadMetadata, store.ActionRead, resourceMRN); err != nil {
		return nil, err
	}
	project, err := s.store.GetProject(ctx, c.TenantUUID, slug)
	if err != nil {
		s.recordFailure(ctx, c, store.ActionRead, resourceMRN, err)
		return nil, err
	}
	if err := s.recordSuccess(ctx, c, audit.Event{Action: store.ActionRead, ResourceMRN: resourceMRN}); err != nil {
		return nil, err
	}
	return project, nil
}

// UpdateProject rewrites a project's descriptive fields. The slug is not editable —
// it is an MRN segment, and renaming it would silently repoint every grant written
// against the old name.
func (s *Service) UpdateProject(ctx context.Context, c Caller, in UpdateProjectInput) (*store.Project, error) {
	if err := validate(in); err != nil {
		return nil, err
	}
	resourceMRN := c.mrn(in.Slug, store.ResourceProject)
	if err := s.guard(ctx, c, authz.PermManageProject, store.ActionProjectUpdate, resourceMRN); err != nil {
		return nil, err
	}
	project, err := s.store.UpdateProject(ctx, store.UpdateProjectInput{
		TenantUUID:  c.TenantUUID,
		Slug:        in.Slug,
		Name:        in.Name,
		Description: in.Description,
		Status:      in.Status,
	})
	if err != nil {
		s.recordFailure(ctx, c, store.ActionProjectUpdate, resourceMRN, err)
		return nil, err
	}
	if err := s.recordSuccess(ctx, c, audit.Event{Action: store.ActionProjectUpdate, ResourceMRN: resourceMRN}); err != nil {
		return nil, err
	}
	return project, nil
}

// DeleteProject soft-deletes a project. Its secrets are NOT destroyed — hard
// deletion of encrypted material is a separate, explicitly sanctioned operation, not
// a side effect of removing a project from a list.
func (s *Service) DeleteProject(ctx context.Context, c Caller, slug string) error {
	if err := validate(ProjectRef{Slug: slug}); err != nil {
		return err
	}
	resourceMRN := c.mrn(slug, store.ResourceProject)
	if err := s.guard(ctx, c, authz.PermManageProject, store.ActionProjectDelete, resourceMRN); err != nil {
		return err
	}
	project, err := s.store.GetProject(ctx, c.TenantUUID, slug)
	if err != nil {
		s.recordFailure(ctx, c, store.ActionProjectDelete, resourceMRN, err)
		return err
	}
	if err := s.store.DeleteProject(ctx, c.TenantUUID, project.UUID); err != nil {
		s.recordFailure(ctx, c, store.ActionProjectDelete, resourceMRN, err)
		return err
	}
	return s.recordSuccess(ctx, c, audit.Event{Action: store.ActionProjectDelete, ResourceMRN: resourceMRN})
}

// ---------------------------------------------------------------------------
// Environments
// ---------------------------------------------------------------------------

// CreateEnvironmentInput describes a new environment.
type CreateEnvironmentInput struct {
	Project     string
	Slug        string
	Name        string
	Description string
	Position    int32
}

// CreateEnvironment adds an environment to a project (and its root folder, in one
// transaction — see the store).
func (s *Service) CreateEnvironment(ctx context.Context, c Caller, in CreateEnvironmentInput) (*store.Environment, error) {
	if err := validate(in); err != nil {
		return nil, err
	}
	resourceMRN := c.mrn(in.Project, store.EnvironmentResourcePath(in.Slug))
	if err := s.guard(ctx, c, authz.PermManageEnvironment, store.ActionEnvironmentCreate, resourceMRN); err != nil {
		return nil, err
	}
	env, err := s.store.CreateEnvironment(ctx, store.CreateEnvironmentInput{
		TenantUUID:  c.TenantUUID,
		Project:     in.Project,
		Slug:        in.Slug,
		Name:        in.Name,
		Description: in.Description,
		Position:    in.Position,
	})
	if err != nil {
		s.recordFailure(ctx, c, store.ActionEnvironmentCreate, resourceMRN, err)
		return nil, err
	}
	if err := s.recordSuccess(ctx, c, audit.Event{Action: store.ActionEnvironmentCreate, ResourceMRN: resourceMRN}); err != nil {
		return nil, err
	}
	return env, nil
}

// ListEnvironments returns a project's environments in display order.
func (s *Service) ListEnvironments(ctx context.Context, c Caller, project string) ([]store.Environment, error) {
	if err := validate(ProjectRef{Slug: project}); err != nil {
		return nil, err
	}
	resourceMRN := c.mrn(project, store.ResourceProject)
	if err := s.guard(ctx, c, authz.PermReadMetadata, store.ActionRead, resourceMRN); err != nil {
		return nil, err
	}
	envs, err := s.store.ListEnvironments(ctx, c.TenantUUID, project)
	if err != nil {
		s.recordFailure(ctx, c, store.ActionRead, resourceMRN, err)
		return nil, err
	}
	if err := s.recordSuccess(ctx, c, audit.Event{
		Action:      store.ActionRead,
		ResourceMRN: resourceMRN,
		Metadata:    map[string]any{"environments": len(envs)},
	}); err != nil {
		return nil, err
	}
	return envs, nil
}

// GetEnvironment reads one environment.
func (s *Service) GetEnvironment(ctx context.Context, c Caller, project, slug string) (*store.Environment, error) {
	if err := validate(EnvironmentRef{Project: project, Slug: slug}); err != nil {
		return nil, err
	}
	resourceMRN := c.mrn(project, store.EnvironmentResourcePath(slug))
	if err := s.guard(ctx, c, authz.PermReadMetadata, store.ActionRead, resourceMRN); err != nil {
		return nil, err
	}
	env, err := s.store.GetEnvironment(ctx, c.TenantUUID, project, slug)
	if err != nil {
		s.recordFailure(ctx, c, store.ActionRead, resourceMRN, err)
		return nil, err
	}
	if err := s.recordSuccess(ctx, c, audit.Event{Action: store.ActionRead, ResourceMRN: resourceMRN}); err != nil {
		return nil, err
	}
	return env, nil
}

// UpdateEnvironment rewrites an environment's descriptive fields.
func (s *Service) UpdateEnvironment(ctx context.Context, c Caller, in UpdateEnvironmentInput) (*store.Environment, error) {
	if err := validate(in); err != nil {
		return nil, err
	}
	resourceMRN := c.mrn(in.Project, store.EnvironmentResourcePath(in.Slug))
	if err := s.guard(ctx, c, authz.PermManageEnvironment, store.ActionEnvironmentUpdate, resourceMRN); err != nil {
		return nil, err
	}
	env, err := s.store.UpdateEnvironment(ctx, store.UpdateEnvironmentInput{
		TenantUUID:  c.TenantUUID,
		Project:     in.Project,
		Slug:        in.Slug,
		Name:        in.Name,
		Description: in.Description,
		Position:    in.Position,
		Status:      in.Status,
	})
	if err != nil {
		s.recordFailure(ctx, c, store.ActionEnvironmentUpdate, resourceMRN, err)
		return nil, err
	}
	if err := s.recordSuccess(ctx, c, audit.Event{Action: store.ActionEnvironmentUpdate, ResourceMRN: resourceMRN}); err != nil {
		return nil, err
	}
	return env, nil
}

// DeleteEnvironment soft-deletes an environment.
func (s *Service) DeleteEnvironment(ctx context.Context, c Caller, project, slug string) error {
	if err := validate(EnvironmentRef{Project: project, Slug: slug}); err != nil {
		return err
	}
	resourceMRN := c.mrn(project, store.EnvironmentResourcePath(slug))
	if err := s.guard(ctx, c, authz.PermManageEnvironment, store.ActionEnvironmentDelete, resourceMRN); err != nil {
		return err
	}
	if err := s.store.DeleteEnvironment(ctx, c.TenantUUID, project, slug); err != nil {
		s.recordFailure(ctx, c, store.ActionEnvironmentDelete, resourceMRN, err)
		return err
	}
	return s.recordSuccess(ctx, c, audit.Event{Action: store.ActionEnvironmentDelete, ResourceMRN: resourceMRN})
}

// ---------------------------------------------------------------------------
// Folders
// ---------------------------------------------------------------------------

// CreateFolder creates a folder and any missing ancestors (mkdir -p). Creating an
// existing folder is a no-op returning the existing row.
func (s *Service) CreateFolder(ctx context.Context, c Caller, in CreateFolderInput) (*store.Folder, error) {
	if err := validate(in); err != nil {
		return nil, err
	}
	normalized, err := store.NormalizePath(in.Path)
	if err != nil {
		return nil, apperror.NewValidation(err.Error())
	}
	resourceMRN := c.mrn(in.Project, store.FolderResourcePath(in.Environment, normalized))
	if err := s.guard(ctx, c, authz.PermManageFolder, store.ActionFolderCreate, resourceMRN); err != nil {
		return nil, err
	}
	folder, err := s.store.CreateFolder(ctx, c.TenantUUID, in.Project, in.Environment, normalized)
	if err != nil {
		s.recordFailure(ctx, c, store.ActionFolderCreate, resourceMRN, err)
		return nil, err
	}
	if err := s.recordSuccess(ctx, c, audit.Event{Action: store.ActionFolderCreate, ResourceMRN: resourceMRN}); err != nil {
		return nil, err
	}
	return folder, nil
}

// ListFolders returns the folder subtree at or under a prefix.
func (s *Service) ListFolders(ctx context.Context, c Caller, in ListFoldersInput) ([]store.Folder, error) {
	if err := validate(in); err != nil {
		return nil, err
	}
	normalized, err := store.NormalizePath(in.Prefix)
	if err != nil {
		return nil, apperror.NewValidation(err.Error())
	}
	resourceMRN := c.mrn(in.Project, store.FolderResourcePath(in.Environment, normalized))
	if err := s.guard(ctx, c, authz.PermReadMetadata, store.ActionRead, resourceMRN); err != nil {
		return nil, err
	}
	folders, err := s.store.ListFolders(ctx, c.TenantUUID, in.Project, in.Environment, normalized)
	if err != nil {
		s.recordFailure(ctx, c, store.ActionRead, resourceMRN, err)
		return nil, err
	}
	if err := s.recordSuccess(ctx, c, audit.Event{
		Action:      store.ActionRead,
		ResourceMRN: resourceMRN,
		Metadata:    map[string]any{"folders": len(folders)},
	}); err != nil {
		return nil, err
	}
	return folders, nil
}

// MoveFolder relocates a folder and its whole subtree, recomputing the materialized
// paths AND the MRNs derived from them.
//
// It requires ManageFolder on BOTH the source and the destination. That is the
// non-obvious and load-bearing part: a move rewrites the MRN of every secret beneath
// the folder, so a principal who could move a subtree into a scope it controls could
// bring secrets it never had a grant on into the reach of one it does. Requiring the
// destination grant closes that; the audit row records both ends.
func (s *Service) MoveFolder(ctx context.Context, c Caller, in MoveFolderInput) (*store.Folder, error) {
	if err := validate(in); err != nil {
		return nil, err
	}
	fromPath, err := store.NormalizePath(in.From)
	if err != nil {
		return nil, apperror.NewValidation(err.Error())
	}
	toPath, err := store.NormalizePath(in.To)
	if err != nil {
		return nil, apperror.NewValidation(err.Error())
	}
	fromMRN := c.mrn(in.Project, store.FolderResourcePath(in.Environment, fromPath))
	toMRN := c.mrn(in.Project, store.FolderResourcePath(in.Environment, toPath))
	if err := s.guard(ctx, c, authz.PermManageFolder, store.ActionFolderMove, fromMRN); err != nil {
		return nil, err
	}
	if err := s.guard(ctx, c, authz.PermManageFolder, store.ActionFolderMove, toMRN); err != nil {
		return nil, err
	}
	folder, err := s.store.MoveFolder(ctx, c.TenantUUID, in.Project, in.Environment, fromPath, toPath)
	if err != nil {
		s.recordFailure(ctx, c, store.ActionFolderMove, fromMRN, err)
		return nil, err
	}
	if err := s.recordSuccess(ctx, c, audit.Event{
		Action:      store.ActionFolderMove,
		ResourceMRN: fromMRN,
		Metadata:    map[string]any{"destination": toMRN},
	}); err != nil {
		return nil, err
	}
	return folder, nil
}

// DeleteFolder soft-deletes a folder, its descendants, and every secret inside them
// — each secret entering its own recovery window, so a mistaken folder delete is as
// recoverable as a mistaken secret delete.
//
// It requires DeleteSecret as well as ManageFolder, because it deletes secrets. A
// folder-management grant alone must not be a way to delete credentials.
func (s *Service) DeleteFolder(ctx context.Context, c Caller, in DeleteFolderInput) (int64, error) {
	if err := validate(in); err != nil {
		return 0, err
	}
	normalized, err := store.NormalizePath(in.Path)
	if err != nil {
		return 0, apperror.NewValidation(err.Error())
	}
	resourceMRN := c.mrn(in.Project, store.FolderResourcePath(in.Environment, normalized))
	if err := s.guard(ctx, c, authz.PermManageFolder, store.ActionFolderDelete, resourceMRN); err != nil {
		return 0, err
	}
	if err := s.guard(ctx, c, authz.PermDeleteSecret, store.ActionFolderDelete, resourceMRN); err != nil {
		return 0, err
	}
	deleted, err := s.store.DeleteFolder(ctx, c.TenantUUID, in.Project, in.Environment, normalized, in.RecoveryWindow)
	if err != nil {
		s.recordFailure(ctx, c, store.ActionFolderDelete, resourceMRN, err)
		return 0, err
	}
	if err := s.recordSuccess(ctx, c, audit.Event{
		Action:      store.ActionFolderDelete,
		ResourceMRN: resourceMRN,
		Metadata:    map[string]any{"secrets_deleted": deleted},
	}); err != nil {
		return 0, err
	}
	return deleted, nil
}
