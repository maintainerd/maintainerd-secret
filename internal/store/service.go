package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/maintainerd/secret/internal/crypto"
	"github.com/maintainerd/secret/internal/platform/apperror"
	"github.com/maintainerd/secret/internal/storage"
)

// Policy is the configurable behaviour of the store, loaded from config once at
// boot. It is a value rather than a pointer to config so tests can construct a
// service with explicit policy and no environment.
type Policy struct {
	// KeepVersions is the default number of versions retained per secret.
	KeepVersions int32
	// RecoveryWindow is the default period a soft-deleted secret stays restorable.
	RecoveryWindow time.Duration
	// RewrapBatch is how many versions one rewrap pass takes per query.
	RewrapBatch int32
	// DefaultTenant / DefaultProject / DefaultEnvironment name the scope the
	// flat-key compatibility RPCs address.
	DefaultTenant      string
	DefaultProject     string
	DefaultEnvironment string
}

// Service is the durable secret store.
type Service struct {
	repo   TxRepository
	ring   *crypto.KeyRing
	policy Policy
	// now is injectable so recovery-window and retention behaviour is testable
	// without sleeping. Production passes time.Now.
	now func() time.Time
}

// NewService builds the store. ring must contain the active root key plus every
// superseded key still referenced by existing versions.
func NewService(repo TxRepository, ring *crypto.KeyRing, policy Policy) (*Service, error) {
	if repo == nil {
		return nil, fmt.Errorf("store: repository is required")
	}
	if ring == nil {
		return nil, fmt.Errorf("store: key ring is required")
	}
	if policy.KeepVersions < 1 {
		// Clamped rather than rejected: 0 would mean "keep nothing", and the only
		// version there would be to delete is the live one. Retention must never be
		// able to express deleting the current value.
		policy.KeepVersions = 1
	}
	if policy.RewrapBatch < 1 {
		policy.RewrapBatch = 100
	}
	return &Service{repo: repo, ring: ring, policy: policy, now: time.Now}, nil
}

// SetClock overrides the time source. Test-only.
func (s *Service) SetClock(fn func() time.Time) {
	if fn != nil {
		s.now = fn
	}
}

// Policy returns the active policy.
func (s *Service) Policy() Policy { return s.policy }

// ---------------------------------------------------------------------------
// Tenants
// ---------------------------------------------------------------------------

// CreateTenantInput describes a new tenant mirror.
type CreateTenantInput struct {
	// AuthTenantUUID links this mirror to Auth's authoritative tenant. Nil for a
	// standalone install, which owns its own tenant names.
	AuthTenantUUID *uuid.UUID
	Name           string
	DisplayName    string
	IsSystem       bool
}

// CreateTenant registers a tenant.
func (s *Service) CreateTenant(ctx context.Context, in CreateTenantInput) (*Tenant, error) {
	if err := ValidateSlug("tenant name", in.Name); err != nil {
		return nil, apperror.NewValidation(err.Error())
	}
	meta, err := encodeObject(nil)
	if err != nil {
		return nil, apperror.NewInternal("encode tenant metadata", err)
	}
	row, err := s.repo.CreateTenant(ctx, storage.CreateTenantParams{
		AuthTenantUuid: uuidPtr(in.AuthTenantUUID),
		Name:           in.Name,
		DisplayName:    in.DisplayName,
		Status:         "active",
		IsSystem:       in.IsSystem,
		Metadata:       meta,
	})
	if err != nil {
		return nil, mapWriteError(err, "tenant", fmt.Sprintf("tenant %q already exists", in.Name))
	}
	t := toTenant(row)
	return &t, nil
}

// GetTenant reads a tenant by UUID.
func (s *Service) GetTenant(ctx context.Context, tenantUUID uuid.UUID) (*Tenant, error) {
	row, err := s.repo.GetTenantByUUID(ctx, tenantUUID)
	if err != nil {
		return nil, mapReadError(err, "tenant")
	}
	t := toTenant(row)
	return &t, nil
}

// GetTenantByName reads a tenant by its slug name.
func (s *Service) GetTenantByName(ctx context.Context, name string) (*Tenant, error) {
	row, err := s.repo.GetTenantByName(ctx, name)
	if err != nil {
		return nil, mapReadError(err, "tenant")
	}
	t := toTenant(row)
	return &t, nil
}

// ListTenants pages through tenants.
func (s *Service) ListTenants(ctx context.Context, page, limit int) ([]Tenant, int64, error) {
	page, limit = normalizePage(page, limit)
	rows, err := s.repo.ListTenants(ctx, storage.ListTenantsParams{
		Limit:  int32(limit),
		Offset: int32((page - 1) * limit),
	})
	if err != nil {
		return nil, 0, apperror.NewInternal("list tenants", err)
	}
	total, err := s.repo.CountTenants(ctx)
	if err != nil {
		return nil, 0, apperror.NewInternal("count tenants", err)
	}
	out := make([]Tenant, 0, len(rows))
	for _, r := range rows {
		out = append(out, toTenant(r))
	}
	return out, total, nil
}

// DeleteTenant soft-deletes a tenant. The cascade to its projects, secrets and
// versions is NOT performed here: hard-deleting a tenant's encrypted material is a
// separate, explicitly sanctioned operation (the tenant_delete GUC), not a
// side-effect of removing it from a list.
func (s *Service) DeleteTenant(ctx context.Context, tenantUUID uuid.UUID) error {
	n, err := s.repo.SoftDeleteTenant(ctx, tenantUUID)
	if err != nil {
		return apperror.NewInternal("soft delete tenant", err)
	}
	if n == 0 {
		return apperror.NewNotFound("tenant")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Projects
// ---------------------------------------------------------------------------

// CreateProjectInput describes a new project.
type CreateProjectInput struct {
	TenantUUID  uuid.UUID
	Name        string
	Slug        string
	Description string
}

// CreateProject adds a project to a tenant.
func (s *Service) CreateProject(ctx context.Context, in CreateProjectInput) (*Project, error) {
	if err := ValidateSlug("project slug", in.Slug); err != nil {
		return nil, apperror.NewValidation(err.Error())
	}
	tenant, err := s.repo.GetTenantByUUID(ctx, in.TenantUUID)
	if err != nil {
		return nil, mapReadError(err, "tenant")
	}
	name := in.Name
	if name == "" {
		name = in.Slug
	}
	meta, err := encodeObject(nil)
	if err != nil {
		return nil, apperror.NewInternal("encode project metadata", err)
	}
	row, err := s.repo.CreateProject(ctx, storage.CreateProjectParams{
		TenantID:    tenant.TenantID,
		Name:        name,
		Slug:        in.Slug,
		Description: in.Description,
		Status:      "active",
		Metadata:    meta,
	})
	if err != nil {
		return nil, mapWriteError(err, "project", fmt.Sprintf("project %q already exists in this tenant", in.Slug))
	}
	p := toProject(row)
	return &p, nil
}

// GetProject reads a project by slug within a tenant.
func (s *Service) GetProject(ctx context.Context, tenantUUID uuid.UUID, slug string) (*Project, error) {
	tenant, err := s.repo.GetTenantByUUID(ctx, tenantUUID)
	if err != nil {
		return nil, mapReadError(err, "tenant")
	}
	row, err := s.repo.GetProjectBySlug(ctx, storage.GetProjectBySlugParams{
		TenantID: tenant.TenantID,
		Slug:     slug,
	})
	if err != nil {
		return nil, mapReadError(err, "project")
	}
	p := toProject(row)
	return &p, nil
}

// ListProjects pages through a tenant's projects.
func (s *Service) ListProjects(ctx context.Context, tenantUUID uuid.UUID, page, limit int) ([]Project, int64, error) {
	tenant, err := s.repo.GetTenantByUUID(ctx, tenantUUID)
	if err != nil {
		return nil, 0, mapReadError(err, "tenant")
	}
	page, limit = normalizePage(page, limit)
	rows, err := s.repo.ListProjectsByTenant(ctx, storage.ListProjectsByTenantParams{
		TenantID: tenant.TenantID,
		Limit:    int32(limit),
		Offset:   int32((page - 1) * limit),
	})
	if err != nil {
		return nil, 0, apperror.NewInternal("list projects", err)
	}
	total, err := s.repo.CountProjectsByTenant(ctx, tenant.TenantID)
	if err != nil {
		return nil, 0, apperror.NewInternal("count projects", err)
	}
	out := make([]Project, 0, len(rows))
	for _, r := range rows {
		out = append(out, toProject(r))
	}
	return out, total, nil
}

// DeleteProject soft-deletes a project.
func (s *Service) DeleteProject(ctx context.Context, tenantUUID, projectUUID uuid.UUID) error {
	tenant, err := s.repo.GetTenantByUUID(ctx, tenantUUID)
	if err != nil {
		return mapReadError(err, "tenant")
	}
	n, err := s.repo.SoftDeleteProject(ctx, storage.SoftDeleteProjectParams{
		TenantID:    tenant.TenantID,
		ProjectUuid: projectUUID,
	})
	if err != nil {
		return apperror.NewInternal("soft delete project", err)
	}
	if n == 0 {
		return apperror.NewNotFound("project")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Environments
// ---------------------------------------------------------------------------

// CreateEnvironmentInput describes a new environment.
type CreateEnvironmentInput struct {
	TenantUUID  uuid.UUID
	Project     string
	Name        string
	Slug        string
	Description string
	Position    int32
}

// CreateEnvironment adds an environment to a project AND creates its root folder.
//
// Both happen in one transaction because an environment without a root folder is
// not a usable environment: every secret address resolves through a folder, so a
// half-created environment would accept no writes while appearing to exist. This is
// also the only place a root folder is ever created.
func (s *Service) CreateEnvironment(ctx context.Context, in CreateEnvironmentInput) (*Environment, error) {
	if err := ValidateSlug("environment slug", in.Slug); err != nil {
		return nil, apperror.NewValidation(err.Error())
	}
	tenant, err := s.repo.GetTenantByUUID(ctx, in.TenantUUID)
	if err != nil {
		return nil, mapReadError(err, "tenant")
	}
	project, err := s.repo.GetProjectBySlug(ctx, storage.GetProjectBySlugParams{
		TenantID: tenant.TenantID,
		Slug:     in.Project,
	})
	if err != nil {
		return nil, mapReadError(err, "project")
	}
	name := in.Name
	if name == "" {
		name = in.Slug
	}
	meta, err := encodeObject(nil)
	if err != nil {
		return nil, apperror.NewInternal("encode environment metadata", err)
	}

	var out Environment
	err = s.repo.InTx(ctx, func(tx Repository) error {
		row, err := tx.CreateEnvironment(ctx, storage.CreateEnvironmentParams{
			ProjectID:   project.ProjectID,
			Name:        name,
			Slug:        in.Slug,
			Description: in.Description,
			Position:    in.Position,
			Status:      "active",
			Metadata:    meta,
		})
		if err != nil {
			return mapWriteError(err, "environment", fmt.Sprintf("environment %q already exists in project %q", in.Slug, in.Project))
		}
		if _, err := tx.CreateFolder(ctx, storage.CreateFolderParams{
			EnvironmentID:  row.EnvironmentID,
			ParentFolderID: pgtype.Int8{},
			Name:           "",
			Path:           "/",
			Metadata:       meta,
		}); err != nil {
			return apperror.NewInternal("create environment root folder", err)
		}
		out = toEnvironment(row)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// GetEnvironment reads an environment by slug.
func (s *Service) GetEnvironment(ctx context.Context, tenantUUID uuid.UUID, project, slug string) (*Environment, error) {
	scope, err := s.resolveEnvironment(ctx, s.repo, tenantUUID, project, slug)
	if err != nil {
		return nil, err
	}
	e := toEnvironment(scope.environment)
	return &e, nil
}

// ListEnvironments returns a project's environments in display order.
func (s *Service) ListEnvironments(ctx context.Context, tenantUUID uuid.UUID, project string) ([]Environment, error) {
	tenant, err := s.repo.GetTenantByUUID(ctx, tenantUUID)
	if err != nil {
		return nil, mapReadError(err, "tenant")
	}
	proj, err := s.repo.GetProjectBySlug(ctx, storage.GetProjectBySlugParams{
		TenantID: tenant.TenantID,
		Slug:     project,
	})
	if err != nil {
		return nil, mapReadError(err, "project")
	}
	rows, err := s.repo.ListEnvironmentsByProject(ctx, storage.ListEnvironmentsByProjectParams{
		ProjectID: proj.ProjectID,
		TenantID:  tenant.TenantID,
	})
	if err != nil {
		return nil, apperror.NewInternal("list environments", err)
	}
	out := make([]Environment, 0, len(rows))
	for _, r := range rows {
		out = append(out, toEnvironment(r))
	}
	return out, nil
}

// DeleteEnvironment soft-deletes an environment.
func (s *Service) DeleteEnvironment(ctx context.Context, tenantUUID uuid.UUID, project, slug string) error {
	scope, err := s.resolveEnvironment(ctx, s.repo, tenantUUID, project, slug)
	if err != nil {
		return err
	}
	n, err := s.repo.SoftDeleteEnvironment(ctx, storage.SoftDeleteEnvironmentParams{
		EnvironmentUuid: scope.environment.EnvironmentUuid,
		TenantID:        scope.tenant.TenantID,
	})
	if err != nil {
		return apperror.NewInternal("soft delete environment", err)
	}
	if n == 0 {
		return apperror.NewNotFound("environment")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Folders
// ---------------------------------------------------------------------------

// CreateFolder creates a folder, creating any missing ancestors along the way
// (mkdir -p). Creating an existing folder is a no-op returning the existing row,
// which is what makes a write that specifies a deep path idempotent.
func (s *Service) CreateFolder(ctx context.Context, tenantUUID uuid.UUID, project, environment, folderPath string) (*Folder, error) {
	normalized, err := NormalizePath(folderPath)
	if err != nil {
		return nil, apperror.NewValidation(err.Error())
	}
	scope, err := s.resolveEnvironment(ctx, s.repo, tenantUUID, project, environment)
	if err != nil {
		return nil, err
	}

	var out Folder
	err = s.repo.InTx(ctx, func(tx Repository) error {
		row, err := ensureFolderPath(ctx, tx, scope, normalized)
		if err != nil {
			return err
		}
		out = toFolder(row)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// ListFolders returns the folder subtree at or under prefix, ordered by path.
func (s *Service) ListFolders(ctx context.Context, tenantUUID uuid.UUID, project, environment, prefix string) ([]Folder, error) {
	normalized, err := NormalizePath(prefix)
	if err != nil {
		return nil, apperror.NewValidation(err.Error())
	}
	scope, err := s.resolveEnvironment(ctx, s.repo, tenantUUID, project, environment)
	if err != nil {
		return nil, err
	}
	rows, err := s.repo.ListFoldersBySubtree(ctx, storage.ListFoldersBySubtreeParams{
		EnvironmentID: scope.environment.EnvironmentID,
		Path:          normalized,
		PathPattern:   SubtreePattern(normalized),
		TenantID:      scope.tenant.TenantID,
	})
	if err != nil {
		return nil, apperror.NewInternal("list folders", err)
	}
	out := make([]Folder, 0, len(rows))
	for _, r := range rows {
		out = append(out, toFolder(r))
	}
	return out, nil
}

// MoveFolder relocates a folder and its whole subtree.
//
// Three writes, one transaction, and each one is necessary:
//
//  1. ReparentFolder    — the moved node's parent_folder_id, name and own path.
//  2. MoveFolderSubtreePaths — every descendant's materialized path, by prefix
//     substitution. This is the cost of materializing paths, paid here so that
//     every read is a single indexed comparison.
//  3. RefreshSecretMrnPathsInSubtree — the MRN resource paths derived from those
//     folder paths. Skipping this is not a cosmetic bug: policy evaluation compares
//     mrn_resource_path, so a stale MRN is a secret that a grant no longer matches
//     (or worse, one that a different grant now does).
func (s *Service) MoveFolder(ctx context.Context, tenantUUID uuid.UUID, project, environment, from, to string) (*Folder, error) {
	oldPath, err := NormalizePath(from)
	if err != nil {
		return nil, apperror.NewValidation(err.Error())
	}
	newPath, err := NormalizePath(to)
	if err != nil {
		return nil, apperror.NewValidation(err.Error())
	}
	if oldPath == "/" {
		return nil, apperror.NewForbidden("an environment's root folder cannot be moved")
	}
	if newPath == "/" {
		return nil, apperror.NewValidation("a folder cannot be moved onto the root path")
	}
	if oldPath == newPath {
		return nil, apperror.NewValidation("source and destination folder paths are the same")
	}
	// Moving a folder inside its own subtree would detach the subtree from the
	// tree: the node's new parent would be one of its own descendants, and the
	// prefix substitution would produce paths that grow without bound.
	if IsAtOrUnder(newPath, oldPath) {
		return nil, apperror.NewValidation(fmt.Sprintf("cannot move %s into its own subtree at %s", oldPath, newPath))
	}

	scope, err := s.resolveEnvironment(ctx, s.repo, tenantUUID, project, environment)
	if err != nil {
		return nil, err
	}
	newParentPath, newName := SplitPath(newPath)

	var out Folder
	err = s.repo.InTx(ctx, func(tx Repository) error {
		node, err := tx.GetFolderByPath(ctx, storage.GetFolderByPathParams{
			EnvironmentID: scope.environment.EnvironmentID,
			Path:          oldPath,
			TenantID:      scope.tenant.TenantID,
		})
		if err != nil {
			return mapReadError(err, "folder")
		}
		if _, err := tx.GetFolderByPath(ctx, storage.GetFolderByPathParams{
			EnvironmentID: scope.environment.EnvironmentID,
			Path:          newPath,
			TenantID:      scope.tenant.TenantID,
		}); err == nil {
			return apperror.NewConflict(fmt.Sprintf("a folder already exists at %s", newPath))
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return apperror.NewInternal("check destination folder", err)
		}

		newParent, err := ensureFolderPath(ctx, tx, scope, newParentPath)
		if err != nil {
			return err
		}

		moved, err := tx.ReparentFolder(ctx, storage.ReparentFolderParams{
			ParentFolderID: pgtype.Int8{Int64: newParent.FolderID, Valid: true},
			Name:           newName,
			Path:           newPath,
			FolderID:       node.FolderID,
		})
		if err != nil {
			return mapWriteError(err, "folder", fmt.Sprintf("a folder already exists at %s", newPath))
		}
		// Descendants only: the node's own path was just set above, so it no longer
		// matches oldPath and is not double-rewritten.
		if _, err := tx.MoveFolderSubtreePaths(ctx, storage.MoveFolderSubtreePathsParams{
			NewPath:        newPath,
			OldPath:        oldPath,
			EnvironmentID:  scope.environment.EnvironmentID,
			OldPathPattern: SubtreePattern(oldPath),
		}); err != nil {
			return apperror.NewInternal("move folder subtree", err)
		}
		if _, err := tx.RefreshSecretMrnPathsInSubtree(ctx, storage.RefreshSecretMrnPathsInSubtreeParams{
			TenantID:      scope.tenant.TenantID,
			EnvironmentID: scope.environment.EnvironmentID,
			Path:          newPath,
			PathPattern:   SubtreePattern(newPath),
		}); err != nil {
			return apperror.NewInternal("refresh secret mrn paths", err)
		}
		out = toFolder(moved)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteFolder soft-deletes a folder, its descendants, and every secret inside
// them — each secret entering its own recovery window, so a mistaken folder delete
// is as recoverable as a mistaken secret delete.
func (s *Service) DeleteFolder(ctx context.Context, tenantUUID uuid.UUID, project, environment, folderPath string, window *time.Duration) (int64, error) {
	normalized, err := NormalizePath(folderPath)
	if err != nil {
		return 0, apperror.NewValidation(err.Error())
	}
	if normalized == "/" {
		return 0, apperror.NewForbidden("an environment's root folder cannot be deleted")
	}
	scope, err := s.resolveEnvironment(ctx, s.repo, tenantUUID, project, environment)
	if err != nil {
		return 0, err
	}
	destroyAfter := s.destroyAfter(window)

	var secretsDeleted int64
	err = s.repo.InTx(ctx, func(tx Repository) error {
		if _, err := tx.GetFolderByPath(ctx, storage.GetFolderByPathParams{
			EnvironmentID: scope.environment.EnvironmentID,
			Path:          normalized,
			TenantID:      scope.tenant.TenantID,
		}); err != nil {
			return mapReadError(err, "folder")
		}
		n, err := tx.SoftDeleteSecretsInFolderSubtree(ctx, storage.SoftDeleteSecretsInFolderSubtreeParams{
			DestroyAfter:  pgtype.Timestamptz{Time: destroyAfter, Valid: true},
			TenantID:      scope.tenant.TenantID,
			EnvironmentID: scope.environment.EnvironmentID,
			Path:          normalized,
			PathPattern:   SubtreePattern(normalized),
		})
		if err != nil {
			return apperror.NewInternal("soft delete secrets in folder", err)
		}
		secretsDeleted = n
		if _, err := tx.SoftDeleteFolderSubtree(ctx, storage.SoftDeleteFolderSubtreeParams{
			EnvironmentID: scope.environment.EnvironmentID,
			Path:          normalized,
			PathPattern:   SubtreePattern(normalized),
		}); err != nil {
			return apperror.NewInternal("soft delete folder subtree", err)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return secretsDeleted, nil
}

// ---------------------------------------------------------------------------
// Scope + address resolution
// ---------------------------------------------------------------------------

// scope is a tenant/project/environment resolved to rows. Every id in it came from
// a tenant-scoped query, which is what makes passing the ids onward safe.
type scope struct {
	tenant      storage.Tenant
	project     storage.Project
	environment storage.Environment
}

// address is a scope plus the folder and key: everything needed to locate one
// secret.
type address struct {
	scope
	folder storage.Folder
	key    string
}

// identity renders the AAD identity for a version of this secret.
//
// Both bound values are STABLE UUIDs, not names or paths: a tenant rename, a folder
// move or a delete-and-restore must not invalidate a single ciphertext. See
// crypto.Identity for why binding the mutable address would be a data-loss bug
// rather than a security control.
func (a address) identity(secretUUID uuid.UUID, version int32) crypto.Identity {
	return crypto.Identity{
		TenantUUID: a.tenant.TenantUuid.String(),
		SecretUUID: secretUUID.String(),
		Version:    version,
	}
}

func (a address) mrnResourcePath() string {
	return mrnResourcePath(a.environment.Slug, a.folder.Path, a.key)
}

// resolveEnvironment walks tenant -> project -> environment, each step through a
// tenant-scoped query.
func (s *Service) resolveEnvironment(ctx context.Context, repo Repository, tenantUUID uuid.UUID, project, environment string) (scope, error) {
	tenant, err := repo.GetTenantByUUID(ctx, tenantUUID)
	if err != nil {
		return scope{}, mapReadError(err, "tenant")
	}
	proj, err := repo.GetProjectBySlug(ctx, storage.GetProjectBySlugParams{
		TenantID: tenant.TenantID,
		Slug:     project,
	})
	if err != nil {
		return scope{}, mapReadError(err, "project")
	}
	env, err := repo.GetEnvironmentBySlug(ctx, storage.GetEnvironmentBySlugParams{
		ProjectID: proj.ProjectID,
		Slug:      environment,
		TenantID:  tenant.TenantID,
	})
	if err != nil {
		return scope{}, mapReadError(err, "environment")
	}
	return scope{tenant: tenant, project: proj, environment: env}, nil
}

// resolveAddress resolves a SecretRef all the way to a folder row.
func (s *Service) resolveAddress(ctx context.Context, repo Repository, ref SecretRef) (address, error) {
	if err := ValidateKey(ref.Key); err != nil {
		return address{}, apperror.NewValidation(err.Error())
	}
	folderPath, err := NormalizePath(ref.FolderPath)
	if err != nil {
		return address{}, apperror.NewValidation(err.Error())
	}
	sc, err := s.resolveEnvironment(ctx, repo, ref.TenantUUID, ref.Project, ref.Environment)
	if err != nil {
		return address{}, err
	}
	folder, err := repo.GetFolderByPath(ctx, storage.GetFolderByPathParams{
		EnvironmentID: sc.environment.EnvironmentID,
		Path:          folderPath,
		TenantID:      sc.tenant.TenantID,
	})
	if err != nil {
		return address{}, mapReadError(err, "folder")
	}
	return address{scope: sc, folder: folder, key: ref.Key}, nil
}

// ensureFolderPath creates every missing folder along normalized, returning the
// leaf. Idempotent: an existing folder is returned as-is.
//
// The walk is top-down and one level at a time because parent_folder_id has to be
// correct at each step — the materialized path is derived data, and building it
// without the adjacency link would leave a tree that reads correctly until the
// first move.
func ensureFolderPath(ctx context.Context, repo Repository, sc scope, normalized string) (storage.Folder, error) {
	current, err := repo.GetFolderByPath(ctx, storage.GetFolderByPathParams{
		EnvironmentID: sc.environment.EnvironmentID,
		Path:          "/",
		TenantID:      sc.tenant.TenantID,
	})
	if err != nil {
		return storage.Folder{}, mapReadError(err, "environment root folder")
	}
	if normalized == "/" {
		return current, nil
	}

	meta, err := encodeObject(nil)
	if err != nil {
		return storage.Folder{}, apperror.NewInternal("encode folder metadata", err)
	}

	built := ""
	for _, segment := range splitSegments(normalized) {
		built = JoinPath(built, segment)
		existing, err := repo.GetFolderByPath(ctx, storage.GetFolderByPathParams{
			EnvironmentID: sc.environment.EnvironmentID,
			Path:          built,
			TenantID:      sc.tenant.TenantID,
		})
		if err == nil {
			current = existing
			continue
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return storage.Folder{}, apperror.NewInternal("read folder", err)
		}
		created, err := repo.CreateFolder(ctx, storage.CreateFolderParams{
			EnvironmentID:  sc.environment.EnvironmentID,
			ParentFolderID: pgtype.Int8{Int64: current.FolderID, Valid: true},
			Name:           segment,
			Path:           built,
			Metadata:       meta,
		})
		if err != nil {
			return storage.Folder{}, mapWriteError(err, "folder", fmt.Sprintf("a folder already exists at %s", built))
		}
		current = created
	}
	return current, nil
}

func splitSegments(normalized string) []string {
	if normalized == "/" {
		return nil
	}
	out := make([]string, 0, 4)
	start := 1
	for i := 1; i <= len(normalized); i++ {
		if i == len(normalized) || normalized[i] == '/' {
			out = append(out, normalized[start:i])
			start = i + 1
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// destroyAfter computes the end of a recovery window.
func (s *Service) destroyAfter(window *time.Duration) time.Time {
	d := s.policy.RecoveryWindow
	if window != nil {
		d = *window
	}
	if d < 0 {
		d = 0
	}
	return s.now().Add(d)
}

func normalizePage(page, limit int) (int, int) {
	if page < 1 {
		page = 1
	}
	if limit < 1 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	return page, limit
}

// mapReadError turns a query error into a typed service error. pgx.ErrNoRows
// becomes NotFound, and — because every read query is tenant-scoped — that same
// NotFound is what a cross-tenant read produces. The two are indistinguishable to
// the caller by design: a distinct "exists but not yours" would confirm the
// existence of another tenant's secret.
func mapReadError(err error, entity string) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return apperror.NewNotFound(entity)
	}
	return apperror.NewInternal("read "+entity, err)
}

// mapWriteError turns a write error into a typed service error, translating
// Postgres' unique-violation and foreign-key codes into a Conflict the caller can
// act on rather than an opaque internal error.
func mapWriteError(err error, entity, conflictMessage string) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case sqlstateUniqueViolation, sqlstateExclusionViolation:
			return apperror.NewConflict(conflictMessage)
		case sqlstateForeignKeyViolation:
			return apperror.NewConflict(fmt.Sprintf("%s references something that does not exist", entity))
		case sqlstateCheckViolation:
			return apperror.NewValidation(fmt.Sprintf("%s violates the %s constraint", entity, pgErr.ConstraintName))
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return apperror.NewNotFound(entity)
	}
	return apperror.NewInternal("write "+entity, err)
}

// The SQLSTATE codes this package translates. Named because a bare "23505" in a
// switch is unreadable, and because the immutability triggers on secret_versions
// and audit_log raise plain exceptions rather than these, so the set matters.
const (
	sqlstateForeignKeyViolation = "23503"
	sqlstateUniqueViolation     = "23505"
	sqlstateCheckViolation      = "23514"
	sqlstateExclusionViolation  = "23P01"
)
