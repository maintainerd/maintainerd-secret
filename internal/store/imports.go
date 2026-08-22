package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/maintainerd/secret/internal/platform/apperror"
	"github.com/maintainerd/secret/internal/storage"
)

// Scope imports: one folder inherits another folder's secrets. See
// migrations/00010_create_scope_imports.sql for the model and the precedence rule.
//
// PRECEDENCE, RESTATED HERE BECAUSE IT IS THE WHOLE SEMANTIC: the target's own
// value always wins. Imports are consulted only for keys the target does not
// define, in `position` order, first hit wins. The opposite direction — an import
// shadowing a value someone deliberately set in this environment — would turn a
// convenience feature into a way to silently replace a production credential.

// maxImportDepth bounds how far the resolver will follow a chain of imports.
//
// It is a SECOND line of defence, not the primary one: CreateImport refuses to
// create a cycle by walking the existing chain first. This bound exists for the
// cycle that arrives by another route — a restore, a manual INSERT, a future
// migration — where the alternative is a request that never returns. Eight levels
// is far past any legitimate configuration (dev -> staging -> preprod is three) and
// still small enough that the walk is cheap.
const maxImportDepth = 8

// ScopeImport is one import edge as it leaves this package.
type ScopeImport struct {
	UUID uuid.UUID `json:"import_uuid"`
	// FolderPath is the importing folder; empty on the by-target listing, where the
	// caller already knows it.
	FolderPath        string    `json:"folder_path,omitempty"`
	SourceProject     string    `json:"source_project"`
	SourceEnvironment string    `json:"source_environment"`
	SourceFolderPath  string    `json:"source_folder_path"`
	Position          int32     `json:"position"`
	Enabled           bool      `json:"enabled"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// CreateImportInput describes a new import edge. Both scopes are addressed by name,
// like everything else in this API.
type CreateImportInput struct {
	TenantUUID  uuid.UUID
	Project     string
	Environment string
	FolderPath  string
	// The source may live in another project and environment of the same tenant —
	// that is the "shared" folder pattern. It may never live in another TENANT: the
	// query layer scopes every read by tenant_id, and an import across that boundary
	// would be a supported cross-tenant read path.
	SourceProject     string
	SourceEnvironment string
	SourceFolderPath  string
	Position          int32
}

// CreateImport adds an import edge, refusing anything that would create a cycle.
//
// The cycle check walks the SOURCE's own import chain looking for the target. It
// runs inside the same transaction as the insert so a concurrent pair of inserts
// cannot each pass the check against a graph that does not include the other — the
// classic time-of-check race that would produce exactly the cycle both callers were
// refused individually.
func (s *Service) CreateImport(ctx context.Context, in CreateImportInput) (*ScopeImport, error) {
	targetPath, err := NormalizePath(in.FolderPath)
	if err != nil {
		return nil, apperror.NewValidation(err.Error())
	}
	sourcePath, err := NormalizePath(in.SourceFolderPath)
	if err != nil {
		return nil, apperror.NewValidation(err.Error())
	}
	meta, err := encodeObject(nil)
	if err != nil {
		return nil, apperror.NewInternal("encode import metadata", err)
	}

	var out ScopeImport
	err = s.repo.InTx(ctx, func(tx Repository) error {
		target, err := s.resolveFolder(ctx, tx, in.TenantUUID, in.Project, in.Environment, targetPath)
		if err != nil {
			return err
		}
		source, err := s.resolveFolder(ctx, tx, in.TenantUUID, in.SourceProject, in.SourceEnvironment, sourcePath)
		if err != nil {
			return err
		}
		if target.folder.FolderID == source.folder.FolderID {
			return apperror.NewValidation("a scope cannot import itself")
		}
		if err := assertNoImportCycle(ctx, tx, target.tenant.TenantID, source.folder.FolderID, target.folder.FolderID); err != nil {
			return err
		}
		row, err := tx.CreateScopeImport(ctx, storage.CreateScopeImportParams{
			TenantID:            target.tenant.TenantID,
			EnvironmentID:       target.environment.EnvironmentID,
			FolderID:            target.folder.FolderID,
			SourceEnvironmentID: source.environment.EnvironmentID,
			SourceFolderID:      source.folder.FolderID,
			Position:            in.Position,
			Enabled:             true,
			Metadata:            meta,
		})
		if err != nil {
			return mapWriteError(err, "scope import", "this scope already imports that one")
		}
		out = ScopeImport{
			UUID:              row.ImportUuid,
			FolderPath:        target.folder.Path,
			SourceProject:     source.project.Slug,
			SourceEnvironment: source.environment.Slug,
			SourceFolderPath:  source.folder.Path,
			Position:          row.Position,
			Enabled:           row.Enabled,
			CreatedAt:         row.CreatedAt,
			UpdatedAt:         row.UpdatedAt,
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// ListImports returns one folder's import chain in precedence order.
func (s *Service) ListImports(ctx context.Context, tenantUUID uuid.UUID, project, environment, folderPath string) ([]ScopeImport, error) {
	normalized, err := NormalizePath(folderPath)
	if err != nil {
		return nil, apperror.NewValidation(err.Error())
	}
	target, err := s.resolveFolder(ctx, s.repo, tenantUUID, project, environment, normalized)
	if err != nil {
		return nil, err
	}
	rows, err := s.repo.ListScopeImportsByTarget(ctx, storage.ListScopeImportsByTargetParams{
		TenantID: target.tenant.TenantID,
		FolderID: target.folder.FolderID,
	})
	if err != nil {
		return nil, apperror.NewInternal("list scope imports", err)
	}
	out := make([]ScopeImport, 0, len(rows))
	for _, r := range rows {
		out = append(out, ScopeImport{
			UUID:              r.ImportUuid,
			FolderPath:        normalized,
			SourceProject:     r.SourceProjectSlug,
			SourceEnvironment: r.SourceEnvironmentSlug,
			SourceFolderPath:  r.SourceFolderPath,
			Position:          r.Position,
			Enabled:           r.Enabled,
			CreatedAt:         r.CreatedAt,
			UpdatedAt:         r.UpdatedAt,
		})
	}
	return out, nil
}

// ListEnvironmentImports returns every import edge in one environment, which is what
// a console renders and what an operator checks before deleting a shared folder.
func (s *Service) ListEnvironmentImports(ctx context.Context, tenantUUID uuid.UUID, project, environment string) ([]ScopeImport, error) {
	sc, err := s.resolveEnvironment(ctx, s.repo, tenantUUID, project, environment)
	if err != nil {
		return nil, err
	}
	rows, err := s.repo.ListScopeImportsByEnvironment(ctx, storage.ListScopeImportsByEnvironmentParams{
		TenantID:      sc.tenant.TenantID,
		EnvironmentID: sc.environment.EnvironmentID,
	})
	if err != nil {
		return nil, apperror.NewInternal("list environment imports", err)
	}
	out := make([]ScopeImport, 0, len(rows))
	for _, r := range rows {
		out = append(out, ScopeImport{
			UUID:              r.ImportUuid,
			FolderPath:        r.FolderPath,
			SourceProject:     r.SourceProjectSlug,
			SourceEnvironment: r.SourceEnvironmentSlug,
			SourceFolderPath:  r.SourceFolderPath,
			Position:          r.Position,
			Enabled:           r.Enabled,
			CreatedAt:         r.CreatedAt,
			UpdatedAt:         r.UpdatedAt,
		})
	}
	return out, nil
}

// SetImportEnabled toggles an edge and/or reorders it.
func (s *Service) SetImportEnabled(ctx context.Context, tenantUUID, importUUID uuid.UUID, enabled bool, position int32) (*ScopeImport, error) {
	tenant, err := s.repo.GetTenantByUUID(ctx, tenantUUID)
	if err != nil {
		return nil, mapReadError(err, "tenant")
	}
	row, err := s.repo.SetScopeImportEnabled(ctx, storage.SetScopeImportEnabledParams{
		Enabled:    enabled,
		Position:   position,
		TenantID:   tenant.TenantID,
		ImportUuid: importUUID,
	})
	if err != nil {
		return nil, mapReadError(err, "scope import")
	}
	return &ScopeImport{
		UUID:      row.ImportUuid,
		Position:  row.Position,
		Enabled:   row.Enabled,
		CreatedAt: row.CreatedAt,
		UpdatedAt: row.UpdatedAt,
	}, nil
}

// DeleteImport removes an edge. The imported secrets are untouched — an import is a
// resolution rule, not a copy, so removing it only narrows what the target resolves.
func (s *Service) DeleteImport(ctx context.Context, tenantUUID, importUUID uuid.UUID) error {
	tenant, err := s.repo.GetTenantByUUID(ctx, tenantUUID)
	if err != nil {
		return mapReadError(err, "tenant")
	}
	n, err := s.repo.SoftDeleteScopeImport(ctx, storage.SoftDeleteScopeImportParams{
		TenantID:   tenant.TenantID,
		ImportUuid: importUUID,
	})
	if err != nil {
		return apperror.NewInternal("delete scope import", err)
	}
	if n == 0 {
		return apperror.NewNotFound("scope import")
	}
	return nil
}

// ImportedSource is one hop of a resolved import chain: where to look next, named
// the way a lookup needs it.
type ImportedSource struct {
	Project     string
	Environment string
	FolderPath  string
	folderID    int64
}

// ResolveImportChain flattens a folder's imports into the ordered list of scopes to
// consult after the folder's own contents, following nested imports breadth-first.
//
// BREADTH-FIRST, not depth-first, and the difference is a semantic rather than a
// performance choice. With `staging` importing `dev` and `shared`, and `dev`
// importing `base`, breadth-first yields dev, shared, base — every DIRECT import is
// consulted before any indirect one. Depth-first would yield dev, base, shared,
// letting a transitive import of dev outrank an explicit import of shared, which
// nobody writing that configuration intends.
//
// Already-visited folders are skipped, so a diamond (staging imports dev and
// shared, both importing base) consults base once, and a cycle that exists in the
// data despite CreateImport terminates instead of looping.
func (s *Service) ResolveImportChain(ctx context.Context, repo Repository, tenantID, folderID int64) ([]ImportedSource, error) {
	visited := map[int64]bool{folderID: true}
	frontier := []int64{folderID}
	out := []ImportedSource{}

	for depth := 0; depth < maxImportDepth && len(frontier) > 0; depth++ {
		var next []int64
		for _, current := range frontier {
			rows, err := repo.ListScopeImportsByTarget(ctx, storage.ListScopeImportsByTargetParams{
				TenantID: tenantID,
				FolderID: current,
			})
			if err != nil {
				return nil, apperror.NewInternal("resolve import chain", err)
			}
			for _, r := range rows {
				if visited[r.SourceFolderID] {
					continue
				}
				visited[r.SourceFolderID] = true
				out = append(out, ImportedSource{
					Project:     r.SourceProjectSlug,
					Environment: r.SourceEnvironmentSlug,
					FolderPath:  r.SourceFolderPath,
					folderID:    r.SourceFolderID,
				})
				next = append(next, r.SourceFolderID)
			}
		}
		frontier = next
	}
	return out, nil
}

// ImportChainFor is the API-facing form of ResolveImportChain: it takes a folder by
// name and returns the ordered scopes a lookup should fall through to after that
// folder's own contents.
func (s *Service) ImportChainFor(ctx context.Context, tenantUUID uuid.UUID, project, environment, folderPath string) ([]ImportedSource, error) {
	normalized, err := NormalizePath(folderPath)
	if err != nil {
		return nil, apperror.NewValidation(err.Error())
	}
	target, err := s.resolveFolder(ctx, s.repo, tenantUUID, project, environment, normalized)
	if err != nil {
		return nil, err
	}
	return s.ResolveImportChain(ctx, s.repo, target.tenant.TenantID, target.folder.FolderID)
}

// assertNoImportCycle refuses an edge target <- source when target is already
// reachable from source through existing imports.
//
// The walk is over the SOURCE's chain because that is the direction resolution
// follows: adding "target imports source" makes everything source imports reachable
// from target, so a cycle exists exactly when target is already in source's
// transitive closure.
func assertNoImportCycle(ctx context.Context, repo Repository, tenantID, sourceFolderID, targetFolderID int64) error {
	visited := map[int64]bool{}
	frontier := []int64{sourceFolderID}
	path := []int64{sourceFolderID}

	for depth := 0; depth <= maxImportDepth && len(frontier) > 0; depth++ {
		var next []int64
		for _, current := range frontier {
			rows, err := repo.ListScopeImportsByTarget(ctx, storage.ListScopeImportsByTargetParams{
				TenantID: tenantID,
				FolderID: current,
			})
			if err != nil {
				return apperror.NewInternal("check import cycle", err)
			}
			for _, r := range rows {
				if r.SourceFolderID == targetFolderID {
					// Named precisely: an operator staring at three environments needs
					// to know WHICH existing import closes the loop, not merely that
					// one does.
					return apperror.NewValidation(fmt.Sprintf(
						"this import would create a cycle: %s/%s%s already imports the scope you are importing into",
						r.SourceProjectSlug, r.SourceEnvironmentSlug, r.SourceFolderPath))
				}
				if visited[r.SourceFolderID] {
					continue
				}
				visited[r.SourceFolderID] = true
				next = append(next, r.SourceFolderID)
				path = append(path, r.SourceFolderID)
			}
		}
		frontier = next
	}
	if len(path) > maxImportDepth {
		return apperror.NewValidation(fmt.Sprintf(
			"the import chain reachable from this source is deeper than the %d levels this service resolves", maxImportDepth))
	}
	return nil
}

// folderScope is a scope plus a resolved folder row.
type folderScope struct {
	scope
	folder storage.Folder
}

// resolveFolder walks tenant -> project -> environment -> folder, every step through
// a tenant-scoped query.
func (s *Service) resolveFolder(ctx context.Context, repo Repository, tenantUUID uuid.UUID, project, environment, normalizedPath string) (folderScope, error) {
	sc, err := s.resolveEnvironment(ctx, repo, tenantUUID, project, environment)
	if err != nil {
		return folderScope{}, err
	}
	folder, err := repo.GetFolderByPath(ctx, storage.GetFolderByPathParams{
		EnvironmentID: sc.environment.EnvironmentID,
		Path:          normalizedPath,
		TenantID:      sc.tenant.TenantID,
	})
	if err != nil {
		return folderScope{}, mapReadError(err, "folder")
	}
	return folderScope{scope: sc, folder: folder}, nil
}
