package api

import (
	"context"

	"github.com/google/uuid"

	"github.com/maintainerd/secret/internal/audit"
	"github.com/maintainerd/secret/internal/platform/apperror"
	"github.com/maintainerd/secret/internal/platform/authz"
	"github.com/maintainerd/secret/internal/store"
)

// Scope imports: management, and the read-time fall-through they exist for.
//
// PRECEDENCE, ONCE MORE, BECAUSE IT IS THE SEMANTIC: the target's own value wins.
// An import is consulted only for a key the target does not define. That direction is
// the safe one — the reverse would let an import silently shadow a value someone
// deliberately set in this environment, which for a production credential is an
// incident rather than a preference.
//
// AUTHORIZATION FOLLOWS THE VALUE, NOT THE ADDRESS. When staging imports dev and a
// caller reveals staging/DB_PASSWORD, the value it receives is DEV's. So the reveal
// grant is checked against DEV's MRN — the secret actually being decrypted — not
// staging's. Checking the requested address instead would make an import a way to
// launder a read: import prod into a scope you control, and read prod's values
// through your own MRNs. The audit row likewise names the resolved secret, with the
// requested address recorded alongside it, so the trail says what was read and what
// was asked for.

// CreateImportInput describes a new import edge.
type CreateImportInput struct {
	Project     string
	Environment string
	FolderPath  string
	// SourceProject may differ from Project (the shared-folder pattern). It may
	// never be another TENANT: every query is tenant-scoped, and an import across
	// that boundary would be a supported cross-tenant read.
	SourceProject     string
	SourceEnvironment string
	SourceFolderPath  string
	Position          int32
}

// CreateImport adds an import edge, refusing cycles.
//
// It requires ManageFolder on the TARGET and — this is the part that matters —
// GetSecret on the SOURCE subtree. Creating an import makes the source's values
// readable through the target, so a principal that could create one without holding
// reveal on the source would have manufactured itself a read path. Requiring the
// reveal grant at creation time means an import can never widen what its creator can
// see.
func (s *Service) CreateImport(ctx context.Context, c Caller, in CreateImportInput) (*store.ScopeImport, error) {
	if err := validate(in); err != nil {
		return nil, err
	}
	targetPath, err := store.NormalizePath(in.FolderPath)
	if err != nil {
		return nil, apperror.NewValidation(err.Error())
	}
	sourcePath, err := store.NormalizePath(in.SourceFolderPath)
	if err != nil {
		return nil, apperror.NewValidation(err.Error())
	}
	targetMRN := c.mrn(in.Project, store.FolderResourcePath(in.Environment, targetPath))
	// The source is named by the MRN of a secret DIRECTLY under it, because a grant
	// over secrets is written against the secret prefix (secret/dev/...), not the
	// folder prefix. Using the folder MRN here would demand a folder grant for what
	// is really a question about reading values.
	sourceSecretPrefixMRN := c.mrn(in.SourceProject,
		store.SecretResourcePath(in.SourceEnvironment, sourcePath, importProbeKey))
	if err := s.guard(ctx, c, authz.PermManageFolder, store.ActionImportCreate, targetMRN); err != nil {
		return nil, err
	}
	if err := s.guard(ctx, c, authz.PermGetSecret, store.ActionImportCreate, sourceSecretPrefixMRN); err != nil {
		return nil, err
	}

	edge, err := s.store.CreateImport(ctx, store.CreateImportInput{
		TenantUUID:        c.TenantUUID,
		Project:           in.Project,
		Environment:       in.Environment,
		FolderPath:        targetPath,
		SourceProject:     in.SourceProject,
		SourceEnvironment: in.SourceEnvironment,
		SourceFolderPath:  sourcePath,
		Position:          in.Position,
	})
	if err != nil {
		s.recordFailure(ctx, c, store.ActionImportCreate, targetMRN, err)
		return nil, err
	}
	if err := s.recordSuccess(ctx, c, audit.Event{
		Action:      store.ActionImportCreate,
		ResourceMRN: c.mrn(in.Project, store.ImportResourcePath(edge.UUID)),
		Metadata: map[string]any{
			"target": targetMRN,
			"source": c.mrn(in.SourceProject, store.FolderResourcePath(in.SourceEnvironment, sourcePath)),
		},
	}); err != nil {
		return nil, err
	}
	return edge, nil
}

// importProbeKey is the placeholder key used to build a "secrets under this folder"
// MRN for a permission check. It is never read or written; it exists only so the
// check is made against a concrete, parseable MRN in the secret namespace, which is
// what a grant like secret/dev/* is written to match.
const importProbeKey = "_"

// ListImports returns one folder's import chain in precedence order.
func (s *Service) ListImports(ctx context.Context, c Caller, in ListImportsInput) ([]store.ScopeImport, error) {
	if err := validate(in); err != nil {
		return nil, err
	}
	normalized, err := store.NormalizePath(in.FolderPath)
	if err != nil {
		return nil, apperror.NewValidation(err.Error())
	}
	resourceMRN := c.mrn(in.Project, store.FolderResourcePath(in.Environment, normalized))
	if err := s.guard(ctx, c, authz.PermReadMetadata, store.ActionRead, resourceMRN); err != nil {
		return nil, err
	}
	edges, err := s.store.ListImports(ctx, c.TenantUUID, in.Project, in.Environment, normalized)
	if err != nil {
		s.recordFailure(ctx, c, store.ActionRead, resourceMRN, err)
		return nil, err
	}
	if err := s.recordSuccess(ctx, c, audit.Event{
		Action:      store.ActionRead,
		ResourceMRN: resourceMRN,
		Metadata:    map[string]any{"imports": len(edges)},
	}); err != nil {
		return nil, err
	}
	return edges, nil
}

// SetImportEnabled toggles and reorders an edge.
func (s *Service) SetImportEnabled(ctx context.Context, c Caller, in UpdateImportInput) (*store.ScopeImport, error) {
	if err := validate(in); err != nil {
		return nil, err
	}
	importUUID, err := uuid.Parse(in.ImportUUID)
	if err != nil {
		return nil, apperror.NewValidation("import_uuid must be a valid UUID")
	}
	resourceMRN := c.mrn("", store.ImportResourcePath(importUUID))
	if err := s.guard(ctx, c, authz.PermManageFolder, store.ActionImportUpdate, resourceMRN); err != nil {
		return nil, err
	}
	edge, err := s.store.SetImportEnabled(ctx, c.TenantUUID, importUUID, in.Enabled, in.Position)
	if err != nil {
		s.recordFailure(ctx, c, store.ActionImportUpdate, resourceMRN, err)
		return nil, err
	}
	if err := s.recordSuccess(ctx, c, audit.Event{
		Action:      store.ActionImportUpdate,
		ResourceMRN: resourceMRN,
		Metadata:    map[string]any{"enabled": in.Enabled, "position": in.Position},
	}); err != nil {
		return nil, err
	}
	return edge, nil
}

// DeleteImport removes an edge. The imported secrets are untouched — an import is a
// resolution rule, not a copy.
func (s *Service) DeleteImport(ctx context.Context, c Caller, in ImportRef) error {
	if err := validate(in); err != nil {
		return err
	}
	importUUID, err := uuid.Parse(in.ImportUUID)
	if err != nil {
		return apperror.NewValidation("import_uuid must be a valid UUID")
	}
	resourceMRN := c.mrn("", store.ImportResourcePath(importUUID))
	if err := s.guard(ctx, c, authz.PermManageFolder, store.ActionImportDelete, resourceMRN); err != nil {
		return err
	}
	if err := s.store.DeleteImport(ctx, c.TenantUUID, importUUID); err != nil {
		s.recordFailure(ctx, c, store.ActionImportDelete, resourceMRN, err)
		return err
	}
	return s.recordSuccess(ctx, c, audit.Event{Action: store.ActionImportDelete, ResourceMRN: resourceMRN})
}

// resolvedAddress is where a lookup actually landed.
type resolvedAddress struct {
	addr SecretAddress
	mrn  string
	// importedFrom is the MRN of the source folder when the key came from an import,
	// empty when it came from the requested scope.
	importedFrom string
}

// resolveThroughImports finds the scope that actually holds addr.Key.
//
// The existence probe is an UNAUTHORIZED metadata read, deliberately, and this is the
// one place in the service where that happens. The reason it is safe: the probe's
// result is never returned to the caller. It only selects WHICH MRN the permission
// check is then made against, and a caller that holds no grant on any candidate gets
// a denial regardless of which one existed. The alternative — checking permission on
// every candidate before probing — would emit a denial audit row for every scope in
// the chain on every miss, burying the real denials.
func (s *Service) resolveThroughImports(ctx context.Context, c Caller, addr SecretAddress) (resolvedAddress, error) {
	ownMRN, err := s.store.SecretMRN(ctx, addr.ref(c))
	if err != nil {
		return resolvedAddress{}, err
	}
	if _, derr := s.store.DescribeSecret(ctx, addr.ref(c)); derr == nil {
		return resolvedAddress{addr: addr, mrn: ownMRN}, nil
	} else if !apperror.IsNotFound(derr) {
		return resolvedAddress{}, derr
	}

	sources, err := s.store.ImportChainFor(ctx, c.TenantUUID, addr.Project, addr.Environment, addr.FolderPath)
	if err != nil {
		return resolvedAddress{}, err
	}
	for _, src := range sources {
		candidate := SecretAddress{
			Project:     src.Project,
			Environment: src.Environment,
			FolderPath:  src.FolderPath,
			Key:         addr.Key,
		}
		if _, derr := s.store.DescribeSecret(ctx, candidate.ref(c)); derr != nil {
			if apperror.IsNotFound(derr) {
				continue
			}
			return resolvedAddress{}, derr
		}
		candidateMRN, merr := s.store.SecretMRN(ctx, candidate.ref(c))
		if merr != nil {
			return resolvedAddress{}, merr
		}
		return resolvedAddress{
			addr:         candidate,
			mrn:          candidateMRN,
			importedFrom: c.mrn(src.Project, store.FolderResourcePath(src.Environment, src.FolderPath)),
		}, nil
	}
	// Nothing in the chain has it. The error is the ordinary not-found so a caller
	// cannot tell "no such key anywhere" from "no such key and there are imports",
	// which would otherwise map the import topology.
	return resolvedAddress{}, apperror.NewNotFound("secret")
}
