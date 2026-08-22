package store

import (
	"context"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/require"

	"github.com/maintainerd/secret/internal/crypto"
	"github.com/maintainerd/secret/internal/storage"
)

// fakeRepo is an in-memory Repository covering the paths these tests exercise.
//
// It EMBEDS storage.Querier as a nil interface on purpose. Any query a test path
// reaches that the fake has not modelled panics with a nil dereference naming the
// method, so a new data dependency shows up as a loud failure rather than a zero
// value that quietly changes behaviour — the same intent as core's "the untested
// paths panic so an accidental call is loud".
//
// It is a MODEL, not a mock: it reproduces the invariants the real schema enforces
// (tenant scoping on every read, the address uniqueness index, the append-only rule
// on versions, the recovery-window guard on destruction) so a service-layer test can
// actually fail when the service gets one of them wrong. Where an invariant is
// enforced by SQL that this fake reimplements, the SQL text is additionally asserted
// on directly in tenancy_test.go.
type fakeRepo struct {
	storage.Querier

	nextID map[string]int64

	tenants      map[int64]*storage.Tenant
	projects     map[int64]*storage.Project
	environments map[int64]*storage.Environment
	folders      map[int64]*storage.Folder
	secrets      map[int64]*storage.Secret
	versions     map[int64]*storage.SecretVersion
	rootKeys     map[string]*storage.RootKey
	auditLog     []storage.AuditLog
	setupState   *storage.SetupState

	// deleteAllowed mirrors the transaction-local GUC the append-only trigger
	// checks. A delete attempted without it is refused, exactly as the trigger
	// would refuse it.
	deleteAllowed string
	rewrapAllowed bool

	now func() time.Time

	// txDepth records nesting so a test can assert an operation really ran inside a
	// transaction.
	txDepth   int
	maxTxSeen int
	// forUpdateCalls counts row-lock acquisitions on the write path.
	forUpdateCalls int
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{
		nextID:       map[string]int64{},
		tenants:      map[int64]*storage.Tenant{},
		projects:     map[int64]*storage.Project{},
		environments: map[int64]*storage.Environment{},
		folders:      map[int64]*storage.Folder{},
		secrets:      map[int64]*storage.Secret{},
		versions:     map[int64]*storage.SecretVersion{},
		rootKeys:     map[string]*storage.RootKey{},
		now:          time.Now,
	}
}

func (f *fakeRepo) id(kind string) int64 {
	f.nextID[kind]++
	return f.nextID[kind]
}

// InTx runs fn against the same store. The fake has no rollback: these tests assert
// on the rules the service applies, and a test that needed rollback semantics would
// be testing Postgres rather than the service.
func (f *fakeRepo) InTx(ctx context.Context, fn func(Repository) error) error {
	f.txDepth++
	if f.txDepth > f.maxTxSeen {
		f.maxTxSeen = f.txDepth
	}
	defer func() {
		f.txDepth--
		if f.txDepth == 0 {
			// The GUC is transaction-local; it must not survive the transaction.
			f.deleteAllowed = ""
			f.rewrapAllowed = false
		}
	}()
	return fn(f)
}

// ---------------------------------------------------------------------------
// Tenants
// ---------------------------------------------------------------------------

func (f *fakeRepo) CreateTenant(_ context.Context, arg storage.CreateTenantParams) (storage.Tenant, error) {
	for _, t := range f.tenants {
		if t.Name == arg.Name && !t.DeletedAt.Valid {
			return storage.Tenant{}, uniqueViolation("uq_tenants_name")
		}
	}
	row := storage.Tenant{
		TenantID:       f.id("tenant"),
		TenantUuid:     uuid.New(),
		AuthTenantUuid: arg.AuthTenantUuid,
		Name:           arg.Name,
		DisplayName:    arg.DisplayName,
		Status:         arg.Status,
		IsSystem:       arg.IsSystem,
		Metadata:       arg.Metadata,
		CreatedAt:      f.now(),
		UpdatedAt:      f.now(),
	}
	f.tenants[row.TenantID] = &row
	return row, nil
}

func (f *fakeRepo) GetTenantByID(_ context.Context, id int64) (storage.Tenant, error) {
	if t, ok := f.tenants[id]; ok && !t.DeletedAt.Valid {
		return *t, nil
	}
	return storage.Tenant{}, pgx.ErrNoRows
}

func (f *fakeRepo) GetTenantByUUID(_ context.Context, id uuid.UUID) (storage.Tenant, error) {
	for _, t := range f.tenants {
		if t.TenantUuid == id && !t.DeletedAt.Valid {
			return *t, nil
		}
	}
	return storage.Tenant{}, pgx.ErrNoRows
}

func (f *fakeRepo) GetTenantByName(_ context.Context, name string) (storage.Tenant, error) {
	for _, t := range f.tenants {
		if t.Name == name && !t.DeletedAt.Valid {
			return *t, nil
		}
	}
	return storage.Tenant{}, pgx.ErrNoRows
}

func (f *fakeRepo) SoftDeleteTenant(_ context.Context, id uuid.UUID) (int64, error) {
	for _, t := range f.tenants {
		if t.TenantUuid == id && !t.DeletedAt.Valid {
			t.DeletedAt = pgtype.Timestamptz{Time: f.now(), Valid: true}
			return 1, nil
		}
	}
	return 0, nil
}

// ---------------------------------------------------------------------------
// Projects
// ---------------------------------------------------------------------------

func (f *fakeRepo) CreateProject(_ context.Context, arg storage.CreateProjectParams) (storage.Project, error) {
	for _, p := range f.projects {
		if p.TenantID == arg.TenantID && p.Slug == arg.Slug && !p.DeletedAt.Valid {
			return storage.Project{}, uniqueViolation("uq_projects_tenant_slug")
		}
	}
	row := storage.Project{
		ProjectID:   f.id("project"),
		ProjectUuid: uuid.New(),
		TenantID:    arg.TenantID,
		Name:        arg.Name,
		Slug:        arg.Slug,
		Description: arg.Description,
		Status:      arg.Status,
		Metadata:    arg.Metadata,
		CreatedAt:   f.now(),
		UpdatedAt:   f.now(),
	}
	f.projects[row.ProjectID] = &row
	return row, nil
}

// GetProjectBySlug is tenant-scoped: the tenant id is part of the lookup, so a
// project in another tenant is not merely hidden, it is unreachable.
func (f *fakeRepo) GetProjectBySlug(_ context.Context, arg storage.GetProjectBySlugParams) (storage.Project, error) {
	for _, p := range f.projects {
		if p.TenantID == arg.TenantID && p.Slug == arg.Slug && !p.DeletedAt.Valid {
			return *p, nil
		}
	}
	return storage.Project{}, pgx.ErrNoRows
}

func (f *fakeRepo) GetProjectByID(_ context.Context, arg storage.GetProjectByIDParams) (storage.Project, error) {
	if p, ok := f.projects[arg.ProjectID]; ok && p.TenantID == arg.TenantID && !p.DeletedAt.Valid {
		return *p, nil
	}
	return storage.Project{}, pgx.ErrNoRows
}

// ---------------------------------------------------------------------------
// Environments
// ---------------------------------------------------------------------------

func (f *fakeRepo) CreateEnvironment(_ context.Context, arg storage.CreateEnvironmentParams) (storage.Environment, error) {
	for _, e := range f.environments {
		// Unconditional unique (project_id, slug) — not partial on deleted_at, so a
		// deleted environment's slug stays reserved.
		if e.ProjectID == arg.ProjectID && e.Slug == arg.Slug {
			return storage.Environment{}, uniqueViolation("uq_environments_project_slug")
		}
	}
	row := storage.Environment{
		EnvironmentID:   f.id("environment"),
		EnvironmentUuid: uuid.New(),
		ProjectID:       arg.ProjectID,
		Name:            arg.Name,
		Slug:            arg.Slug,
		Description:     arg.Description,
		Position:        arg.Position,
		Status:          arg.Status,
		Metadata:        arg.Metadata,
		CreatedAt:       f.now(),
		UpdatedAt:       f.now(),
	}
	f.environments[row.EnvironmentID] = &row
	return row, nil
}

// tenantOwnsProject mirrors the project subquery the environment/folder queries use
// for tenant scoping.
func (f *fakeRepo) tenantOwnsProject(tenantID, projectID int64) bool {
	p, ok := f.projects[projectID]
	return ok && p.TenantID == tenantID && !p.DeletedAt.Valid
}

func (f *fakeRepo) tenantOwnsEnvironment(tenantID, environmentID int64) bool {
	e, ok := f.environments[environmentID]
	return ok && !e.DeletedAt.Valid && f.tenantOwnsProject(tenantID, e.ProjectID)
}

func (f *fakeRepo) GetEnvironmentBySlug(_ context.Context, arg storage.GetEnvironmentBySlugParams) (storage.Environment, error) {
	for _, e := range f.environments {
		if e.ProjectID == arg.ProjectID && e.Slug == arg.Slug && !e.DeletedAt.Valid &&
			f.tenantOwnsProject(arg.TenantID, e.ProjectID) {
			return *e, nil
		}
	}
	return storage.Environment{}, pgx.ErrNoRows
}

func (f *fakeRepo) ListEnvironmentsByProject(_ context.Context, arg storage.ListEnvironmentsByProjectParams) ([]storage.Environment, error) {
	out := []storage.Environment{}
	for _, e := range f.environments {
		if e.ProjectID == arg.ProjectID && !e.DeletedAt.Valid && f.tenantOwnsProject(arg.TenantID, e.ProjectID) {
			out = append(out, *e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Position != out[j].Position {
			return out[i].Position < out[j].Position
		}
		return out[i].Slug < out[j].Slug
	})
	return out, nil
}

// ---------------------------------------------------------------------------
// Folders
// ---------------------------------------------------------------------------

func (f *fakeRepo) CreateFolder(_ context.Context, arg storage.CreateFolderParams) (storage.Folder, error) {
	for _, fo := range f.folders {
		if fo.EnvironmentID == arg.EnvironmentID && fo.Path == arg.Path && !fo.DeletedAt.Valid {
			return storage.Folder{}, uniqueViolation("uq_folders_environment_path")
		}
	}
	row := storage.Folder{
		FolderID:       f.id("folder"),
		FolderUuid:     uuid.New(),
		EnvironmentID:  arg.EnvironmentID,
		ParentFolderID: arg.ParentFolderID,
		Name:           arg.Name,
		Path:           arg.Path,
		Metadata:       arg.Metadata,
		CreatedAt:      f.now(),
		UpdatedAt:      f.now(),
	}
	f.folders[row.FolderID] = &row
	return row, nil
}

func (f *fakeRepo) GetFolderByPath(_ context.Context, arg storage.GetFolderByPathParams) (storage.Folder, error) {
	for _, fo := range f.folders {
		if fo.EnvironmentID == arg.EnvironmentID && fo.Path == arg.Path && !fo.DeletedAt.Valid &&
			f.tenantOwnsEnvironment(arg.TenantID, fo.EnvironmentID) {
			return *fo, nil
		}
	}
	return storage.Folder{}, pgx.ErrNoRows
}

func (f *fakeRepo) GetFolderByID(_ context.Context, arg storage.GetFolderByIDParams) (storage.Folder, error) {
	if fo, ok := f.folders[arg.FolderID]; ok && !fo.DeletedAt.Valid &&
		f.tenantOwnsEnvironment(arg.TenantID, fo.EnvironmentID) {
		return *fo, nil
	}
	return storage.Folder{}, pgx.ErrNoRows
}

func (f *fakeRepo) ListFoldersBySubtree(_ context.Context, arg storage.ListFoldersBySubtreeParams) ([]storage.Folder, error) {
	out := []storage.Folder{}
	for _, fo := range f.folders {
		if fo.EnvironmentID != arg.EnvironmentID || fo.DeletedAt.Valid {
			continue
		}
		if !f.tenantOwnsEnvironment(arg.TenantID, fo.EnvironmentID) {
			continue
		}
		if fo.Path == arg.Path || likeMatch(fo.Path, arg.PathPattern) {
			out = append(out, *fo)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func (f *fakeRepo) ReparentFolder(_ context.Context, arg storage.ReparentFolderParams) (storage.Folder, error) {
	fo, ok := f.folders[arg.FolderID]
	if !ok || fo.DeletedAt.Valid {
		return storage.Folder{}, pgx.ErrNoRows
	}
	for _, other := range f.folders {
		if other.FolderID != arg.FolderID && other.EnvironmentID == fo.EnvironmentID &&
			other.Path == arg.Path && !other.DeletedAt.Valid {
			return storage.Folder{}, uniqueViolation("uq_folders_environment_path")
		}
	}
	fo.ParentFolderID = arg.ParentFolderID
	fo.Name = arg.Name
	fo.Path = arg.Path
	fo.UpdatedAt = f.now()
	return *fo, nil
}

func (f *fakeRepo) MoveFolderSubtreePaths(_ context.Context, arg storage.MoveFolderSubtreePathsParams) (int64, error) {
	var n int64
	for _, fo := range f.folders {
		if fo.EnvironmentID != arg.EnvironmentID || fo.DeletedAt.Valid {
			continue
		}
		if fo.Path == arg.OldPath || likeMatch(fo.Path, arg.OldPathPattern) {
			fo.Path = arg.NewPath + fo.Path[len(arg.OldPath):]
			fo.UpdatedAt = f.now()
			n++
		}
	}
	return n, nil
}

func (f *fakeRepo) SoftDeleteFolderSubtree(_ context.Context, arg storage.SoftDeleteFolderSubtreeParams) (int64, error) {
	var n int64
	for _, fo := range f.folders {
		if fo.EnvironmentID != arg.EnvironmentID || fo.DeletedAt.Valid {
			continue
		}
		if fo.Path == arg.Path || likeMatch(fo.Path, arg.PathPattern) {
			fo.DeletedAt = pgtype.Timestamptz{Time: f.now(), Valid: true}
			n++
		}
	}
	return n, nil
}

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

func (f *fakeRepo) CreateSecret(_ context.Context, arg storage.CreateSecretParams) (storage.Secret, error) {
	for _, s := range f.secrets {
		// uq_secrets_address, partial on deleted_at.
		if s.EnvironmentID == arg.EnvironmentID && s.FolderID == arg.FolderID &&
			s.Key == arg.Key && !s.DeletedAt.Valid {
			return storage.Secret{}, uniqueViolation("uq_secrets_address")
		}
	}
	row := storage.Secret{
		SecretID:        f.id("secret"),
		SecretUuid:      uuid.New(),
		TenantID:        arg.TenantID,
		ProjectID:       arg.ProjectID,
		EnvironmentID:   arg.EnvironmentID,
		FolderID:        arg.FolderID,
		MrnService:      arg.MrnService,
		MrnTenant:       arg.MrnTenant,
		MrnProject:      arg.MrnProject,
		MrnResourcePath: arg.MrnResourcePath,
		Key:             arg.Key,
		Description:     arg.Description,
		Tags:            arg.Tags,
		CurrentVersion:  0,
		KeepVersions:    arg.KeepVersions,
		RotationPolicy:  arg.RotationPolicy,
		ExpiresAt:       arg.ExpiresAt,
		Metadata:        arg.Metadata,
		CreatedAt:       f.now(),
		UpdatedAt:       f.now(),
	}
	f.secrets[row.SecretID] = &row
	return row, nil
}

func (f *fakeRepo) findSecretByAddress(arg storage.GetSecretByAddressParams) (storage.Secret, error) {
	for _, s := range f.secrets {
		if s.TenantID == arg.TenantID && s.EnvironmentID == arg.EnvironmentID &&
			s.FolderID == arg.FolderID && s.Key == arg.Key && !s.DeletedAt.Valid {
			return *s, nil
		}
	}
	return storage.Secret{}, pgx.ErrNoRows
}

func (f *fakeRepo) GetSecretByAddress(_ context.Context, arg storage.GetSecretByAddressParams) (storage.Secret, error) {
	return f.findSecretByAddress(arg)
}

func (f *fakeRepo) GetSecretByAddressForUpdate(_ context.Context, arg storage.GetSecretByAddressForUpdateParams) (storage.Secret, error) {
	f.forUpdateCalls++
	return f.findSecretByAddress(storage.GetSecretByAddressParams(arg))
}

func (f *fakeRepo) GetSecretByUUID(_ context.Context, arg storage.GetSecretByUUIDParams) (storage.Secret, error) {
	for _, s := range f.secrets {
		if s.TenantID == arg.TenantID && s.SecretUuid == arg.SecretUuid && !s.DeletedAt.Valid {
			return *s, nil
		}
	}
	return storage.Secret{}, pgx.ErrNoRows
}

func (f *fakeRepo) GetDeletedSecretByUUID(_ context.Context, arg storage.GetDeletedSecretByUUIDParams) (storage.Secret, error) {
	for _, s := range f.secrets {
		if s.TenantID == arg.TenantID && s.SecretUuid == arg.SecretUuid && s.DeletedAt.Valid {
			return *s, nil
		}
	}
	return storage.Secret{}, pgx.ErrNoRows
}

func (f *fakeRepo) SetSecretCurrentVersion(_ context.Context, arg storage.SetSecretCurrentVersionParams) (storage.Secret, error) {
	s, ok := f.secrets[arg.SecretID]
	if !ok || s.TenantID != arg.TenantID || s.DeletedAt.Valid {
		return storage.Secret{}, pgx.ErrNoRows
	}
	// current_version only moves forward, matching the WHERE clause.
	if s.CurrentVersion >= arg.CurrentVersion {
		return storage.Secret{}, pgx.ErrNoRows
	}
	s.CurrentVersion = arg.CurrentVersion
	if arg.MarkRotated {
		s.RotatedAt = pgtype.Timestamptz{Time: f.now(), Valid: true}
	}
	s.UpdatedAt = f.now()
	return *s, nil
}

func (f *fakeRepo) UpdateSecretMeta(_ context.Context, arg storage.UpdateSecretMetaParams) (storage.Secret, error) {
	for _, s := range f.secrets {
		if s.TenantID == arg.TenantID && s.SecretUuid == arg.SecretUuid && !s.DeletedAt.Valid {
			s.Description = arg.Description
			s.Tags = arg.Tags
			s.KeepVersions = arg.KeepVersions
			s.RotationPolicy = arg.RotationPolicy
			s.ExpiresAt = arg.ExpiresAt
			s.Metadata = arg.Metadata
			s.UpdatedAt = f.now()
			return *s, nil
		}
	}
	return storage.Secret{}, pgx.ErrNoRows
}

func (f *fakeRepo) ListSecretMetaBySubtree(_ context.Context, arg storage.ListSecretMetaBySubtreeParams) ([]storage.ListSecretMetaBySubtreeRow, error) {
	rows := []storage.ListSecretMetaBySubtreeRow{}
	for _, s := range f.secrets {
		if s.TenantID != arg.TenantID || s.EnvironmentID != arg.EnvironmentID || s.DeletedAt.Valid {
			continue
		}
		folder, ok := f.folders[s.FolderID]
		if !ok || folder.DeletedAt.Valid {
			continue
		}
		if folder.Path != arg.Path && !likeMatch(folder.Path, arg.PathPattern) {
			continue
		}
		rows = append(rows, storage.ListSecretMetaBySubtreeRow{
			SecretUuid:      s.SecretUuid,
			FolderPath:      folder.Path,
			Key:             s.Key,
			Description:     s.Description,
			Tags:            s.Tags,
			CurrentVersion:  s.CurrentVersion,
			KeepVersions:    s.KeepVersions,
			RotationPolicy:  s.RotationPolicy,
			MrnResourcePath: s.MrnResourcePath,
			RotatedAt:       s.RotatedAt,
			ExpiresAt:       s.ExpiresAt,
			CreatedAt:       s.CreatedAt,
			UpdatedAt:       s.UpdatedAt,
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].FolderPath != rows[j].FolderPath {
			return rows[i].FolderPath < rows[j].FolderPath
		}
		return rows[i].Key < rows[j].Key
	})
	start := int(arg.RowOffset)
	if start > len(rows) {
		start = len(rows)
	}
	end := start + int(arg.RowLimit)
	if end > len(rows) {
		end = len(rows)
	}
	return rows[start:end], nil
}

func (f *fakeRepo) CountSecretsInSubtree(_ context.Context, arg storage.CountSecretsInSubtreeParams) (int64, error) {
	rows, err := f.ListSecretMetaBySubtree(context.Background(), storage.ListSecretMetaBySubtreeParams{
		TenantID:      arg.TenantID,
		EnvironmentID: arg.EnvironmentID,
		Path:          arg.Path,
		PathPattern:   arg.PathPattern,
		RowLimit:      1 << 30,
	})
	return int64(len(rows)), err
}

func (f *fakeRepo) ListDeletedSecretMeta(_ context.Context, arg storage.ListDeletedSecretMetaParams) ([]storage.ListDeletedSecretMetaRow, error) {
	rows := []storage.ListDeletedSecretMetaRow{}
	for _, s := range f.secrets {
		if s.TenantID != arg.TenantID || s.EnvironmentID != arg.EnvironmentID || !s.DeletedAt.Valid {
			continue
		}
		folder := f.folders[s.FolderID]
		path := "/"
		if folder != nil {
			path = folder.Path
		}
		rows = append(rows, storage.ListDeletedSecretMetaRow{
			SecretUuid:     s.SecretUuid,
			FolderPath:     path,
			Key:            s.Key,
			CurrentVersion: s.CurrentVersion,
			DeletedAt:      s.DeletedAt,
			DestroyAfter:   s.DestroyAfter,
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Key < rows[j].Key })
	return rows, nil
}

func (f *fakeRepo) SoftDeleteSecret(_ context.Context, arg storage.SoftDeleteSecretParams) (storage.Secret, error) {
	s, ok := f.secrets[arg.SecretID]
	if !ok || s.TenantID != arg.TenantID || s.DeletedAt.Valid {
		return storage.Secret{}, pgx.ErrNoRows
	}
	s.DeletedAt = pgtype.Timestamptz{Time: f.now(), Valid: true}
	s.DestroyAfter = arg.DestroyAfter
	s.UpdatedAt = f.now()
	return *s, nil
}

func (f *fakeRepo) SoftDeleteSecretsInFolderSubtree(_ context.Context, arg storage.SoftDeleteSecretsInFolderSubtreeParams) (int64, error) {
	var n int64
	for _, s := range f.secrets {
		if s.TenantID != arg.TenantID || s.EnvironmentID != arg.EnvironmentID || s.DeletedAt.Valid {
			continue
		}
		folder, ok := f.folders[s.FolderID]
		if !ok {
			continue
		}
		if folder.Path == arg.Path || likeMatch(folder.Path, arg.PathPattern) {
			s.DeletedAt = pgtype.Timestamptz{Time: f.now(), Valid: true}
			s.DestroyAfter = arg.DestroyAfter
			s.UpdatedAt = f.now()
			n++
		}
	}
	return n, nil
}

func (f *fakeRepo) RestoreSecret(_ context.Context, arg storage.RestoreSecretParams) (storage.Secret, error) {
	for _, s := range f.secrets {
		if s.TenantID != arg.TenantID || s.SecretUuid != arg.SecretUuid || !s.DeletedAt.Valid {
			continue
		}
		// The address index only covers live rows, so restoring can collide with a
		// secret created at the same address in the meantime.
		for _, other := range f.secrets {
			if other.SecretID != s.SecretID && other.EnvironmentID == s.EnvironmentID &&
				other.FolderID == s.FolderID && other.Key == s.Key && !other.DeletedAt.Valid {
				return storage.Secret{}, uniqueViolation("uq_secrets_address")
			}
		}
		s.DeletedAt = pgtype.Timestamptz{}
		s.DestroyAfter = pgtype.Timestamptz{}
		s.UpdatedAt = f.now()
		return *s, nil
	}
	return storage.Secret{}, pgx.ErrNoRows
}

func (f *fakeRepo) HardDeleteSecret(_ context.Context, arg storage.HardDeleteSecretParams) (int64, error) {
	for id, s := range f.secrets {
		if s.TenantID != arg.TenantID || s.SecretUuid != arg.SecretUuid {
			continue
		}
		// The recovery-window guard, as it appears in the SQL WHERE clause.
		if !s.DeletedAt.Valid || !s.DestroyAfter.Valid || s.DestroyAfter.Time.After(f.now()) {
			return 0, nil
		}
		// The cascade into secret_versions passes through the append-only trigger.
		for vid, v := range f.versions {
			if v.SecretID != id {
				continue
			}
			if f.deleteAllowed != "secret_destroy" && f.deleteAllowed != "tenant_delete" {
				return 0, fmt.Errorf("secret_versions rows are append-only and may only be deleted by retention, secret destruction or tenant deletion")
			}
			delete(f.versions, vid)
		}
		delete(f.secrets, id)
		return 1, nil
	}
	return 0, nil
}

func (f *fakeRepo) RefreshSecretMrnPathsInSubtree(_ context.Context, arg storage.RefreshSecretMrnPathsInSubtreeParams) (int64, error) {
	var n int64
	for _, s := range f.secrets {
		if s.TenantID != arg.TenantID || s.EnvironmentID != arg.EnvironmentID || s.DeletedAt.Valid {
			continue
		}
		folder, ok := f.folders[s.FolderID]
		if !ok {
			continue
		}
		if folder.Path != arg.Path && !likeMatch(folder.Path, arg.PathPattern) {
			continue
		}
		env, ok := f.environments[s.EnvironmentID]
		if !ok {
			continue
		}
		// Mirrors the SQL expression exactly, including the root-folder branch.
		if folder.Path == "/" {
			s.MrnResourcePath = "secret/" + env.Slug + "/" + s.Key
		} else {
			s.MrnResourcePath = "secret/" + env.Slug + folder.Path + "/" + s.Key
		}
		s.UpdatedAt = f.now()
		n++
	}
	return n, nil
}

// ---------------------------------------------------------------------------
// Versions
// ---------------------------------------------------------------------------

func (f *fakeRepo) CreateSecretVersion(_ context.Context, arg storage.CreateSecretVersionParams) (storage.SecretVersion, error) {
	for _, v := range f.versions {
		if v.SecretID == arg.SecretID && v.Version == arg.Version {
			return storage.SecretVersion{}, uniqueViolation("uq_secret_versions_secret_version")
		}
	}
	if _, ok := f.rootKeys[arg.KekID]; !ok {
		// The FK from secret_versions.kek_id to root_keys.
		return storage.SecretVersion{}, foreignKeyViolation("secret_versions_kek_id_fkey")
	}
	row := storage.SecretVersion{
		VersionID:  f.id("version"),
		SecretID:   arg.SecretID,
		Version:    arg.Version,
		Ciphertext: arg.Ciphertext,
		Nonce:      arg.Nonce,
		DekWrapped: arg.DekWrapped,
		DekNonce:   arg.DekNonce,
		KekID:      arg.KekID,
		ValueType:  arg.ValueType,
		Checksum:   arg.Checksum,
		CreatedAt:  f.now(),
	}
	f.versions[row.VersionID] = &row
	return row, nil
}

func (f *fakeRepo) versionsOf(secretID int64) []*storage.SecretVersion {
	out := []*storage.SecretVersion{}
	for _, v := range f.versions {
		if v.SecretID == secretID {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version > out[j].Version })
	return out
}

func (f *fakeRepo) GetLatestSecretVersion(_ context.Context, secretID int64) (storage.SecretVersion, error) {
	vs := f.versionsOf(secretID)
	if len(vs) == 0 {
		return storage.SecretVersion{}, pgx.ErrNoRows
	}
	return *vs[0], nil
}

func (f *fakeRepo) GetSecretVersion(_ context.Context, arg storage.GetSecretVersionParams) (storage.SecretVersion, error) {
	for _, v := range f.versions {
		if v.SecretID == arg.SecretID && v.Version == arg.Version {
			return *v, nil
		}
	}
	return storage.SecretVersion{}, pgx.ErrNoRows
}

func (f *fakeRepo) GetLatestVersionChecksum(_ context.Context, secretID int64) (storage.GetLatestVersionChecksumRow, error) {
	vs := f.versionsOf(secretID)
	if len(vs) == 0 {
		return storage.GetLatestVersionChecksumRow{}, pgx.ErrNoRows
	}
	return storage.GetLatestVersionChecksumRow{Version: vs[0].Version, Checksum: vs[0].Checksum}, nil
}

func (f *fakeRepo) ListSecretVersionMeta(_ context.Context, arg storage.ListSecretVersionMetaParams) ([]storage.ListSecretVersionMetaRow, error) {
	vs := f.versionsOf(arg.SecretID)
	rows := []storage.ListSecretVersionMetaRow{}
	for _, v := range vs {
		rows = append(rows, storage.ListSecretVersionMetaRow{
			VersionID: v.VersionID,
			SecretID:  v.SecretID,
			Version:   v.Version,
			KekID:     v.KekID,
			ValueType: v.ValueType,
			Checksum:  v.Checksum,
			CreatedAt: v.CreatedAt,
		})
	}
	start := int(arg.Offset)
	if start > len(rows) {
		start = len(rows)
	}
	end := start + int(arg.Limit)
	if end > len(rows) {
		end = len(rows)
	}
	return rows[start:end], nil
}

func (f *fakeRepo) CountSecretVersions(_ context.Context, secretID int64) (int64, error) {
	return int64(len(f.versionsOf(secretID))), nil
}

func (f *fakeRepo) ListPrunableVersions(_ context.Context, arg storage.ListPrunableVersionsParams) ([]storage.ListPrunableVersionsRow, error) {
	vs := f.versionsOf(arg.SecretID) // newest first
	keep := map[int32]bool{}
	for i, v := range vs {
		if int32(i) < arg.KeepVersions {
			keep[v.Version] = true
		}
	}
	rows := []storage.ListPrunableVersionsRow{}
	for _, v := range vs {
		if v.Version == arg.CurrentVersion || keep[v.Version] {
			continue
		}
		rows = append(rows, storage.ListPrunableVersionsRow{VersionID: v.VersionID, Version: v.Version})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Version < rows[j].Version })
	return rows, nil
}

// DeleteSecretVersion refuses without the GUC, exactly as the append-only trigger
// does. This is what makes the retention test meaningful rather than decorative.
func (f *fakeRepo) DeleteSecretVersion(_ context.Context, versionID int64) (int64, error) {
	switch f.deleteAllowed {
	case "retention", "secret_destroy", "tenant_delete":
	default:
		return 0, fmt.Errorf("secret_versions rows are append-only and may only be deleted by retention, secret destruction or tenant deletion")
	}
	if _, ok := f.versions[versionID]; !ok {
		return 0, nil
	}
	delete(f.versions, versionID)
	return 1, nil
}

func (f *fakeRepo) AllowSecretVersionDelete(_ context.Context, reason string) error {
	if f.txDepth == 0 {
		// set_config(..., is_local => true) outside a transaction has no effect.
		return fmt.Errorf("delete authorization must be set inside a transaction")
	}
	f.deleteAllowed = reason
	return nil
}

func (f *fakeRepo) AllowSecretVersionRewrap(_ context.Context) error {
	if f.txDepth == 0 {
		return fmt.Errorf("rewrap authorization must be set inside a transaction")
	}
	f.rewrapAllowed = true
	return nil
}

func (f *fakeRepo) ListVersionWrapsByKEK(_ context.Context, arg storage.ListVersionWrapsByKEKParams) ([]storage.ListVersionWrapsByKEKRow, error) {
	ids := []int64{}
	for id, v := range f.versions {
		if v.KekID == arg.KekID {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	rows := []storage.ListVersionWrapsByKEKRow{}
	for _, id := range ids {
		v := f.versions[id]
		rows = append(rows, storage.ListVersionWrapsByKEKRow{
			VersionID:  v.VersionID,
			KekID:      v.KekID,
			DekWrapped: v.DekWrapped,
			DekNonce:   v.DekNonce,
		})
		if int32(len(rows)) == arg.Limit {
			break
		}
	}
	return rows, nil
}

func (f *fakeRepo) CountVersionsByKEK(_ context.Context, kekID string) (int64, error) {
	var n int64
	for _, v := range f.versions {
		if v.KekID == kekID {
			n++
		}
	}
	return n, nil
}

// RewrapSecretVersion enforces both halves of the trigger's contract: the GUC must
// be set, and only the wrapping columns may change.
func (f *fakeRepo) RewrapSecretVersion(_ context.Context, arg storage.RewrapSecretVersionParams) (int64, error) {
	if !f.rewrapAllowed {
		return 0, fmt.Errorf("secret_versions rows are immutable and cannot be updated")
	}
	v, ok := f.versions[arg.VersionID]
	if !ok || v.KekID != arg.FromKekID {
		return 0, nil
	}
	v.DekWrapped = arg.DekWrapped
	v.DekNonce = arg.DekNonce
	v.KekID = arg.KekID
	return 1, nil
}

// ---------------------------------------------------------------------------
// Root keys
// ---------------------------------------------------------------------------

func (f *fakeRepo) MarkOtherRootKeysRetiring(_ context.Context, kekID string) (int64, error) {
	var n int64
	for _, k := range f.rootKeys {
		if k.State == "active" && k.KekID != kekID {
			k.State = "retiring"
			n++
		}
	}
	return n, nil
}

func (f *fakeRepo) UpsertActiveRootKey(_ context.Context, arg storage.UpsertActiveRootKeyParams) (storage.RootKey, error) {
	for _, k := range f.rootKeys {
		if k.State == "active" && k.KekID != arg.KekID {
			return storage.RootKey{}, uniqueViolation("uq_root_keys_single_active")
		}
	}
	if k, ok := f.rootKeys[arg.KekID]; ok {
		k.State = "active"
		k.Provider = arg.Provider
		k.RetiredAt = pgtype.Timestamptz{}
		return *k, nil
	}
	row := storage.RootKey{
		KekID:       arg.KekID,
		Provider:    arg.Provider,
		State:       "active",
		CreatedAt:   f.now(),
		ActivatedAt: pgtype.Timestamptz{Time: f.now(), Valid: true},
	}
	f.rootKeys[arg.KekID] = &row
	return row, nil
}

func (f *fakeRepo) GetRootKey(_ context.Context, kekID string) (storage.RootKey, error) {
	if k, ok := f.rootKeys[kekID]; ok {
		return *k, nil
	}
	return storage.RootKey{}, pgx.ErrNoRows
}

func (f *fakeRepo) GetActiveRootKey(_ context.Context) (storage.RootKey, error) {
	for _, k := range f.rootKeys {
		if k.State == "active" {
			return *k, nil
		}
	}
	return storage.RootKey{}, pgx.ErrNoRows
}

func (f *fakeRepo) ListRootKeysByState(_ context.Context, state string) ([]storage.RootKey, error) {
	out := []storage.RootKey{}
	for _, k := range f.rootKeys {
		if k.State == state {
			out = append(out, *k)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].KekID < out[j].KekID })
	return out, nil
}

func (f *fakeRepo) RetireRootKey(_ context.Context, kekID string) (int64, error) {
	k, ok := f.rootKeys[kekID]
	if !ok || k.State == "active" {
		return 0, nil
	}
	k.State = "retired"
	k.RetiredAt = pgtype.Timestamptz{Time: f.now(), Valid: true}
	return 1, nil
}

// ---------------------------------------------------------------------------
// Audit + setup
// ---------------------------------------------------------------------------

func (f *fakeRepo) AppendAuditEvent(_ context.Context, arg storage.AppendAuditEventParams) (storage.AuditLog, error) {
	row := storage.AuditLog{
		EventID:      f.id("audit"),
		EventUuid:    uuid.New(),
		TenantID:     arg.TenantID,
		ActorSubject: arg.ActorSubject,
		ActorKind:    arg.ActorKind,
		Action:       arg.Action,
		ResourceMrn:  arg.ResourceMrn,
		SecretID:     arg.SecretID,
		Version:      arg.Version,
		Outcome:      arg.Outcome,
		Reason:       arg.Reason,
		IpAddress:    arg.IpAddress,
		UserAgent:    arg.UserAgent,
		RequestID:    arg.RequestID,
		Metadata:     arg.Metadata,
		CreatedAt:    f.now(),
	}
	f.auditLog = append(f.auditLog, row)
	return row, nil
}

func (f *fakeRepo) EnsureSetupState(_ context.Context) error {
	if f.setupState == nil {
		f.setupState = &storage.SetupState{ID: 1, CreatedAt: f.now(), UpdatedAt: f.now()}
	}
	return nil
}

func (f *fakeRepo) GetSetupState(_ context.Context) (storage.SetupState, error) {
	if f.setupState == nil {
		return storage.SetupState{}, pgx.ErrNoRows
	}
	return *f.setupState, nil
}

// CompleteSetup mirrors the guarded upsert: the update only applies while
// completed_at IS NULL, so a second caller matches nothing and gets no row.
func (f *fakeRepo) CompleteSetup(_ context.Context, arg storage.CompleteSetupParams) (storage.SetupState, error) {
	if f.setupState == nil {
		f.setupState = &storage.SetupState{ID: 1, CreatedAt: f.now()}
	}
	if f.setupState.CompletedAt.Valid {
		return storage.SetupState{}, pgx.ErrNoRows
	}
	f.setupState.CompletedAt = pgtype.Timestamptz{Time: f.now(), Valid: true}
	f.setupState.Controller = arg.Controller
	f.setupState.ControllerKind = arg.ControllerKind
	f.setupState.UpdatedAt = f.now()
	return *f.setupState, nil
}

var _ TxRepository = (*fakeRepo)(nil)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func uniqueViolation(constraint string) error {
	return &pgconn.PgError{Code: sqlstateUniqueViolation, ConstraintName: constraint, Message: "duplicate key value violates unique constraint"}
}

func foreignKeyViolation(constraint string) error {
	return &pgconn.PgError{Code: sqlstateForeignKeyViolation, ConstraintName: constraint, Message: "insert or update violates foreign key constraint"}
}

// likeMatch implements the subset of SQL LIKE the store uses: a literal prefix with
// backslash escapes, terminated by a single trailing '%'. Reimplemented here so the
// fake honours the escaping SubtreePattern applies — a fake that ignored it would
// hide the '_'-as-wildcard bug the escaping exists to prevent.
func likeMatch(value, pattern string) bool {
	if !strings.HasSuffix(pattern, "%") {
		return value == unescapeLike(pattern)
	}
	prefix := unescapeLike(strings.TrimSuffix(pattern, "%"))
	return strings.HasPrefix(value, prefix)
}

func unescapeLike(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// testFixture is a fully wired store over the fake repository.
type testFixture struct {
	t      *testing.T
	repo   *fakeRepo
	svc    *Service
	ring   *crypto.KeyRing
	tenant Tenant
	clock  time.Time
}

// newFixture builds a store with one tenant, project and environment, and a
// registered root key.
func newFixture(t *testing.T, opts ...func(*Policy)) *testFixture {
	t.Helper()
	repo := newFakeRepo()
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	fx := &testFixture{t: t, repo: repo, clock: base}
	repo.now = func() time.Time { return fx.clock }

	ring := mustKeyRing(t, 0x01)
	policy := Policy{
		KeepVersions:       3,
		RecoveryWindow:     30 * 24 * time.Hour,
		RewrapBatch:        10,
		DefaultTenant:      "default",
		DefaultProject:     "default",
		DefaultEnvironment: "default",
	}
	for _, opt := range opts {
		opt(&policy)
	}
	svc, err := NewService(repo, ring, policy)
	require.NoError(t, err)
	svc.SetClock(func() time.Time { return fx.clock })

	fx.svc = svc
	fx.ring = ring

	_, err = svc.EnsureActiveRootKey(context.Background())
	require.NoError(t, err)

	tenant, err := svc.CreateTenant(context.Background(), CreateTenantInput{Name: "acme", DisplayName: "Acme"})
	require.NoError(t, err)
	fx.tenant = *tenant

	_, err = svc.CreateProject(context.Background(), CreateProjectInput{
		TenantUUID: tenant.UUID, Slug: "billing-app", Name: "Billing",
	})
	require.NoError(t, err)
	_, err = svc.CreateEnvironment(context.Background(), CreateEnvironmentInput{
		TenantUUID: tenant.UUID, Project: "billing-app", Slug: "prod", Name: "Production",
	})
	require.NoError(t, err)
	return fx
}

func mustKeyRing(t *testing.T, keyByte byte) *crypto.KeyRing {
	t.Helper()
	p := mustProvider(t, keyByte)
	ring, err := crypto.NewKeyRing(p)
	require.NoError(t, err)
	return ring
}

func mustProvider(t *testing.T, keyByte byte) crypto.RootKeyProvider {
	t.Helper()
	raw := make([]byte, crypto.KeySize)
	for i := range raw {
		raw[i] = keyByte
	}
	p, err := crypto.NewRootKeyProvider(crypto.ProviderConfig{
		Provider: crypto.ProviderEnv,
		AppEnv:   "production",
		Key:      hex.EncodeToString(raw),
	})
	require.NoError(t, err)
	return p
}

// advance moves the fixture's clock, for recovery-window tests.
func (fx *testFixture) advance(d time.Duration) { fx.clock = fx.clock.Add(d) }

// ref builds a SecretRef in the fixture's default project/environment.
func (fx *testFixture) ref(folderPath, key string) SecretRef {
	return SecretRef{
		TenantUUID:  fx.tenant.UUID,
		Project:     "billing-app",
		Environment: "prod",
		FolderPath:  folderPath,
		Key:         key,
	}
}

// put is a convenience write that creates folders as needed.
func (fx *testFixture) put(folderPath, key, value string) *PutResult {
	fx.t.Helper()
	res, err := fx.svc.PutSecret(context.Background(), PutSecretInput{
		Ref:           fx.ref(folderPath, key),
		Value:         []byte(value),
		CreateFolders: true,
	})
	require.NoError(fx.t, err)
	return res
}
