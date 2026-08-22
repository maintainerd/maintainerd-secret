package api

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/require"

	sdkauthz "github.com/maintainerd/sdk/authz"
	"github.com/maintainerd/secret/internal/audit"
	"github.com/maintainerd/secret/internal/crypto"
	"github.com/maintainerd/secret/internal/platform/permissions"
	"github.com/maintainerd/secret/internal/storage"
	"github.com/maintainerd/secret/internal/store"
)

// fakeRepo is an in-memory storage.Querier covering the paths these tests exercise.
//
// It EMBEDS storage.Querier as a nil interface on purpose, the same technique the
// store package's own fake uses: any query a code path reaches that this fake has not
// modelled panics with a nil dereference NAMING THE METHOD, so a new data dependency
// shows up as a loud failure rather than a zero value that quietly changes behaviour.
//
// It is a MODEL, not a mock: tenant scoping, the address uniqueness rule and the
// append-only version rule are reproduced, so an api-level test can actually fail when
// the layer under test gets one of them wrong.
type fakeRepo struct {
	storage.Querier

	mu     sync.Mutex
	nextID map[string]int64

	tenants      map[int64]*storage.Tenant
	projects     map[int64]*storage.Project
	environments map[int64]*storage.Environment
	folders      map[int64]*storage.Folder
	secrets      map[int64]*storage.Secret
	versions     map[int64]*storage.SecretVersion
	imports      map[int64]*storage.ScopeImport
	auditLog     []storage.AuditLog

	// The transit and dynamic-secret tables. Modelled in
	// fixture_transit_dynamic_test.go, where the queries that read them live.
	transitKeys     map[int64]*storage.TransitKey
	transitVersions map[int64]*storage.TransitKeyVersion
	dynamicRoles    map[int64]*storage.DynamicRole
	dynamicLeases   map[int64]*storage.DynamicLease
	// secretLeases are the read leases issued against static secrets. Modelled in
	// leases_test.go; the POLICY itself lives on the secrets row.
	secretLeases map[int64]*storage.SecretLease

	// auditErr, when set, makes every audit append fail. It is how the "a reveal
	// cannot succeed without an audit row" test removes the trail without removing
	// the store.
	auditErr error
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
		imports:      map[int64]*storage.ScopeImport{},

		transitKeys:     map[int64]*storage.TransitKey{},
		transitVersions: map[int64]*storage.TransitKeyVersion{},
		dynamicRoles:    map[int64]*storage.DynamicRole{},
		dynamicLeases:   map[int64]*storage.DynamicLease{},
		secretLeases:    map[int64]*storage.SecretLease{},
	}
}

func (f *fakeRepo) id(kind string) int64 {
	f.nextID[kind]++
	return f.nextID[kind]
}

// InTx flattens nesting, like the real txRepository does.
func (f *fakeRepo) InTx(ctx context.Context, fn func(store.Repository) error) error {
	return fn(f)
}

// --- tenants ---------------------------------------------------------------

func (f *fakeRepo) CreateTenant(_ context.Context, arg storage.CreateTenantParams) (storage.Tenant, error) {
	for _, t := range f.tenants {
		if t.Name == arg.Name && !t.DeletedAt.Valid {
			return storage.Tenant{}, uniqueViolation()
		}
	}
	id := f.id("tenant")
	row := storage.Tenant{
		TenantID: id, TenantUuid: uuid.New(), AuthTenantUuid: arg.AuthTenantUuid,
		Name: arg.Name, DisplayName: arg.DisplayName, Status: arg.Status,
		IsSystem: arg.IsSystem, Metadata: arg.Metadata,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	f.tenants[id] = &row
	return row, nil
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

// --- projects --------------------------------------------------------------

func (f *fakeRepo) CreateProject(_ context.Context, arg storage.CreateProjectParams) (storage.Project, error) {
	for _, p := range f.projects {
		if p.TenantID == arg.TenantID && p.Slug == arg.Slug && !p.DeletedAt.Valid {
			return storage.Project{}, uniqueViolation()
		}
	}
	id := f.id("project")
	row := storage.Project{
		ProjectID: id, ProjectUuid: uuid.New(), TenantID: arg.TenantID,
		Name: arg.Name, Slug: arg.Slug, Description: arg.Description,
		Status: arg.Status, Metadata: arg.Metadata,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	f.projects[id] = &row
	return row, nil
}

func (f *fakeRepo) GetProjectBySlug(_ context.Context, arg storage.GetProjectBySlugParams) (storage.Project, error) {
	for _, p := range f.projects {
		if p.TenantID == arg.TenantID && p.Slug == arg.Slug && !p.DeletedAt.Valid {
			return *p, nil
		}
	}
	return storage.Project{}, pgx.ErrNoRows
}

// --- environments ----------------------------------------------------------

func (f *fakeRepo) CreateEnvironment(_ context.Context, arg storage.CreateEnvironmentParams) (storage.Environment, error) {
	for _, e := range f.environments {
		if e.ProjectID == arg.ProjectID && e.Slug == arg.Slug {
			return storage.Environment{}, uniqueViolation()
		}
	}
	id := f.id("environment")
	row := storage.Environment{
		EnvironmentID: id, EnvironmentUuid: uuid.New(), ProjectID: arg.ProjectID,
		Name: arg.Name, Slug: arg.Slug, Description: arg.Description,
		Position: arg.Position, Status: arg.Status, Metadata: arg.Metadata,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	f.environments[id] = &row
	return row, nil
}

// tenantOwnsProject reproduces the tenant subquery every environment read carries.
func (f *fakeRepo) tenantOwnsProject(tenantID, projectID int64) bool {
	p, ok := f.projects[projectID]
	return ok && p.TenantID == tenantID && !p.DeletedAt.Valid
}

func (f *fakeRepo) GetEnvironmentBySlug(_ context.Context, arg storage.GetEnvironmentBySlugParams) (storage.Environment, error) {
	if !f.tenantOwnsProject(arg.TenantID, arg.ProjectID) {
		return storage.Environment{}, pgx.ErrNoRows
	}
	for _, e := range f.environments {
		if e.ProjectID == arg.ProjectID && e.Slug == arg.Slug && !e.DeletedAt.Valid {
			return *e, nil
		}
	}
	return storage.Environment{}, pgx.ErrNoRows
}

// --- folders ---------------------------------------------------------------

func (f *fakeRepo) tenantOwnsEnvironment(tenantID, envID int64) bool {
	e, ok := f.environments[envID]
	return ok && f.tenantOwnsProject(tenantID, e.ProjectID)
}

func (f *fakeRepo) CreateFolder(_ context.Context, arg storage.CreateFolderParams) (storage.Folder, error) {
	for _, fo := range f.folders {
		if fo.EnvironmentID == arg.EnvironmentID && fo.Path == arg.Path && !fo.DeletedAt.Valid {
			return storage.Folder{}, uniqueViolation()
		}
	}
	id := f.id("folder")
	row := storage.Folder{
		FolderID: id, FolderUuid: uuid.New(), EnvironmentID: arg.EnvironmentID,
		ParentFolderID: arg.ParentFolderID, Name: arg.Name, Path: arg.Path,
		Metadata: arg.Metadata, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	f.folders[id] = &row
	return row, nil
}

func (f *fakeRepo) GetFolderByPath(_ context.Context, arg storage.GetFolderByPathParams) (storage.Folder, error) {
	if !f.tenantOwnsEnvironment(arg.TenantID, arg.EnvironmentID) {
		return storage.Folder{}, pgx.ErrNoRows
	}
	for _, fo := range f.folders {
		if fo.EnvironmentID == arg.EnvironmentID && fo.Path == arg.Path && !fo.DeletedAt.Valid {
			return *fo, nil
		}
	}
	return storage.Folder{}, pgx.ErrNoRows
}

// --- secrets ---------------------------------------------------------------

func (f *fakeRepo) CreateSecret(_ context.Context, arg storage.CreateSecretParams) (storage.Secret, error) {
	for _, s := range f.secrets {
		if s.EnvironmentID == arg.EnvironmentID && s.FolderID == arg.FolderID &&
			s.Key == arg.Key && !s.DeletedAt.Valid {
			return storage.Secret{}, uniqueViolation()
		}
	}
	id := f.id("secret")
	row := storage.Secret{
		SecretID: id, SecretUuid: uuid.New(), TenantID: arg.TenantID,
		ProjectID: arg.ProjectID, EnvironmentID: arg.EnvironmentID, FolderID: arg.FolderID,
		MrnService: arg.MrnService, MrnTenant: arg.MrnTenant, MrnProject: arg.MrnProject,
		MrnResourcePath: arg.MrnResourcePath, Key: arg.Key, Description: arg.Description,
		Tags: arg.Tags, CurrentVersion: 0, KeepVersions: arg.KeepVersions,
		RotationPolicy: arg.RotationPolicy, ExpiresAt: arg.ExpiresAt, Metadata: arg.Metadata,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	f.secrets[id] = &row
	return row, nil
}

func (f *fakeRepo) findSecret(tenantID, envID, folderID int64, key string) (storage.Secret, error) {
	for _, s := range f.secrets {
		if s.TenantID == tenantID && s.EnvironmentID == envID &&
			s.FolderID == folderID && s.Key == key && !s.DeletedAt.Valid {
			return *s, nil
		}
	}
	return storage.Secret{}, pgx.ErrNoRows
}

func (f *fakeRepo) GetSecretByAddress(_ context.Context, arg storage.GetSecretByAddressParams) (storage.Secret, error) {
	return f.findSecret(arg.TenantID, arg.EnvironmentID, arg.FolderID, arg.Key)
}

func (f *fakeRepo) GetSecretByAddressForUpdate(_ context.Context, arg storage.GetSecretByAddressForUpdateParams) (storage.Secret, error) {
	return f.findSecret(arg.TenantID, arg.EnvironmentID, arg.FolderID, arg.Key)
}

func (f *fakeRepo) GetSecretByUUID(_ context.Context, arg storage.GetSecretByUUIDParams) (storage.Secret, error) {
	for _, s := range f.secrets {
		if s.TenantID == arg.TenantID && s.SecretUuid == arg.SecretUuid {
			return *s, nil
		}
	}
	return storage.Secret{}, pgx.ErrNoRows
}

func (f *fakeRepo) SetSecretCurrentVersion(_ context.Context, arg storage.SetSecretCurrentVersionParams) (storage.Secret, error) {
	s, ok := f.secrets[arg.SecretID]
	if !ok || s.TenantID != arg.TenantID {
		return storage.Secret{}, pgx.ErrNoRows
	}
	s.CurrentVersion = arg.CurrentVersion
	if arg.MarkRotated {
		s.RotatedAt = pgtype.Timestamptz{Time: time.Now(), Valid: true}
	}
	s.UpdatedAt = time.Now()
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
			s.UpdatedAt = time.Now()
			return *s, nil
		}
	}
	return storage.Secret{}, pgx.ErrNoRows
}

func (f *fakeRepo) ListSecretMetaBySubtree(_ context.Context, arg storage.ListSecretMetaBySubtreeParams) ([]storage.ListSecretMetaBySubtreeRow, error) {
	out := []storage.ListSecretMetaBySubtreeRow{}
	for _, s := range f.secrets {
		if s.TenantID != arg.TenantID || s.EnvironmentID != arg.EnvironmentID || s.DeletedAt.Valid {
			continue
		}
		folder := f.folders[s.FolderID]
		if folder == nil || !pathInSubtree(folder.Path, arg.Path) {
			continue
		}
		out = append(out, storage.ListSecretMetaBySubtreeRow{
			SecretUuid: s.SecretUuid, FolderPath: folder.Path, Key: s.Key,
			Description: s.Description, Tags: s.Tags, CurrentVersion: s.CurrentVersion,
			KeepVersions: s.KeepVersions, RotationPolicy: s.RotationPolicy,
			MrnTenant: s.MrnTenant, MrnProject: s.MrnProject, MrnResourcePath: s.MrnResourcePath,
			RotatedAt: s.RotatedAt, ExpiresAt: s.ExpiresAt,
			CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt,
		})
	}
	return out, nil
}

func (f *fakeRepo) CountSecretsInSubtree(_ context.Context, arg storage.CountSecretsInSubtreeParams) (int64, error) {
	rows, _ := f.ListSecretMetaBySubtree(context.Background(), storage.ListSecretMetaBySubtreeParams{
		TenantID: arg.TenantID, EnvironmentID: arg.EnvironmentID,
		Path: arg.Path, PathPattern: arg.PathPattern,
	})
	return int64(len(rows)), nil
}

// pathInSubtree mirrors `path = @path OR path LIKE @path_pattern`.
func pathInSubtree(path, prefix string) bool {
	if prefix == "/" {
		return true
	}
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

// --- versions --------------------------------------------------------------

func (f *fakeRepo) CreateSecretVersion(_ context.Context, arg storage.CreateSecretVersionParams) (storage.SecretVersion, error) {
	for _, v := range f.versions {
		if v.SecretID == arg.SecretID && v.Version == arg.Version {
			return storage.SecretVersion{}, uniqueViolation()
		}
	}
	id := f.id("version")
	row := storage.SecretVersion{
		VersionID: id, SecretID: arg.SecretID, Version: arg.Version,
		Ciphertext: arg.Ciphertext, Nonce: arg.Nonce, DekWrapped: arg.DekWrapped,
		DekNonce: arg.DekNonce, KekID: arg.KekID, ValueType: arg.ValueType,
		Checksum: arg.Checksum, CreatedAt: time.Now(),
	}
	f.versions[id] = &row
	return row, nil
}

func (f *fakeRepo) GetLatestSecretVersion(_ context.Context, secretID int64) (storage.SecretVersion, error) {
	var best *storage.SecretVersion
	for _, v := range f.versions {
		if v.SecretID != secretID {
			continue
		}
		if best == nil || v.Version > best.Version {
			best = v
		}
	}
	if best == nil {
		return storage.SecretVersion{}, pgx.ErrNoRows
	}
	return *best, nil
}

func (f *fakeRepo) GetSecretVersion(_ context.Context, arg storage.GetSecretVersionParams) (storage.SecretVersion, error) {
	for _, v := range f.versions {
		if v.SecretID == arg.SecretID && v.Version == arg.Version {
			return *v, nil
		}
	}
	return storage.SecretVersion{}, pgx.ErrNoRows
}

func (f *fakeRepo) GetSecretVersionValueType(_ context.Context, arg storage.GetSecretVersionValueTypeParams) (string, error) {
	for _, v := range f.versions {
		if v.SecretID == arg.SecretID && v.Version == arg.Version {
			return v.ValueType, nil
		}
	}
	return "", pgx.ErrNoRows
}

func (f *fakeRepo) GetLatestVersionChecksum(ctx context.Context, secretID int64) (storage.GetLatestVersionChecksumRow, error) {
	v, err := f.GetLatestSecretVersion(ctx, secretID)
	if err != nil {
		return storage.GetLatestVersionChecksumRow{}, err
	}
	return storage.GetLatestVersionChecksumRow{Version: v.Version, Checksum: v.Checksum}, nil
}

func (f *fakeRepo) ListPrunableVersions(_ context.Context, _ storage.ListPrunableVersionsParams) ([]storage.ListPrunableVersionsRow, error) {
	// Retention is exercised in the store package's own tests; here it is a no-op so
	// api-level tests are not coupled to pruning behaviour.
	return []storage.ListPrunableVersionsRow{}, nil
}

func (f *fakeRepo) ListSecretVersionMeta(_ context.Context, arg storage.ListSecretVersionMetaParams) ([]storage.ListSecretVersionMetaRow, error) {
	out := []storage.ListSecretVersionMetaRow{}
	for _, v := range f.versions {
		if v.SecretID != arg.SecretID {
			continue
		}
		out = append(out, storage.ListSecretVersionMetaRow{
			Version: v.Version, KekID: v.KekID, ValueType: v.ValueType,
			Checksum: v.Checksum, CreatedAt: v.CreatedAt,
		})
	}
	return out, nil
}

func (f *fakeRepo) CountSecretVersions(_ context.Context, secretID int64) (int64, error) {
	n := int64(0)
	for _, v := range f.versions {
		if v.SecretID == secretID {
			n++
		}
	}
	return n, nil
}

// ListSecretsWithRotationPolicy mirrors the SQL filter: enabled policies on live
// rows, with the addressing columns joined in. Due-ness is decided in Go, so this
// does no time arithmetic — exactly like the real query.
func (f *fakeRepo) ListSecretsWithRotationPolicy(_ context.Context, arg storage.ListSecretsWithRotationPolicyParams) ([]storage.ListSecretsWithRotationPolicyRow, error) {
	if arg.RowOffset > 0 {
		return []storage.ListSecretsWithRotationPolicyRow{}, nil
	}
	out := []storage.ListSecretsWithRotationPolicyRow{}
	for _, s := range f.secrets {
		if s.DeletedAt.Valid || !bytes.Contains(s.RotationPolicy, []byte(`"enabled":true`)) {
			continue
		}
		tenant := f.tenants[s.TenantID]
		project := f.projects[s.ProjectID]
		env := f.environments[s.EnvironmentID]
		folder := f.folders[s.FolderID]
		if tenant == nil || project == nil || env == nil || folder == nil {
			continue
		}
		out = append(out, storage.ListSecretsWithRotationPolicyRow{
			SecretID: s.SecretID, SecretUuid: s.SecretUuid, TenantUuid: tenant.TenantUuid,
			ProjectSlug: project.Slug, EnvironmentSlug: env.Slug, FolderPath: folder.Path,
			Key: s.Key, CurrentVersion: s.CurrentVersion, RotationPolicy: s.RotationPolicy,
			RotatedAt: s.RotatedAt, CreatedAt: s.CreatedAt,
			MrnTenant: s.MrnTenant, MrnProject: s.MrnProject, MrnResourcePath: s.MrnResourcePath,
		})
	}
	return out, nil
}

// --- scope imports ---------------------------------------------------------

func (f *fakeRepo) CreateScopeImport(_ context.Context, arg storage.CreateScopeImportParams) (storage.ScopeImport, error) {
	id := f.id("import")
	row := storage.ScopeImport{
		ImportID: id, ImportUuid: uuid.New(), TenantID: arg.TenantID,
		EnvironmentID: arg.EnvironmentID, FolderID: arg.FolderID,
		SourceEnvironmentID: arg.SourceEnvironmentID, SourceFolderID: arg.SourceFolderID,
		Position: arg.Position, Enabled: arg.Enabled, Metadata: arg.Metadata,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	f.imports[id] = &row
	return row, nil
}

func (f *fakeRepo) ListScopeImportsByTarget(_ context.Context, arg storage.ListScopeImportsByTargetParams) ([]storage.ListScopeImportsByTargetRow, error) {
	out := []storage.ListScopeImportsByTargetRow{}
	for _, imp := range f.imports {
		if imp.TenantID != arg.TenantID || imp.FolderID != arg.FolderID || !imp.Enabled || imp.DeletedAt.Valid {
			continue
		}
		srcFolder := f.folders[imp.SourceFolderID]
		srcEnv := f.environments[imp.SourceEnvironmentID]
		if srcFolder == nil || srcEnv == nil {
			continue
		}
		srcProject := f.projects[srcEnv.ProjectID]
		if srcProject == nil {
			continue
		}
		out = append(out, storage.ListScopeImportsByTargetRow{
			ImportUuid: imp.ImportUuid, ImportID: imp.ImportID, TenantID: imp.TenantID,
			EnvironmentID: imp.EnvironmentID, FolderID: imp.FolderID,
			SourceEnvironmentID: imp.SourceEnvironmentID, SourceFolderID: imp.SourceFolderID,
			Position: imp.Position, Enabled: imp.Enabled,
			CreatedAt: imp.CreatedAt, UpdatedAt: imp.UpdatedAt,
			SourceEnvironmentSlug: srcEnv.Slug, SourceFolderPath: srcFolder.Path,
			SourceProjectSlug: srcProject.Slug,
		})
	}
	return out, nil
}

// --- audit -----------------------------------------------------------------

func (f *fakeRepo) AppendAuditEvent(_ context.Context, arg storage.AppendAuditEventParams) (storage.AuditLog, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.auditErr != nil {
		return storage.AuditLog{}, f.auditErr
	}
	row := storage.AuditLog{
		EventID: f.id("audit"), EventUuid: uuid.New(), TenantID: arg.TenantID,
		ActorSubject: arg.ActorSubject, ActorKind: arg.ActorKind, Action: arg.Action,
		ResourceMrn: arg.ResourceMrn, SecretID: arg.SecretID, Version: arg.Version,
		Outcome: arg.Outcome, Reason: arg.Reason, IpAddress: arg.IpAddress,
		UserAgent: arg.UserAgent, RequestID: arg.RequestID, Metadata: arg.Metadata,
		CreatedAt: time.Now(),
	}
	f.auditLog = append(f.auditLog, row)
	return row, nil
}

// auditRows returns a snapshot of the trail.
func (f *fakeRepo) auditRows() []storage.AuditLog {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]storage.AuditLog, len(f.auditLog))
	copy(out, f.auditLog)
	return out
}

// countAudit counts rows matching an action and outcome ("" matches any).
func (f *fakeRepo) countAudit(action, outcome string) int {
	n := 0
	for _, row := range f.auditRows() {
		if action != "" && row.Action != action {
			continue
		}
		if outcome != "" && row.Outcome != outcome {
			continue
		}
		n++
	}
	return n
}

// uniqueViolation returns the real driver error the store translates into a
// Conflict. It has to be the actual *pgconn.PgError: the store matches on the type,
// so a stand-in would silently take the "unexpected internal error" branch and a test
// asserting a conflict would pass for the wrong reason.
func uniqueViolation() error {
	return &pgconn.PgError{Code: "23505", Message: "duplicate key value violates unique constraint"}
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

type fixture struct {
	t     *testing.T
	repo  *fakeRepo
	store *store.Service
	api   *Service
	notes *recordingNotifier
	// tenant is the tenant every caller in these tests is scoped to.
	tenant store.Tenant
}

// recordingNotifier captures webhook notifications instead of delivering them.
type recordingNotifier struct {
	mu   sync.Mutex
	sent []Notification
}

func (n *recordingNotifier) Notify(_ context.Context, note Notification) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.sent = append(n.sent, note)
}

func (n *recordingNotifier) all() []Notification {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]Notification, len(n.sent))
	copy(out, n.sent)
	return out
}

// newFixture builds an api service over an in-memory store with one tenant, one
// project ("billing-app") and two environments ("dev" and "prod").
//
// Two environments rather than one because the property most of these tests exist to
// check — "may read staging, not prod" — is not expressible with one.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	repo := newFakeRepo()
	ring := mustKeyRing(t)
	st, err := store.NewService(repo, ring, store.Policy{
		KeepVersions:       5,
		RecoveryWindow:     30 * 24 * time.Hour,
		RewrapBatch:        10,
		DefaultTenant:      "acme",
		DefaultProject:     "billing-app",
		DefaultEnvironment: "prod",
	})
	require.NoError(t, err)

	auditor, err := audit.New(st)
	require.NoError(t, err)
	notes := &recordingNotifier{}
	svc, err := New(st, auditor, notes, Options{DefaultTenant: "acme"})
	require.NoError(t, err)

	ctx := context.Background()
	tenant, err := st.CreateTenant(ctx, store.CreateTenantInput{Name: "acme", DisplayName: "Acme"})
	require.NoError(t, err)
	_, err = st.CreateProject(ctx, store.CreateProjectInput{TenantUUID: tenant.UUID, Slug: "billing-app", Name: "Billing"})
	require.NoError(t, err)
	for _, env := range []string{"dev", "prod"} {
		_, err = st.CreateEnvironment(ctx, store.CreateEnvironmentInput{
			TenantUUID: tenant.UUID, Project: "billing-app", Slug: env, Name: env,
		})
		require.NoError(t, err)
	}

	return &fixture{t: t, repo: repo, store: st, api: svc, notes: notes, tenant: *tenant}
}

// caller builds a Caller with the given grants.
//
// BlanketActions is set from permissions.BlanketActions() exactly as the guard
// sets it on a real request. Leaving it nil would give this fixture a principal
// for which secret:Admin covers nothing — a test double that is more restrictive
// than production, which is the direction that produces false confidence.
func (fx *fixture) caller(grants ...sdkauthz.Grant) Caller {
	return Caller{
		Claims: &sdkauthz.Claims{
			Subject:        "user-1",
			Kind:           sdkauthz.ActorKindUser,
			Tenant:         "acme",
			Grants:         grants,
			BlanketActions: permissions.BlanketActions(),
		},
		Actor:      audit.Actor{Subject: "user-1", Kind: store.ActorKindUser, IP: "203.0.113.7", RequestID: "req-1"},
		TenantUUID: fx.tenant.UUID,
		TenantName: fx.tenant.Name,
	}
}

// admin is a caller with a blanket grant, for arranging test state.
func (fx *fixture) admin() Caller {
	return fx.caller(sdkauthz.Grant{Action: permissions.PermAdmin})
}

// addr builds an address in the fixture's project.
func addr(environment, folderPath, key string) SecretAddress {
	return SecretAddress{Project: "billing-app", Environment: environment, FolderPath: folderPath, Key: key}
}

// seed writes a secret as the admin caller.
func (fx *fixture) seed(environment, folderPath, key, value string) *store.PutResult {
	fx.t.Helper()
	res, err := fx.api.PutSecret(context.Background(), fx.admin(), PutSecretInput{
		Address:       addr(environment, folderPath, key),
		Value:         []byte(value),
		CreateFolders: true,
	})
	require.NoError(fx.t, err)
	return res
}

// seedReference writes a reference-typed secret THROUGH THE STORE, deliberately
// bypassing the api layer's write-time template check.
//
// That is not a shortcut around validation, it is what keeps the read-path tests
// meaningful. Several of them seed a malformed template ON PURPOSE (an unterminated
// placeholder, an address with no environment) to prove the RESOLVER refuses it. The
// api layer now also refuses such a template at write time — see
// validateReferenceTemplate — so seeding through PutSecret would exercise the write
// check twice and the read check never. Both matter: the write check is the early,
// legible rejection; the read check is the backstop for a row that arrived by any
// other route (a rotation, a direct store write, or data written before the write
// check existed). The write side is covered in validation_secret_test.go.
func (fx *fixture) seedReference(environment, folderPath, key, template string) {
	fx.t.Helper()
	address := addr(environment, folderPath, key)
	_, err := fx.api.Store().PutSecret(context.Background(), store.PutSecretInput{
		Ref:           address.ref(fx.admin()),
		Value:         []byte(template),
		ValueType:     store.ValueTypeReference,
		CreateFolders: true,
	})
	require.NoError(fx.t, err)
}

func mustKeyRing(t *testing.T) *crypto.KeyRing {
	t.Helper()
	raw := make([]byte, crypto.KeySize)
	for i := range raw {
		raw[i] = 0x2a
	}
	p, err := crypto.NewRootKeyProvider(crypto.ProviderConfig{
		Provider: crypto.ProviderEnv,
		AppEnv:   "production",
		Key:      hex.EncodeToString(raw),
	})
	require.NoError(t, err)
	ring, err := crypto.NewKeyRing(p)
	require.NoError(t, err)
	return ring
}

// errAuditDown is the failure injected to prove a reveal cannot succeed unaudited.
var errAuditDown = errors.New("audit sink is down")

// containsValue reports whether a haystack contains the plaintext, for the
// "no value ever appears here" assertions.
func containsValue(haystack []byte, value string) bool {
	return bytes.Contains(haystack, []byte(value))
}
