package setup

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/maintainerd/secret/internal/audit"
	"github.com/maintainerd/secret/internal/crypto"
	"github.com/maintainerd/secret/internal/platform/apperror"
	"github.com/maintainerd/secret/internal/storage"
	"github.com/maintainerd/secret/internal/store"
)

// fakeRepo models the rows the setup surface touches. As elsewhere, the embedded nil
// Querier makes any unmodelled query panic by name rather than return a zero value.
type fakeRepo struct {
	storage.Querier

	next         map[string]int64
	tenants      map[int64]*storage.Tenant
	projects     map[int64]*storage.Project
	environments map[int64]*storage.Environment
	folders      map[int64]*storage.Folder
	setupState   *storage.SetupState
	auditRows    []storage.AuditLog
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{
		next:         map[string]int64{},
		tenants:      map[int64]*storage.Tenant{},
		projects:     map[int64]*storage.Project{},
		environments: map[int64]*storage.Environment{},
		folders:      map[int64]*storage.Folder{},
	}
}

func (f *fakeRepo) id(kind string) int64 { f.next[kind]++; return f.next[kind] }

func (f *fakeRepo) InTx(_ context.Context, fn func(store.Repository) error) error { return fn(f) }

func (f *fakeRepo) CreateTenant(_ context.Context, arg storage.CreateTenantParams) (storage.Tenant, error) {
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

func (f *fakeRepo) GetTenantByName(_ context.Context, name string) (storage.Tenant, error) {
	for _, t := range f.tenants {
		if t.Name == name {
			return *t, nil
		}
	}
	return storage.Tenant{}, pgx.ErrNoRows
}

func (f *fakeRepo) GetTenantByUUID(_ context.Context, id uuid.UUID) (storage.Tenant, error) {
	for _, t := range f.tenants {
		if t.TenantUuid == id {
			return *t, nil
		}
	}
	return storage.Tenant{}, pgx.ErrNoRows
}

func (f *fakeRepo) CreateProject(_ context.Context, arg storage.CreateProjectParams) (storage.Project, error) {
	id := f.id("project")
	row := storage.Project{
		ProjectID: id, ProjectUuid: uuid.New(), TenantID: arg.TenantID,
		Name: arg.Name, Slug: arg.Slug, Status: arg.Status, Metadata: arg.Metadata,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	f.projects[id] = &row
	return row, nil
}

func (f *fakeRepo) GetProjectBySlug(_ context.Context, arg storage.GetProjectBySlugParams) (storage.Project, error) {
	for _, p := range f.projects {
		if p.TenantID == arg.TenantID && p.Slug == arg.Slug {
			return *p, nil
		}
	}
	return storage.Project{}, pgx.ErrNoRows
}

func (f *fakeRepo) CreateEnvironment(_ context.Context, arg storage.CreateEnvironmentParams) (storage.Environment, error) {
	id := f.id("environment")
	row := storage.Environment{
		EnvironmentID: id, EnvironmentUuid: uuid.New(), ProjectID: arg.ProjectID,
		Name: arg.Name, Slug: arg.Slug, Status: arg.Status, Metadata: arg.Metadata,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	f.environments[id] = &row
	return row, nil
}

func (f *fakeRepo) GetEnvironmentBySlug(_ context.Context, arg storage.GetEnvironmentBySlugParams) (storage.Environment, error) {
	for _, e := range f.environments {
		if e.ProjectID == arg.ProjectID && e.Slug == arg.Slug {
			return *e, nil
		}
	}
	return storage.Environment{}, pgx.ErrNoRows
}

func (f *fakeRepo) CreateFolder(_ context.Context, arg storage.CreateFolderParams) (storage.Folder, error) {
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
	for _, fo := range f.folders {
		if fo.EnvironmentID == arg.EnvironmentID && fo.Path == arg.Path {
			return *fo, nil
		}
	}
	return storage.Folder{}, pgx.ErrNoRows
}

func (f *fakeRepo) GetSetupState(_ context.Context) (storage.SetupState, error) {
	if f.setupState == nil {
		return storage.SetupState{}, pgx.ErrNoRows
	}
	return *f.setupState, nil
}

func (f *fakeRepo) EnsureSetupState(_ context.Context) error {
	if f.setupState == nil {
		f.setupState = &storage.SetupState{ID: 1, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	}
	return nil
}

// CompleteSetup reproduces the one-shot guard: the DO UPDATE branch only fires when
// completed_at IS NULL, so a second caller updates no row and receives none.
func (f *fakeRepo) CompleteSetup(_ context.Context, arg storage.CompleteSetupParams) (storage.SetupState, error) {
	if f.setupState == nil {
		f.setupState = &storage.SetupState{ID: 1}
	}
	if f.setupState.CompletedAt.Valid {
		return storage.SetupState{}, pgx.ErrNoRows
	}
	f.setupState.CompletedAt = pgtype.Timestamptz{Time: time.Now(), Valid: true}
	f.setupState.Controller = arg.Controller
	f.setupState.ControllerKind = arg.ControllerKind
	return *f.setupState, nil
}

func (f *fakeRepo) AppendAuditEvent(_ context.Context, arg storage.AppendAuditEventParams) (storage.AuditLog, error) {
	row := storage.AuditLog{
		EventID: f.id("audit"), EventUuid: uuid.New(), TenantID: arg.TenantID,
		ActorSubject: arg.ActorSubject, ActorKind: arg.ActorKind, Action: arg.Action,
		ResourceMrn: arg.ResourceMrn, Outcome: arg.Outcome, Metadata: arg.Metadata,
		CreatedAt: time.Now(),
	}
	f.auditRows = append(f.auditRows, row)
	return row, nil
}

// ---------------------------------------------------------------------------

func newTestService(t *testing.T, opts Options) (*Service, *fakeRepo) {
	t.Helper()
	repo := newFakeRepo()
	raw := make([]byte, crypto.KeySize)
	for i := range raw {
		raw[i] = 0x11
	}
	provider, err := crypto.NewRootKeyProvider(crypto.ProviderConfig{
		Provider: crypto.ProviderEnv, AppEnv: "production", Key: hex.EncodeToString(raw),
	})
	require.NoError(t, err)
	ring, err := crypto.NewKeyRing(provider)
	require.NoError(t, err)

	st, err := store.NewService(repo, ring, store.Policy{
		KeepVersions:       5,
		RecoveryWindow:     time.Hour,
		DefaultTenant:      "acme",
		DefaultProject:     "default",
		DefaultEnvironment: "default",
	})
	require.NoError(t, err)
	auditor, err := audit.New(st)
	require.NoError(t, err)

	if opts.DefaultTenant == "" {
		opts.DefaultTenant = "acme"
	}
	if opts.DefaultProject == "" {
		opts.DefaultProject = "default"
	}
	if opts.DefaultEnvironment == "" {
		opts.DefaultEnvironment = "default"
	}
	svc, err := New(st, auditor, opts)
	require.NoError(t, err)
	return svc, repo
}

// TestSetupRequiresAnAuditor: setup writes the first rows in the trail — who
// provisioned this vault and when — so running it unauditably would leave the single
// most important event in the instance's life unrecorded.
func TestSetupRequiresAnAuditor(t *testing.T) {
	svc, _ := newTestService(t, Options{BootstrapToken: "t"})
	_, err := New(svc.store, nil, Options{})
	require.ErrorIs(t, err, audit.ErrNoAuditor)
}

// TestEmptyTokenDisablesSetupOutsideDevelopment is the prototype's bug, fixed: empty
// used to mean "setup is open".
func TestEmptyTokenDisablesSetupOutsideDevelopment(t *testing.T) {
	svc, _ := newTestService(t, Options{BootstrapToken: "", Development: false})
	require.ErrorIs(t, svc.CheckToken(""), ErrSetupDisabled)
	require.ErrorIs(t, svc.CheckToken("anything"), ErrSetupDisabled)

	dev, _ := newTestService(t, Options{BootstrapToken: "", Development: true})
	require.NoError(t, dev.CheckToken(""), "development may run without a token")
}

func TestWrongTokenIsRefused(t *testing.T) {
	svc, _ := newTestService(t, Options{BootstrapToken: "correct-horse"})
	require.NoError(t, svc.CheckToken("correct-horse"))

	err := svc.CheckToken("wrong")
	require.Error(t, err)
	assert.True(t, apperror.IsForbidden(err))
	assert.Error(t, svc.CheckToken(""))
}

// TestProvisionCreatesTheDefaultScopeAndIsIdempotent: a controller whose response was
// lost must be able to retry, and a retry must converge rather than report a conflict
// that reads as "somebody else claimed this instance".
func TestProvisionCreatesTheDefaultScopeAndIsIdempotent(t *testing.T) {
	svc, repo := newTestService(t, Options{BootstrapToken: "t"})
	ctx := context.Background()

	first, err := svc.Provision(ctx, ProvisionInput{Controller: "core", Mode: ModeControlled}, audit.Actor{})
	require.NoError(t, err)
	assert.False(t, first.AlreadyExisted)
	assert.Equal(t, "acme", first.Tenant)
	assert.Equal(t, "default", first.Project)
	assert.Equal(t, "default", first.Environment)
	assert.Len(t, repo.tenants, 1)
	assert.Len(t, repo.projects, 1)
	assert.Len(t, repo.environments, 1)

	second, err := svc.Provision(ctx, ProvisionInput{Controller: "core", Mode: ModeControlled}, audit.Actor{})
	require.NoError(t, err, "a retry must converge, not conflict")
	assert.True(t, second.AlreadyExisted)
	assert.Equal(t, first.TenantUUID, second.TenantUUID)
	assert.Len(t, repo.tenants, 1, "no duplicate tenant")
	assert.Len(t, repo.projects, 1)
}

// TestProvisionRecordsTheAuthTenantMapping is the controlled-mode fact Core needs:
// which Auth tenant this instance's secrets hang off.
func TestProvisionRecordsTheAuthTenantMapping(t *testing.T) {
	svc, repo := newTestService(t, Options{BootstrapToken: "t"})
	authTenant := uuid.New()

	_, err := svc.Provision(context.Background(), ProvisionInput{
		Controller: "core", Mode: ModeControlled, AuthTenantUUID: &authTenant,
	}, audit.Actor{})
	require.NoError(t, err)

	for _, tenant := range repo.tenants {
		require.True(t, tenant.AuthTenantUuid.Valid)
		assert.Equal(t, authTenant, uuid.UUID(tenant.AuthTenantUuid.Bytes))
		assert.True(t, tenant.IsSystem, "the first tenant of an install is the system tenant")
	}
}

// TestCompleteIsSingleUse: the durable lock, enforced by the database rather than by a
// check-then-act in Go.
func TestCompleteIsSingleUse(t *testing.T) {
	svc, _ := newTestService(t, Options{BootstrapToken: "t"})
	ctx := context.Background()
	_, err := svc.Provision(ctx, ProvisionInput{Controller: "core", Mode: ModeControlled}, audit.Actor{})
	require.NoError(t, err)

	status, err := svc.Complete(ctx, "core", ModeControlled, audit.Actor{})
	require.NoError(t, err)
	assert.True(t, status.Completed)
	assert.Equal(t, ModeControlled, status.Mode)

	_, err = svc.Complete(ctx, "someone-else", ModeControlled, audit.Actor{})
	require.Error(t, err, "the setup window closes exactly once")
	assert.True(t, apperror.IsConflict(err))
}

// TestRefuseWhenOrchestrated is the rule that gives an instance exactly ONE setup
// path. Both surfaces create the first tenant; two open paths is a race whose winner
// owns the vault, and the REST one is reachable by anything on the network.
func TestRefuseWhenOrchestrated(t *testing.T) {
	svc, _ := newTestService(t, Options{BootstrapToken: "t"})
	ctx := context.Background()

	refuse, err := svc.RefuseWhenOrchestrated(ctx)
	require.NoError(t, err)
	assert.False(t, refuse, "before setup, the wizard is open")

	_, err = svc.Provision(ctx, ProvisionInput{Controller: "core", Mode: ModeControlled}, audit.Actor{})
	require.NoError(t, err)
	refuse, err = svc.RefuseWhenOrchestrated(ctx)
	require.NoError(t, err)
	assert.False(t, refuse, "provisioning alone does not close the wizard; completion does")

	_, err = svc.Complete(ctx, "core", ModeControlled, audit.Actor{})
	require.NoError(t, err)
	refuse, err = svc.RefuseWhenOrchestrated(ctx)
	require.NoError(t, err)
	assert.True(t, refuse, "an orchestrated instance refuses the REST wizard")

	status, err := svc.Status(ctx)
	require.NoError(t, err)
	assert.False(t, status.RESTWizardOpen)
}

// TestStandaloneCompletionDoesNotMarkTheInstanceOrchestrated: the condition is
// "an orchestrator owns this instance", not merely "setup is complete".
func TestStandaloneCompletionDoesNotMarkTheInstanceOrchestrated(t *testing.T) {
	svc, _ := newTestService(t, Options{BootstrapToken: "t"})
	ctx := context.Background()

	_, status, err := svc.ProvisionAndComplete(ctx, ProvisionInput{Controller: "operator"}, audit.Actor{})
	require.NoError(t, err)
	assert.True(t, status.Completed)
	assert.Equal(t, ModeStandalone, status.Mode)
	assert.Equal(t, store.ControllerKindOperator, status.ControllerKind)

	refuse, err := svc.RefuseWhenOrchestrated(ctx)
	require.NoError(t, err)
	assert.False(t, refuse, "a standalone install was never orchestrated")
}

// TestCoreModeClosesTheRESTWizardFromTheFirstBoot.
//
// MAINTAINERD_MODE=core is the operator DECLARING that a controller owns
// first-run. Without this, there is a window between "the instance is up" and
// "core has provisioned it" in which the REST wizard is reachable by anything on
// the network and would hand the vault to whoever posts first. The bootstrap
// token still gates that window; a declared mode is a second, free gate.
func TestCoreModeClosesTheRESTWizardFromTheFirstBoot(t *testing.T) {
	svc, _ := newTestService(t, Options{BootstrapToken: "t", CoreAttached: true})
	ctx := context.Background()

	refuse, err := svc.RefuseWhenOrchestrated(ctx)
	require.NoError(t, err)
	assert.True(t, refuse, "core mode refuses the wizard before anything has been provisioned")

	status, err := svc.Status(ctx)
	require.NoError(t, err)
	assert.False(t, status.RESTWizardOpen)
	assert.False(t, status.Completed, "refusing the wizard is not the same as being provisioned")
}

// TestStandaloneIsTheDefaultAndLeavesTheWizardOpen is the other half, and the
// reason CoreAttached defaults to false: an operator who never adopts core, and
// therefore never sets MAINTAINERD_MODE, must still be able to provision. Nothing
// about the gRPC SetupService changes in either mode — an instance that starts
// standalone and is later adopted by core has to remain provisionable.
func TestStandaloneIsTheDefaultAndLeavesTheWizardOpen(t *testing.T) {
	svc, _ := newTestService(t, Options{BootstrapToken: "t"})
	ctx := context.Background()

	refuse, err := svc.RefuseWhenOrchestrated(ctx)
	require.NoError(t, err)
	assert.False(t, refuse)

	_, status, err := svc.ProvisionAndComplete(ctx, ProvisionInput{Controller: "operator"}, audit.Actor{})
	require.NoError(t, err)
	assert.True(t, status.Completed)
	assert.Equal(t, ModeStandalone, status.Mode)
}

// TestAnonymousStatusIsOneBit: a client has to know whether to show a wizard, and
// nothing else about an unprovisioned vault is safe to hand out.
func TestAnonymousStatusIsOneBit(t *testing.T) {
	full := Status{
		Completed: true, Controller: "core", ControllerKind: "service",
		Mode: ModeControlled, Tenant: "acme", AuthTenantUUID: uuid.NewString(),
		Project: "default", Environment: "default", Permissions: []string{"secret:Admin"},
	}
	anon := AnonymousStatus(full)
	assert.True(t, anon.Completed)
	assert.Empty(t, anon.Controller)
	assert.Empty(t, anon.ControllerKind)
	assert.Empty(t, anon.Tenant)
	assert.Empty(t, anon.AuthTenantUUID)
	assert.Empty(t, anon.Project)
	assert.Empty(t, anon.Permissions)
}

// TestStatusReportsTheEnforcedPermissions so a controller registers exactly what is
// enforced instead of a hand-maintained copy that drifts.
func TestStatusReportsTheEnforcedPermissions(t *testing.T) {
	svc, _ := newTestService(t, Options{
		BootstrapToken:      "t",
		DeclaredPermissions: []string{"secret:GetSecret", "secret:ReadMetadata"},
	})
	status, err := svc.Status(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"secret:GetSecret", "secret:ReadMetadata"}, status.Permissions)
}

// TestProvisionIsAudited: the first rows in the trail.
func TestProvisionIsAudited(t *testing.T) {
	svc, repo := newTestService(t, Options{BootstrapToken: "t"})
	ctx := context.Background()
	_, err := svc.Provision(ctx, ProvisionInput{Controller: "core", Mode: ModeControlled}, audit.Actor{})
	require.NoError(t, err)
	_, err = svc.Complete(ctx, "core", ModeControlled, audit.Actor{})
	require.NoError(t, err)

	actions := map[string]bool{}
	for _, row := range repo.auditRows {
		actions[row.Action] = true
		assert.Equal(t, store.ActorKindSetup, row.ActorKind)
		assert.Equal(t, "core", row.ActorSubject)
	}
	assert.True(t, actions[store.ActionSetupProvision])
	assert.True(t, actions[store.ActionSetupComplete])
}

func TestDescribeMode(t *testing.T) {
	assert.Contains(t, DescribeMode(ModeControlled), "gRPC SetupService")
	assert.Contains(t, DescribeMode(ModeStandalone), "REST wizard")
	assert.Equal(t, "not provisioned", DescribeMode(""))
}
