package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/maintainerd/secret/internal/crypto"
	"github.com/maintainerd/secret/internal/platform/apperror"
)

// ---------------------------------------------------------------------------
// Root key registration
// ---------------------------------------------------------------------------

func TestEnsureActiveRootKeyIsIdempotent(t *testing.T) {
	// Restarting with the same key must resolve to the same registry row: kek_id is
	// a fingerprint of the material, so a restart cannot orphan the rows the
	// previous process wrote.
	fx := newFixture(t)
	ctx := context.Background()

	first, err := fx.svc.EnsureActiveRootKey(ctx)
	require.NoError(t, err)
	second, err := fx.svc.EnsureActiveRootKey(ctx)
	require.NoError(t, err)

	assert.Equal(t, first.KekID, second.KekID)
	assert.Equal(t, "active", second.State)
	assert.Equal(t, crypto.ProviderEnv, second.Provider)
	assert.Len(t, fx.repo.rootKeys, 1)
}

func TestEnsureActiveRootKeyDemotesTheIncumbent(t *testing.T) {
	// Booting with a NEW key is the first half of a rotation: the new key becomes
	// active, the old becomes 'retiring' (not retired — versions still point at it).
	fx := newFixture(t)
	ctx := context.Background()
	oldKEK := fx.ring.Active().KeyID()

	newProvider := mustProvider(t, 0x77)
	newRing, err := crypto.NewKeyRing(newProvider, fx.ring.Active())
	require.NoError(t, err)
	svc, err := NewService(fx.repo, newRing, fx.svc.Policy())
	require.NoError(t, err)

	row, err := svc.EnsureActiveRootKey(ctx)
	require.NoError(t, err)
	assert.Equal(t, newProvider.KeyID(), row.KekID)
	assert.Equal(t, "active", row.State)

	old, err := fx.repo.GetRootKey(ctx, oldKEK)
	require.NoError(t, err)
	assert.Equal(t, "retiring", old.State, "a superseded key must not be retired while versions reference it")

	pending, err := svc.PendingRewrapKeys(ctx)
	require.NoError(t, err)
	require.Len(t, pending, 1)
	assert.Equal(t, oldKEK, pending[0].KekID)
}

func TestPutSecretRequiresARegisteredRootKey(t *testing.T) {
	// secret_versions.kek_id is a foreign key to root_keys, so a write under an
	// unregistered key must fail rather than writing a row nobody can attribute.
	repo := newFakeRepo()
	svc, err := NewService(repo, mustKeyRing(t, 0x0a), Policy{
		KeepVersions: 3, DefaultTenant: "default", DefaultProject: "default", DefaultEnvironment: "default",
	})
	require.NoError(t, err)
	ctx := context.Background()

	tenant, err := svc.CreateTenant(ctx, CreateTenantInput{Name: "acme"})
	require.NoError(t, err)
	_, err = svc.CreateProject(ctx, CreateProjectInput{TenantUUID: tenant.UUID, Slug: "app"})
	require.NoError(t, err)
	_, err = svc.CreateEnvironment(ctx, CreateEnvironmentInput{TenantUUID: tenant.UUID, Project: "app", Slug: "prod"})
	require.NoError(t, err)

	// No EnsureActiveRootKey call.
	_, err = svc.PutSecret(ctx, PutSecretInput{
		Ref:   SecretRef{TenantUUID: tenant.UUID, Project: "app", Environment: "prod", Key: "TOKEN"},
		Value: []byte("v"), CreateFolders: true,
	})
	require.Error(t, err)

	// After registration the same write succeeds.
	_, err = svc.EnsureActiveRootKey(ctx)
	require.NoError(t, err)
	_, err = svc.PutSecret(ctx, PutSecretInput{
		Ref:   SecretRef{TenantUUID: tenant.UUID, Project: "app", Environment: "prod", Key: "TOKEN"},
		Value: []byte("v"), CreateFolders: true,
	})
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// Rewrap through the store
// ---------------------------------------------------------------------------

// rotateTo boots a second service over the same repository with newKey active and
// oldKey still readable — the state a process restart with a new root key produces.
func rotateTo(t *testing.T, fx *testFixture, newKey crypto.RootKeyProvider) *Service {
	t.Helper()
	ring, err := crypto.NewKeyRing(newKey, fx.ring.Active())
	require.NoError(t, err)
	svc, err := NewService(fx.repo, ring, fx.svc.Policy())
	require.NoError(t, err)
	svc.SetClock(func() time.Time { return fx.clock })
	_, err = svc.EnsureActiveRootKey(context.Background())
	require.NoError(t, err)
	return svc
}

func TestRewrapRootKeyPreservesEveryValue(t *testing.T) {
	fx := newFixture(t, func(p *Policy) { p.KeepVersions = 10; p.RewrapBatch = 3 })
	ctx := context.Background()
	oldKEK := fx.ring.Active().KeyID()

	// A spread of secrets and versions, so the rewrap has real work.
	want := map[string]string{}
	for i := 1; i <= 4; i++ {
		key := fmt.Sprintf("KEY_%d", i)
		fx.put("/db", key, fmt.Sprintf("value-%d-v1", i))
		fx.put("/db", key, fmt.Sprintf("value-%d-v2", i))
		want[key] = fmt.Sprintf("value-%d-v2", i)
	}
	ciphertextBefore := map[int64][]byte{}
	for id, v := range fx.repo.versions {
		ciphertextBefore[id] = append([]byte(nil), v.Ciphertext...)
	}

	newKey := mustProvider(t, 0x78)
	svc := rotateTo(t, fx, newKey)

	report, err := svc.RewrapRootKey(ctx, oldKEK)
	require.NoError(t, err)
	assert.EqualValues(t, 8, report.Rewrapped)
	assert.EqualValues(t, 0, report.Remaining)
	assert.True(t, report.Retired)

	// THE POINT: not one ciphertext byte changed. Only the wrapped DEKs moved.
	for id, before := range ciphertextBefore {
		require.Contains(t, fx.repo.versions, id)
		assert.Equal(t, before, fx.repo.versions[id].Ciphertext, "a rewrap must not rewrite payloads")
		assert.Equal(t, newKey.KeyID(), fx.repo.versions[id].KekID)
	}

	// Every value still decrypts under the new key.
	for key, value := range want {
		got, err := svc.GetSecret(ctx, fx.ref("/db", key))
		require.NoError(t, err, key)
		assert.Equal(t, value, string(got.Value.Bytes()), key)
		got.Zero()
	}

	// The old key is retired only now that nothing references it.
	old, err := fx.repo.GetRootKey(ctx, oldKEK)
	require.NoError(t, err)
	assert.Equal(t, "retired", old.State)
}

func TestRewrapRootKeyIsIdempotent(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()
	oldKEK := fx.ring.Active().KeyID()
	fx.put("/", "TOKEN", "v")

	svc := rotateTo(t, fx, mustProvider(t, 0x79))

	first, err := svc.RewrapRootKey(ctx, oldKEK)
	require.NoError(t, err)
	assert.EqualValues(t, 1, first.Rewrapped)

	second, err := svc.RewrapRootKey(ctx, oldKEK)
	require.NoError(t, err)
	assert.EqualValues(t, 0, second.Rewrapped, "re-running a completed rotation must do nothing")
}

func TestRewrapRequiresTheSanctionedGUC(t *testing.T) {
	// The fake refuses an UPDATE on a version without the rewrap GUC, exactly as the
	// trigger does — so a successful rewrap proves the store set it, and the
	// permission must not outlive its transaction.
	fx := newFixture(t)
	ctx := context.Background()
	oldKEK := fx.ring.Active().KeyID()
	fx.put("/", "TOKEN", "v")

	svc := rotateTo(t, fx, mustProvider(t, 0x7a))
	_, err := svc.RewrapRootKey(ctx, oldKEK)
	require.NoError(t, err)
	assert.False(t, fx.repo.rewrapAllowed, "the rewrap authorization must not outlive its transaction")
}

func TestRewrapUnknownKeyIsNotFound(t *testing.T) {
	fx := newFixture(t)
	_, err := fx.svc.RewrapRootKey(context.Background(), "env:0000000000000000000000")
	require.Error(t, err)
	assert.True(t, apperror.IsNotFound(err))

	_, err = fx.svc.RewrapRootKey(context.Background(), "")
	assert.True(t, apperror.IsValidation(err))
}

func TestReadFailsClearlyWhenAKeyIsMissingFromTheRing(t *testing.T) {
	// Rows wrapped under a key this process was not given must produce an actionable
	// error, not a decrypt failure that looks like corruption.
	fx := newFixture(t)
	ctx := context.Background()
	fx.put("/", "TOKEN", "v")

	// A ring that has only the new key — the old one was not supplied.
	lonelyRing, err := crypto.NewKeyRing(mustProvider(t, 0x7b))
	require.NoError(t, err)
	svc, err := NewService(fx.repo, lonelyRing, fx.svc.Policy())
	require.NoError(t, err)

	_, err = svc.GetSecret(ctx, fx.ref("/", "TOKEN"))
	require.Error(t, err)
	assert.True(t, apperror.IsUnavailable(err), "a missing root key is a dependency problem, not corruption")
	assert.Contains(t, err.Error(), "cannot be read until it is supplied")
}

func TestReadsKeepWorkingMidRotation(t *testing.T) {
	// The whole reason the keyring is keyed by kek_id: during a rotation the store
	// legitimately holds versions under several keys, and reads must not stop.
	fx := newFixture(t, func(p *Policy) { p.KeepVersions = 10 })
	ctx := context.Background()
	fx.put("/", "OLD", "old-value")

	svc := rotateTo(t, fx, mustProvider(t, 0x7c))
	// A write after the rotation lands under the NEW key.
	_, err := svc.PutSecret(ctx, PutSecretInput{Ref: fx.ref("/", "NEW"), Value: []byte("new-value"), CreateFolders: true})
	require.NoError(t, err)

	// Both are readable before any rewrap has run.
	for key, want := range map[string]string{"OLD": "old-value", "NEW": "new-value"} {
		got, err := svc.GetSecret(ctx, fx.ref("/", key))
		require.NoError(t, err, key)
		assert.Equal(t, want, string(got.Value.Bytes()))
		got.Zero()
	}

	// And the two versions really are wrapped under different keys.
	keks := map[string]bool{}
	for _, v := range fx.repo.versions {
		keks[v.KekID] = true
	}
	assert.Len(t, keks, 2)
}

func TestFolderMoveDoesNotBreakDecryption(t *testing.T) {
	// The regression this store's AAD design turns on. Binding the folder path would
	// make an administrative folder move destroy every value beneath it; the AAD
	// binds the secret's immutable UUID instead. See crypto.Identity.
	fx := newFixture(t, func(p *Policy) { p.KeepVersions = 10 })
	ctx := context.Background()
	fx.put("/db/primary", "PASSWORD", "v1")
	fx.put("/db/primary", "PASSWORD", "v2")

	_, err := fx.svc.MoveFolder(ctx, fx.tenant.UUID, "billing-app", "prod", "/db", "/data")
	require.NoError(t, err)

	// Every version still decrypts at the new address.
	for version, want := range map[int32]string{1: "v1", 2: "v2"} {
		got, err := fx.svc.GetSecretVersion(ctx, fx.ref("/data/primary", "PASSWORD"), version)
		require.NoError(t, err, "a folder move must not make a value undecryptable")
		assert.Equal(t, want, string(got.Value.Bytes()))
		got.Zero()
	}

	// Renaming the tenant would be the same class of bug; the AAD binds its UUID.
	latest, err := fx.svc.GetSecret(ctx, fx.ref("/data/primary", "PASSWORD"))
	require.NoError(t, err)
	assert.Equal(t, "v2", string(latest.Value.Bytes()))
	latest.Zero()
}

// ---------------------------------------------------------------------------
// The durable setup lock
// ---------------------------------------------------------------------------

func TestSetupLockIsOneShotAndDurable(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()

	state, err := fx.svc.SetupState(ctx)
	require.NoError(t, err)
	assert.False(t, state.Complete, "a fresh install has an open setup window")

	done, err := fx.svc.CompleteSetup(ctx, "core@maintainerd", ControllerKindService)
	require.NoError(t, err)
	assert.True(t, done.Complete)
	assert.Equal(t, "core@maintainerd", done.Controller)
	assert.Equal(t, ControllerKindService, done.ControllerKind)

	// A second attempt is refused.
	_, err = fx.svc.CompleteSetup(ctx, "attacker", ControllerKindService)
	require.Error(t, err)
	assert.True(t, apperror.IsConflict(err))

	// THE FIX: a "restart" — a brand new Service over the same storage — still sees
	// the lock closed. The prototype held this in process memory, so every restart
	// reopened the setup window.
	restarted, err := NewService(fx.repo, fx.ring, fx.svc.Policy())
	require.NoError(t, err)
	after, err := restarted.SetupState(ctx)
	require.NoError(t, err)
	assert.True(t, after.Complete, "the setup lock must survive a restart")
	assert.Equal(t, "core@maintainerd", after.Controller)

	_, err = restarted.CompleteSetup(ctx, "attacker-after-restart", ControllerKindService)
	require.Error(t, err)
	assert.True(t, apperror.IsConflict(err))
}

func TestCompleteSetupValidatesItsInput(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()

	_, err := fx.svc.CompleteSetup(ctx, "   ", ControllerKindService)
	assert.True(t, apperror.IsValidation(err))

	_, err = fx.svc.CompleteSetup(ctx, "core", "sysadmin")
	assert.True(t, apperror.IsValidation(err))

	// An empty kind defaults to service rather than writing a completed lock with no
	// recorded controller kind, which the schema's CHECK would reject anyway.
	done, err := fx.svc.CompleteSetup(ctx, "operator@acme", "")
	require.NoError(t, err)
	assert.Equal(t, ControllerKindService, done.ControllerKind)
}

func TestSetupSupportsOperatorMode(t *testing.T) {
	fx := newFixture(t)
	done, err := fx.svc.CompleteSetup(context.Background(), "reyco", ControllerKindOperator)
	require.NoError(t, err)
	assert.Equal(t, ControllerKindOperator, done.ControllerKind)
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

func TestRecordAuditWritesReadEvents(t *testing.T) {
	// Reads are the point. An audit table for a secret store that only recorded
	// mutations would miss the event an incident review opens with.
	fx := newFixture(t)
	ctx := context.Background()
	res := fx.put("/db", "PASSWORD", "v")
	version := int32(1)

	require.NoError(t, fx.svc.RecordAudit(ctx, AuditEvent{
		TenantUUID:   &fx.tenant.UUID,
		ActorSubject: "svc:billing-app",
		ActorKind:    ActorKindService,
		Action:       ActionReveal,
		ResourceMRN:  "mrn:secret:acme:billing-app:secret/prod/db/PASSWORD",
		SecretUUID:   &res.SecretUUID,
		Version:      &version,
		IPAddress:    "10.1.2.3",
		UserAgent:    "maintainerd-sdk/1.0",
		RequestID:    "req-42",
		Metadata:     map[string]any{"reason": "deploy"},
	}))

	require.Len(t, fx.repo.auditLog, 1)
	row := fx.repo.auditLog[0]
	assert.Equal(t, ActionReveal, row.Action)
	assert.Equal(t, "svc:billing-app", row.ActorSubject)
	assert.Equal(t, OutcomeSuccess, row.Outcome)
	assert.True(t, row.TenantID.Valid)
	assert.True(t, row.SecretID.Valid, "a live secret should be linked")
	require.NotNil(t, row.IpAddress)
	assert.Equal(t, "10.1.2.3", row.IpAddress.String())

	// No audit field can carry a value.
	rendered := fmt.Sprintf("%+v", row)
	assert.NotContains(t, rendered, "\"v\"")
}

func TestRecordAuditAllowsPlatformScopedEvents(t *testing.T) {
	// The bootstrap call that creates the first tenant cannot reference one, which is
	// why tenant_id is nullable.
	fx := newFixture(t)
	require.NoError(t, fx.svc.RecordAudit(context.Background(), AuditEvent{
		ActorSubject: "setup",
		ActorKind:    ActorKindSetup,
		Action:       ActionSetupComplete,
		Outcome:      OutcomeSuccess,
	}))
	require.Len(t, fx.repo.auditLog, 1)
	assert.False(t, fx.repo.auditLog[0].TenantID.Valid)
}

func TestRecordAuditRecordsDenials(t *testing.T) {
	fx := newFixture(t)
	require.NoError(t, fx.svc.RecordAudit(context.Background(), AuditEvent{
		TenantUUID:   &fx.tenant.UUID,
		ActorSubject: "user:mallory",
		ActorKind:    ActorKindUser,
		Action:       ActionReveal,
		Outcome:      OutcomeDenied,
		Reason:       "no grant for secret:GetSecret",
	}))
	require.Len(t, fx.repo.auditLog, 1)
	assert.Equal(t, OutcomeDenied, fx.repo.auditLog[0].Outcome)
}

func TestRecordAuditRequiresAnAction(t *testing.T) {
	fx := newFixture(t)
	err := fx.svc.RecordAudit(context.Background(), AuditEvent{ActorSubject: "x"})
	assert.True(t, apperror.IsValidation(err))
}

func TestRecordAuditToleratesABadIP(t *testing.T) {
	// Losing the audit row would be far worse than losing the IP field.
	fx := newFixture(t)
	require.NoError(t, fx.svc.RecordAudit(context.Background(), AuditEvent{
		Action: ActionRead, IPAddress: "not-an-ip",
	}))
	require.Len(t, fx.repo.auditLog, 1)
	assert.Nil(t, fx.repo.auditLog[0].IpAddress)
}
