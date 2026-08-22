package store

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/maintainerd/secret/internal/crypto"
	"github.com/maintainerd/secret/internal/platform/apperror"
	"github.com/maintainerd/secret/internal/storage"
)

// ---------------------------------------------------------------------------
// Durability and versioning
// ---------------------------------------------------------------------------

func TestPutSecretCreatesVersionOne(t *testing.T) {
	fx := newFixture(t)
	res := fx.put("/", "DB_PASSWORD", "first-value")

	assert.True(t, res.Created)
	assert.False(t, res.Unchanged)
	assert.EqualValues(t, 1, res.Version)
	assert.NotEqual(t, uuid.Nil, res.SecretUUID)

	// The value is durable and decryptable, which is the whole point of the
	// replacement: the prototype lost every secret on restart.
	revealed, err := fx.svc.GetSecret(context.Background(), fx.ref("/", "DB_PASSWORD"))
	require.NoError(t, err)
	defer revealed.Zero()
	assert.Equal(t, "first-value", string(revealed.Value.Bytes()))
	assert.EqualValues(t, 1, revealed.Version)
	assert.Equal(t, ValueTypeOpaque, revealed.ValueType)

	// Version 1 is a creation, not a rotation.
	stored := fx.repo.secrets[1]
	require.NotNil(t, stored)
	assert.False(t, stored.RotatedAt.Valid, "creating a secret must not record a rotation")
}

func TestPutSecretAppendsImmutableVersions(t *testing.T) {
	fx := newFixture(t, func(p *Policy) { p.KeepVersions = 10 })
	fx.put("/", "TOKEN", "v1")

	v1 := *fx.repo.versions[1]

	res := fx.put("/", "TOKEN", "v2")
	assert.False(t, res.Created)
	assert.EqualValues(t, 2, res.Version)

	// The version-1 row is untouched: same ciphertext, same nonce, same checksum.
	// History is appended to, never rewritten.
	after := *fx.repo.versions[1]
	assert.Equal(t, v1.Ciphertext, after.Ciphertext)
	assert.Equal(t, v1.Nonce, after.Nonce)
	assert.Equal(t, v1.Checksum, after.Checksum)
	assert.EqualValues(t, 1, after.Version)

	// current_version advanced, and a second value IS a rotation.
	stored := fx.repo.secrets[1]
	assert.EqualValues(t, 2, stored.CurrentVersion)
	assert.True(t, stored.RotatedAt.Valid, "a new value for an existing secret is a rotation")

	// Both versions remain readable at their own version number.
	for version, want := range map[int32]string{1: "v1", 2: "v2"} {
		got, err := fx.svc.GetSecretVersion(context.Background(), fx.ref("/", "TOKEN"), version)
		require.NoError(t, err)
		assert.Equal(t, want, string(got.Value.Bytes()))
		got.Zero()
	}

	// And the latest read follows current_version.
	latest, err := fx.svc.GetSecret(context.Background(), fx.ref("/", "TOKEN"))
	require.NoError(t, err)
	assert.Equal(t, "v2", string(latest.Value.Bytes()))
	latest.Zero()
}

func TestPutSecretTakesARowLock(t *testing.T) {
	// Two concurrent writes must serialize or they both compute the same next
	// version and the second collides on uq_secret_versions_secret_version.
	fx := newFixture(t)
	before := fx.repo.forUpdateCalls
	fx.put("/", "TOKEN", "v1")
	assert.Greater(t, fx.repo.forUpdateCalls, before, "the write path must lock the secret row")
	assert.GreaterOrEqual(t, fx.repo.maxTxSeen, 1, "the write path must run in a transaction")
}

func TestGetSecretVersionRejectsUnknownVersion(t *testing.T) {
	fx := newFixture(t)
	fx.put("/", "TOKEN", "v1")

	_, err := fx.svc.GetSecretVersion(context.Background(), fx.ref("/", "TOKEN"), 99)
	require.Error(t, err)
	assert.True(t, apperror.IsNotFound(err))

	_, err = fx.svc.GetSecretVersion(context.Background(), fx.ref("/", "TOKEN"), 0)
	require.Error(t, err)
	assert.True(t, apperror.IsValidation(err))
}

// ---------------------------------------------------------------------------
// Checksum-based no-op detection
// ---------------------------------------------------------------------------

func TestPutSecretUnchangedValueCreatesNoVersion(t *testing.T) {
	// The rotation-loop guard. A reconciler that resubmits the same value every few
	// minutes must not inflate version history — otherwise retention silently
	// discards the real history and get-by-version becomes useless.
	fx := newFixture(t)
	first := fx.put("/", "TOKEN", "steady-value")
	require.EqualValues(t, 1, first.Version)
	require.Len(t, fx.repo.versions, 1)

	for i := 0; i < 5; i++ {
		res := fx.put("/", "TOKEN", "steady-value")
		assert.True(t, res.Unchanged, "an unchanged write must be reported as a no-op")
		assert.False(t, res.Created)
		assert.EqualValues(t, 1, res.Version, "the existing version is returned")
	}
	assert.Len(t, fx.repo.versions, 1, "an unchanged write must not append a version")
	assert.EqualValues(t, 1, fx.repo.secrets[1].CurrentVersion)

	// A genuinely different value still appends.
	changed := fx.put("/", "TOKEN", "new-value")
	assert.False(t, changed.Unchanged)
	assert.EqualValues(t, 2, changed.Version)
	assert.Len(t, fx.repo.versions, 2)
}

func TestPutSecretNoOpDetectionIsExactNotFuzzy(t *testing.T) {
	fx := newFixture(t)
	fx.put("/", "TOKEN", "value")

	// A trailing space is a different secret. Treating near-misses as no-ops would
	// silently drop a real credential change.
	res := fx.put("/", "TOKEN", "value ")
	assert.False(t, res.Unchanged)
	assert.EqualValues(t, 2, res.Version)
}

func TestPutSecretNoOpDetectionNeedsNoDecryption(t *testing.T) {
	// Change detection must work with a root key that cannot open the stored rows —
	// that is the proof it is comparing the stored checksum rather than decrypting.
	fx := newFixture(t)
	fx.put("/", "TOKEN", "steady")

	// Swap in an unrelated active key. Reads of the old version will now fail, but a
	// no-op write must still be detected.
	otherRing, err := crypto.NewKeyRing(mustProvider(t, 0x99))
	require.NoError(t, err)
	svc, err := NewService(fx.repo, otherRing, fx.svc.Policy())
	require.NoError(t, err)
	svc.SetClock(func() time.Time { return fx.clock })
	_, err = svc.EnsureActiveRootKey(context.Background())
	require.NoError(t, err)

	res, err := svc.PutSecret(context.Background(), PutSecretInput{
		Ref: fx.ref("/", "TOKEN"), Value: []byte("steady"), CreateFolders: true,
	})
	require.NoError(t, err)
	assert.True(t, res.Unchanged, "no-op detection must not require the root key")
	assert.Len(t, fx.repo.versions, 1)
}

// ---------------------------------------------------------------------------
// Listing: metadata only
// ---------------------------------------------------------------------------

func TestListSecretsReturnsNoCiphertext(t *testing.T) {
	fx := newFixture(t)
	fx.put("/", "ROOT_TOKEN", "root-secret-value")
	fx.put("/db/primary", "PASSWORD", "primary-secret-value")

	metas, total, err := fx.svc.ListSecrets(context.Background(), ListSecretsInput{
		TenantUUID: fx.tenant.UUID, Project: "billing-app", Environment: "prod", PathPrefix: "/",
	})
	require.NoError(t, err)
	assert.EqualValues(t, 2, total)
	require.Len(t, metas, 2)

	// Structural: the returned type has no field that could hold a value.
	metaType := reflect.TypeOf(SecretMeta{})
	for i := 0; i < metaType.NumField(); i++ {
		name := strings.ToLower(metaType.Field(i).Name)
		for _, banned := range []string{"value", "ciphertext", "nonce", "dek", "plaintext", "secretvalue"} {
			assert.NotContains(t, name, banned,
				"SecretMeta.%s looks like it could carry a payload; listing must be metadata only", metaType.Field(i).Name)
		}
	}

	// Behavioural: no plaintext appears anywhere in the rendered result.
	rendered := fmt.Sprintf("%+v", metas)
	assert.NotContains(t, rendered, "root-secret-value")
	assert.NotContains(t, rendered, "primary-secret-value")

	// The listing row sqlc generated must likewise have no payload column.
	rowType := reflect.TypeOf(storage.ListSecretMetaBySubtreeRow{})
	for i := 0; i < rowType.NumField(); i++ {
		name := strings.ToLower(rowType.Field(i).Name)
		for _, banned := range []string{"ciphertext", "nonce", "dek"} {
			assert.NotContains(t, name, banned,
				"the listing query selects %s; it must not touch payload columns", rowType.Field(i).Name)
		}
	}
}

func TestListVersionsReturnsNoCiphertext(t *testing.T) {
	// Version history is browsable metadata, not a bulk decryption endpoint.
	fx := newFixture(t, func(p *Policy) { p.KeepVersions = 10 })
	fx.put("/", "TOKEN", "v1")
	fx.put("/", "TOKEN", "v2")

	versions, total, err := fx.svc.ListVersions(context.Background(), fx.ref("/", "TOKEN"), 1, 50)
	require.NoError(t, err)
	assert.EqualValues(t, 2, total)
	require.Len(t, versions, 2)
	assert.EqualValues(t, 2, versions[0].Version, "newest first")

	rendered := fmt.Sprintf("%+v", versions)
	assert.NotContains(t, rendered, "v1")
	assert.NotContains(t, rendered, "v2")

	rowType := reflect.TypeOf(storage.ListSecretVersionMetaRow{})
	for i := 0; i < rowType.NumField(); i++ {
		name := strings.ToLower(rowType.Field(i).Name)
		for _, banned := range []string{"ciphertext", "nonce", "dek"} {
			assert.NotContains(t, name, banned)
		}
	}
}

func TestListSecretsScopesByPathPrefix(t *testing.T) {
	fx := newFixture(t)
	fx.put("/", "ROOT", "a")
	fx.put("/db", "DB", "b")
	fx.put("/db/primary", "PRIMARY", "c")
	fx.put("/db/replica", "REPLICA", "d")
	fx.put("/cache", "CACHE", "e")

	cases := map[string][]string{
		"/":            {"CACHE", "DB", "PRIMARY", "REPLICA", "ROOT"},
		"/db":          {"DB", "PRIMARY", "REPLICA"},
		"/db/primary":  {"PRIMARY"},
		"/cache":       {"CACHE"},
		"/nonexistent": {},
	}
	for prefix, want := range cases {
		t.Run(prefix, func(t *testing.T) {
			metas, _, err := fx.svc.ListSecrets(context.Background(), ListSecretsInput{
				TenantUUID: fx.tenant.UUID, Project: "billing-app", Environment: "prod", PathPrefix: prefix,
			})
			require.NoError(t, err)
			got := make([]string, 0, len(metas))
			for _, m := range metas {
				got = append(got, m.Key)
			}
			assert.ElementsMatch(t, want, got)
		})
	}
}

func TestListSecretsPrefixDoesNotLeakAcrossSimilarNames(t *testing.T) {
	// '_' is a LIKE wildcard AND a legal folder-name character. Without escaping,
	// listing /my_folder would also return /myXfolder — a cross-folder read caused
	// purely by string handling.
	fx := newFixture(t)
	fx.put("/my_folder", "MINE", "mine")
	fx.put("/myXfolder", "THEIRS", "theirs")
	fx.put("/my-folder", "OTHER", "other")

	metas, _, err := fx.svc.ListSecrets(context.Background(), ListSecretsInput{
		TenantUUID: fx.tenant.UUID, Project: "billing-app", Environment: "prod", PathPrefix: "/my_folder",
	})
	require.NoError(t, err)
	require.Len(t, metas, 1)
	assert.Equal(t, "MINE", metas[0].Key)
}

// ---------------------------------------------------------------------------
// Tenant isolation
// ---------------------------------------------------------------------------

func TestNoCrossTenantReads(t *testing.T) {
	// Two tenants with the SAME project slug, environment slug, folder path and key.
	// Only the tenant UUID differs, so anything that reads across is a tenancy bug
	// and not a naming coincidence.
	fx := newFixture(t)
	ctx := context.Background()

	other, err := fx.svc.CreateTenant(ctx, CreateTenantInput{Name: "globex", DisplayName: "Globex"})
	require.NoError(t, err)
	_, err = fx.svc.CreateProject(ctx, CreateProjectInput{TenantUUID: other.UUID, Slug: "billing-app"})
	require.NoError(t, err)
	_, err = fx.svc.CreateEnvironment(ctx, CreateEnvironmentInput{TenantUUID: other.UUID, Project: "billing-app", Slug: "prod"})
	require.NoError(t, err)

	fx.put("/db", "PASSWORD", "acme-password")
	otherRef := SecretRef{TenantUUID: other.UUID, Project: "billing-app", Environment: "prod", FolderPath: "/db", Key: "PASSWORD"}
	_, err = fx.svc.PutSecret(ctx, PutSecretInput{Ref: otherRef, Value: []byte("globex-password"), CreateFolders: true})
	require.NoError(t, err)

	// Each tenant sees only its own value.
	acme, err := fx.svc.GetSecret(ctx, fx.ref("/db", "PASSWORD"))
	require.NoError(t, err)
	assert.Equal(t, "acme-password", string(acme.Value.Bytes()))
	acme.Zero()

	globex, err := fx.svc.GetSecret(ctx, otherRef)
	require.NoError(t, err)
	assert.Equal(t, "globex-password", string(globex.Value.Bytes()))
	globex.Zero()

	// And each listing is scoped.
	for _, tc := range []struct {
		tenant uuid.UUID
		want   int
	}{{fx.tenant.UUID, 1}, {other.UUID, 1}} {
		metas, total, err := fx.svc.ListSecrets(ctx, ListSecretsInput{
			TenantUUID: tc.tenant, Project: "billing-app", Environment: "prod", PathPrefix: "/",
		})
		require.NoError(t, err)
		assert.EqualValues(t, tc.want, total)
		assert.Len(t, metas, tc.want)
	}
}

func TestUnknownTenantIsNotFoundNotALeak(t *testing.T) {
	fx := newFixture(t)
	fx.put("/db", "PASSWORD", "value")

	stranger := SecretRef{
		TenantUUID: uuid.New(), Project: "billing-app", Environment: "prod", FolderPath: "/db", Key: "PASSWORD",
	}
	_, err := fx.svc.GetSecret(context.Background(), stranger)
	require.Error(t, err)
	assert.True(t, apperror.IsNotFound(err))
	// The message must not confirm that the secret exists for someone else.
	assert.NotContains(t, strings.ToLower(err.Error()), "forbidden")
	assert.NotContains(t, strings.ToLower(err.Error()), "another tenant")
}

func TestCrossTenantRestoreAndDestroyRefused(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()
	other, err := fx.svc.CreateTenant(ctx, CreateTenantInput{Name: "globex"})
	require.NoError(t, err)

	fx.put("/", "TOKEN", "v")
	deleted, err := fx.svc.DeleteSecret(ctx, fx.ref("/", "TOKEN"), nil)
	require.NoError(t, err)

	// The other tenant cannot restore or destroy it, even holding the UUID.
	_, err = fx.svc.RestoreSecret(ctx, other.UUID, deleted.UUID)
	require.Error(t, err)
	assert.True(t, apperror.IsNotFound(err))

	err = fx.svc.DestroySecret(ctx, other.UUID, deleted.UUID)
	require.Error(t, err)
	assert.True(t, apperror.IsNotFound(err))
}

// ---------------------------------------------------------------------------
// Soft delete, recovery window, restore, destroy
// ---------------------------------------------------------------------------

func TestDeleteOpensRecoveryWindowAndKeepsVersions(t *testing.T) {
	fx := newFixture(t)
	fx.put("/", "TOKEN", "v1")
	versionsBefore := len(fx.repo.versions)

	deleted, err := fx.svc.DeleteSecret(context.Background(), fx.ref("/", "TOKEN"), nil)
	require.NoError(t, err)
	require.NotNil(t, deleted.DestroyAfter)
	assert.Equal(t, fx.clock.Add(30*24*time.Hour), *deleted.DestroyAfter)

	// Nothing was destroyed — that is what makes the window meaningful.
	assert.Len(t, fx.repo.versions, versionsBefore)

	// The secret is gone from reads and listings.
	_, err = fx.svc.GetSecret(context.Background(), fx.ref("/", "TOKEN"))
	assert.True(t, apperror.IsNotFound(err))
	metas, total, err := fx.svc.ListSecrets(context.Background(), ListSecretsInput{
		TenantUUID: fx.tenant.UUID, Project: "billing-app", Environment: "prod",
	})
	require.NoError(t, err)
	assert.EqualValues(t, 0, total)
	assert.Empty(t, metas)

	// But visible in the recovery view.
	pending, err := fx.svc.ListDeletedSecrets(context.Background(), fx.tenant.UUID, "billing-app", "prod", 1, 50)
	require.NoError(t, err)
	require.Len(t, pending, 1)
	assert.Equal(t, "TOKEN", pending[0].Key)
}

func TestRestoreBringsBackHistoryIntact(t *testing.T) {
	fx := newFixture(t, func(p *Policy) { p.KeepVersions = 10 })
	fx.put("/db", "PASSWORD", "v1")
	fx.put("/db", "PASSWORD", "v2")

	deleted, err := fx.svc.DeleteSecret(context.Background(), fx.ref("/db", "PASSWORD"), nil)
	require.NoError(t, err)

	restored, err := fx.svc.RestoreSecret(context.Background(), fx.tenant.UUID, deleted.UUID)
	require.NoError(t, err)
	assert.EqualValues(t, 2, restored.CurrentVersion)
	assert.Equal(t, "/db", restored.FolderPath)

	// Both versions still decrypt: the AAD identity is unchanged by a delete and
	// restore round trip.
	for version, want := range map[int32]string{1: "v1", 2: "v2"} {
		got, err := fx.svc.GetSecretVersion(context.Background(), fx.ref("/db", "PASSWORD"), version)
		require.NoError(t, err)
		assert.Equal(t, want, string(got.Value.Bytes()))
		got.Zero()
	}
}

func TestRestoreConflictsWithALiveSecretAtTheSameAddress(t *testing.T) {
	fx := newFixture(t)
	fx.put("/", "TOKEN", "old")
	deleted, err := fx.svc.DeleteSecret(context.Background(), fx.ref("/", "TOKEN"), nil)
	require.NoError(t, err)

	// The address was freed by the delete, so a new secret can take it.
	fx.put("/", "TOKEN", "new")

	_, err = fx.svc.RestoreSecret(context.Background(), fx.tenant.UUID, deleted.UUID)
	require.Error(t, err)
	assert.True(t, apperror.IsConflict(err), "the collision must be surfaced, not silently renamed")
}

func TestDestroyRefusedInsideTheWindow(t *testing.T) {
	fx := newFixture(t)
	fx.put("/", "TOKEN", "v1")
	deleted, err := fx.svc.DeleteSecret(context.Background(), fx.ref("/", "TOKEN"), nil)
	require.NoError(t, err)

	err = fx.svc.DestroySecret(context.Background(), fx.tenant.UUID, deleted.UUID)
	require.Error(t, err)
	assert.True(t, apperror.IsForbidden(err))
	assert.Contains(t, err.Error(), "recovery window")

	// Still there, still restorable.
	assert.Len(t, fx.repo.versions, 1)
	_, err = fx.svc.RestoreSecret(context.Background(), fx.tenant.UUID, deleted.UUID)
	require.NoError(t, err)
}

func TestDestroyAllowedPastTheWindow(t *testing.T) {
	fx := newFixture(t)
	fx.put("/", "TOKEN", "v1")
	fx.put("/", "TOKEN", "v2")
	deleted, err := fx.svc.DeleteSecret(context.Background(), fx.ref("/", "TOKEN"), nil)
	require.NoError(t, err)

	fx.advance(31 * 24 * time.Hour)

	require.NoError(t, fx.svc.DestroySecret(context.Background(), fx.tenant.UUID, deleted.UUID))
	assert.Empty(t, fx.repo.secrets, "the secret row must be gone")
	assert.Empty(t, fx.repo.versions, "every version must be gone")

	// And it is not restorable afterwards.
	_, err = fx.svc.RestoreSecret(context.Background(), fx.tenant.UUID, deleted.UUID)
	assert.True(t, apperror.IsNotFound(err))
}

func TestDestroyRequiresTheSanctionedGUC(t *testing.T) {
	// The cascade into secret_versions is refused by the append-only trigger unless
	// the transaction declares its reason. Proven here by checking the GUC really
	// was set for the destroy, and that it does not survive the transaction.
	fx := newFixture(t)
	fx.put("/", "TOKEN", "v1")
	deleted, err := fx.svc.DeleteSecret(context.Background(), fx.ref("/", "TOKEN"), nil)
	require.NoError(t, err)
	fx.advance(31 * 24 * time.Hour)

	require.NoError(t, fx.svc.DestroySecret(context.Background(), fx.tenant.UUID, deleted.UUID))
	assert.Empty(t, fx.repo.deleteAllowed, "the delete authorization must not outlive its transaction")
}

func TestDestroyOfALiveSecretIsNotFound(t *testing.T) {
	fx := newFixture(t)
	res := fx.put("/", "TOKEN", "v1")
	err := fx.svc.DestroySecret(context.Background(), fx.tenant.UUID, res.SecretUUID)
	require.Error(t, err)
	assert.True(t, apperror.IsNotFound(err), "a live secret must be deleted before it can be destroyed")
}

func TestDeleteAcceptsACustomWindow(t *testing.T) {
	fx := newFixture(t)
	fx.put("/", "TOKEN", "v1")
	window := 2 * time.Hour
	deleted, err := fx.svc.DeleteSecret(context.Background(), fx.ref("/", "TOKEN"), &window)
	require.NoError(t, err)
	assert.Equal(t, fx.clock.Add(window), *deleted.DestroyAfter)
}

// ---------------------------------------------------------------------------
// Version retention
// ---------------------------------------------------------------------------

func TestRetentionPrunesOldestButNeverTheCurrent(t *testing.T) {
	fx := newFixture(t, func(p *Policy) { p.KeepVersions = 3 })

	for i := 1; i <= 6; i++ {
		fx.put("/", "TOKEN", fmt.Sprintf("v%d", i))
	}

	remaining := fx.repo.versionsOf(1)
	require.Len(t, remaining, 3, "retention must keep exactly KeepVersions")

	got := []int32{}
	for _, v := range remaining {
		got = append(got, v.Version)
	}
	assert.Equal(t, []int32{6, 5, 4}, got, "the newest are kept, the oldest pruned")

	// The live value survived and still decrypts.
	latest, err := fx.svc.GetSecret(context.Background(), fx.ref("/", "TOKEN"))
	require.NoError(t, err)
	assert.Equal(t, "v6", string(latest.Value.Bytes()))
	latest.Zero()

	// A pruned version is genuinely gone.
	_, err = fx.svc.GetSecretVersion(context.Background(), fx.ref("/", "TOKEN"), 1)
	assert.True(t, apperror.IsNotFound(err))
}

func TestRetentionRespectsPerSecretOverride(t *testing.T) {
	fx := newFixture(t, func(p *Policy) { p.KeepVersions = 2 })
	keep := int32(5)

	_, err := fx.svc.PutSecret(context.Background(), PutSecretInput{
		Ref: fx.ref("/", "TOKEN"), Value: []byte("v1"), KeepVersions: &keep, CreateFolders: true,
	})
	require.NoError(t, err)
	for i := 2; i <= 7; i++ {
		fx.put("/", "TOKEN", fmt.Sprintf("v%d", i))
	}
	assert.Len(t, fx.repo.versionsOf(1), 5, "the secret's own retention wins over the service default")
}

func TestRetentionOfOneKeepsOnlyTheCurrentVersion(t *testing.T) {
	// The boundary that matters: keep=1 must prune everything except the live value,
	// and must never prune the live value itself.
	fx := newFixture(t, func(p *Policy) { p.KeepVersions = 1 })
	fx.put("/", "TOKEN", "v1")
	fx.put("/", "TOKEN", "v2")
	fx.put("/", "TOKEN", "v3")

	remaining := fx.repo.versionsOf(1)
	require.Len(t, remaining, 1)
	assert.EqualValues(t, 3, remaining[0].Version)

	latest, err := fx.svc.GetSecret(context.Background(), fx.ref("/", "TOKEN"))
	require.NoError(t, err)
	assert.Equal(t, "v3", string(latest.Value.Bytes()))
	latest.Zero()
}

func TestPolicyKeepVersionsIsClampedToAtLeastOne(t *testing.T) {
	// A retention of zero would mean "keep nothing", and the only version there is
	// to delete is the live one.
	repo := newFakeRepo()
	svc, err := NewService(repo, mustKeyRing(t, 0x02), Policy{KeepVersions: 0})
	require.NoError(t, err)
	assert.EqualValues(t, 1, svc.Policy().KeepVersions)
}

func TestPruneVersionsOnDemand(t *testing.T) {
	fx := newFixture(t, func(p *Policy) { p.KeepVersions = 10 })
	for i := 1; i <= 5; i++ {
		fx.put("/", "TOKEN", fmt.Sprintf("v%d", i))
	}
	require.Len(t, fx.repo.versionsOf(1), 5)

	// Lower the retention, then prune explicitly — the path a scheduled job uses.
	keep := int32(2)
	_, err := fx.svc.UpdateSecretMeta(context.Background(), UpdateSecretMetaInput{
		Ref: fx.ref("/", "TOKEN"), KeepVersions: &keep,
	})
	require.NoError(t, err)

	pruned, err := fx.svc.PruneVersions(context.Background(), fx.ref("/", "TOKEN"))
	require.NoError(t, err)
	assert.Equal(t, 3, pruned)
	assert.Len(t, fx.repo.versionsOf(1), 2)
}

func TestPruningRequiresTheSanctionedGUC(t *testing.T) {
	fx := newFixture(t, func(p *Policy) { p.KeepVersions = 1 })
	fx.put("/", "TOKEN", "v1")
	fx.put("/", "TOKEN", "v2")
	// The fake refuses a version delete without the GUC, exactly as the trigger
	// does, so reaching this point at all proves the service set it — and it must
	// not have leaked past the transaction.
	assert.Empty(t, fx.repo.deleteAllowed)
	assert.Len(t, fx.repo.versionsOf(1), 1)
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

func TestUpdateSecretMetaDoesNotCreateAVersion(t *testing.T) {
	fx := newFixture(t)
	fx.put("/", "TOKEN", "v1")
	require.Len(t, fx.repo.versions, 1)

	expires := fx.clock.Add(90 * 24 * time.Hour)
	meta, err := fx.svc.UpdateSecretMeta(context.Background(), UpdateSecretMetaInput{
		Ref:            fx.ref("/", "TOKEN"),
		Description:    "the api token",
		Tags:           []string{"api", "rotate-90d"},
		RotationPolicy: map[string]any{"interval": "90d"},
		ExpiresAt:      &expires,
	})
	require.NoError(t, err)
	assert.Equal(t, "the api token", meta.Description)
	assert.ElementsMatch(t, []string{"api", "rotate-90d"}, meta.Tags)
	assert.Equal(t, "90d", meta.RotationPolicy["interval"])
	require.NotNil(t, meta.ExpiresAt)
	assert.Len(t, fx.repo.versions, 1, "a metadata edit must not append a version")
}

func TestPutSecretMetadataOnlyAppliesOnCreate(t *testing.T) {
	// A routine value rotation must not silently reset retention or expiry by
	// omitting fields it does not care about.
	fx := newFixture(t)
	keep := int32(7)
	_, err := fx.svc.PutSecret(context.Background(), PutSecretInput{
		Ref: fx.ref("/", "TOKEN"), Value: []byte("v1"),
		Description: "original", KeepVersions: &keep, CreateFolders: true,
	})
	require.NoError(t, err)

	// A bare rotation with no metadata at all.
	fx.put("/", "TOKEN", "v2")

	stored := fx.repo.secrets[1]
	assert.Equal(t, "original", stored.Description, "a value rotation must not clear the description")
	require.True(t, stored.KeepVersions.Valid)
	assert.EqualValues(t, 7, stored.KeepVersions.Int32, "a value rotation must not reset retention")
}

func TestValueTypeValidation(t *testing.T) {
	fx := newFixture(t)
	for _, vt := range []string{ValueTypeOpaque, ValueTypeJSON, ValueTypeReference} {
		_, err := fx.svc.PutSecret(context.Background(), PutSecretInput{
			Ref: fx.ref("/", "K_"+strings.ToUpper(vt)), Value: []byte("v"), ValueType: vt, CreateFolders: true,
		})
		require.NoError(t, err, vt)
	}
	_, err := fx.svc.PutSecret(context.Background(), PutSecretInput{
		Ref: fx.ref("/", "BAD"), Value: []byte("v"), ValueType: "encrypted", CreateFolders: true,
	})
	require.Error(t, err)
	assert.True(t, apperror.IsValidation(err))
}

func TestPutSecretRequiresAValue(t *testing.T) {
	fx := newFixture(t)
	_, err := fx.svc.PutSecret(context.Background(), PutSecretInput{Ref: fx.ref("/", "TOKEN")})
	require.Error(t, err)
	assert.True(t, apperror.IsValidation(err))

	// An empty (but non-nil) value is legitimate — an empty string is a value.
	_, err = fx.svc.PutSecret(context.Background(), PutSecretInput{
		Ref: fx.ref("/", "TOKEN"), Value: []byte{}, CreateFolders: true,
	})
	require.NoError(t, err)
}

func TestPutSecretWithoutCreateFoldersRequiresTheFolder(t *testing.T) {
	fx := newFixture(t)
	_, err := fx.svc.PutSecret(context.Background(), PutSecretInput{
		Ref: fx.ref("/db/primary", "PASSWORD"), Value: []byte("v"),
	})
	require.Error(t, err)
	assert.True(t, apperror.IsNotFound(err))
}

// ---------------------------------------------------------------------------
// MRN
// ---------------------------------------------------------------------------

func TestSecretCarriesParsedMRNColumns(t *testing.T) {
	fx := newFixture(t)
	fx.put("/db/primary", "PASSWORD", "v")

	stored := fx.repo.secrets[1]
	assert.Equal(t, "secret", stored.MrnService)
	assert.Equal(t, "acme", stored.MrnTenant)
	assert.Equal(t, "billing-app", stored.MrnProject)
	// The environment segment is present, which is what lets a grant distinguish
	// prod from staging for the same key name.
	assert.Equal(t, "secret/prod/db/primary/PASSWORD", stored.MrnResourcePath)
	assert.Equal(t, "mrn:secret:acme:billing-app:secret/prod/db/primary/PASSWORD",
		mrn(stored.MrnTenant, stored.MrnProject, stored.MrnResourcePath))
}

func TestMRNResourcePathAtEnvironmentRoot(t *testing.T) {
	fx := newFixture(t)
	fx.put("/", "DB_PASSWORD", "v")
	assert.Equal(t, "secret/prod/DB_PASSWORD", fx.repo.secrets[1].MrnResourcePath)
}

func TestMRNIsDistinctPerEnvironment(t *testing.T) {
	// The same key in two environments must not share an MRN, or "may read staging,
	// not prod" would be inexpressible.
	fx := newFixture(t)
	ctx := context.Background()
	_, err := fx.svc.CreateEnvironment(ctx, CreateEnvironmentInput{
		TenantUUID: fx.tenant.UUID, Project: "billing-app", Slug: "staging", Position: 1,
	})
	require.NoError(t, err)

	fx.put("/", "DB_PASSWORD", "prod-value")
	stagingRef := SecretRef{
		TenantUUID: fx.tenant.UUID, Project: "billing-app", Environment: "staging", FolderPath: "/", Key: "DB_PASSWORD",
	}
	_, err = fx.svc.PutSecret(ctx, PutSecretInput{Ref: stagingRef, Value: []byte("staging-value"), CreateFolders: true})
	require.NoError(t, err)

	paths := map[string]bool{}
	for _, s := range fx.repo.secrets {
		paths[s.MrnResourcePath] = true
	}
	assert.Len(t, paths, 2, "each environment's copy must have its own MRN")
	assert.True(t, paths["secret/prod/DB_PASSWORD"])
	assert.True(t, paths["secret/staging/DB_PASSWORD"])
}
