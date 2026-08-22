package api

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sdkauthz "github.com/maintainerd/sdk/authz"
	"github.com/maintainerd/secret/internal/platform/apperror"
	"github.com/maintainerd/secret/internal/platform/permissions"
	"github.com/maintainerd/secret/internal/store"
)

// Secret references: resolution, the escalation guard, and cycle detection.

// TestReferenceResolvesAtReadTime is the baseline: a reference-typed value renders to
// the value it points at, with the surrounding literal text preserved.
func TestReferenceResolvesAtReadTime(t *testing.T) {
	fx := newFixture(t)
	fx.seed("prod", "/db", "PASSWORD", "s3cr3t")
	fx.seedReference("prod", "/app", "DSN", "postgres://app:${billing-app/prod/db/PASSWORD}@db:5432/app")

	revealed, err := fx.api.Reveal(context.Background(), fx.admin(), addr("prod", "/app", "DSN"), 0)
	require.NoError(t, err)
	defer revealed.Secret.Zero()

	assert.Equal(t, "postgres://app:s3cr3t@db:5432/app", string(revealed.Secret.Value.Bytes()))
	assert.Equal(t, []string{"mrn:secret:acme:billing-app:secret/prod/db/PASSWORD"}, revealed.ReferenceHops)
}

// TestReferenceResolvesSeveralPlaceholders checks a template with more than one
// pointer, which is the shape a real connection string takes.
func TestReferenceResolvesSeveralPlaceholders(t *testing.T) {
	fx := newFixture(t)
	fx.seed("prod", "/db", "USER", "app")
	fx.seed("prod", "/db", "PASSWORD", "s3cr3t")
	fx.seedReference("prod", "/app", "DSN",
		"postgres://${billing-app/prod/db/USER}:${billing-app/prod/db/PASSWORD}@db/app")

	revealed, err := fx.api.Reveal(context.Background(), fx.admin(), addr("prod", "/app", "DSN"), 0)
	require.NoError(t, err)
	defer revealed.Secret.Zero()
	assert.Equal(t, "postgres://app:s3cr3t@db/app", string(revealed.Secret.Value.Bytes()))
	assert.Len(t, revealed.ReferenceHops, 2)
}

// TestReferenceRequiresRevealOnEveryHop is the escalation guard, and it is the reason
// the reference resolver exists in the api layer rather than the store.
//
// The caller may reveal everything in dev, including a dev secret that POINTS AT
// prod. Without a per-hop check it would receive prod's value through its own dev
// grant. With one, the hop is refused — a reference is a convenience for the
// authorized, never a bridge for the unauthorized.
func TestReferenceRequiresRevealOnEveryHop(t *testing.T) {
	fx := newFixture(t)
	fx.seed("prod", "/db", "PASSWORD", "prod-only-value")
	fx.seedReference("dev", "/", "SNEAKY", "${billing-app/prod/db/PASSWORD}")

	devOnly := fx.caller(sdkauthz.Grant{
		Action:   permissions.PermGetSecret,
		Resource: "mrn:secret:acme:billing-app:secret/dev/*",
	})

	_, err := fx.api.Reveal(context.Background(), devOnly, addr("dev", "/", "SNEAKY"), 0)
	require.Error(t, err, "a reference must not become a privilege-escalation path")
	assert.True(t, apperror.IsForbidden(err))

	// The refused hop is audited against the TARGET's MRN, so the trail shows what
	// was actually reached for.
	found := false
	for _, row := range fx.repo.auditRows() {
		if row.Action == store.ActionReferenceResolve && row.Outcome == store.OutcomeDenied {
			found = true
			assert.Equal(t, "mrn:secret:acme:billing-app:secret/prod/db/PASSWORD", row.ResourceMrn)
		}
	}
	assert.True(t, found, "a refused reference hop is audited")
}

// TestReferenceHopIsAudited proves each hop produces its own row, so "who actually
// saw the underlying value" is answerable — the caller revealed a pointer, but the
// value it pointed at was decrypted too.
func TestReferenceHopIsAudited(t *testing.T) {
	fx := newFixture(t)
	fx.seed("prod", "/db", "PASSWORD", "s3cr3t")
	fx.seedReference("prod", "/app", "DSN", "${billing-app/prod/db/PASSWORD}")

	revealed, err := fx.api.Reveal(context.Background(), fx.admin(), addr("prod", "/app", "DSN"), 0)
	require.NoError(t, err)
	revealed.Secret.Zero()

	assert.Equal(t, 1, fx.repo.countAudit(store.ActionReferenceResolve, store.OutcomeSuccess))
	assert.Equal(t, 1, fx.repo.countAudit(store.ActionReveal, store.OutcomeSuccess))
}

// TestReferenceCycleIsDetectedAndNamed: a loop must produce a precise error naming
// the cycle, not a timeout and not a depth-exceeded message that sends an operator
// hunting for a long chain that does not exist.
func TestReferenceCycleIsDetectedAndNamed(t *testing.T) {
	fx := newFixture(t)
	fx.seedReference("prod", "/", "A", "${billing-app/prod/B}")
	fx.seedReference("prod", "/", "B", "${billing-app/prod/A}")

	_, err := fx.api.Reveal(context.Background(), fx.admin(), addr("prod", "/", "A"), 0)
	require.Error(t, err)
	assert.True(t, apperror.IsValidation(err))
	assert.Contains(t, err.Error(), "reference cycle detected")
	assert.Contains(t, err.Error(), "secret/prod/A")
	assert.Contains(t, err.Error(), "secret/prod/B")
}

// TestSelfReferenceIsACycle catches the zero-length loop on the first hop rather than
// the second, which is why the chain is seeded with the origin MRN.
func TestSelfReferenceIsACycle(t *testing.T) {
	fx := newFixture(t)
	fx.seedReference("prod", "/", "SELF", "${billing-app/prod/SELF}")

	_, err := fx.api.Reveal(context.Background(), fx.admin(), addr("prod", "/", "SELF"), 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reference cycle detected")
}

// TestReferenceDepthIsBounded is the backstop for a chain that is legitimately shaped
// but unreasonably long — no cycle, just too many hops.
func TestReferenceDepthIsBounded(t *testing.T) {
	fx := newFixture(t)
	fx.api.opts.ReferenceMaxDepth = 2

	fx.seed("prod", "/", "LEAF", "leaf-value")
	fx.seedReference("prod", "/", "C", "${billing-app/prod/LEAF}")
	fx.seedReference("prod", "/", "B", "${billing-app/prod/C}")
	fx.seedReference("prod", "/", "A", "${billing-app/prod/B}")

	_, err := fx.api.Reveal(context.Background(), fx.admin(), addr("prod", "/", "A"), 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "maximum depth")
}

// TestUnterminatedPlaceholderIsRejected: a malformed reference must not be handed to
// a consumer as literal text — "${billing-app/prod/db/PASSWORD" is not a password.
func TestUnterminatedPlaceholderIsRejected(t *testing.T) {
	fx := newFixture(t)
	fx.seedReference("prod", "/", "BROKEN", "${billing-app/prod/db/PASSWORD")

	_, err := fx.api.Reveal(context.Background(), fx.admin(), addr("prod", "/", "BROKEN"), 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unterminated")
}

// TestReferenceAddressMustNameAnEnvironment: an implicit environment would make a
// reference mean something different after it is copied from staging to prod while
// looking identical.
func TestReferenceAddressMustNameAnEnvironment(t *testing.T) {
	fx := newFixture(t)
	fx.seedReference("prod", "/", "SHORT", "${PASSWORD}")

	_, err := fx.api.Reveal(context.Background(), fx.admin(), addr("prod", "/", "SHORT"), 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "project/environment")
}

// ---------------------------------------------------------------------------
// Scope imports
// ---------------------------------------------------------------------------

// TestImportFallsThroughForAMissingKey is the feature: staging imports dev, so a key
// staging does not define resolves to dev's.
func TestImportFallsThroughForAMissingKey(t *testing.T) {
	fx := newFixture(t)
	fx.seed("dev", "/", "SHARED", "from-dev")
	// The target environment needs its root folder to exist, which CreateEnvironment
	// already made; the import edge is created against it.
	_, err := fx.api.CreateImport(context.Background(), fx.admin(), CreateImportInput{
		Project: "billing-app", Environment: "prod", FolderPath: "/",
		SourceProject: "billing-app", SourceEnvironment: "dev", SourceFolderPath: "/",
	})
	require.NoError(t, err)

	revealed, err := fx.api.Reveal(context.Background(), fx.admin(), addr("prod", "/", "SHARED"), 0)
	require.NoError(t, err)
	defer revealed.Secret.Zero()
	assert.Equal(t, "from-dev", string(revealed.Secret.Value.Bytes()))
	// The MRN reported is the one that was actually read, not the one asked for.
	assert.Equal(t, "mrn:secret:acme:billing-app:secret/dev/SHARED", revealed.Secret.Meta.MRN)
}

// TestOwnValueWinsOverAnImport is the precedence rule. The opposite direction would
// let an import silently shadow a value someone deliberately set in this environment.
func TestOwnValueWinsOverAnImport(t *testing.T) {
	fx := newFixture(t)
	fx.seed("dev", "/", "SHARED", "from-dev")
	fx.seed("prod", "/", "SHARED", "from-prod")
	_, err := fx.api.CreateImport(context.Background(), fx.admin(), CreateImportInput{
		Project: "billing-app", Environment: "prod", FolderPath: "/",
		SourceProject: "billing-app", SourceEnvironment: "dev", SourceFolderPath: "/",
	})
	require.NoError(t, err)

	revealed, err := fx.api.Reveal(context.Background(), fx.admin(), addr("prod", "/", "SHARED"), 0)
	require.NoError(t, err)
	defer revealed.Secret.Zero()
	assert.Equal(t, "from-prod", string(revealed.Secret.Value.Bytes()))
}

// TestImportedReadIsAuthorizedAgainstTheSourceMRN: authorization follows the VALUE.
// A caller with a prod-only grant that reads an imported dev value is refused,
// because dev's MRN is what is actually being decrypted.
func TestImportedReadIsAuthorizedAgainstTheSourceMRN(t *testing.T) {
	fx := newFixture(t)
	fx.seed("dev", "/", "SHARED", "from-dev")
	_, err := fx.api.CreateImport(context.Background(), fx.admin(), CreateImportInput{
		Project: "billing-app", Environment: "prod", FolderPath: "/",
		SourceProject: "billing-app", SourceEnvironment: "dev", SourceFolderPath: "/",
	})
	require.NoError(t, err)

	prodOnly := fx.caller(sdkauthz.Grant{
		Action:   permissions.PermGetSecret,
		Resource: "mrn:secret:acme:billing-app:secret/prod/*",
	})
	_, err = fx.api.Reveal(context.Background(), prodOnly, addr("prod", "/", "SHARED"), 0)
	require.Error(t, err, "an import must not launder a read through the importing scope's MRN")
	assert.True(t, apperror.IsForbidden(err))
}

// TestImportCreationRequiresRevealOnTheSource: creating an import makes the source
// readable through the target, so a principal that could create one without holding
// reveal on the source would have manufactured itself a read path.
func TestImportCreationRequiresRevealOnTheSource(t *testing.T) {
	fx := newFixture(t)
	folderManager := fx.caller(
		sdkauthz.Grant{Action: permissions.PermManageFolder},
		sdkauthz.Grant{Action: permissions.PermGetSecret, Resource: "mrn:secret:acme:billing-app:secret/prod/*"},
	)
	_, err := fx.api.CreateImport(context.Background(), folderManager, CreateImportInput{
		Project: "billing-app", Environment: "prod", FolderPath: "/",
		SourceProject: "billing-app", SourceEnvironment: "dev", SourceFolderPath: "/",
	})
	require.Error(t, err, "importing dev requires reveal on dev")
	assert.True(t, apperror.IsForbidden(err))
}

// TestImportCycleIsRefused: a loop would make resolution non-terminating, so the edge
// that would close it is refused at creation with a message naming the offender.
func TestImportCycleIsRefused(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()
	_, err := fx.api.CreateImport(ctx, fx.admin(), CreateImportInput{
		Project: "billing-app", Environment: "prod", FolderPath: "/",
		SourceProject: "billing-app", SourceEnvironment: "dev", SourceFolderPath: "/",
	})
	require.NoError(t, err)

	_, err = fx.api.CreateImport(ctx, fx.admin(), CreateImportInput{
		Project: "billing-app", Environment: "dev", FolderPath: "/",
		SourceProject: "billing-app", SourceEnvironment: "prod", SourceFolderPath: "/",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cycle")
}
