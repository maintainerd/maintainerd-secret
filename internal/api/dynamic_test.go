package api

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sdkauthz "github.com/maintainerd/sdk/authz"
	"github.com/maintainerd/secret/internal/audit"
	"github.com/maintainerd/secret/internal/dynamic"
	"github.com/maintainerd/secret/internal/platform/apperror"
	"github.com/maintainerd/secret/internal/platform/permissions"
	"github.com/maintainerd/secret/internal/storage"
	"github.com/maintainerd/secret/internal/store"
)

// Dynamic-secret tests. The properties under test are the ones that make this feature
// safe to hand to a workload: the configure/issue permission split, the audit guarantee
// on an issue, and the fact that neither the generated password nor the administrative
// DSN reaches the trail, an error, or any surface other than the single issue response.

const (
	dynamicRoleMRN = "mrn:secret:acme:billing-app:dynamic-role/reporting"
	// adminDSN is the most privileged credential in the flow: the account that can
	// CREATE ROLE. It is stored as a secret and referenced, never written into a config
	// column — see store.ValidateDSNSecretRef and the CHECK constraint in
	// migrations/00012.
	adminDSN     = "postgres://vaultadmin:sup3r-s3cret@db.internal:5432/reporting"
	dsnSecretRef = "billing-app/prod/db/DSN"

	// The quoting of {{password}} and {{expiration}} is left to the renderer, which
	// substitutes each as an already-quoted SQL literal. Writing '{{password}}' here —
	// which this fixture originally did — is refused by Config.Validate, because the
	// doubled quotes leave the password OUTSIDE any quoted run and so defeat both
	// redaction paths, putting a live credential into the append-only audit row. The
	// role NAME is an identifier, not a literal, so its double quotes are correct and
	// stay.
	creationSQL = `CREATE ROLE "{{name}}" WITH LOGIN PASSWORD {{password}} VALID UNTIL {{expiration}};
GRANT SELECT ON ALL TABLES IN SCHEMA public TO "{{name}}";`
	revocationSQL = `DROP ROLE IF EXISTS "{{name}}";`
)

// useProvisioner installs a fake provisioner on the fixture's api service.
//
// It writes through the unexported options rather than rebuilding the Service, because
// a second Service would come with a second store and these tests need the one the
// fixture already seeded. Same reason the fixture reaches into the repo directly.
func (fx *fixture) useProvisioner() *fakeProvisioner {
	fx.t.Helper()
	prov := &fakeProvisioner{}
	fx.api.opts.Provisioner = prov
	return prov
}

// seedDynamicRole stores the admin DSN as a secret and registers a role referencing it.
func (fx *fixture) seedDynamicRole() *store.DynamicRoleDetail {
	fx.t.Helper()
	fx.seed("prod", "/db", "DSN", adminDSN)
	role, err := fx.api.CreateDynamicRole(context.Background(), fx.admin(), CreateDynamicRoleInput{
		Project:       "billing-app",
		Name:          "reporting",
		DSNSecretRef:  dsnSecretRef,
		CreationSQL:   creationSQL,
		RevocationSQL: revocationSQL,
	})
	require.NoError(fx.t, err)
	return role
}

// ---------------------------------------------------------------------------
// The issue path, and what it does and does not record
// ---------------------------------------------------------------------------

// TestIssuingDisclosesThePasswordOnceAndRecordsItNowhere is the sharpest form of the
// no-leak rule, because it checks BOTH directions at once: the generated password must
// reach the target database (or the account it creates is unusable) and must reach the
// caller (or the credential is useless), and it must appear in no audit row, no lease
// row and no subsequent read.
func TestIssuingDisclosesThePasswordOnceAndRecordsItNowhere(t *testing.T) {
	fx := newFixture(t)
	prov := fx.useProvisioner()
	fx.seedDynamicRole()
	ctx := context.Background()

	issued, err := fx.api.IssueDynamicCredential(ctx, fx.admin(), IssueDynamicCredentialInput{
		Project: "billing-app", Name: "reporting",
	})
	require.NoError(t, err)
	require.NotNil(t, issued.Credential)
	password := issued.Credential.Password
	require.NotEmpty(t, password)
	require.NoError(t, dynamic.ValidateRoleName(issued.Credential.RoleName))

	// It DID reach the target database — the rendered CREATE ROLE carries it, which is
	// the only way the account can be logged into.
	require.Len(t, prov.createSQL, 1)
	assert.Contains(t, prov.createSQL[0], password)
	assert.Contains(t, prov.createSQL[0], issued.Credential.RoleName)
	// And the target database was reached with the ADMIN DSN, resolved from its secret.
	assert.Equal(t, []string{adminDSN}, prov.dsns)

	// It reached NOTHING else. The audit trail records the role name (what a revocation
	// needs, and what an operator greps pg_roles for) and never the password.
	rows := fx.repo.auditRows()
	raw, err := json.Marshal(rows)
	require.NoError(t, err)
	assert.False(t, containsValue(raw, password),
		"no audit row may contain a dynamic credential's password")
	assert.False(t, containsValue(raw, adminDSN),
		"and none may contain the administrative DSN either")

	var issues int
	for _, row := range rows {
		if row.Action != store.ActionDynamicIssue {
			continue
		}
		issues++
		assert.Equal(t, store.OutcomeSuccess, row.Outcome)
		assert.Equal(t, dynamicRoleMRN, row.ResourceMrn)
		assert.Contains(t, string(row.Metadata), issued.Credential.RoleName,
			"the role name IS recorded: it is what a revocation takes and what makes a "+
				"stranded account findable")
		assert.Contains(t, string(row.Metadata), `"requester":"user-1"`)
	}
	require.Equal(t, 1, issues, "issuing writes exactly one issue row")

	// Nor does the durable lease row, on any path that reads it back.
	leases, total, err := fx.api.ListDynamicLeases(ctx, fx.admin(), ListDynamicLeasesInput{
		Project: "billing-app", Name: "reporting",
	})
	require.NoError(t, err)
	assert.EqualValues(t, 1, total)
	listed, err := json.Marshal(leases)
	require.NoError(t, err)
	assert.False(t, containsValue(listed, password),
		"there is no read-it-back path for a dynamic credential")
	assert.False(t, containsValue(listed, adminDSN))
}

// TestIssuingCannotSucceedWithoutAnAuditRowAndRevokesWhatItMinted.
//
// This is the audit guarantee, and it is stricter than the reveal's because the failure
// leaves something behind: a reveal that cannot be audited only has to destroy a buffer,
// while an issue that cannot be audited has already created a live database account. So
// the account is DROPPED and the lease closed, which is the only outcome that ends with
// nothing unaccounted for. Returning the credential would leave a live account nobody
// can prove was issued; returning an error and leaving it up would leave one nobody
// knows to revoke.
func TestIssuingCannotSucceedWithoutAnAuditRowAndRevokesWhatItMinted(t *testing.T) {
	fx := newFixture(t)
	prov := fx.useProvisioner()
	fx.seedDynamicRole()
	ctx := context.Background()

	fx.repo.auditErr = errAuditDown

	issued, err := fx.api.IssueDynamicCredential(ctx, fx.admin(), IssueDynamicCredentialInput{
		Project: "billing-app", Name: "reporting",
	})
	require.Error(t, err, "an issue must not succeed when its audit row cannot be written")
	assert.Nil(t, issued, "and no credential may be handed back")

	assert.Len(t, prov.createSQL, 1, "the account was created before the audit write failed")
	assert.Equal(t, 1, prov.revokeCount(), "so it was dropped again rather than left live")

	rows := fx.repo.leaseRows()
	require.Len(t, rows, 1)
	assert.True(t, rows[0].RevokedAt.Valid,
		"the lease is closed, so nothing tells the reaper to chase an account that is gone")
	assert.Equal(t, store.DynamicRevokeExplicit, rows[0].RevokeReason)
}

// TestIssuingRefusesWithoutAnAuditor is the structural half: a *Service with no auditor
// must not mint a credential at all, and must not do the work leading up to one.
func TestIssuingRefusesWithoutAnAuditor(t *testing.T) {
	fx := newFixture(t)
	prov := fx.useProvisioner()
	fx.seedDynamicRole()

	unaudited := &Service{
		store:   fx.store,
		auditor: nil,
		opts:    Options{ReferenceMaxDepth: 8, Provisioner: prov},
	}
	_, err := unaudited.IssueDynamicCredential(context.Background(), fx.admin(), IssueDynamicCredentialInput{
		Project: "billing-app", Name: "reporting",
	})
	require.ErrorIs(t, err, audit.ErrNoAuditor)
	assert.Empty(t, prov.createSQL, "and it stopped BEFORE contacting the target database")
}

// TestIssuingWithNoProvisionerIsAnExplicitUnavailability rather than a lease recorded
// for an account that was never created. An operator who has not configured outbound
// provisioning gets told so.
func TestIssuingWithNoProvisionerIsAnExplicitUnavailability(t *testing.T) {
	fx := newFixture(t)
	fx.seedDynamicRole()

	_, err := fx.api.IssueDynamicCredential(context.Background(), fx.admin(), IssueDynamicCredentialInput{
		Project: "billing-app", Name: "reporting",
	})
	require.Error(t, err)
	assert.True(t, apperror.IsUnavailable(err))
	assert.Empty(t, fx.repo.leaseRows(), "no lease is recorded for a credential that does not exist")
}

// TestATargetDatabaseRefusalIsNotACredential. The store runs the creation DDL inside
// the transaction that inserted the lease, so a refusal from the target database leaves
// no lease and no credential — the caller gets the target's refusal, and the refusal is
// on the trail as a failed issue rather than as silence.
func TestATargetDatabaseRefusalIsNotACredential(t *testing.T) {
	fx := newFixture(t)
	prov := fx.useProvisioner()
	prov.createErr = errTargetDown
	fx.seedDynamicRole()

	issued, err := fx.api.IssueDynamicCredential(context.Background(), fx.admin(), IssueDynamicCredentialInput{
		Project: "billing-app", Name: "reporting",
	})
	require.Error(t, err)
	assert.Nil(t, issued)
	assert.True(t, apperror.IsUnavailable(err),
		"the target database being unreachable is not this service being broken")
	assert.Equal(t, 1, fx.repo.countAudit(store.ActionDynamicIssue, store.OutcomeError),
		"a failed issue is recorded, so an operator can see that credentials stopped flowing")
}

// TestARefusedRevocationLeavesTheLeaseOpen.
//
// The ordering here is the OPPOSITE of the issue path's, and deliberately: on issue the
// risk is an account nobody knows about, so the record is written first; on revoke the
// risk is an account everybody believes is gone, so the record is written LAST. A
// revocation the target refused leaves the lease open with an error and an incremented
// attempt count, so the reaper keeps trying and an operator can see a stranded account.
func TestARefusedRevocationLeavesTheLeaseOpen(t *testing.T) {
	fx := newFixture(t)
	prov := fx.useProvisioner()
	fx.seedDynamicRole()
	ctx := context.Background()

	issued, err := fx.api.IssueDynamicCredential(ctx, fx.admin(), IssueDynamicCredentialInput{
		Project: "billing-app", Name: "reporting",
	})
	require.NoError(t, err)

	prov.revokeErr = errTargetDown
	_, err = fx.api.RevokeDynamicCredential(ctx, fx.admin(), RevokeDynamicCredentialInput{
		Project: "billing-app", Name: "reporting", LeaseUUID: issued.Lease.UUID.String(),
	})
	require.Error(t, err)
	assert.True(t, apperror.IsUnavailable(err))

	rows := fx.repo.leaseRows()
	require.Len(t, rows, 1)
	assert.False(t, rows[0].RevokedAt.Valid,
		"the account still exists, so the row that demands its revocation must survive")
	assert.EqualValues(t, 1, rows[0].RevokeAttempts)
	assert.Contains(t, rows[0].RevokeError, errTargetDown.Error())
	assert.NotContains(t, rows[0].RevokeError, issued.Credential.Password,
		"and the recorded error must not carry the credential")
}

// ---------------------------------------------------------------------------
// The permission split
// ---------------------------------------------------------------------------

// TestIssuingIsNotRoleManagement is the split the whole feature rests on. Configuring a
// role decides what every credential issued from it can do; issuing one asks for the
// account that configuration already described. Collapsing them would mean any workload
// that can ask for a credential can also rewrite the SQL that decides what it may do.
func TestIssuingIsNotRoleManagement(t *testing.T) {
	fx := newFixture(t)
	fx.useProvisioner()
	fx.seedDynamicRole()
	ctx := context.Background()

	workload := fx.caller(grantOn(permissions.PermIssueDynamicCredential, dynamicRoleMRN))

	issued, err := fx.api.IssueDynamicCredential(ctx, workload, IssueDynamicCredentialInput{
		Project: "billing-app", Name: "reporting",
	})
	require.NoError(t, err, "IssueDynamicCredential alone is enough to ask for a credential")
	require.NotEmpty(t, issued.Credential.Password)

	_, err = fx.api.UpdateDynamicRole(ctx, workload, UpdateDynamicRoleInput{
		Project: "billing-app", Name: "reporting", DSNSecretRef: dsnSecretRef,
		CreationSQL: creationSQL, RevocationSQL: revocationSQL,
	})
	assert.True(t, apperror.IsForbidden(err), "rewriting the role's SQL needs ManageDynamicRole")

	_, err = fx.api.CreateDynamicRole(ctx, workload, CreateDynamicRoleInput{
		Project: "billing-app", Name: "other", DSNSecretRef: dsnSecretRef,
		CreationSQL: creationSQL, RevocationSQL: revocationSQL,
	})
	assert.True(t, apperror.IsForbidden(err), "and so does registering a new one")

	assert.True(t, apperror.IsForbidden(
		fx.api.DeleteDynamicRole(ctx, workload, DynamicRoleRef{Project: "billing-app", Name: "reporting"})),
		"and deleting one")

	// The other direction: a role administrator holds no ability to mint a credential.
	// Configuring what an account may do and creating one are different acts.
	admin := fx.caller(grantOn(permissions.PermManageDynamicRole, dynamicRoleMRN))
	_, err = fx.api.IssueDynamicCredential(ctx, admin, IssueDynamicCredentialInput{
		Project: "billing-app", Name: "reporting",
	})
	assert.True(t, apperror.IsForbidden(err), "ManageDynamicRole is not IssueDynamicCredential")
}

// TestIssuingIsNotAWayToReadTheDSN is the property that makes handing
// secret:IssueDynamicCredential to a workload reasonable at all.
//
// store.resolveDynamicDSN reveals the administrative connection string WITHOUT a
// caller-scoped grant check on that secret — the one place in this service where a value
// is decrypted without one — precisely so that issuing a credential does not require the
// ability to read the account that creates it. This checks the other half: the holder
// still cannot read that secret through the ordinary path, and the DSN appears nowhere in
// what it receives.
func TestIssuingIsNotAWayToReadTheDSN(t *testing.T) {
	fx := newFixture(t)
	fx.useProvisioner()
	fx.seedDynamicRole()
	ctx := context.Background()

	workload := fx.caller(grantOn(permissions.PermIssueDynamicCredential, dynamicRoleMRN))

	issued, err := fx.api.IssueDynamicCredential(ctx, workload, IssueDynamicCredentialInput{
		Project: "billing-app", Name: "reporting",
	})
	require.NoError(t, err)
	handed, err := json.Marshal(issued)
	require.NoError(t, err)
	assert.False(t, containsValue(handed, adminDSN),
		"the DSN is never returned to the caller on any path")

	_, err = fx.api.Reveal(ctx, workload, addr("prod", "/db", "DSN"), 0)
	require.Error(t, err, "the grant that mints credentials must not read the account that mints them")
	assert.True(t, apperror.IsForbidden(err))
	assert.NotContains(t, err.Error(), adminDSN)
}

// ---------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------

// TestRevokingUsesTheIssueGrantAndIsIdempotent.
//
// The SAME grant deliberately: behind the management grant, no workload could return a
// credential, so credentials would be left to expire instead of revoked. Refusing a
// revoke is the wrong direction to fail. And a retry reports success rather than a
// conflict — making the safe action look like a failure teaches callers not to take it.
func TestRevokingUsesTheIssueGrantAndIsIdempotent(t *testing.T) {
	fx := newFixture(t)
	prov := fx.useProvisioner()
	fx.seedDynamicRole()
	ctx := context.Background()

	workload := fx.caller(grantOn(permissions.PermIssueDynamicCredential, dynamicRoleMRN))
	issued, err := fx.api.IssueDynamicCredential(ctx, workload, IssueDynamicCredentialInput{
		Project: "billing-app", Name: "reporting",
	})
	require.NoError(t, err)

	lease, err := fx.api.RevokeDynamicCredential(ctx, workload, RevokeDynamicCredentialInput{
		Project: "billing-app", Name: "reporting", LeaseUUID: issued.Lease.UUID.String(),
	})
	require.NoError(t, err, "the issue grant carries the revoke")
	require.NotNil(t, lease.RevokedAt)
	assert.Equal(t, 1, prov.revokeCount())
	assert.Contains(t, prov.revokeSQL[0], issued.Credential.RoleName)
	assert.NotContains(t, prov.revokeSQL[0], issued.Credential.Password,
		"a revocation takes a NAME, which is why the password never has to be stored")

	again, err := fx.api.RevokeDynamicCredential(ctx, workload, RevokeDynamicCredentialInput{
		Project: "billing-app", Name: "reporting", LeaseUUID: issued.Lease.UUID.String(),
	})
	require.NoError(t, err, "a retried revoke reports success")
	require.NotNil(t, again.RevokedAt)
	assert.Equal(t, 1, prov.revokeCount(), "and does not run DROP ROLE a second time")
}

// TestDeletingARoleIsRefusedWhileCredentialsAreOutstanding. The revocation template
// lives on the config, so deleting it would leave every issued account unrevokable —
// an inconvenience that prevents a permanent one.
func TestDeletingARoleIsRefusedWhileCredentialsAreOutstanding(t *testing.T) {
	fx := newFixture(t)
	fx.useProvisioner()
	fx.seedDynamicRole()
	ctx := context.Background()

	issued, err := fx.api.IssueDynamicCredential(ctx, fx.admin(), IssueDynamicCredentialInput{
		Project: "billing-app", Name: "reporting",
	})
	require.NoError(t, err)

	err = fx.api.DeleteDynamicRole(ctx, fx.admin(), DynamicRoleRef{Project: "billing-app", Name: "reporting"})
	require.Error(t, err)
	assert.True(t, apperror.IsConflict(err))
	assert.Contains(t, err.Error(), "revoke them before deleting the role")

	_, err = fx.api.RevokeDynamicCredential(ctx, fx.admin(), RevokeDynamicCredentialInput{
		Project: "billing-app", Name: "reporting", LeaseUUID: issued.Lease.UUID.String(),
	})
	require.NoError(t, err)
	require.NoError(t, fx.api.DeleteDynamicRole(ctx, fx.admin(),
		DynamicRoleRef{Project: "billing-app", Name: "reporting"}))
}

// ---------------------------------------------------------------------------
// Tenant scoping
// ---------------------------------------------------------------------------

// TestDynamicTenantScopingCannotBeWidenedByARequestParameter.
//
// The DTOs carry no tenant field: the tenant comes from the resolved Caller. The levers
// a caller does have are the PROJECT, the ROLE NAME and — on a revoke — the LEASE UUID,
// and this drives all three across a tenant boundary with identical project and role
// names on both sides.
//
// The lease UUID is the interesting one, because it is the only opaque handle on these
// surfaces: it is resolved by a tenant-scoped query, so naming another tenant's lease is
// a not-found rather than a cross-tenant revoke.
func TestDynamicTenantScopingCannotBeWidenedByARequestParameter(t *testing.T) {
	fx := newFixture(t)
	prov := fx.useProvisioner()
	fx.seedDynamicRole()
	ctx := context.Background()

	other, err := fx.store.CreateTenant(ctx, store.CreateTenantInput{Name: "other", DisplayName: "Other"})
	require.NoError(t, err)
	_, err = fx.store.CreateProject(ctx, store.CreateProjectInput{
		TenantUUID: other.UUID, Slug: "billing-app", Name: "Billing",
	})
	require.NoError(t, err)
	for _, env := range []string{"prod"} {
		_, err = fx.store.CreateEnvironment(ctx, store.CreateEnvironmentInput{
			TenantUUID: other.UUID, Project: "billing-app", Slug: env, Name: env,
		})
		require.NoError(t, err)
	}
	otherCaller := Caller{
		Claims: &sdkauthz.Claims{
			Subject: "user-2", Kind: sdkauthz.ActorKindUser, Tenant: "other",
			Grants:         []sdkauthz.Grant{{Action: permissions.PermAdmin}},
			BlanketActions: permissions.BlanketActions(),
		},
		// A DISTINCT actor subject, so the MRN assertion at the end of this test can tell
		// acme's rows from the other tenant's.
		Actor:      audit.Actor{Subject: "user-2", Kind: store.ActorKindUser},
		TenantUUID: other.UUID,
		TenantName: other.Name,
	}
	// The same project slug and the same role name, in the other tenant.
	_, err = fx.api.PutSecret(ctx, otherCaller, PutSecretInput{
		Address: SecretAddress{Project: "billing-app", Environment: "prod", FolderPath: "/db", Key: "DSN"},
		Value:   []byte("postgres://other:other@other/db"), CreateFolders: true,
	})
	require.NoError(t, err)
	_, err = fx.api.CreateDynamicRole(ctx, otherCaller, CreateDynamicRoleInput{
		Project: "billing-app", Name: "reporting", DSNSecretRef: dsnSecretRef,
		CreationSQL: creationSQL, RevocationSQL: revocationSQL,
	})
	require.NoError(t, err)

	foreign, err := fx.api.IssueDynamicCredential(ctx, otherCaller, IssueDynamicCredentialInput{
		Project: "billing-app", Name: "reporting",
	})
	require.NoError(t, err)
	revokesBefore := prov.revokeCount()

	// An acme admin naming the other tenant's lease UUID, with the project and role
	// spelled exactly as its own.
	_, err = fx.api.RevokeDynamicCredential(ctx, fx.admin(), RevokeDynamicCredentialInput{
		Project: "billing-app", Name: "reporting", LeaseUUID: foreign.Lease.UUID.String(),
	})
	require.Error(t, err, "a lease UUID from another tenant must not be revokable here")
	assert.True(t, apperror.IsNotFound(err),
		"and it reads as not-found rather than forbidden: a distinct answer would confirm "+
			"that another tenant holds that lease")
	assert.Equal(t, revokesBefore, prov.revokeCount(), "the target database was never contacted")

	// A listing is scoped the same way: acme's role has no leases of its own yet.
	leases, total, err := fx.api.ListDynamicLeases(ctx, fx.admin(), ListDynamicLeasesInput{
		Project: "billing-app", Name: "reporting",
	})
	require.NoError(t, err)
	assert.EqualValues(t, 0, total, "the other tenant's lease is not visible here")
	assert.Empty(t, leases)

	// And every MRN acme's requests were checked against names acme's tenant.
	for _, row := range fx.repo.auditRows() {
		if row.ActorSubject != "user-1" || row.ResourceMrn == "" {
			continue
		}
		assert.True(t, strings.HasPrefix(row.ResourceMrn, "mrn:secret:acme:"),
			"an MRN is built from the resolved caller's tenant, got %q", row.ResourceMrn)
	}
}

// TestRoleReadsCarryTheTemplatesButNeverTheDSN. The templates are operator-authored SQL
// and dsn_secret_ref is an ADDRESS, so an operator about to edit a role can see what it
// runs — while the connection string itself has no field on any of these types.
func TestRoleReadsCarryTheTemplatesButNeverTheDSN(t *testing.T) {
	fx := newFixture(t)
	fx.seedDynamicRole()
	ctx := context.Background()

	detail, err := fx.api.GetDynamicRole(ctx, fx.admin(), DynamicRoleRef{Project: "billing-app", Name: "reporting"})
	require.NoError(t, err)
	assert.Equal(t, creationSQL, detail.CreationSQL, "an operator has to see what the role runs")
	assert.Equal(t, dsnSecretRef, detail.DSNSecretRef)

	roles, total, err := fx.api.ListDynamicRoles(ctx, fx.admin(), ListDynamicRolesInput{Project: "billing-app"})
	require.NoError(t, err)
	assert.EqualValues(t, 1, total)

	raw, err := json.Marshal(map[string]any{"detail": detail, "listing": roles})
	require.NoError(t, err)
	assert.False(t, containsValue(raw, adminDSN),
		"the role surfaces carry the DSN's ADDRESS and never the connection string")
}

// ---------------------------------------------------------------------------
// The reaper's engine
// ---------------------------------------------------------------------------

// expire forces a lease past its expiry by rewriting the row's expires_at, which is what
// the passage of time would do. It returns the lease so a test can name it.
func (fx *fixture) expire(leaseUUID uuid.UUID) {
	fx.t.Helper()
	fx.repo.mu.Lock()
	defer fx.repo.mu.Unlock()
	for _, l := range fx.repo.dynamicLeases {
		if l.LeaseUuid == leaseUUID {
			l.ExpiresAt = time.Now().Add(-time.Minute)
			return
		}
	}
	fx.t.Fatalf("no dynamic lease %s to expire", leaseUUID)
}

// TestTheReaperRevokesAnExpiredCredentialAndRecordsIt is the test for the property that
// makes a dynamic credential actually short-lived.
//
// THIS PATH WAS DEAD. ReapExpiredDynamicLeases had no implementation and NewReaper had no
// caller, so a lease could expire and the PostgreSQL role it created went on existing
// forever. Nothing about that was visible: issuing kept working, reading kept working,
// and the only symptom was accounts accumulating in pg_roles on the target database.
// A TTL that nothing enforces is a comment.
func TestTheReaperRevokesAnExpiredCredentialAndRecordsIt(t *testing.T) {
	fx := newFixture(t)
	prov := fx.useProvisioner()
	fx.seedDynamicRole()
	ctx := context.Background()

	issued, err := fx.api.IssueDynamicCredential(ctx, fx.admin(), IssueDynamicCredentialInput{
		Project: "billing-app", Name: "reporting",
	})
	require.NoError(t, err)
	roleName := issued.Credential.RoleName
	password := issued.Credential.Password

	// Not yet due: a live lease must survive a pass, or the TTL means nothing in the
	// other direction and every credential dies on the next tick.
	report, err := fx.api.ReapExpiredDynamicLeases(ctx, 10)
	require.NoError(t, err)
	assert.Zero(t, report.Due, "a lease inside its TTL is not the reaper's business")
	assert.Zero(t, prov.revokeCount())

	fx.expire(issued.Lease.UUID)

	report, err = fx.api.ReapExpiredDynamicLeases(ctx, 10)
	require.NoError(t, err)
	assert.Equal(t, 1, report.Due)
	assert.Equal(t, 1, report.Revoked)
	assert.Zero(t, report.Failed)
	assert.Zero(t, report.Skipped)

	// The DROP actually reached the target database, naming the role — that is the whole
	// point, and a report claiming a revocation without one would be a lie.
	require.Len(t, prov.revokeSQL, 1)
	assert.Contains(t, prov.revokeSQL[0], roleName)
	assert.NotContains(t, prov.revokeSQL[0], password,
		"revoking needs the role name, never the password, which is not stored anyway")

	// It is recorded, attributed to the reaper rather than to a person — so "expired" and
	// "a human revoked this" stay distinguishable in an incident review.
	rows := fx.repo.auditRows()
	var found *storage.AuditLog
	for i := range rows {
		if rows[i].Action == store.ActionDynamicRevoke {
			found = &rows[i]
		}
	}
	require.NotNil(t, found, "an expiry-driven revocation must leave an audit row")
	assert.Equal(t, "maintainerd-secret/dynamic-reaper", found.ActorSubject)
	assert.Equal(t, store.OutcomeSuccess, found.Outcome)

	raw, err := json.Marshal(rows)
	require.NoError(t, err)
	assert.False(t, containsValue(raw, password), "the reaper's own row must not carry the credential")
	assert.False(t, containsValue(raw, adminDSN), "nor the administrative DSN it connected with")

	// IDEMPOTENT. The closed lease is gone from the sweep, so a second pass does not
	// re-DROP a role that no longer exists — which would record a failure for a
	// revocation that actually succeeded.
	report, err = fx.api.ReapExpiredDynamicLeases(ctx, 10)
	require.NoError(t, err)
	assert.Zero(t, report.Due, "a revoked lease must leave the sweep for good")
	assert.Equal(t, 1, prov.revokeCount(), "and must not be dropped twice")
}

// TestAFailedReapLeavesTheLeaseOpen. A revocation the target database refused HAS NOT
// HAPPENED, and the lease row is the only record that a live account still needs
// dropping. Marking it revoked anyway would destroy that record — the account would
// stay live with nothing left pointing at it, which is strictly worse than a retry.
func TestAFailedReapLeavesTheLeaseOpen(t *testing.T) {
	fx := newFixture(t)
	prov := fx.useProvisioner()
	fx.seedDynamicRole()
	ctx := context.Background()

	issued, err := fx.api.IssueDynamicCredential(ctx, fx.admin(), IssueDynamicCredentialInput{
		Project: "billing-app", Name: "reporting",
	})
	require.NoError(t, err)
	fx.expire(issued.Lease.UUID)

	prov.revokeErr = errTargetDown
	report, err := fx.api.ReapExpiredDynamicLeases(ctx, 10)
	require.NoError(t, err, "one unreachable target is not a failed pass")
	assert.Equal(t, 1, report.Due)
	assert.Zero(t, report.Revoked)
	assert.Equal(t, 1, report.Failed)

	// Still claimable, which is what makes the retry possible.
	report, err = fx.api.ReapExpiredDynamicLeases(ctx, 10)
	require.NoError(t, err)
	assert.Equal(t, 1, report.Due, "a failed revocation must stay on the sweep")

	// And once the target comes back, it is revoked.
	prov.revokeErr = nil
	report, err = fx.api.ReapExpiredDynamicLeases(ctx, 10)
	require.NoError(t, err)
	assert.Equal(t, 1, report.Revoked)
}

// TestTheReaperRefusesWithoutAnAuditor. The auditor is a required dependency everywhere
// else in this service, and a sweep that silently dropped database accounts with no trail
// would be the one place it was not.
func TestTheReaperRefusesWithoutAnAuditor(t *testing.T) {
	fx := newFixture(t)
	fx.useProvisioner()
	fx.api.auditor = nil

	_, err := fx.api.ReapExpiredDynamicLeases(context.Background(), 10)
	require.ErrorIs(t, err, audit.ErrNoAuditor)
}

// TestTheReaperIsAQuietNoOpWithNoProvisioner. An instance with no provisioner configured
// cannot have issued anything, so there is nothing overdue to chase. Reporting an error
// would log one every interval forever and train an operator to ignore the reaper's
// output — which is the output that matters when a revocation really is stuck.
func TestTheReaperIsAQuietNoOpWithNoProvisioner(t *testing.T) {
	fx := newFixture(t)
	require.Nil(t, fx.api.opts.Provisioner)

	report, err := fx.api.ReapExpiredDynamicLeases(context.Background(), 10)
	require.NoError(t, err)
	assert.Zero(t, report.Due)
	assert.Zero(t, report.Failed)
}

// TestSkippedMeansTheTargetWasNeverContacted separates the two failure classes, which
// exist so an operator can tell "retry will fix this" from "only you can fix this".
//
// It is worth a test because the obvious implementation is wrong: the store maps a
// provisioner REFUSAL to Unavailable, and so does a missing provisioner — so classifying
// on the error's class files every refused DROP ROLE under "needs an operator" and buries
// the retry signal. The real question is whether the target was ever dialled.
func TestSkippedMeansTheTargetWasNeverContacted(t *testing.T) {
	fx := newFixture(t)
	prov := fx.useProvisioner()
	role := fx.seedDynamicRole()
	ctx := context.Background()

	issued, err := fx.api.IssueDynamicCredential(ctx, fx.admin(), IssueDynamicCredentialInput{
		Project: "billing-app", Name: "reporting",
	})
	require.NoError(t, err)
	fx.expire(issued.Lease.UUID)

	// THE API REFUSES TO CREATE THIS STATE, which is worth asserting first: deleting a
	// role with outstanding leases would strand every account issued from it, because the
	// revocation template is the only way to drop them.
	err = fx.api.DeleteDynamicRole(ctx, fx.admin(), DynamicRoleRef{
		Project: "billing-app", Name: role.Name,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "still outstanding")

	// So the Skipped case is reached the only way it can be — the config going away
	// underneath the lease, by a direct database edit or a restore that lost the row.
	// That is precisely the situation the report's Skipped count is for: nothing to
	// retry, an operator has to put the config back before the account can be dropped.
	fx.repo.mu.Lock()
	for id := range fx.repo.dynamicRoles {
		delete(fx.repo.dynamicRoles, id)
	}
	fx.repo.mu.Unlock()

	report, err := fx.api.ReapExpiredDynamicLeases(ctx, 10)
	require.NoError(t, err)
	assert.Equal(t, 1, report.Due)
	assert.Equal(t, 1, report.Skipped, "a config that is gone is not a retryable failure")
	assert.Zero(t, report.Failed)
	assert.Zero(t, prov.revokeCount(), "and nothing was sent to the target database")
}
