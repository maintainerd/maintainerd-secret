package api

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/maintainerd/secret/internal/platform/apperror"
	"github.com/maintainerd/secret/internal/platform/permissions"
	"github.com/maintainerd/secret/internal/storage"
	"github.com/maintainerd/secret/internal/store"
)

// Lease tests for STATIC secrets. The property these exist for is the permission split:
// a lease is not authorization, so reading a leased secret is still secret:GetSecret and
// nothing more, while MOVING the cap is administration.

// ---------------------------------------------------------------------------
// The lease half of the in-memory store
// ---------------------------------------------------------------------------
//
// The policy lives on the `secrets` row (lease_ttl_seconds, lease_max_ttl_seconds,
// lease_max_reads); the issued leases live in their own table. Both are modelled here,
// including the `revoked_at IS NULL` predicate that decides how many rows a revoke-all
// actually closes.

func (f *fakeRepo) SetSecretLeasePolicy(_ context.Context, arg storage.SetSecretLeasePolicyParams) (storage.Secret, error) {
	for _, s := range f.secrets {
		if s.TenantID == arg.TenantID && s.SecretUuid == arg.SecretUuid && !s.DeletedAt.Valid {
			// All three columns are written together, like the real statement: a TTL left
			// beside a stale max_reads from a previous policy is not a state any caller
			// asked for.
			s.LeaseTtlSeconds = arg.LeaseTtlSeconds
			s.LeaseMaxTtlSeconds = arg.LeaseMaxTtlSeconds
			s.LeaseMaxReads = arg.LeaseMaxReads
			s.UpdatedAt = time.Now()
			return *s, nil
		}
	}
	return storage.Secret{}, pgx.ErrNoRows
}

func (f *fakeRepo) RevokeSecretLeasesForSecret(_ context.Context, arg storage.RevokeSecretLeasesForSecretParams) (int64, error) {
	n := int64(0)
	for _, l := range f.secretLeases {
		if l.TenantID != arg.TenantID || l.SecretID != arg.SecretID || l.RevokedAt.Valid {
			continue
		}
		l.RevokedAt = pgtype.Timestamptz{Time: time.Now(), Valid: true}
		l.RevokeReason = arg.RevokeReason
		l.UpdatedAt = time.Now()
		n++
	}
	return n, nil
}

func (f *fakeRepo) ListSecretLeases(_ context.Context, arg storage.ListSecretLeasesParams) ([]storage.ListSecretLeasesRow, error) {
	out := []storage.ListSecretLeasesRow{}
	if arg.RowOffset > 0 {
		return out, nil
	}
	for _, l := range f.secretLeases {
		if l.TenantID != arg.TenantID || l.SecretID != arg.SecretID {
			continue
		}
		out = append(out, storage.ListSecretLeasesRow{
			LeaseUuid: l.LeaseUuid, SecretID: l.SecretID, ResourceMrn: l.ResourceMrn,
			Requester: l.Requester, RequesterKind: l.RequesterKind,
			IssuedAt: l.IssuedAt, ExpiresAt: l.ExpiresAt, MaxReads: l.MaxReads,
			ReadsUsed: l.ReadsUsed, LastReadAt: l.LastReadAt,
			RevokedAt: l.RevokedAt, RevokeReason: l.RevokeReason,
		})
	}
	return out, nil
}

func (f *fakeRepo) CountSecretLeases(_ context.Context, arg storage.CountSecretLeasesParams) (int64, error) {
	n := int64(0)
	for _, l := range f.secretLeases {
		if l.TenantID == arg.TenantID && l.SecretID == arg.SecretID {
			n++
		}
	}
	return n, nil
}

// seedLease inserts an outstanding lease directly, so a revoke-all has something to
// close. The ENFORCEMENT path (api.enforceReadLease, driven from a reveal) is the store's
// own territory and is not what these tests are about.
func (fx *fixture) seedLease(secretUUID uuid.UUID, requester string) {
	fx.t.Helper()
	var secretID int64
	for _, s := range fx.repo.secrets {
		if s.SecretUuid == secretUUID {
			secretID = s.SecretID
		}
	}
	require.NotZero(fx.t, secretID, "the secret must exist before a lease can be seeded against it")
	id := fx.repo.id("secret_lease")
	fx.repo.secretLeases[id] = &storage.SecretLease{
		LeaseID: id, LeaseUuid: uuid.New(),
		TenantID: 1, SecretID: secretID,
		Requester: requester, RequesterKind: store.ActorKindService,
		IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
}

// ---------------------------------------------------------------------------
// The permission split
// ---------------------------------------------------------------------------

// TestALeaseIsNotAuthorization is the property this whole feature would break without.
//
// Requiring secret:ManageLease to READ a leased secret would make every leased secret
// unreadable by exactly the consumers the lease was written for — and requiring
// secret:GetSecret to see the POLICY would mean a consumer could not discover the cap it
// is subject to until it hit it. Both directions are driven here.
func TestALeaseIsNotAuthorization(t *testing.T) {
	fx := newFixture(t)
	res := fx.seed("prod", "/db", "PASSWORD", "prod-password")
	ctx := context.Background()
	address := addr("prod", "/db", "PASSWORD")

	// A lease administrator: it may move the cap and may NOT read the value.
	leaseAdmin := fx.caller(grantOn(permissions.PermManageLease, ""))
	ttl := int32(3600)
	_, err := fx.api.SetSecretLeasePolicy(ctx, leaseAdmin, SetSecretLeasePolicyInput{
		Address: address, TTLSeconds: &ttl,
	})
	require.NoError(t, err, "ManageLease is enough to set the policy")

	_, err = fx.api.Reveal(ctx, leaseAdmin, address, 0)
	require.Error(t, err, "and it is NOT a way to read the value it governs")
	assert.True(t, apperror.IsForbidden(err))

	// A consumer: it may read the value and may see the policy, and may not change it.
	consumer := fx.caller(
		grantOn(permissions.PermGetSecret, ""),
		grantOn(permissions.PermReadMetadata, ""),
	)
	policy, err := fx.api.GetSecretLeasePolicy(ctx, consumer, SecretLeaseRef{Address: address})
	require.NoError(t, err, "ReadMetadata is enough to see the cap you are subject to")
	assert.True(t, policy.Enabled())

	_, err = fx.api.SetSecretLeasePolicy(ctx, consumer, SetSecretLeasePolicyInput{
		Address: address, TTLSeconds: &ttl,
	})
	require.Error(t, err, "reading the cap must not carry moving it")
	assert.True(t, apperror.IsForbidden(err))

	_, err = fx.api.RevokeSecretLeases(ctx, consumer, SecretLeaseRef{Address: address})
	require.Error(t, err, "nor cutting other consumers off")
	assert.True(t, apperror.IsForbidden(err))

	// Every refusal is audited under the action it attempted.
	assert.Equal(t, 1, fx.repo.countAudit(store.ActionLeasePolicySet, store.OutcomeDenied))
	assert.Equal(t, 1, fx.repo.countAudit(store.ActionLeaseRevoke, store.OutcomeDenied))
	require.NotZero(t, res.SecretUUID)
}

// TestThePolicySurfaceIsAuthorizedAgainstTheSecretNotTheFolder.
//
// A policy governs reads of ONE value, so the grant that changes it has to name that
// value: a check at folder scope would let a principal with folder-wide management
// loosen the cap on the one credential inside it that mattered.
func TestThePolicySurfaceIsAuthorizedAgainstTheSecretNotTheFolder(t *testing.T) {
	fx := newFixture(t)
	fx.seed("prod", "/db", "PASSWORD", "prod-password")
	fx.seed("prod", "/db", "REPLICA_PASSWORD", "replica-password")
	ctx := context.Background()
	ttl := int32(3600)

	// A grant naming exactly one secret.
	scoped := fx.caller(grantOn(permissions.PermManageLease,
		"mrn:secret:acme:billing-app:secret/prod/db/PASSWORD"))

	_, err := fx.api.SetSecretLeasePolicy(ctx, scoped, SetSecretLeasePolicyInput{
		Address: addr("prod", "/db", "PASSWORD"), TTLSeconds: &ttl,
	})
	require.NoError(t, err)

	_, err = fx.api.SetSecretLeasePolicy(ctx, scoped, SetSecretLeasePolicyInput{
		Address: addr("prod", "/db", "REPLICA_PASSWORD"), TTLSeconds: &ttl,
	})
	require.Error(t, err, "a grant on one secret must not reach its neighbour in the same folder")
	assert.True(t, apperror.IsForbidden(err))
}

// TestLeaseTenantScopingCannotBeWidenedByARequestParameter. The address DTO names a
// project, an environment, a folder and a key — and no tenant. The MRN and the store
// scope both come from the resolved Caller, so an identical address in another tenant is
// a different secret and a dev-scoped grant does not reach prod.
func TestLeaseTenantScopingCannotBeWidenedByARequestParameter(t *testing.T) {
	fx := newFixture(t)
	fx.seed("dev", "/db", "PASSWORD", "dev-password")
	fx.seed("prod", "/db", "PASSWORD", "prod-password")
	ctx := context.Background()
	ttl := int32(3600)

	devOnly := fx.caller(grantOn(permissions.PermManageLease,
		"mrn:secret:acme:billing-app:secret/dev/*"))

	_, err := fx.api.SetSecretLeasePolicy(ctx, devOnly, SetSecretLeasePolicyInput{
		Address: addr("dev", "/db", "PASSWORD"), TTLSeconds: &ttl,
	})
	require.NoError(t, err)

	_, err = fx.api.SetSecretLeasePolicy(ctx, devOnly, SetSecretLeasePolicyInput{
		Address: addr("prod", "/db", "PASSWORD"), TTLSeconds: &ttl,
	})
	require.Error(t, err, "a dev-scoped grant must not reach prod")
	assert.True(t, apperror.IsForbidden(err))

	for _, row := range fx.repo.auditRows() {
		if row.ResourceMrn != "" {
			assert.Contains(t, row.ResourceMrn, "mrn:secret:acme:",
				"an MRN is built from the resolved caller's tenant, got %q", row.ResourceMrn)
		}
	}
}

// ---------------------------------------------------------------------------
// The trail
// ---------------------------------------------------------------------------

// TestThePolicyChangeIsOnTheTrailAndTheValueIsNot.
//
// "The cap on the production database password was raised from 10 to 10000" is precisely
// the change an incident review needs to see, and it is unreconstructable from anything
// else — so the policy IS recorded. The value it governs is not, and neither is anything
// derived from it.
func TestThePolicyChangeIsOnTheTrailAndTheValueIsNot(t *testing.T) {
	fx := newFixture(t)
	fx.seed("prod", "/db", "PASSWORD", "the-prod-password")
	ctx := context.Background()
	address := addr("prod", "/db", "PASSWORD")

	ttl, maxReads := int32(3600), int32(10)
	_, err := fx.api.SetSecretLeasePolicy(ctx, fx.admin(), SetSecretLeasePolicyInput{
		Address: address, TTLSeconds: &ttl, MaxReads: &maxReads,
	})
	require.NoError(t, err)

	raised := int32(10000)
	_, err = fx.api.SetSecretLeasePolicy(ctx, fx.admin(), SetSecretLeasePolicyInput{
		Address: address, TTLSeconds: &ttl, MaxReads: &raised,
	})
	require.NoError(t, err)

	var seen []string
	for _, row := range fx.repo.auditRows() {
		if row.Action == store.ActionLeasePolicySet {
			assert.Equal(t, "mrn:secret:acme:billing-app:secret/prod/db/PASSWORD", row.ResourceMrn)
			seen = append(seen, string(row.Metadata))
		}
	}
	require.Len(t, seen, 2)
	assert.Contains(t, seen[0], `"lease_max_reads":10`)
	assert.Contains(t, seen[1], `"lease_max_reads":10000`)

	raw, err := json.Marshal(fx.repo.auditRows())
	require.NoError(t, err)
	assert.False(t, containsValue(raw, "the-prod-password"),
		"a lease-policy row may carry the policy and never the value")
}

// TestRemovingThePolicyIsAnExplicitAuditableActThatClosesTheLeases.
//
// A nil TTL means "remove the policy", which the pointer fields exist to distinguish
// from "the caller did not mention it". Removal closes the leases the policy governed,
// because a lease is an instrument of a policy: leaving live rows behind would mean
// re-enabling the policy silently resumed allowances issued under the old, possibly
// looser, caps.
func TestRemovingThePolicyIsAnExplicitAuditableActThatClosesTheLeases(t *testing.T) {
	fx := newFixture(t)
	res := fx.seed("prod", "/db", "PASSWORD", "prod-password")
	ctx := context.Background()
	address := addr("prod", "/db", "PASSWORD")

	ttl := int32(3600)
	_, err := fx.api.SetSecretLeasePolicy(ctx, fx.admin(), SetSecretLeasePolicyInput{
		Address: address, TTLSeconds: &ttl,
	})
	require.NoError(t, err)
	fx.seedLease(res.SecretUUID, "svc-reconciler")
	fx.seedLease(res.SecretUUID, "svc-reporting")

	leases, total, err := fx.api.ListSecretLeases(ctx, fx.admin(), ListSecretLeasesInput{Address: address})
	require.NoError(t, err)
	assert.EqualValues(t, 2, total)
	require.Len(t, leases, 2)

	meta, err := fx.api.SetSecretLeasePolicy(ctx, fx.admin(), SetSecretLeasePolicyInput{Address: address})
	require.NoError(t, err)
	require.NotNil(t, meta)

	policy, err := fx.api.GetSecretLeasePolicy(ctx, fx.admin(), SecretLeaseRef{Address: address})
	require.NoError(t, err)
	assert.False(t, policy.Enabled(), "the policy is gone, so reads behave as they did before leases existed")

	for _, l := range fx.repo.secretLeases {
		assert.True(t, l.RevokedAt.Valid, "removing the policy closes the leases it governed")
	}

	// policy_removed is recorded EXPLICITLY rather than by omission, because "the cap was
	// removed" and "the cap was not mentioned" are the two states this surface exists to
	// distinguish.
	var removals int
	for _, row := range fx.repo.auditRows() {
		if row.Action == store.ActionLeasePolicySet && strings.Contains(string(row.Metadata), `"policy_removed":true`) {
			removals++
		}
	}
	assert.Equal(t, 1, removals)
}

// TestRevokingLeasesReportsWhatItClosedAndDoesNotLockTheSecret.
//
// Revoking resets allowances; it does not stop the next authorized read from opening a
// fresh lease. Saying so is worth a test, because an operator reaching for this during
// an incident needs to know which of the two it is.
func TestRevokingLeasesReportsWhatItClosedAndDoesNotLockTheSecret(t *testing.T) {
	fx := newFixture(t)
	res := fx.seed("prod", "/db", "PASSWORD", "prod-password")
	ctx := context.Background()
	address := addr("prod", "/db", "PASSWORD")

	ttl := int32(3600)
	_, err := fx.api.SetSecretLeasePolicy(ctx, fx.admin(), SetSecretLeasePolicyInput{
		Address: address, TTLSeconds: &ttl,
	})
	require.NoError(t, err)
	fx.seedLease(res.SecretUUID, "svc-reconciler")

	n, err := fx.api.RevokeSecretLeases(ctx, fx.admin(), SecretLeaseRef{Address: address})
	require.NoError(t, err)
	assert.EqualValues(t, 1, n)

	// Revoking nothing is a legitimate outcome of asking for a clean slate.
	n, err = fx.api.RevokeSecretLeases(ctx, fx.admin(), SecretLeaseRef{Address: address})
	require.NoError(t, err)
	assert.EqualValues(t, 0, n)

	// The POLICY survives, which is what makes this a reset rather than a lock.
	policy, err := fx.api.GetSecretLeasePolicy(ctx, fx.admin(), SecretLeaseRef{Address: address})
	require.NoError(t, err)
	assert.True(t, policy.Enabled())

	assert.Equal(t, 2, fx.repo.countAudit(store.ActionLeaseRevoke, store.OutcomeSuccess))
}
