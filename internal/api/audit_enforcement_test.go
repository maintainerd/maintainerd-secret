package api

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sdkauthz "github.com/maintainerd/sdk/authz"
	"github.com/maintainerd/secret/internal/audit"
	"github.com/maintainerd/secret/internal/platform/apperror"
	"github.com/maintainerd/secret/internal/platform/permissions"
	"github.com/maintainerd/secret/internal/store"
)

// These are the tests for the property the whole service is built around: THERE IS NO
// UNAUDITED PATH TO A SECRET VALUE. Each one attacks it from a different angle —
// construction, the success path, the failure path, and the denial path.

// TestServiceCannotBeBuiltWithoutAnAuditor is the structural half of the guarantee.
// A service that cannot record a reveal must not be constructible at all, so the
// failure is a boot error rather than a silently unaudited runtime.
func TestServiceCannotBeBuiltWithoutAnAuditor(t *testing.T) {
	fx := newFixture(t)
	_, err := New(fx.store, nil, nil, Options{DefaultTenant: "acme"})
	require.ErrorIs(t, err, audit.ErrNoAuditor)
}

// TestRevealRefusesWithoutAnAuditor covers the runtime half: even if a *Service were
// obtained with a nil auditor (a future refactor, a zero value), the reveal path
// refuses rather than proceeding unaudited.
func TestRevealRefusesWithoutAnAuditor(t *testing.T) {
	fx := newFixture(t)
	fx.seed("prod", "/db", "PASSWORD", "prod-password")

	unaudited := &Service{store: fx.store, auditor: nil, opts: Options{ReferenceMaxDepth: 8}}
	_, err := unaudited.Reveal(context.Background(), fx.admin(), addr("prod", "/db", "PASSWORD"), 0)
	require.ErrorIs(t, err, audit.ErrNoAuditor)
}

// TestRevealCannotSucceedWithoutAnAuditRow is the central assertion.
//
// The store is healthy and the caller is authorized — the ONLY thing wrong is that
// the audit sink refuses writes. The reveal must fail, and no value may be returned.
// A vault that hands back a credential it cannot prove it handed back is worse than
// one that refuses.
func TestRevealCannotSucceedWithoutAnAuditRow(t *testing.T) {
	fx := newFixture(t)
	fx.seed("prod", "/db", "PASSWORD", "prod-password")
	before := len(fx.repo.auditRows())

	fx.repo.auditErr = errAuditDown

	revealed, err := fx.api.Reveal(context.Background(), fx.admin(), addr("prod", "/db", "PASSWORD"), 0)
	require.Error(t, err, "a reveal must not succeed when its audit row cannot be written")
	assert.Nil(t, revealed)
	assert.Len(t, fx.repo.auditRows(), before, "no row was written, which is exactly why the reveal failed")
}

// TestRevealWritesExactlyOneAuditRowWithNoValue checks the happy path records what it
// should and nothing it should not.
func TestRevealWritesExactlyOneAuditRowWithNoValue(t *testing.T) {
	fx := newFixture(t)
	fx.seed("prod", "/db", "PASSWORD", "prod-password")

	revealed, err := fx.api.Reveal(context.Background(), fx.admin(), addr("prod", "/db", "PASSWORD"), 0)
	require.NoError(t, err)
	defer revealed.Secret.Zero()
	assert.Equal(t, "prod-password", string(revealed.Secret.Value.Bytes()))

	rows := fx.repo.auditRows()
	reveals := 0
	for _, row := range rows {
		if row.Action == store.ActionReveal {
			reveals++
			assert.Equal(t, store.OutcomeSuccess, row.Outcome)
			assert.Equal(t, "mrn:secret:acme:billing-app:secret/prod/db/PASSWORD", row.ResourceMrn)
			assert.Equal(t, "user-1", row.ActorSubject)
			assert.Equal(t, "203.0.113.7", row.IpAddress.String())
			assert.Equal(t, "req-1", row.RequestID)
			require.True(t, row.Version.Valid)
			assert.EqualValues(t, 1, row.Version.Int32)
		}
	}
	assert.Equal(t, 1, reveals, "a reveal writes exactly one reveal row")

	// And nothing in the whole trail contains the value — not the reason, not the
	// metadata, not the MRN.
	raw, err := json.Marshal(rows)
	require.NoError(t, err)
	assert.False(t, containsValue(raw, "prod-password"),
		"no audit row may contain a secret value")
}

// TestDeniedRevealIsAudited proves the denial path writes a row. A refused access is
// the most interesting row in the table — it is how an over-reaching or compromised
// principal is spotted — so it must never be a silent return.
func TestDeniedRevealIsAudited(t *testing.T) {
	fx := newFixture(t)
	fx.seed("prod", "/db", "PASSWORD", "prod-password")

	// Metadata only: this caller may describe every secret and read none.
	metadataOnly := fx.caller(sdkauthz.Grant{Action: permissions.PermReadMetadata})

	_, err := fx.api.Reveal(context.Background(), metadataOnly, addr("prod", "/db", "PASSWORD"), 0)
	require.Error(t, err)
	assert.True(t, apperror.IsForbidden(err))

	denied := 0
	for _, row := range fx.repo.auditRows() {
		if row.Action == store.ActionReveal && row.Outcome == store.OutcomeDenied {
			denied++
			assert.Contains(t, row.Reason, permissions.PermGetSecret)
		}
	}
	assert.Equal(t, 1, denied, "a denied reveal writes a denial row")
}

// TestReadMetadataIsNotReveal is the permission split the contract requires, stated
// as a test: the same caller may describe a secret and may not read it.
func TestReadMetadataIsNotReveal(t *testing.T) {
	fx := newFixture(t)
	fx.seed("prod", "/db", "PASSWORD", "prod-password")
	metadataOnly := fx.caller(sdkauthz.Grant{Action: permissions.PermReadMetadata})

	meta, err := fx.api.DescribeSecret(context.Background(), metadataOnly, addr("prod", "/db", "PASSWORD"))
	require.NoError(t, err, "ReadMetadata is enough to describe")
	assert.Equal(t, "PASSWORD", meta.Key)

	_, err = fx.api.Reveal(context.Background(), metadataOnly, addr("prod", "/db", "PASSWORD"), 0)
	require.Error(t, err, "ReadMetadata must NOT be enough to reveal")
	assert.True(t, apperror.IsForbidden(err))
}

// TestGrantScopedToOneEnvironmentDoesNotReachAnother is the "may read staging, not
// prod" property — the reason authorization is MRN-level rather than route-level.
func TestGrantScopedToOneEnvironmentDoesNotReachAnother(t *testing.T) {
	fx := newFixture(t)
	fx.seed("dev", "/db", "PASSWORD", "dev-password")
	fx.seed("prod", "/db", "PASSWORD", "prod-password")

	devOnly := fx.caller(sdkauthz.Grant{
		Action:   permissions.PermGetSecret,
		Resource: "mrn:secret:acme:billing-app:secret/dev/*",
	})

	revealed, err := fx.api.Reveal(context.Background(), devOnly, addr("dev", "/db", "PASSWORD"), 0)
	require.NoError(t, err)
	defer revealed.Secret.Zero()
	assert.Equal(t, "dev-password", string(revealed.Secret.Value.Bytes()))

	_, err = fx.api.Reveal(context.Background(), devOnly, addr("prod", "/db", "PASSWORD"), 0)
	require.Error(t, err, "a dev-scoped grant must not reach prod")
	assert.True(t, apperror.IsForbidden(err))
}

// TestListingNeverReturnsAValue is the assertion the contract asks for explicitly.
//
// It checks the STRUCTURE, not a filter: the listing returns []store.SecretMeta,
// which has no value field, and the marshalled response contains no plaintext.
func TestListingNeverReturnsAValue(t *testing.T) {
	fx := newFixture(t)
	fx.seed("prod", "/db", "PASSWORD", "the-prod-password")
	fx.seed("prod", "/db", "USERNAME", "the-prod-username")
	fx.seed("prod", "/", "TOKEN", "the-root-token")

	metas, total, err := fx.api.ListSecrets(context.Background(), fx.admin(), ListSecretsInput{
		Project: "billing-app", Environment: "prod", PathPrefix: "/",
	})
	require.NoError(t, err)
	assert.EqualValues(t, 3, total)

	raw, err := json.Marshal(metas)
	require.NoError(t, err)
	for _, value := range []string{"the-prod-password", "the-prod-username", "the-root-token"} {
		assert.False(t, containsValue(raw, value),
			"a listing must never contain a value; found %q", value)
	}

	// And the prefix listing is scoped, so /db returns two of the three.
	scoped, total, err := fx.api.ListSecrets(context.Background(), fx.admin(), ListSecretsInput{
		Project: "billing-app", Environment: "prod", PathPrefix: "/db",
	})
	require.NoError(t, err)
	assert.EqualValues(t, 2, total)
	assert.Len(t, scoped, 2)
}

// TestBatchGetAuditsEveryItem proves a batch is a transport optimisation and not a
// permission one: N reveals produce N reveal rows.
func TestBatchGetAuditsEveryItem(t *testing.T) {
	fx := newFixture(t)
	fx.seed("prod", "/db", "PASSWORD", "p1")
	fx.seed("prod", "/db", "USERNAME", "p2")
	fx.seed("prod", "/", "TOKEN", "p3")

	results, err := fx.api.BatchGet(context.Background(), fx.admin(), []BatchGetItem{
		{Address: addr("prod", "/db", "PASSWORD")},
		{Address: addr("prod", "/db", "USERNAME")},
		{Address: addr("prod", "/", "TOKEN")},
	})
	require.NoError(t, err)
	defer func() {
		for i := range results {
			results[i].Zero()
		}
	}()
	require.Len(t, results, 3)
	for _, res := range results {
		require.NoError(t, res.Error)
	}
	assert.Equal(t, 3, fx.repo.countAudit(store.ActionReveal, store.OutcomeSuccess),
		"every item in a batch reveal is separately audited")
}

// TestBatchGetIsPerItemAuthorized proves the same for denial: an authorized item and
// an unauthorized one in the same call produce a value and a denial respectively,
// rather than one verdict for the whole list.
func TestBatchGetIsPerItemAuthorized(t *testing.T) {
	fx := newFixture(t)
	fx.seed("dev", "/", "OK", "dev-value")
	fx.seed("prod", "/", "NOPE", "prod-value")

	devOnly := fx.caller(sdkauthz.Grant{
		Action:   permissions.PermGetSecret,
		Resource: "mrn:secret:acme:billing-app:secret/dev/*",
	})
	results, err := fx.api.BatchGet(context.Background(), devOnly, []BatchGetItem{
		{Address: addr("dev", "/", "OK")},
		{Address: addr("prod", "/", "NOPE")},
	})
	require.NoError(t, err)
	defer func() {
		for i := range results {
			results[i].Zero()
		}
	}()
	require.Len(t, results, 2)

	require.NoError(t, results[0].Error)
	assert.Equal(t, "dev-value", string(results[0].Secret.Value.Bytes()))

	require.Error(t, results[1].Error, "the prod item must be refused on its own")
	assert.Nil(t, results[1].Secret)
	assert.Equal(t, 1, fx.repo.countAudit(store.ActionReveal, store.OutcomeDenied))
}

// TestBatchGetAbandonsTheWholeBatchWhenAuditingFails: a partial batch is fine for a
// denial and NOT fine for an unwritable trail, because continuing would produce the
// unaudited reveals the single-item path refuses to produce.
func TestBatchGetAbandonsTheWholeBatchWhenAuditingFails(t *testing.T) {
	fx := newFixture(t)
	fx.seed("prod", "/", "A", "a")
	fx.seed("prod", "/", "B", "b")
	fx.repo.auditErr = errAuditDown

	results, err := fx.api.BatchGet(context.Background(), fx.admin(), []BatchGetItem{
		{Address: addr("prod", "/", "A")},
		{Address: addr("prod", "/", "B")},
	})
	require.Error(t, err)
	assert.Nil(t, results)
}

// ---------------------------------------------------------------------------
// The actor kind on the audit row
// ---------------------------------------------------------------------------

// TestResolveCallerTakesTheActorKindFromTheVerifiedClaims.
//
// actor_kind is the one column that lets an incident review separate "a human read
// the production database password" from "the billing workload read its own
// credential". It is only worth anything if it cannot be influenced by the caller,
// so it is taken from the token the guard VERIFIED and overwrites whatever the
// transport supplied. This test drives that both ways round.
func TestResolveCallerTakesTheActorKindFromTheVerifiedClaims(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()

	cases := []struct {
		name         string
		claimsKind   string
		suppliedKind string
		want         string
	}{
		{
			name:       "a console login is recorded as a user",
			claimsKind: sdkauthz.ActorKindUser,
			want:       store.ActorKindUser,
		},
		{
			name:       "an m2m caller is recorded as a service",
			claimsKind: sdkauthz.ActorKindService,
			want:       store.ActorKindService,
		},
		{
			name:         "the verified claim overwrites anything the transport set",
			claimsKind:   sdkauthz.ActorKindService,
			suppliedKind: store.ActorKindUser,
			want:         store.ActorKindService,
		},
		{
			name:         "and in the other direction, so a workload cannot dress a human up either",
			claimsKind:   sdkauthz.ActorKindUser,
			suppliedKind: store.ActorKindService,
			want:         store.ActorKindUser,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := &sdkauthz.Claims{Subject: "p-1", Kind: tc.claimsKind, Tenant: "acme"}
			c, err := fx.api.ResolveCaller(ctx, claims, audit.Actor{Kind: tc.suppliedKind, IP: "203.0.113.7"}, "acme")
			require.NoError(t, err)
			assert.Equal(t, tc.want, c.Actor.Kind)
		})
	}
}

// TestTheAuditRowCarriesTheActorKind is the same property one layer out: what
// actually lands in audit_log for a reveal performed by each class of caller.
func TestTheAuditRowCarriesTheActorKind(t *testing.T) {
	for _, kind := range []string{store.ActorKindUser, store.ActorKindService} {
		t.Run(kind, func(t *testing.T) {
			fx := newFixture(t)
			fx.seed("prod", "/db", "PASSWORD", "prod-password")
			ctx := context.Background()

			// Built the way a real request is: verified claims in, an Actor carrying only
			// observed provenance, and the kind derived by ResolveCaller.
			claims := &sdkauthz.Claims{
				Subject:        "p-1",
				Kind:           kind,
				Tenant:         "acme",
				Grants:         []sdkauthz.Grant{{Action: permissions.PermAdmin}},
				BlanketActions: permissions.BlanketActions(),
			}
			caller, err := fx.api.ResolveCaller(ctx, claims, audit.Actor{IP: "203.0.113.7", RequestID: "req-1"}, "acme")
			require.NoError(t, err)

			revealed, err := fx.api.Reveal(ctx, caller, addr("prod", "/db", "PASSWORD"), 0)
			require.NoError(t, err)
			defer revealed.Secret.Zero()

			var seen int
			for _, row := range fx.repo.auditRows() {
				if row.Action != store.ActionReveal {
					continue
				}
				seen++
				assert.Equal(t, kind, row.ActorKind,
					"a reveal must record WHICH CLASS of caller read the value")
				assert.Equal(t, "p-1", row.ActorSubject)
			}
			require.Equal(t, 1, seen, "exactly one reveal row")
		})
	}
}

// TestADeniedAttemptRecordsTheActorKindToo. A refused access is the most interesting
// row in the table — it is how an over-reaching or compromised principal is spotted —
// and "which kind of caller was refused" is most of the signal.
func TestADeniedAttemptRecordsTheActorKindToo(t *testing.T) {
	fx := newFixture(t)
	fx.seed("prod", "/db", "PASSWORD", "prod-password")
	ctx := context.Background()

	claims := &sdkauthz.Claims{
		Subject:        "workload-1",
		Kind:           sdkauthz.ActorKindService,
		Tenant:         "acme",
		Grants:         []sdkauthz.Grant{{Action: permissions.PermReadMetadata}},
		BlanketActions: permissions.BlanketActions(),
	}
	caller, err := fx.api.ResolveCaller(ctx, claims, audit.Actor{IP: "203.0.113.7"}, "acme")
	require.NoError(t, err)

	_, err = fx.api.Reveal(ctx, caller, addr("prod", "/db", "PASSWORD"), 0)
	require.Error(t, err, "a metadata grant is not a reveal grant")
	assert.True(t, apperror.IsForbidden(err))

	var denials int
	for _, row := range fx.repo.auditRows() {
		if row.Outcome != store.OutcomeDenied {
			continue
		}
		denials++
		assert.Equal(t, store.ActorKindService, row.ActorKind)
		assert.Equal(t, "workload-1", row.ActorSubject)
	}
	assert.Equal(t, 1, denials)
}
