package api

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sdkauthz "github.com/maintainerd/sdk/authz"
	"github.com/maintainerd/secret/internal/audit"
	"github.com/maintainerd/secret/internal/crypto"
	"github.com/maintainerd/secret/internal/platform/apperror"
	"github.com/maintainerd/secret/internal/platform/permissions"
	"github.com/maintainerd/secret/internal/store"
)

// Transit tests. The properties under test are the ones that would be invisible if they
// broke: the three-way permission split, the audit guarantee on a decrypt, and the fact
// that nothing on any of these paths carries a plaintext or key material.

// seedTransitKey creates a key as the admin caller.
func (fx *fixture) seedTransitKey(name string) *store.TransitKey {
	fx.t.Helper()
	key, err := fx.api.CreateTransitKey(context.Background(), fx.admin(), CreateTransitKeyInput{
		Project: "billing-app",
		Name:    name,
	})
	require.NoError(fx.t, err)
	return key
}

// grantOn builds a grant for one action against one MRN.
func grantOn(action, resource string) sdkauthz.Grant {
	return sdkauthz.Grant{Action: action, Resource: resource}
}

const transitKeyMRN = "mrn:secret:acme:billing-app:transit/pii"

// ---------------------------------------------------------------------------
// The round trip, and what the trail records
// ---------------------------------------------------------------------------

// TestTransitRoundTripRecordsLengthsAndNeverPayloads is the happy path plus the
// no-leak assertion, together — because the interesting question about a successful
// decrypt is not that it worked, it is what the trail now contains.
func TestTransitRoundTripRecordsLengthsAndNeverPayloads(t *testing.T) {
	fx := newFixture(t)
	fx.seedTransitKey("pii")
	ctx := context.Background()
	const secretValue = "4111-1111-1111-1111"

	sealed, err := fx.api.TransitEncrypt(ctx, fx.admin(), TransitEncryptInput{
		Project:   "billing-app",
		Name:      "pii",
		Plaintext: []byte(secretValue),
	})
	require.NoError(t, err)
	assert.EqualValues(t, 1, sealed.KeyVersion)
	assert.NotContains(t, sealed.Ciphertext, secretValue,
		"a token must not contain its own plaintext")

	opened, err := fx.api.TransitDecrypt(ctx, fx.admin(), TransitDecryptInput{
		Project:    "billing-app",
		Ciphertext: sealed.Ciphertext,
	})
	require.NoError(t, err)
	defer opened.Zero()
	assert.Equal(t, secretValue, string(opened.Plaintext.Bytes()))
	assert.Equal(t, "pii", opened.KeyName)

	assert.Equal(t, 1, fx.repo.countAudit(store.ActionTransitEncrypt, store.OutcomeSuccess))
	assert.Equal(t, 1, fx.repo.countAudit(store.ActionTransitDecrypt, store.OutcomeSuccess))

	rows := fx.repo.auditRows()
	var decrypts int
	for _, row := range rows {
		if row.Action != store.ActionTransitDecrypt {
			continue
		}
		decrypts++
		assert.Equal(t, transitKeyMRN, row.ResourceMrn,
			"a decrypt is recorded against the KEY the token named, not the project")
		// The byte count is on the row because a length is not a value, and it is what
		// makes "this caller decrypted 19 bytes a second for an hour" visible.
		assert.Contains(t, string(row.Metadata), `"plaintext_bytes":19`)
	}
	require.Equal(t, 1, decrypts)

	raw, err := json.Marshal(rows)
	require.NoError(t, err)
	assert.False(t, containsValue(raw, secretValue),
		"no audit row may contain a transit plaintext")
	assert.False(t, containsValue(raw, sealed.Ciphertext),
		"no audit row may contain a ciphertext either: a token an attacker could later "+
			"present has no business in a table with a broader read audience than the data "+
			"it protects")
}

// TestTransitDecryptedStructCannotLeakThroughAMarshaller.
//
// crypto.Plaintext redacts through String, %v, %#v, slog and json. That is what makes it
// safe to hold a recovered value in a struct at all — and it is why the REST handler has
// to base64 the bytes by hand rather than passing the struct to a response helper. Both
// halves are checked here, because a future edit that changed Plaintext to a plain
// []byte would break the first and silently make the second unnecessary-looking.
func TestTransitDecryptedStructCannotLeakThroughAMarshaller(t *testing.T) {
	fx := newFixture(t)
	fx.seedTransitKey("pii")
	ctx := context.Background()
	const secretValue = "the-card-number"

	sealed, err := fx.api.TransitEncrypt(ctx, fx.admin(), TransitEncryptInput{
		Project: "billing-app", Name: "pii", Plaintext: []byte(secretValue),
	})
	require.NoError(t, err)
	opened, err := fx.api.TransitDecrypt(ctx, fx.admin(), TransitDecryptInput{
		Project: "billing-app", Ciphertext: sealed.Ciphertext,
	})
	require.NoError(t, err)
	defer opened.Zero()

	marshalled, err := json.Marshal(opened)
	require.NoError(t, err)
	assert.False(t, containsValue(marshalled, secretValue),
		"a marshalled TransitDecrypted must not carry the plaintext")
	assert.Contains(t, string(marshalled), crypto.Redacted)

	assert.NotContains(t, opened.Plaintext.String(), secretValue)

	// And Zero actually overwrites, so the buffer the caller was handed does not outlive
	// the response.
	opened.Zero()
	assert.NotEqual(t, secretValue, string(opened.Plaintext.Bytes()))
}

// ---------------------------------------------------------------------------
// The audit guarantee on a decrypt
// ---------------------------------------------------------------------------

// TestTransitDecryptCannotSucceedWithoutAnAuditRow is the central assertion for this
// surface, and it is the reveal path's assertion applied to transit.
//
// The store is healthy, the key is fine and the caller is authorized — the ONLY thing
// wrong is that the audit sink refuses writes. The decrypt must fail and no plaintext
// may be returned. A vault that hands back a value it cannot prove it handed back is
// worse than one that refuses.
func TestTransitDecryptCannotSucceedWithoutAnAuditRow(t *testing.T) {
	fx := newFixture(t)
	fx.seedTransitKey("pii")
	ctx := context.Background()

	sealed, err := fx.api.TransitEncrypt(ctx, fx.admin(), TransitEncryptInput{
		Project: "billing-app", Name: "pii", Plaintext: []byte("prod-card"),
	})
	require.NoError(t, err)

	before := len(fx.repo.auditRows())
	fx.repo.auditErr = errAuditDown

	opened, err := fx.api.TransitDecrypt(ctx, fx.admin(), TransitDecryptInput{
		Project: "billing-app", Ciphertext: sealed.Ciphertext,
	})
	require.Error(t, err, "a decrypt must not succeed when its audit row cannot be written")
	assert.Nil(t, opened, "and no plaintext may be handed back")
	assert.Len(t, fx.repo.auditRows(), before,
		"no row was written, which is exactly why the decrypt failed")
}

// TestTransitDecryptRefusesWithoutAnAuditor is the structural half: even a *Service
// obtained with a nil auditor (a future refactor, a zero value) refuses rather than
// proceeding unaudited.
func TestTransitDecryptRefusesWithoutAnAuditor(t *testing.T) {
	fx := newFixture(t)
	fx.seedTransitKey("pii")
	sealed, err := fx.api.TransitEncrypt(context.Background(), fx.admin(), TransitEncryptInput{
		Project: "billing-app", Name: "pii", Plaintext: []byte("prod-card"),
	})
	require.NoError(t, err)

	unaudited := &Service{store: fx.store, auditor: nil, opts: Options{ReferenceMaxDepth: 8}}
	_, err = unaudited.TransitDecrypt(context.Background(), fx.admin(), TransitDecryptInput{
		Project: "billing-app", Ciphertext: sealed.Ciphertext,
	})
	require.ErrorIs(t, err, audit.ErrNoAuditor)
}

// ---------------------------------------------------------------------------
// The permission split
// ---------------------------------------------------------------------------

// TestEncryptIsNotDecrypt is the split the transit feature exists on top of. Collapsing
// it would mean every service that WRITES an encrypted column could also READ every
// encrypted column — the same mistake as collapsing ReadMetadata into GetSecret.
func TestEncryptIsNotDecrypt(t *testing.T) {
	fx := newFixture(t)
	fx.seedTransitKey("pii")
	ctx := context.Background()

	ingest := fx.caller(grantOn(permissions.PermEncrypt, transitKeyMRN))
	reader := fx.caller(grantOn(permissions.PermDecrypt, transitKeyMRN))

	sealed, err := fx.api.TransitEncrypt(ctx, ingest, TransitEncryptInput{
		Project: "billing-app", Name: "pii", Plaintext: []byte("card"),
	})
	require.NoError(t, err, "Encrypt alone is enough to seal")

	_, err = fx.api.TransitDecrypt(ctx, ingest, TransitDecryptInput{
		Project: "billing-app", Ciphertext: sealed.Ciphertext,
	})
	require.Error(t, err, "Encrypt must NOT be enough to open")
	assert.True(t, apperror.IsForbidden(err))

	_, err = fx.api.TransitEncrypt(ctx, reader, TransitEncryptInput{
		Project: "billing-app", Name: "pii", Plaintext: []byte("card"),
	})
	require.Error(t, err, "and Decrypt must not be enough to seal either")
	assert.True(t, apperror.IsForbidden(err))

	opened, err := fx.api.TransitDecrypt(ctx, reader, TransitDecryptInput{
		Project: "billing-app", Ciphertext: sealed.Ciphertext,
	})
	require.NoError(t, err)
	defer opened.Zero()

	// The refusals are audited under the actions they attempted, not as a generic
	// denial: an over-reaching principal is spotted from these rows.
	assert.Equal(t, 1, fx.repo.countAudit(store.ActionTransitDecrypt, store.OutcomeDenied))
	assert.Equal(t, 1, fx.repo.countAudit(store.ActionTransitEncrypt, store.OutcomeDenied))
}

// TestTheDataPlaneGrantsAreNotKeyManagement. A workload holding Encrypt and Decrypt on
// a key must not be able to retire, rotate, rename or delete it — raising the decrypt
// floor alone would make every stored token unreadable service-wide.
func TestTheDataPlaneGrantsAreNotKeyManagement(t *testing.T) {
	fx := newFixture(t)
	fx.seedTransitKey("pii")
	ctx := context.Background()

	workload := fx.caller(
		grantOn(permissions.PermEncrypt, transitKeyMRN),
		grantOn(permissions.PermDecrypt, transitKeyMRN),
	)

	_, err := fx.api.RotateTransitKey(ctx, workload, TransitKeyRef{Project: "billing-app", Name: "pii"})
	assert.True(t, apperror.IsForbidden(err), "rotate needs ManageTransitKey")

	_, err = fx.api.UpdateTransitKey(ctx, workload, UpdateTransitKeyInput{
		Project: "billing-app", Name: "pii", MinDecryptVersion: 1,
	})
	assert.True(t, apperror.IsForbidden(err), "raising the decrypt floor needs ManageTransitKey")

	assert.True(t, apperror.IsForbidden(
		fx.api.DeleteTransitKey(ctx, workload, TransitKeyRef{Project: "billing-app", Name: "pii"})),
		"deleting a key needs ManageTransitKey")

	_, err = fx.api.CreateTransitKey(ctx, workload, CreateTransitKeyInput{
		Project: "billing-app", Name: "cards",
	})
	assert.True(t, apperror.IsForbidden(err), "creating a key needs ManageTransitKey")
}

// TestDecryptIsAuthorizedAgainstTheKeyTheTokenNames.
//
// THIS IS THE BUG THE MRN DERIVATION EXISTS TO PREVENT. If a decrypt were authorized
// against the project's transit collection, a grant written for one key would open every
// ciphertext in the project — which is the entire point of having per-key grants. The
// check names the key the token names, and the store then resolves that same name inside
// the caller's own tenant and project, so the key checked is the key opened.
func TestDecryptIsAuthorizedAgainstTheKeyTheTokenNames(t *testing.T) {
	fx := newFixture(t)
	fx.seedTransitKey("pii")
	fx.seedTransitKey("cards")
	ctx := context.Background()

	cardsToken, err := fx.api.TransitEncrypt(ctx, fx.admin(), TransitEncryptInput{
		Project: "billing-app", Name: "cards", Plaintext: []byte("the-card"),
	})
	require.NoError(t, err)

	piiOnly := fx.caller(grantOn(permissions.PermDecrypt, transitKeyMRN))
	_, err = fx.api.TransitDecrypt(ctx, piiOnly, TransitDecryptInput{
		Project: "billing-app", Ciphertext: cardsToken.Ciphertext,
	})
	require.Error(t, err, "a grant on transit/pii must not open a transit/cards token")
	assert.True(t, apperror.IsForbidden(err))
	assert.Contains(t, err.Error(), "mrn:secret:acme:billing-app:transit/cards",
		"the refusal names the key the TOKEN asked for, so an operator can see which grant is missing")

	// And the denial row is against the same key, not against the one the caller holds.
	var denied int
	for _, row := range fx.repo.auditRows() {
		if row.Action == store.ActionTransitDecrypt && row.Outcome == store.OutcomeDenied {
			denied++
			assert.Equal(t, "mrn:secret:acme:billing-app:transit/cards", row.ResourceMrn)
		}
	}
	assert.Equal(t, 1, denied)
}

// ---------------------------------------------------------------------------
// Tenant scoping
// ---------------------------------------------------------------------------

// TestTransitTenantScopingCannotBeWidenedByARequestParameter.
//
// The DTOs carry no tenant field, deliberately: the tenant comes from the resolved
// Caller and nothing a request body can say. So the only lever a caller has is the
// PROJECT and the KEY NAME — and this drives the case where both are identical in two
// tenants, which is the shape that would break if the tenant ever came from the payload.
//
// A token minted in the other tenant is presented while scoped to acme. It names the key
// "pii", acme has a key called "pii", and the decrypt must still fail: the store rebuilds
// the AAD from the ROW IT FOUND (bound to the tenant UUID and the key UUID), so
// authentication fails rather than opening the wrong key or reaching across the tenant
// boundary.
func TestTransitTenantScopingCannotBeWidenedByARequestParameter(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()
	fx.seedTransitKey("pii")

	// A second tenant with the SAME project slug and the SAME key name.
	other, err := fx.store.CreateTenant(ctx, store.CreateTenantInput{Name: "other", DisplayName: "Other"})
	require.NoError(t, err)
	_, err = fx.store.CreateProject(ctx, store.CreateProjectInput{
		TenantUUID: other.UUID, Slug: "billing-app", Name: "Billing",
	})
	require.NoError(t, err)
	otherCaller := Caller{
		Claims: &sdkauthz.Claims{
			Subject: "user-2", Kind: sdkauthz.ActorKindUser, Tenant: "other",
			Grants:         []sdkauthz.Grant{{Action: permissions.PermAdmin}},
			BlanketActions: permissions.BlanketActions(),
		},
		// A DISTINCT actor subject, so a trail assertion can tell the two apart.
		Actor:      audit.Actor{Subject: "user-2", Kind: store.ActorKindUser},
		TenantUUID: other.UUID,
		TenantName: other.Name,
	}
	_, err = fx.api.CreateTransitKey(ctx, otherCaller, CreateTransitKeyInput{
		Project: "billing-app", Name: "pii",
	})
	require.NoError(t, err)

	const otherSecret = "other-tenants-card"
	foreign, err := fx.api.TransitEncrypt(ctx, otherCaller, TransitEncryptInput{
		Project: "billing-app", Name: "pii", Plaintext: []byte(otherSecret),
	})
	require.NoError(t, err)

	opened, err := fx.api.TransitDecrypt(ctx, fx.admin(), TransitDecryptInput{
		Project: "billing-app", Ciphertext: foreign.Ciphertext,
	})
	require.Error(t, err, "a token from another tenant must not open here, however the request is addressed")
	assert.Nil(t, opened)
	assert.NotContains(t, err.Error(), otherSecret,
		"and the refusal must not quote the value it failed to recover")

	// The MRN the check used is in the CALLER's tenant, never the token's.
	for _, row := range fx.repo.auditRows() {
		if row.Action == store.ActionTransitDecrypt {
			assert.True(t, strings.HasPrefix(row.ResourceMrn, "mrn:secret:acme:"),
				"the audited MRN is built from the resolved caller's tenant, got %q", row.ResourceMrn)
		}
	}

	// And a listing is scoped the same way: acme sees one key, not two.
	keys, total, err := fx.api.ListTransitKeys(ctx, fx.admin(), ListTransitKeysInput{Project: "billing-app"})
	require.NoError(t, err)
	assert.EqualValues(t, 1, total)
	require.Len(t, keys, 1)
	assert.Equal(t, "pii", keys[0].Name)
}

// TestTransitListingsAndVersionsCarryNoMaterial. The store types have no material
// field, so this is a structural check rather than a filter — but it is worth pinning,
// because "the key never leaves the service" is transit's whole value proposition and a
// listing query that started selecting a material column would end it.
func TestTransitListingsAndVersionsCarryNoMaterial(t *testing.T) {
	fx := newFixture(t)
	fx.seedTransitKey("pii")
	ctx := context.Background()
	_, err := fx.api.RotateTransitKey(ctx, fx.admin(), TransitKeyRef{Project: "billing-app", Name: "pii"})
	require.NoError(t, err)

	keys, _, err := fx.api.ListTransitKeys(ctx, fx.admin(), ListTransitKeysInput{Project: "billing-app"})
	require.NoError(t, err)
	versions, total, err := fx.api.ListTransitKeyVersions(ctx, fx.admin(), ListTransitKeyVersionsInput{
		Project: "billing-app", Name: "pii",
	})
	require.NoError(t, err)
	assert.EqualValues(t, 2, total, "a rotation keeps the old version, so both decrypt")

	raw, err := json.Marshal(map[string]any{"keys": keys, "versions": versions})
	require.NoError(t, err)
	for _, forbidden := range []string{"material", "ciphertext", "dek"} {
		assert.NotContains(t, strings.ToLower(string(raw)), forbidden,
			"a transit listing must not carry a field named %q", forbidden)
	}
}

// TestARotatedKeyStillOpensItsOldTokens. A rotation that could no longer read its own
// history is not a rotation, it is data loss with a reassuring name — and the api layer
// must not be the thing that breaks it.
func TestARotatedKeyStillOpensItsOldTokens(t *testing.T) {
	fx := newFixture(t)
	fx.seedTransitKey("pii")
	ctx := context.Background()

	old, err := fx.api.TransitEncrypt(ctx, fx.admin(), TransitEncryptInput{
		Project: "billing-app", Name: "pii", Plaintext: []byte("sealed-under-v1"),
	})
	require.NoError(t, err)
	require.EqualValues(t, 1, old.KeyVersion)

	rotated, err := fx.api.RotateTransitKey(ctx, fx.admin(), TransitKeyRef{Project: "billing-app", Name: "pii"})
	require.NoError(t, err)
	assert.EqualValues(t, 2, rotated.CurrentVersion)

	opened, err := fx.api.TransitDecrypt(ctx, fx.admin(), TransitDecryptInput{
		Project: "billing-app", Ciphertext: old.Ciphertext,
	})
	require.NoError(t, err)
	defer opened.Zero()
	assert.Equal(t, "sealed-under-v1", string(opened.Plaintext.Bytes()))
	assert.EqualValues(t, 1, opened.KeyVersion, "it opened under the version that sealed it")
}
