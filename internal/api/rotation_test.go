package api

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/maintainerd/secret/internal/platform/apperror"
	"github.com/maintainerd/secret/internal/platform/authz"
	"github.com/maintainerd/secret/internal/rotation"
	"github.com/maintainerd/secret/internal/store"
)

// Rotation, rollback and the change notifications they emit.

// TestRotateSecretWritesANewVersionWithoutReturningIt is the permission shape that
// makes rotation safe to automate: the rotator replaces the credential and never sees
// it, so a rotate grant is not a read grant wearing a hat.
func TestRotateSecretWritesANewVersionWithoutReturningIt(t *testing.T) {
	fx := newFixture(t)
	fx.seed("prod", "/db", "PASSWORD", "original")

	rotatorOnly := fx.caller(authz.Grant{Action: authz.PermRotateSecret})
	result, err := fx.api.RotateSecret(context.Background(), rotatorOnly, RotateSecretInput{
		Address: addr("prod", "/db", "PASSWORD"),
	})
	require.NoError(t, err)
	assert.EqualValues(t, 2, result.Version)
	assert.False(t, result.Unchanged)

	// The rotated value is not in the result — there is nowhere for it to be.
	admin := fx.admin()
	revealed, err := fx.api.Reveal(context.Background(), admin, addr("prod", "/db", "PASSWORD"), 0)
	require.NoError(t, err)
	defer revealed.Secret.Zero()
	assert.NotEqual(t, "original", string(revealed.Secret.Value.Bytes()))
	assert.Len(t, revealed.Secret.Value.Bytes(), rotation.DefaultLength)

	assert.Equal(t, 1, fx.repo.countAudit(store.ActionRotate, store.OutcomeSuccess))
}

// TestRotateRequiresItsOwnGrant: a write grant is not a rotate grant. They are split
// because rotation is what you hand to an automated principal.
func TestRotateRequiresItsOwnGrant(t *testing.T) {
	fx := newFixture(t)
	fx.seed("prod", "/db", "PASSWORD", "original")

	writerOnly := fx.caller(authz.Grant{Action: authz.PermPutSecret})
	_, err := fx.api.RotateSecret(context.Background(), writerOnly, RotateSecretInput{
		Address: addr("prod", "/db", "PASSWORD"),
	})
	require.Error(t, err)
	assert.True(t, apperror.IsForbidden(err))
}

// TestRotateRefusesToCreateASecret: a rotation creates a VERSION, not a secret. A
// rotate that created one would let a rotate grant write brand-new credentials at any
// address it names.
func TestRotateRefusesToCreateASecret(t *testing.T) {
	fx := newFixture(t)
	_, err := fx.api.RotateSecret(context.Background(), fx.admin(), RotateSecretInput{
		Address: addr("prod", "/db", "NOT_THERE"),
	})
	require.Error(t, err)
	assert.True(t, apperror.IsNotFound(err))
}

// TestRotateWithASuppliedValue covers the two-sided case: the caller rolled the
// upstream credential and hands the result here.
func TestRotateWithASuppliedValue(t *testing.T) {
	fx := newFixture(t)
	fx.seed("prod", "/db", "PASSWORD", "original")

	_, err := fx.api.RotateSecret(context.Background(), fx.admin(), RotateSecretInput{
		Address:   addr("prod", "/db", "PASSWORD"),
		Generator: rotation.Spec{Type: rotation.GeneratorSupplied, Value: "rolled-upstream"},
	})
	require.NoError(t, err)

	revealed, err := fx.api.Reveal(context.Background(), fx.admin(), addr("prod", "/db", "PASSWORD"), 0)
	require.NoError(t, err)
	defer revealed.Secret.Zero()
	assert.Equal(t, "rolled-upstream", string(revealed.Secret.Value.Bytes()))
}

// TestRollbackWritesANewVersionAndNeverMutatesHistory is the append-only guarantee at
// the API level: after a rollback there are three versions, and version 1 still holds
// what it always held.
func TestRollbackWritesANewVersionAndNeverMutatesHistory(t *testing.T) {
	fx := newFixture(t)
	fx.seed("prod", "/db", "PASSWORD", "v1-value")
	fx.seed("prod", "/db", "PASSWORD", "v2-value")

	result, err := fx.api.Rollback(context.Background(), fx.admin(), addr("prod", "/db", "PASSWORD"), 1)
	require.NoError(t, err)
	assert.EqualValues(t, 3, result.Version, "a rollback appends; it does not rewind")

	current, err := fx.api.Reveal(context.Background(), fx.admin(), addr("prod", "/db", "PASSWORD"), 0)
	require.NoError(t, err)
	defer current.Secret.Zero()
	assert.Equal(t, "v1-value", string(current.Secret.Value.Bytes()))

	v2, err := fx.api.Reveal(context.Background(), fx.admin(), addr("prod", "/db", "PASSWORD"), 2)
	require.NoError(t, err)
	defer v2.Secret.Zero()
	assert.Equal(t, "v2-value", string(v2.Secret.Value.Bytes()), "history is untouched")

	assert.Equal(t, 1, fx.repo.countAudit(store.ActionRollback, store.OutcomeSuccess))
}

// TestRollbackRequiresRevealAsWellAsWrite: a rollback republishes a value the caller
// did not supply, so a write-only principal could otherwise use it as a read
// primitive.
func TestRollbackRequiresRevealAsWellAsWrite(t *testing.T) {
	fx := newFixture(t)
	fx.seed("prod", "/db", "PASSWORD", "v1")
	fx.seed("prod", "/db", "PASSWORD", "v2")

	writerOnly := fx.caller(authz.Grant{Action: authz.PermPutSecret})
	_, err := fx.api.Rollback(context.Background(), writerOnly, addr("prod", "/db", "PASSWORD"), 1)
	require.Error(t, err)
	assert.True(t, apperror.IsForbidden(err))
}

// TestUnchangedWriteDoesNotNotify: the checksum no-op exists so a re-entrant
// reconciler does not inflate version history; announcing it anyway would wake every
// subscriber on every pass, which is the same storm by another route.
func TestUnchangedWriteDoesNotNotify(t *testing.T) {
	fx := newFixture(t)
	fx.seed("prod", "/db", "PASSWORD", "same-value")
	before := len(fx.notes.all())

	result, err := fx.api.PutSecret(context.Background(), fx.admin(), PutSecretInput{
		Address: addr("prod", "/db", "PASSWORD"),
		Value:   []byte("same-value"),
	})
	require.NoError(t, err)
	assert.True(t, result.Unchanged)
	assert.Len(t, fx.notes.all(), before, "an unchanged write announces nothing")
}

// TestChangeAndRotationNotifyWithNoValue checks the notification payload the api layer
// hands the webhook notifier: an MRN and a version, and structurally nowhere to put a
// credential.
func TestChangeAndRotationNotifyWithNoValue(t *testing.T) {
	fx := newFixture(t)
	fx.seed("prod", "/db", "PASSWORD", "first")

	notes := fx.notes.all()
	require.Len(t, notes, 1)
	assert.Equal(t, store.WebhookEventSecretChanged, notes[0].Event)
	assert.Equal(t, "mrn:secret:acme:billing-app:secret/prod/db/PASSWORD", notes[0].ResourceMRN)
	assert.EqualValues(t, 1, notes[0].Version)

	_, err := fx.api.RotateSecret(context.Background(), fx.admin(), RotateSecretInput{
		Address: addr("prod", "/db", "PASSWORD"),
	})
	require.NoError(t, err)
	notes = fx.notes.all()
	require.Len(t, notes, 2)
	assert.Equal(t, store.WebhookEventSecretRotated, notes[1].Event)
	assert.EqualValues(t, 2, notes[1].Version)
}

// TestScheduledRotationRotatesDueSecretsAndAuditsThem drives the engine the
// background loop calls, without a loop and without a clock.
func TestScheduledRotationRotatesDueSecretsAndAuditsThem(t *testing.T) {
	fx := newFixture(t)
	fx.seed("prod", "/db", "PASSWORD", "original")

	// A one-hour interval on a secret created "now" is not yet due...
	_, err := fx.api.SetRotationPolicy(context.Background(), fx.admin(), addr("prod", "/db", "PASSWORD"),
		rotation.Policy{Enabled: true, Interval: "1h"})
	require.NoError(t, err)

	result, err := fx.api.RotateDueSecrets(context.Background(), 10)
	require.NoError(t, err)
	assert.Equal(t, 0, result.Due, "a freshly created secret is not immediately due")

	// ...but backdating the creation makes it so. The store reads rotated_at, falling
	// back to created_at, so a policy attached to an existing secret actually fires.
	for _, s := range fx.repo.secrets {
		s.CreatedAt = s.CreatedAt.Add(-2 * time.Hour)
		s.RotatedAt.Valid = false
	}

	result, err = fx.api.RotateDueSecrets(context.Background(), 10)
	require.NoError(t, err)
	assert.Equal(t, 1, result.Due)
	assert.Equal(t, 1, result.Rotated)
	assert.Equal(t, 0, result.Failed)

	assert.Equal(t, 1, fx.repo.countAudit(store.ActionRotationScheduled, store.OutcomeSuccess))
	for _, row := range fx.repo.auditRows() {
		if row.Action == store.ActionRotationScheduled {
			assert.Equal(t, "maintainerd-secret/rotator", row.ActorSubject,
				"a scheduled rotation is attributed to the scheduler, never to a human")
		}
	}
}

// TestRotationPolicyRejectsAStoredGeneratorValue: a policy lives in readable
// metadata, so a value in one would be a credential outside encrypted custody.
func TestRotationPolicyRejectsAStoredGeneratorValue(t *testing.T) {
	fx := newFixture(t)
	fx.seed("prod", "/db", "PASSWORD", "original")

	_, err := fx.api.PutSecret(context.Background(), fx.admin(), PutSecretInput{
		Address: addr("prod", "/", "OTHER"),
		Value:   []byte("v"),
		RotationPolicy: map[string]any{
			"enabled":   true,
			"interval":  "24h",
			"generator": map[string]any{"type": "supplied", "value": "hunter2"},
		},
	})
	require.Error(t, err)
	assert.True(t, apperror.IsValidation(err))
	assert.Contains(t, err.Error(), "must not contain a generator value")
}

// TestScheduledPolicyCannotUseTheSuppliedGenerator: a scheduler has nobody to ask, so
// a policy that requires a supplied value would either stall or write a placeholder
// over a live credential.
func TestScheduledPolicyCannotUseTheSuppliedGenerator(t *testing.T) {
	fx := newFixture(t)
	fx.seed("prod", "/db", "PASSWORD", "original")

	_, err := fx.api.SetRotationPolicy(context.Background(), fx.admin(), addr("prod", "/db", "PASSWORD"),
		rotation.Policy{
			Enabled:   true,
			Interval:  "24h",
			Generator: rotation.Spec{Type: rotation.GeneratorSupplied, Value: "x"},
		})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "scheduled rotation policy")
}
