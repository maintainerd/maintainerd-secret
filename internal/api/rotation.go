package api

import (
	"context"
	"log/slog"
	"time"

	"github.com/maintainerd/secret/internal/audit"
	"github.com/maintainerd/secret/internal/crypto"
	"github.com/maintainerd/secret/internal/platform/apperror"
	"github.com/maintainerd/secret/internal/platform/authz"
	"github.com/maintainerd/secret/internal/rotation"
	"github.com/maintainerd/secret/internal/store"
)

// Rotation: on demand, and on a schedule.
//
// A ROTATION IS AN ORDINARY WRITE WITH A DIFFERENT NAME, and that is the design.
// It creates a version through the same path a put does — same envelope, same
// append-only history, same retention — so there is no second write path with its own
// bugs. What rotation adds is (a) a generator, so the new value need not be supplied,
// (b) a schedule, and (c) a distinct action in the audit trail, because "the
// credential was replaced on schedule" and "somebody set a new value" are different
// events.
//
// A ROTATION IS NOT A ROLL OF THE UPSTREAM CREDENTIAL. This service can generate a
// new value and store it; it cannot tell PostgreSQL about it. Two-sided rotation is
// the caller's job, which is why the `supplied` generator exists: the caller rotates
// the upstream credential and hands the result here. A SCHEDULED policy may not use
// it (nobody is there to supply a value when the schedule fires), so an automated
// rotation is only correct for a credential this service is the source of truth for —
// an API token a consumer reads, not a password a database also holds.

// RotateSecretInput is a manual rotation.
type RotateSecretInput struct {
	Address SecretAddress
	// Generator says how to produce the new value. The zero value means a random
	// alphanumeric string of the default length.
	Generator rotation.Spec
}

// RotateSecret rotates a value now.
//
// It requires secret:RotateSecret — NOT secret:PutSecret. The two are separate grants
// because rotation is the operation you want to hand to an automated principal: a
// rotator needs to replace credentials forever and needs no ability to write an
// arbitrary chosen value anywhere. Handing it PutSecret to do a rotation would give
// it exactly that.
//
// It does NOT require secret:GetSecret, and the new value is NOT returned in the
// rotate response unless the caller supplied it. A rotation is "make this credential
// different"; reading the result is a reveal, with its own grant and its own audit
// row. A rotate that returned the value would be a reveal with a weaker permission.
func (s *Service) RotateSecret(ctx context.Context, c Caller, in RotateSecretInput) (*store.PutResult, error) {
	if err := validate(in); err != nil {
		return nil, err
	}
	ref := in.Address.ref(c)
	resourceMRN, err := s.store.SecretMRN(ctx, ref)
	if err != nil {
		return nil, err
	}
	if err := s.guard(ctx, c, authz.PermRotateSecret, store.ActionRotate, resourceMRN); err != nil {
		return nil, err
	}
	// Validate again on the local copy: the DTO rule proved the spec is usable, and
	// this call is what NORMALIZES it (the zero value becomes a random alphanumeric of
	// the default length) before Generate reads it.
	spec := in.Generator
	if err := spec.Validate(false); err != nil {
		return nil, apperror.NewValidation(err.Error())
	}
	// The secret must already exist: a rotation creates a version, not a secret. A
	// rotate that created one would let a RotateSecret grant write brand-new
	// credentials at any address it names.
	if _, err := s.store.DescribeSecret(ctx, ref); err != nil {
		s.recordFailure(ctx, c, store.ActionRotate, resourceMRN, err)
		return nil, err
	}

	value, err := spec.Generate()
	if err != nil {
		s.recordFailure(ctx, c, store.ActionRotate, resourceMRN, err)
		return nil, apperror.NewInternal("generate rotated value", err)
	}
	defer crypto.Zero(value)

	result, err := s.store.PutSecret(ctx, store.PutSecretInput{Ref: ref, Value: value})
	if err != nil {
		s.recordFailure(ctx, c, store.ActionRotate, resourceMRN, err)
		return nil, err
	}
	if err := s.recordSuccess(ctx, c, audit.Event{
		Action:      store.ActionRotate,
		ResourceMRN: resourceMRN,
		SecretUUID:  &result.SecretUUID,
		Version:     int32Ptr(result.Version),
		Metadata: map[string]any{
			"generator": spec.Type,
			"scheduled": false,
			"unchanged": result.Unchanged,
		},
	}); err != nil {
		return nil, err
	}
	if !result.Unchanged {
		s.notify(ctx, c, in.Address.Project, store.WebhookEventSecretRotated, resourceMRN, result.Version)
	}
	return result, nil
}

// SetRotationPolicy attaches, edits or disables a secret's rotation schedule.
//
// It requires secret:ManageRotation rather than PutSecret or RotateSecret: deciding
// that a credential rotates every 30 days is an administrative act, distinct both
// from writing a value and from performing a rotation.
func (s *Service) SetRotationPolicy(ctx context.Context, c Caller, addr SecretAddress, policy rotation.Policy) (*store.SecretMeta, error) {
	if err := validate(SetRotationPolicyInput{Address: addr, Policy: policy}); err != nil {
		return nil, err
	}
	ref := addr.ref(c)
	resourceMRN, err := s.store.SecretMRN(ctx, ref)
	if err != nil {
		return nil, err
	}
	if err := s.guard(ctx, c, authz.PermManageRotation, store.ActionRotationPolicySet, resourceMRN); err != nil {
		return nil, err
	}
	meta, err := s.store.SetRotationPolicy(ctx, ref, policy)
	if err != nil {
		s.recordFailure(ctx, c, store.ActionRotationPolicySet, resourceMRN, err)
		return nil, err
	}
	if err := s.recordSuccess(ctx, c, audit.Event{
		Action:      store.ActionRotationPolicySet,
		ResourceMRN: resourceMRN,
		SecretUUID:  &meta.UUID,
		Metadata:    map[string]any{"enabled": policy.Enabled, "interval": policy.Interval},
	}); err != nil {
		return nil, err
	}
	return meta, nil
}

// RotationResult reports one pass of the scheduled rotator.
type RotationResult struct {
	Due     int
	Rotated int
	Failed  int
	Skipped int
}

// scheduledActor is the identity a scheduled rotation is recorded under.
//
// It is a SERVICE actor with a fixed subject rather than a borrowed operator
// identity, because nobody asked for this rotation — the schedule did. Attributing it
// to the operator who last set the policy would make the trail say a human replaced a
// credential at 03:00, which is the kind of false attribution an incident review acts
// on.
var scheduledActor = audit.Actor{
	Subject: "maintainerd-secret/rotator",
	Kind:    store.ActorKindService,
}

// RotateDueSecrets rotates every secret whose policy says it is overdue.
//
// IT PERFORMS NO PERMISSION CHECK, and that is correct rather than an omission: there
// is no caller. The scheduler is the service acting on a policy an authorized
// principal already installed (SetRotationPolicy is the gated operation), so the
// authorization decision was made then. What it does do — unconditionally — is write
// an audit row per rotation, attributed to the rotator itself.
//
// A failure on one secret NEVER stops the pass. A single unreadable root key, a
// conflicting concurrent write, or a malformed policy must not stop every other
// credential in the store from rotating.
func (s *Service) RotateDueSecrets(ctx context.Context, limit int) (RotationResult, error) {
	var out RotationResult
	if s.auditor == nil {
		return out, audit.ErrNoAuditor
	}
	due, err := s.store.DueRotations(ctx, time.Now(), limit)
	if err != nil {
		return out, err
	}
	out.Due = len(due)

	for _, item := range due {
		value, gerr := item.Policy.Generator.Generate()
		if gerr != nil {
			out.Skipped++
			slog.Warn("rotation: skipping a secret whose generator is unusable",
				"mrn", item.MRN, "error", gerr)
			continue
		}
		result, perr := s.store.PutSecret(ctx, store.PutSecretInput{Ref: item.Ref, Value: value})
		crypto.Zero(value)
		if perr != nil {
			out.Failed++
			slog.Warn("rotation: scheduled rotation failed", "mrn", item.MRN, "error", perr)
			// The failure is recorded under the rotator's identity so an operator can
			// see that the schedule fired and did not land — the most likely way for a
			// credential to quietly stop rotating.
			s.auditor.RecordError(ctx, scheduledActor, audit.Event{
				TenantUUID:  &item.Ref.TenantUUID,
				Action:      store.ActionRotationScheduled,
				ResourceMRN: item.MRN,
				SecretUUID:  &item.SecretUUID,
				Reason:      redactedReason(perr),
			})
			continue
		}
		out.Rotated++
		lateBy := time.Since(item.DueAt).Truncate(time.Second)
		if aerr := s.auditor.Record(ctx, scheduledActor, audit.Event{
			TenantUUID:  &item.Ref.TenantUUID,
			Action:      store.ActionRotationScheduled,
			ResourceMRN: item.MRN,
			SecretUUID:  &result.SecretUUID,
			Version:     int32Ptr(result.Version),
			Outcome:     store.OutcomeSuccess,
			Metadata: map[string]any{
				"generator": item.Policy.Generator.Type,
				"scheduled": true,
				"interval":  item.Policy.Interval,
				"late_by":   lateBy.String(),
				"due_at":    item.DueAt.UTC().Format(time.RFC3339),
			},
		}); aerr != nil {
			// The rotation has already landed; the version exists. Reporting it as a
			// failure would be a lie, so this is logged loudly instead — a store that
			// cannot write audit rows is an operational alarm, not a rotation bug.
			slog.Error("rotation: rotated a secret but could not record the audit row",
				"mrn", item.MRN, "version", result.Version, "error", aerr)
		}
		if s.notifier != nil && !result.Unchanged {
			s.notifier.Notify(ctx, Notification{
				TenantUUID:  item.Ref.TenantUUID,
				Project:     item.Ref.Project,
				Event:       store.WebhookEventSecretRotated,
				ResourceMRN: item.MRN,
				Version:     result.Version,
				Actor:       scheduledActor,
			})
		}
	}
	return out, nil
}
