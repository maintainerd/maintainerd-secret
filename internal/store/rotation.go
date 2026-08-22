package store

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/maintainerd/secret/internal/platform/apperror"
	"github.com/maintainerd/secret/internal/rotation"
	"github.com/maintainerd/secret/internal/storage"
)

// DueRotation is one secret the scheduler should rotate, with everything the write
// path needs to address it — and nothing else. No ciphertext, no plaintext: a
// scheduled rotation generates a NEW value, so it never reads the current one.
type DueRotation struct {
	Ref        SecretRef
	SecretUUID uuid.UUID
	MRN        string
	Version    int32
	Policy     rotation.Policy
	// DueAt is when this secret became due, carried through so the audit row and
	// the log line can say how late the rotation is rather than merely that it ran.
	DueAt time.Time
}

// DueRotations returns the secrets whose rotation policy says they are overdue.
//
// The query returns every ENABLED policy and the due-ness arithmetic happens here,
// for the reason documented on the query itself: parsing a Go duration inside
// Postgres is a worse failure mode than paging a few extra rows.
//
// A secret whose policy does not parse is SKIPPED WITH A WARNING rather than failing
// the pass. One malformed policy must not stop every other secret in the store from
// rotating — but it must be visible, because the operator believes that credential
// is on a schedule and it is not. (The same malformed policy is rejected at write
// time; a row that has one arrived by migration, restore, or direct SQL.)
func (s *Service) DueRotations(ctx context.Context, now time.Time, limit int) ([]DueRotation, error) {
	if limit < 1 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	// The scan is over enabled policies, of which there are far fewer than secrets,
	// and it pages until it has `limit` DUE items or runs out of candidates.
	const pageSize = 200
	out := make([]DueRotation, 0, limit)
	for offset := 0; len(out) < limit; offset += pageSize {
		rows, err := s.repo.ListSecretsWithRotationPolicy(ctx, storage.ListSecretsWithRotationPolicyParams{
			RowLimit:  pageSize,
			RowOffset: int32(offset),
		})
		if err != nil {
			return nil, apperror.NewInternal("list rotation policies", err)
		}
		if len(rows) == 0 {
			break
		}
		for _, r := range rows {
			policy, perr := rotation.ParsePolicy(decodeObject(r.RotationPolicy))
			if perr != nil {
				slog.Warn("rotation: skipping a secret whose rotation policy is malformed",
					"mrn", mrn(r.MrnTenant, r.MrnProject, r.MrnResourcePath), "error", perr)
				continue
			}
			if !policy.Enabled {
				continue
			}
			// A secret that has never rotated is measured from its creation, so
			// attaching a policy to an existing secret actually fires.
			last := r.CreatedAt
			if r.RotatedAt.Valid {
				last = r.RotatedAt.Time
			}
			due, derr := policy.NextDue(last)
			if derr != nil {
				slog.Warn("rotation: skipping a secret whose rotation interval is unusable",
					"mrn", mrn(r.MrnTenant, r.MrnProject, r.MrnResourcePath), "error", derr)
				continue
			}
			if due.After(now) {
				continue
			}
			out = append(out, DueRotation{
				Ref: SecretRef{
					TenantUUID:  r.TenantUuid,
					Project:     r.ProjectSlug,
					Environment: r.EnvironmentSlug,
					FolderPath:  r.FolderPath,
					Key:         r.Key,
				},
				SecretUUID: r.SecretUuid,
				MRN:        mrn(r.MrnTenant, r.MrnProject, r.MrnResourcePath),
				Version:    r.CurrentVersion,
				Policy:     policy,
				DueAt:      due,
			})
			if len(out) >= limit {
				break
			}
		}
		if len(rows) < pageSize {
			break
		}
	}
	return out, nil
}

// SetRotationPolicy attaches (or clears) a rotation policy without touching the
// value or the rest of the metadata.
//
// It is separate from UpdateSecretMeta for the same reason UpdateSecretMeta is
// separate from PutSecret: a caller changing a schedule should not have to restate
// the description and tags, and a caller editing a description should not be able to
// silently disable rotation by omitting the policy.
func (s *Service) SetRotationPolicy(ctx context.Context, ref SecretRef, policy rotation.Policy) (*SecretMeta, error) {
	if policy.Enabled {
		if _, err := policy.IntervalDuration(); err != nil {
			return nil, apperror.NewValidation(err.Error())
		}
		if err := policy.Generator.Validate(true); err != nil {
			return nil, apperror.NewValidation(err.Error())
		}
	}
	addr, err := s.resolveAddress(ctx, s.repo, ref)
	if err != nil {
		return nil, err
	}
	row, err := s.repo.GetSecretByAddress(ctx, storage.GetSecretByAddressParams{
		TenantID:      addr.tenant.TenantID,
		EnvironmentID: addr.environment.EnvironmentID,
		FolderID:      addr.folder.FolderID,
		Key:           addr.key,
	})
	if err != nil {
		return nil, mapReadError(err, "secret")
	}
	rotationJSON, err := encodeObject(policy.Map())
	if err != nil {
		return nil, apperror.NewInternal("encode rotation policy", err)
	}
	// The remaining metadata is carried through unchanged from the row that was just
	// read, because UpdateSecretMeta is a full rewrite. Reading first and re-writing
	// what was read is what makes this a policy-only edit.
	tags, err := encodeTags(decodeTags(row.Tags))
	if err != nil {
		return nil, apperror.NewInternal("encode secret tags", err)
	}
	meta, err := encodeObject(decodeObject(row.Metadata))
	if err != nil {
		return nil, apperror.NewInternal("encode secret metadata", err)
	}
	updated, err := s.repo.UpdateSecretMeta(ctx, storage.UpdateSecretMetaParams{
		Description:    row.Description,
		Tags:           tags,
		KeepVersions:   row.KeepVersions,
		RotationPolicy: rotationJSON,
		ExpiresAt:      row.ExpiresAt,
		Metadata:       meta,
		TenantID:       addr.tenant.TenantID,
		SecretUuid:     row.SecretUuid,
	})
	if err != nil {
		return nil, mapReadError(err, "secret")
	}
	out := secretRowToMeta(updated, addr.folder.Path, s.policy.KeepVersions)
	return &out, nil
}
