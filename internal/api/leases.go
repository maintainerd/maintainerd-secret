package api

import (
	"context"
	"errors"
	"time"

	"github.com/maintainerd/secret/internal/audit"
	"github.com/maintainerd/secret/internal/lease"
	"github.com/maintainerd/secret/internal/platform/apperror"
	"github.com/maintainerd/secret/internal/platform/permissions"
	"github.com/maintainerd/secret/internal/store"
)

// Read leases on static secrets: the policy surfaces, and the enforcement hook the
// reveal path calls.
//
// THE PERMISSION SPLIT IS THE THING TO GET RIGHT HERE. Reading a leased secret still
// requires secret:GetSecret and nothing more — a lease is not authorization, so
// demanding secret:ManageLease to read would make every leased secret unreadable by
// exactly the consumers the lease was written for. secret:ManageLease is the
// ADMINISTRATIVE grant: setting the policy, clearing it, and cutting outstanding
// leases off. Those surfaces are user-only, because deciding a credential may be read
// ten times an hour is a policy call and a workload making it is the signal rather than
// the workflow.

// SetSecretLeasePolicy sets or clears a secret's lease policy.
//
// Requires secret:ManageLease against the SECRET's own MRN — not the folder's, and not
// the tenant's. The policy governs reads of one value, so the grant that changes it has
// to name that value: a policy check at scope would let a principal with folder-wide
// management loosen the cap on the one credential inside it that mattered.
func (s *Service) SetSecretLeasePolicy(ctx context.Context, c Caller, in SetSecretLeasePolicyInput) (*store.SecretMeta, error) {
	if err := validate(in); err != nil {
		return nil, err
	}
	resourceMRN, err := s.store.SecretMRN(ctx, in.Address.ref(c))
	if err != nil {
		return nil, err
	}
	if err := s.guard(ctx, c, permissions.PermManageLease, store.ActionLeasePolicySet, resourceMRN); err != nil {
		return nil, err
	}
	meta, err := s.store.SetSecretLeasePolicy(ctx, store.SetSecretLeasePolicyInput{
		Ref: in.Address.ref(c),
		Policy: store.SecretLeasePolicy{
			TTLSeconds:    in.TTLSeconds,
			MaxTTLSeconds: in.MaxTTLSeconds,
			MaxReads:      in.MaxReads,
		},
	})
	if err != nil {
		s.recordFailure(ctx, c, store.ActionLeasePolicySet, resourceMRN, err)
		return nil, err
	}
	// The audit row records the POLICY, which is metadata about how the value may be
	// read and never the value. "The cap on the production database password was raised
	// from 10 to 10000" is precisely the change an incident review needs to see, and it
	// is unreconstructable from anything else.
	if err := s.recordSuccess(ctx, c, audit.Event{
		Action:      store.ActionLeasePolicySet,
		ResourceMRN: resourceMRN,
		SecretUUID:  &meta.UUID,
		Metadata:    leasePolicyMetadata(in),
	}); err != nil {
		return nil, err
	}
	return meta, nil
}

// leasePolicyMetadata renders the policy for the audit row. Nils are rendered
// explicitly as null-equivalents rather than omitted, because "the cap was removed" and
// "the cap was not mentioned" are the two states this surface exists to distinguish and
// an omitted key would collapse them.
func leasePolicyMetadata(in SetSecretLeasePolicyInput) map[string]any {
	meta := map[string]any{"policy_removed": in.TTLSeconds == nil}
	if in.TTLSeconds != nil {
		meta["lease_ttl_seconds"] = *in.TTLSeconds
	}
	if in.MaxTTLSeconds != nil {
		meta["lease_max_ttl_seconds"] = *in.MaxTTLSeconds
	}
	if in.MaxReads != nil {
		meta["lease_max_reads"] = *in.MaxReads
	}
	return meta
}

// GetSecretLeasePolicy reads a secret's lease policy.
//
// Requires secret:ReadMetadata, not secret:ManageLease: a policy is metadata about how
// a value may be read, and a consumer that can see "this secret allows 10 reads an
// hour" can plan around it instead of discovering the cap as an unexplained refusal
// mid-incident. It discloses nothing about the value.
func (s *Service) GetSecretLeasePolicy(ctx context.Context, c Caller, in SecretLeaseRef) (store.SecretLeasePolicy, error) {
	if err := validate(in); err != nil {
		return store.SecretLeasePolicy{}, err
	}
	resourceMRN, err := s.store.SecretMRN(ctx, in.Address.ref(c))
	if err != nil {
		return store.SecretLeasePolicy{}, err
	}
	if err := s.guard(ctx, c, permissions.PermReadMetadata, store.ActionRead, resourceMRN); err != nil {
		return store.SecretLeasePolicy{}, err
	}
	policy, err := s.store.GetSecretLeasePolicy(ctx, in.Address.ref(c))
	if err != nil {
		s.recordFailure(ctx, c, store.ActionRead, resourceMRN, err)
		return store.SecretLeasePolicy{}, err
	}
	if err := s.recordSuccess(ctx, c, audit.Event{
		Action:      store.ActionRead,
		ResourceMRN: resourceMRN,
		Metadata:    map[string]any{"read": "lease_policy", "leased": policy.Enabled()},
	}); err != nil {
		return store.SecretLeasePolicy{}, err
	}
	return policy, nil
}

// ListSecretLeases pages a secret's issued leases, newest first.
//
// Requires secret:ReadMetadata. The rows are metadata — who holds a lease, until when,
// how much of their allowance is left — and that IS the answer to "who is currently
// able to read the production database password", which a static secret cannot give at
// all. No value and no ciphertext is involved.
func (s *Service) ListSecretLeases(ctx context.Context, c Caller, in ListSecretLeasesInput) ([]store.SecretLease, int64, error) {
	if err := validate(in); err != nil {
		return nil, 0, err
	}
	page, limit := in.Pagination.resolved()
	resourceMRN, err := s.store.SecretMRN(ctx, in.Address.ref(c))
	if err != nil {
		return nil, 0, err
	}
	if err := s.guard(ctx, c, permissions.PermReadMetadata, store.ActionRead, resourceMRN); err != nil {
		return nil, 0, err
	}
	leases, total, err := s.store.ListSecretLeases(ctx, in.Address.ref(c), page, limit)
	if err != nil {
		s.recordFailure(ctx, c, store.ActionRead, resourceMRN, err)
		return nil, 0, err
	}
	if err := s.recordSuccess(ctx, c, audit.Event{
		Action:      store.ActionRead,
		ResourceMRN: resourceMRN,
		Metadata:    map[string]any{"read": "leases", "returned": len(leases), "total": total},
	}); err != nil {
		return nil, 0, err
	}
	return leases, total, nil
}

// RevokeSecretLeases closes every outstanding lease on one secret.
//
// The operator's "cut this consumer off now" control, and it requires
// secret:ManageLease and a user principal. It does NOT stop the next read from opening
// a fresh lease — that would be a different operation (removing the policy, or
// revoking the grant) — and saying so plainly matters, because an operator reaching for
// this during an incident needs to know it resets allowances rather than locking the
// secret.
func (s *Service) RevokeSecretLeases(ctx context.Context, c Caller, in SecretLeaseRef) (int64, error) {
	if err := validate(in); err != nil {
		return 0, err
	}
	resourceMRN, err := s.store.SecretMRN(ctx, in.Address.ref(c))
	if err != nil {
		return 0, err
	}
	if err := s.guard(ctx, c, permissions.PermManageLease, store.ActionLeaseRevoke, resourceMRN); err != nil {
		return 0, err
	}
	n, err := s.store.RevokeSecretLeases(ctx, in.Address.ref(c))
	if err != nil {
		s.recordFailure(ctx, c, store.ActionLeaseRevoke, resourceMRN, err)
		return 0, err
	}
	if err := s.recordSuccess(ctx, c, audit.Event{
		Action:      store.ActionLeaseRevoke,
		ResourceMRN: resourceMRN,
		Metadata:    map[string]any{"revoked": n},
	}); err != nil {
		return 0, err
	}
	return n, nil
}

// ---------------------------------------------------------------------------
// Enforcement
// ---------------------------------------------------------------------------

// enforceReadLease is the hook the reveal path calls BEFORE it decrypts anything.
//
// It returns (nil, nil) for a secret with no lease policy, which is the overwhelmingly
// common case and the one that must stay exactly as fast and exactly as permissive as
// it was before leases existed. A feature that silently started gating every read in
// the store would be an outage, not a feature.
//
// WHEN THE LEASE REFUSES, NOTHING IS DECRYPTED. The refusal is audited under its own
// action (store.ActionLeaseRefused, outcome denied) rather than as a denied reveal,
// because an allowance running out and a principal lacking a grant are different events
// — and a review that could not tell them apart would read a consumer hitting its cap
// as an authorization attack.
//
// ORDERING: the read is CONSUMED HERE, before the decrypt. That is the conservative
// direction — a decrypt that fails afterwards costs the caller one allowance, whereas
// consuming after a successful decrypt would let a caller that abandons the response
// mid-flight read without spending anything.
func (s *Service) enforceReadLease(ctx context.Context, c Caller, ref store.SecretRef, resourceMRN string) (*store.LeaseDecision, error) {
	decision, err := s.store.AuthorizeLeasedRead(ctx, ref, c.Actor.Subject, c.Actor.Kind, resourceMRN, 0)
	if err != nil {
		var refusal *lease.Refusal
		if errors.As(err, &refusal) {
			s.auditor.RecordDenied(ctx, c.Actor, audit.Event{
				TenantUUID:  c.tenantPtr(),
				Action:      store.ActionLeaseRefused,
				ResourceMRN: resourceMRN,
				Reason:      refusal.Reason,
			})
			// Forbidden rather than TooManyRequests-shaped: this is not
			// rate-limiting infrastructure protecting the service, it is a policy
			// decision that this principal may not read this value right now, and the
			// transports already map Forbidden to 403 / PermissionDenied.
			return nil, apperror.NewForbidden(refusal.Reason)
		}
		return nil, err
	}
	if !decision.Governed {
		return nil, nil
	}
	// A NEW lease is its own audited event: "a consumer that was not reading this
	// credential has started" is a fact worth a row, and it is not visible in the
	// reveal row that follows.
	if decision.Issued && decision.Lease != nil {
		if err := s.recordSuccess(ctx, c, audit.Event{
			Action:      store.ActionLeaseIssue,
			ResourceMRN: resourceMRN,
			Metadata:    leaseMetadata(decision.Lease),
		}); err != nil {
			return nil, err
		}
	}
	return decision, nil
}

// leaseMetadata renders a lease for an audit row or a reveal's metadata. Numbers and
// timestamps only — there is no field here that could hold a value.
func leaseMetadata(l *store.SecretLease) map[string]any {
	if l == nil {
		return nil
	}
	meta := map[string]any{
		"lease_uuid": l.UUID.String(),
		"expires_at": l.ExpiresAt.UTC().Format(time.RFC3339),
		"reads_used": l.ReadsUsed,
	}
	if remaining, capped := l.Remaining(); capped {
		meta["reads_remaining"] = remaining
		meta["max_reads"] = *l.MaxReads
	}
	return meta
}
