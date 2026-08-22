package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/maintainerd/secret/internal/lease"
	"github.com/maintainerd/secret/internal/platform/apperror"
	"github.com/maintainerd/secret/internal/storage"
)

// Read leases on static secrets: the policy on the secret, the issued leases, and the
// one transaction that decides whether a reveal is served.
//
// WHAT LIVES WHERE. internal/lease owns the DECISION (a pure function over the policy,
// the lease and the clock); internal/api owns the guard and the audit trail; this file
// owns the rows and the LOCK. The lock is the part that is only correct in one place:
// two concurrent reveals that both read reads_used = 9 against a cap of 10 would both
// be served, which is exactly the pattern the cap exists to refuse.

// Lease revoke reasons.
const (
	// LeaseRevokeExpired is a lease superseded because its TTL ran out.
	LeaseRevokeExpired = "expired"
	// LeaseRevokeExplicit is a lease the holder or an operator gave up.
	LeaseRevokeExplicit = "explicit"
	// LeaseRevokePolicy is a lease invalidated because the policy that governed it was
	// removed, or the secret was deleted.
	LeaseRevokePolicy = "policy"
)

// SecretLeasePolicy is a secret's lease configuration as it crosses this package's
// boundary. Seconds rather than durations because that is what the columns hold and
// what both transports send; internal/lease works in durations.
type SecretLeasePolicy struct {
	// TTLSeconds is the lease lifetime. Nil means NO POLICY — reads of this secret
	// behave exactly as they did before leases existed.
	TTLSeconds *int32 `json:"lease_ttl_seconds,omitempty"`
	// MaxTTLSeconds is the ceiling on a caller-requested TTL. Nil means the default is
	// also the maximum.
	MaxTTLSeconds *int32 `json:"lease_max_ttl_seconds,omitempty"`
	// MaxReads is how many reads one lease may serve. Nil means unlimited within the
	// TTL.
	MaxReads *int32 `json:"lease_max_reads,omitempty"`
}

// Enabled reports whether this is a policy at all.
func (p SecretLeasePolicy) Enabled() bool { return p.TTLSeconds != nil && *p.TTLSeconds > 0 }

// toLeasePolicy converts to the decision package's shape.
func (p SecretLeasePolicy) toLeasePolicy() lease.Policy {
	var out lease.Policy
	if p.TTLSeconds != nil {
		out.TTL = time.Duration(*p.TTLSeconds) * time.Second
	}
	if p.MaxTTLSeconds != nil {
		out.MaxTTL = time.Duration(*p.MaxTTLSeconds) * time.Second
	}
	if p.MaxReads != nil {
		out.MaxReads = *p.MaxReads
	}
	return out
}

// SecretLease is an issued read lease as it leaves this package.
type SecretLease struct {
	UUID          uuid.UUID  `json:"lease_uuid"`
	ResourceMRN   string     `json:"resource_mrn"`
	Requester     string     `json:"requester"`
	RequesterKind string     `json:"requester_kind"`
	IssuedAt      time.Time  `json:"issued_at"`
	ExpiresAt     time.Time  `json:"expires_at"`
	MaxReads      *int32     `json:"max_reads,omitempty"`
	ReadsUsed     int32      `json:"reads_used"`
	LastReadAt    *time.Time `json:"last_read_at,omitempty"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
	RevokeReason  string     `json:"revoke_reason,omitempty"`
}

// Remaining reports the reads left on this lease and whether it is capped at all.
func (l SecretLease) Remaining() (remaining int32, capped bool) {
	if l.MaxReads == nil || *l.MaxReads <= 0 {
		return 0, false
	}
	left := *l.MaxReads - l.ReadsUsed
	if left < 0 {
		left = 0
	}
	return left, true
}

// SetSecretLeasePolicyInput sets or clears a secret's lease policy.
type SetSecretLeasePolicyInput struct {
	Ref    SecretRef
	Policy SecretLeasePolicy
}

// SetSecretLeasePolicy writes a secret's lease policy.
//
// CLEARING THE POLICY REVOKES THE OUTSTANDING LEASES, in the same transaction. A lease
// is an instrument of a policy; once the policy is gone the lease governs nothing, and
// leaving live rows behind would mean re-enabling the policy silently resumed
// allowances issued under the old one — including their old, possibly looser, caps.
//
// Tightening a policy does NOT retroactively invalidate leases already handed out: the
// cap on a live lease is the snapshot taken at issue, and the tightened one applies to
// the next lease, which is at most one TTL away. That asymmetry is deliberate — removal
// is an operator saying "this is no longer governed", while tightening is an operator
// saying "govern it more from here on".
func (s *Service) SetSecretLeasePolicy(ctx context.Context, in SetSecretLeasePolicyInput) (*SecretMeta, error) {
	if err := validateLeasePolicy(in.Policy); err != nil {
		return nil, apperror.NewValidation(err.Error())
	}
	addr, err := s.resolveAddress(ctx, s.repo, in.Ref)
	if err != nil {
		return nil, err
	}

	var out SecretMeta
	err = s.repo.InTx(ctx, func(tx Repository) error {
		row, err := tx.GetSecretByAddress(ctx, storage.GetSecretByAddressParams{
			TenantID:      addr.tenant.TenantID,
			EnvironmentID: addr.environment.EnvironmentID,
			FolderID:      addr.folder.FolderID,
			Key:           addr.key,
		})
		if err != nil {
			return mapReadError(err, "secret")
		}
		updated, err := tx.SetSecretLeasePolicy(ctx, storage.SetSecretLeasePolicyParams{
			LeaseTtlSeconds:    int4(in.Policy.TTLSeconds),
			LeaseMaxTtlSeconds: int4(in.Policy.MaxTTLSeconds),
			LeaseMaxReads:      int4(in.Policy.MaxReads),
			TenantID:           addr.tenant.TenantID,
			SecretUuid:         row.SecretUuid,
		})
		if err != nil {
			return mapWriteError(err, "secret lease policy", "that lease policy could not be applied")
		}
		if !in.Policy.Enabled() {
			if _, err := tx.RevokeSecretLeasesForSecret(ctx, storage.RevokeSecretLeasesForSecretParams{
				RevokeReason: LeaseRevokePolicy,
				TenantID:     addr.tenant.TenantID,
				SecretID:     row.SecretID,
			}); err != nil {
				return apperror.NewInternal("revoke leases for unleased secret", err)
			}
		}
		out = secretRowToMeta(updated, addr.folder.Path, s.policy.KeepVersions)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// GetSecretLeasePolicy reads a secret's lease policy.
func (s *Service) GetSecretLeasePolicy(ctx context.Context, ref SecretRef) (SecretLeasePolicy, error) {
	row, _, err := s.secretRowByRef(ctx, ref)
	if err != nil {
		return SecretLeasePolicy{}, err
	}
	return leasePolicyFromRow(row), nil
}

// LeaseDecision is the outcome of enforcing a lease on one read.
type LeaseDecision struct {
	// Governed reports whether the secret carries a lease policy at all. False means
	// no lease was issued and none was consumed — the pre-lease behaviour, unchanged.
	Governed bool
	// Lease is the lease the read was served against, when Governed is true.
	Lease *SecretLease
	// Issued reports whether this read created the lease (as opposed to consuming an
	// existing one). Worth surfacing because "a new consumer started reading this
	// credential" is a different event from "an existing one read it again".
	Issued bool
}

// AuthorizeLeasedRead is the enforcement path: it decides whether a reveal may be
// served, issues or supersedes a lease as needed, and consumes one read.
//
// IT IS ONE TRANSACTION AND IT TAKES A ROW LOCK, and both are load-bearing. The
// sequence is lock the requester's live lease, ask internal/lease what to do, then act:
//
//	Consume    -> ConsumeSecretLease, which RE-CHECKS the cap in its WHERE clause. Zero
//	              rows means another path already took the last read, and the refusal
//	              is the same one the decision would have produced.
//	Issue      -> insert a lease, then consume its first read.
//	Supersede  -> revoke the expired row, insert a successor, consume its first read.
//	Refuse     -> return a lease.Refusal, which the api layer maps to a precise error
//	              and an audit row. No value is decrypted.
//
// A read is CONSUMED BEFORE THE VALUE IS DECRYPTED, by the caller's ordering. That is
// the conservative direction: a decrypt that fails after a consumed read costs the
// caller one allowance, whereas consuming after a successful decrypt would let a caller
// that abandons the response mid-flight read without spending anything.
//
// `requester` is the authenticated principal, and it is part of the lease's identity:
// two workloads reading one secret get two independent allowances, because one noisy
// consumer must not be able to exhaust another's.
func (s *Service) AuthorizeLeasedRead(ctx context.Context, ref SecretRef, requester, requesterKind, resourceMRN string, requestedTTL time.Duration) (*LeaseDecision, error) {
	row, _, err := s.secretRowByRef(ctx, ref)
	if err != nil {
		return nil, err
	}
	policy := leasePolicyFromRow(row)
	if !policy.Enabled() {
		return &LeaseDecision{Governed: false}, nil
	}

	lp := policy.toLeasePolicy()
	ttl, err := lp.ResolveTTL(requestedTTL)
	if err != nil {
		return nil, apperror.NewValidation(err.Error())
	}

	out := &LeaseDecision{Governed: true}
	err = s.repo.InTx(ctx, func(tx Repository) error {
		existing, err := tx.GetLiveSecretLeaseForUpdate(ctx, storage.GetLiveSecretLeaseForUpdateParams{
			TenantID:  row.TenantID,
			SecretID:  row.SecretID,
			Requester: requester,
		})
		var state *lease.State
		switch {
		case err == nil:
			state = &lease.State{
				ExpiresAt: existing.ExpiresAt,
				ReadsUsed: existing.ReadsUsed,
			}
			if existing.MaxReads.Valid {
				state.MaxReads = existing.MaxReads.Int32
			}
		case errors.Is(err, pgx.ErrNoRows):
			state = nil
		default:
			return apperror.NewInternal("read secret lease", err)
		}

		decision, reason := lease.Evaluate(lease.Request{
			Policy:          lp,
			Existing:        state,
			SecretExpiresAt: timePtr(row.ExpiresAt),
			Now:             s.now(),
		})

		switch decision {
		case lease.Refuse:
			return lease.NewRefusal(reason)
		case lease.Supersede:
			if _, err := tx.RevokeSecretLease(ctx, storage.RevokeSecretLeaseParams{
				RevokeReason: LeaseRevokeExpired,
				LeaseID:      existing.LeaseID,
			}); err != nil {
				return apperror.NewInternal("retire expired secret lease", err)
			}
			fallthrough
		case lease.Issue:
			issued, err := tx.CreateSecretLease(ctx, storage.CreateSecretLeaseParams{
				TenantID:      row.TenantID,
				SecretID:      row.SecretID,
				ResourceMrn:   resourceMRN,
				Requester:     requester,
				RequesterKind: defaultRequesterKind(requesterKind),
				ExpiresAt:     s.now().Add(ttl),
				MaxReads:      int4(policy.MaxReads),
			})
			if err != nil {
				return mapWriteError(err, "secret lease", "a lease for this requester already exists on this secret")
			}
			existing = issued
			out.Issued = true
		case lease.Consume:
			// Nothing to create; fall through to the consume below.
		}

		n, err := tx.ConsumeSecretLease(ctx, existing.LeaseID)
		if err != nil {
			return apperror.NewInternal("consume secret lease", err)
		}
		if n == 0 {
			// The cap or the expiry was re-checked in SQL under the lock and refused.
			// Reaching here means the lease changed between the decision and the update
			// — another path took the last read, or the TTL elapsed in between — so the
			// honest answer is the same refusal the decision would have produced.
			if existing.MaxReads.Valid {
				return lease.NewRefusal(fmt.Sprintf(
					"this lease has served its %d permitted reads and is refused until it expires at %s",
					existing.MaxReads.Int32, existing.ExpiresAt.UTC().Format(time.RFC3339)))
			}
			return lease.NewRefusal(fmt.Sprintf("this lease expired at %s",
				existing.ExpiresAt.UTC().Format(time.RFC3339)))
		}
		existing.ReadsUsed++
		l := toSecretLease(existing)
		out.Lease = &l
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ListSecretLeases pages one secret's lease history, newest first.
func (s *Service) ListSecretLeases(ctx context.Context, ref SecretRef, page, limit int) ([]SecretLease, int64, error) {
	row, _, err := s.secretRowByRef(ctx, ref)
	if err != nil {
		return nil, 0, err
	}
	page, limit = normalizePage(page, limit)
	rows, err := s.repo.ListSecretLeases(ctx, storage.ListSecretLeasesParams{
		TenantID:  row.TenantID,
		SecretID:  row.SecretID,
		RowLimit:  int32(limit),
		RowOffset: int32((page - 1) * limit),
	})
	if err != nil {
		return nil, 0, apperror.NewInternal("list secret leases", err)
	}
	total, err := s.repo.CountSecretLeases(ctx, storage.CountSecretLeasesParams{
		TenantID: row.TenantID,
		SecretID: row.SecretID,
	})
	if err != nil {
		return nil, 0, apperror.NewInternal("count secret leases", err)
	}
	out := make([]SecretLease, 0, len(rows))
	for _, r := range rows {
		l := SecretLease{
			UUID:          r.LeaseUuid,
			ResourceMRN:   r.ResourceMrn,
			Requester:     r.Requester,
			RequesterKind: r.RequesterKind,
			IssuedAt:      r.IssuedAt,
			ExpiresAt:     r.ExpiresAt,
			ReadsUsed:     r.ReadsUsed,
			RevokeReason:  r.RevokeReason,
		}
		if r.MaxReads.Valid {
			v := r.MaxReads.Int32
			l.MaxReads = &v
		}
		l.LastReadAt = timePtr(r.LastReadAt)
		l.RevokedAt = timePtr(r.RevokedAt)
		out = append(out, l)
	}
	return out, total, nil
}

// RevokeSecretLeases closes every outstanding lease on one secret.
//
// The operator-facing "cut this consumer off now" control. It returns how many were
// closed rather than an error when there were none: revoking nothing is a legitimate
// outcome of asking for a clean slate, and reporting it as a failure would make the
// safe action look like a broken one.
func (s *Service) RevokeSecretLeases(ctx context.Context, ref SecretRef) (int64, error) {
	row, _, err := s.secretRowByRef(ctx, ref)
	if err != nil {
		return 0, err
	}
	n, err := s.repo.RevokeSecretLeasesForSecret(ctx, storage.RevokeSecretLeasesForSecretParams{
		RevokeReason: LeaseRevokeExplicit,
		TenantID:     row.TenantID,
		SecretID:     row.SecretID,
	})
	if err != nil {
		return 0, apperror.NewInternal("revoke secret leases", err)
	}
	return n, nil
}

// ExpireDueSecretLeases retires leases whose TTL has run out.
//
// HOUSEKEEPING, NOT ENFORCEMENT — and the distinction matters, because it is what makes
// this safe to run on a timer and safe to skip entirely. The consume path already
// refuses an expired lease under its row lock, so nothing depends on this having run;
// what it buys is that the one-live-lease-per-requester index does not fill with dead
// rows nobody will consume again.
func (s *Service) ExpireDueSecretLeases(ctx context.Context, limit int) (int64, error) {
	if limit < 1 {
		limit = 100
	}
	n, err := s.repo.ExpireDueSecretLeases(ctx, int32(limit))
	if err != nil {
		return 0, apperror.NewInternal("expire due secret leases", err)
	}
	return n, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// LeaseTTLBounds are the bounds a policy's TTL must fall inside.
//
// The floor is a full minute rather than a second: a lease shorter than the time it
// takes a consumer to receive and use a value is not a policy, it is an outage that
// looks like one. The ceiling stops a "lease" being a permanent grant with a
// countdown, which is the same argument the dynamic role's MaxTTLCeiling makes.
const (
	MinLeaseTTL = time.Minute
	MaxLeaseTTL = 30 * 24 * time.Hour
	// MaxLeaseReads bounds the use-count cap. It is generous because a legitimate
	// consumer may read on every request; it exists so the column cannot hold a value
	// that makes the cap meaningless while appearing to be one.
	MaxLeaseReads = 1 << 20
)

// validateLeasePolicy bounds a lease policy. The database's check constraints are the
// authority; these produce a useful message instead of a constraint name.
func validateLeasePolicy(p SecretLeasePolicy) error {
	if p.TTLSeconds == nil {
		// Clearing the policy. The other two fields must be cleared with it — a cap
		// without a TTL is a cap nothing enforces, and the check constraint refuses it
		// anyway.
		if p.MaxTTLSeconds != nil || p.MaxReads != nil {
			return fmt.Errorf("lease_max_ttl_seconds and lease_max_reads require lease_ttl_seconds; clear all three to remove the policy")
		}
		return nil
	}
	ttl := time.Duration(*p.TTLSeconds) * time.Second
	if ttl < MinLeaseTTL {
		return fmt.Errorf("lease_ttl_seconds must be at least %d (%s)", int(MinLeaseTTL.Seconds()), MinLeaseTTL)
	}
	if ttl > MaxLeaseTTL {
		return fmt.Errorf("lease_ttl_seconds must be at most %d (%s)", int(MaxLeaseTTL.Seconds()), MaxLeaseTTL)
	}
	if p.MaxTTLSeconds != nil {
		maxTTL := time.Duration(*p.MaxTTLSeconds) * time.Second
		if maxTTL < ttl {
			return fmt.Errorf("lease_max_ttl_seconds (%d) must not be shorter than lease_ttl_seconds (%d)",
				*p.MaxTTLSeconds, *p.TTLSeconds)
		}
		if maxTTL > MaxLeaseTTL {
			return fmt.Errorf("lease_max_ttl_seconds must be at most %d (%s)", int(MaxLeaseTTL.Seconds()), MaxLeaseTTL)
		}
	}
	if p.MaxReads != nil {
		if *p.MaxReads < 1 {
			return fmt.Errorf("lease_max_reads must be at least 1; omit it for unlimited reads within the TTL")
		}
		if *p.MaxReads > MaxLeaseReads {
			return fmt.Errorf("lease_max_reads must be at most %d", MaxLeaseReads)
		}
	}
	return nil
}

// leasePolicyFromRow reads the policy off a secret row.
func leasePolicyFromRow(row storage.Secret) SecretLeasePolicy {
	var p SecretLeasePolicy
	if row.LeaseTtlSeconds.Valid {
		v := row.LeaseTtlSeconds.Int32
		p.TTLSeconds = &v
	}
	if row.LeaseMaxTtlSeconds.Valid {
		v := row.LeaseMaxTtlSeconds.Int32
		p.MaxTTLSeconds = &v
	}
	if row.LeaseMaxReads.Valid {
		v := row.LeaseMaxReads.Int32
		p.MaxReads = &v
	}
	return p
}

// secretRowByRef resolves a SecretRef to its row and address.
func (s *Service) secretRowByRef(ctx context.Context, ref SecretRef) (storage.Secret, address, error) {
	addr, err := s.resolveAddress(ctx, s.repo, ref)
	if err != nil {
		return storage.Secret{}, address{}, err
	}
	row, err := s.repo.GetSecretByAddress(ctx, storage.GetSecretByAddressParams{
		TenantID:      addr.tenant.TenantID,
		EnvironmentID: addr.environment.EnvironmentID,
		FolderID:      addr.folder.FolderID,
		Key:           addr.key,
	})
	if err != nil {
		return storage.Secret{}, address{}, mapReadError(err, "secret")
	}
	return row, addr, nil
}

func toSecretLease(r storage.SecretLease) SecretLease {
	l := SecretLease{
		UUID:          r.LeaseUuid,
		ResourceMRN:   r.ResourceMrn,
		Requester:     r.Requester,
		RequesterKind: r.RequesterKind,
		IssuedAt:      r.IssuedAt,
		ExpiresAt:     r.ExpiresAt,
		ReadsUsed:     r.ReadsUsed,
		RevokeReason:  r.RevokeReason,
	}
	if r.MaxReads.Valid {
		v := r.MaxReads.Int32
		l.MaxReads = &v
	}
	l.LastReadAt = timePtr(r.LastReadAt)
	l.RevokedAt = timePtr(r.RevokedAt)
	return l
}
