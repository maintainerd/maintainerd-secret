package api

import (
	"fmt"

	validation "github.com/go-ozzo/ozzo-validation/v4"

	"github.com/maintainerd/secret/internal/store"
)

// Lease-policy request DTOs.
//
// THE THREE POLICY FIELDS ARE POINTERS, and that is the load-bearing detail. A lease
// policy is removed by CLEARING it, so the DTO has to distinguish "the caller did not
// mention lease_max_reads" from "the caller set it to nothing" — which an int32 cannot
// do, because both arrive as zero. With pointers, a nil TTL means "remove the policy"
// and is an explicit, auditable act rather than an omission.

// SetSecretLeasePolicyInput sets or clears a secret's lease policy.
//
// ALL THREE FIELDS ARE WRITTEN TOGETHER: they are one policy, and a TTL left beside a
// stale max_reads from a previous policy is not a state any caller asked for. Sending
// all three nil removes the policy and revokes the leases it governed.
type SetSecretLeasePolicyInput struct {
	Address SecretAddress `json:"address"`
	// TTLSeconds is the lease lifetime. Nil REMOVES the policy — reads of this secret
	// go back to behaving exactly as they did before leases existed.
	TTLSeconds *int32 `json:"lease_ttl_seconds"`
	// MaxTTLSeconds is the ceiling on a caller-requested TTL. Nil means the default is
	// also the maximum — an absent ceiling must never be read as an unbounded one.
	MaxTTLSeconds *int32 `json:"lease_max_ttl_seconds"`
	// MaxReads is how many reads one lease may serve, per TTL window, per requester.
	// Nil means unlimited within the TTL.
	MaxReads *int32 `json:"lease_max_reads"`
}

// Validate checks a lease-policy write.
func (in SetSecretLeasePolicyInput) Validate() error {
	return validation.ValidateStruct(&in,
		validation.Field(&in.Address),
		validation.Field(&in.TTLSeconds, leasePolicyTTLRule("lease_ttl_seconds")),
		validation.Field(&in.MaxTTLSeconds, leasePolicyTTLRule("lease_max_ttl_seconds")),
		validation.Field(&in.MaxReads, leaseMaxReadsRule),
		// The cross-field rules — a ceiling below the default, a cap without a TTL —
		// live in store.SetSecretLeasePolicy rather than here, so that ONE function
		// answers "is this a coherent policy" for both transports and for any future
		// caller. A second copy here could disagree with the store's and would then
		// either reject policies the store accepts or accept ones it rejects.
	)
}

// SecretLeaseRef addresses one secret's leases — the read and revoke-all path.
type SecretLeaseRef struct {
	Address SecretAddress `json:"address"`
}

// Validate checks a lease reference.
func (in SecretLeaseRef) Validate() error {
	return validation.ValidateStruct(&in, validation.Field(&in.Address))
}

// ListSecretLeasesInput pages one secret's lease history.
type ListSecretLeasesInput struct {
	Address    SecretAddress `json:"address"`
	Pagination `json:"page"`
}

// Validate checks a lease listing request.
func (in ListSecretLeasesInput) Validate() error {
	return validation.ValidateStruct(&in,
		validation.Field(&in.Address),
		validation.Field(&in.Pagination),
	)
}

// ---------------------------------------------------------------------------
// Shared lease field rules
// ---------------------------------------------------------------------------

// leasePolicyTTLRule bounds a lease TTL against the store's own bounds, so a value this
// validator accepts is one the columns and the check constraints will take.
func leasePolicyTTLRule(field string) validation.Rule {
	return validation.By(func(value any) error {
		seconds, ok := asInt32Ptr(value)
		if !ok || seconds == nil {
			return nil // nil means "clear it"; the store decides whether that is coherent.
		}
		minimum := int32(store.MinLeaseTTL.Seconds())
		maximum := int32(store.MaxLeaseTTL.Seconds())
		if *seconds < minimum {
			return validation.NewError("validation_lease_ttl_seconds",
				fmt.Sprintf("%s must be at least %d", field, minimum))
		}
		if *seconds > maximum {
			return validation.NewError("validation_lease_ttl_seconds",
				fmt.Sprintf("%s must be at most %d", field, maximum))
		}
		return nil
	})
}

// leaseMaxReadsRule bounds the use-count cap.
var leaseMaxReadsRule = validation.By(func(value any) error {
	reads, ok := asInt32Ptr(value)
	if !ok || reads == nil {
		return nil // nil means unlimited within the TTL.
	}
	if *reads < 1 {
		return validation.NewError("validation_lease_max_reads",
			"lease_max_reads must be at least 1; omit it for unlimited reads within the TTL")
	}
	if *reads > store.MaxLeaseReads {
		return validation.NewError("validation_lease_max_reads",
			fmt.Sprintf("lease_max_reads must be at most %d", store.MaxLeaseReads))
	}
	return nil
})

// asInt32Ptr recovers an *int32 from ozzo's any.
//
// ozzo DEREFERENCES a pointer field before handing it to a By rule when the pointer is
// non-nil, and hands the nil pointer through when it is nil. Both shapes therefore
// arrive here, and a rule that only handled one would silently skip validation for half
// its inputs — which for a bound is the same as not having it.
func asInt32Ptr(value any) (*int32, bool) {
	switch v := value.(type) {
	case nil:
		return nil, true
	case *int32:
		return v, true
	case int32:
		return &v, true
	default:
		return nil, false
	}
}
