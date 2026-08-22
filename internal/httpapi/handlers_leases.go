package httpapi

import (
	"net/http"

	"github.com/maintainerd/secret/internal/api"
	"github.com/maintainerd/secret/internal/platform/response"
)

// Lease handlers for STATIC secrets: the policy surfaces and the operator's cut-off.
//
// THEY LIVE ON THE /secrets SEGMENT, not on a segment of their own, because a lease has
// no resource path of its own (see internal/store/resources.go): the policy governs
// reads of ONE secret and is authorized against that secret's MRN. A /leases segment
// would invite a grant that could revoke leases on a secret it holds nothing else over.
// The shape is /secrets/rotation-policy's, for the same reason: an administrative
// property of one secret, addressed the way every other /secrets route addresses one.
//
// NONE OF THESE RESPONSES CAN CARRY A VALUE. A policy is three numbers, a lease is a
// UUID, two timestamps and a read count. There is no decrypt on any of these paths —
// the lease ENFORCEMENT hook (api.enforceReadLease) is inside the reveal, not here.

// setLeasePolicyRequest embeds the shared address so the JSON is identical to every
// other /secrets body.
type setLeasePolicyRequest struct {
	api.SecretAddress
	// The three fields are POINTERS so "the caller did not mention max_reads" is
	// distinguishable from "the caller set it to nothing" — an int32 collapses both to
	// zero. A nil TTL REMOVES the policy, which is an explicit, auditable act.
	TTLSeconds    *int32 `json:"lease_ttl_seconds"`
	MaxTTLSeconds *int32 `json:"lease_max_ttl_seconds"`
	MaxReads      *int32 `json:"lease_max_reads"`
}

// setLeasePolicy sets or clears a secret's lease policy.
//
// Administrative: deciding that a credential may be read ten times an hour is a policy
// call, which is why the route is user-only and requires secret:ManageLease against the
// SECRET's own MRN rather than the folder's.
func (s *Server) setLeasePolicy(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	var req setLeasePolicyRequest
	if !decode(w, r, &req) {
		return
	}
	meta, err := s.api.SetSecretLeasePolicy(r.Context(), c, api.SetSecretLeasePolicyInput{
		Address:       req.SecretAddress,
		TTLSeconds:    req.TTLSeconds,
		MaxTTLSeconds: req.MaxTTLSeconds,
		MaxReads:      req.MaxReads,
	})
	if err != nil {
		response.ServiceError(w, r, "could not set the lease policy", err)
		return
	}
	if req.TTLSeconds == nil {
		response.OK(w, meta, "lease policy removed; reads of this secret are no longer metered")
		return
	}
	response.OK(w, meta, "lease policy set")
}

// getLeasePolicy reads a secret's lease policy.
//
// secret:ReadMetadata, NOT secret:ManageLease: a consumer that can see "this secret
// allows 10 reads an hour" can plan around the cap instead of meeting it as an
// unexplained refusal mid-incident. It discloses nothing about the value.
func (s *Server) getLeasePolicy(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	addr, ok := addressQuery(w, r)
	if !ok {
		return
	}
	policy, err := s.api.GetSecretLeasePolicy(r.Context(), c, api.SecretLeaseRef{Address: addr})
	if err != nil {
		response.ServiceError(w, r, "could not read the lease policy", err)
		return
	}
	response.OK(w, policy, "")
}

// listSecretLeases pages a secret's issued leases, newest first. Metadata: who holds a
// lease, until when, how much of their allowance is left — which IS the answer to "who
// is currently able to read this credential", and which a secret with no lease policy
// cannot give at all.
func (s *Server) listSecretLeases(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	addr, ok := addressQuery(w, r)
	if !ok {
		return
	}
	page, limit := response.PageParams(r)
	leases, total, err := s.api.ListSecretLeases(r.Context(), c, api.ListSecretLeasesInput{
		Address:    addr,
		Pagination: api.Pagination{Page: page, Limit: limit},
	})
	if err != nil {
		response.ServiceError(w, r, "could not list the secret's leases", err)
		return
	}
	response.List(w, leases, page, limit, total)
}

// revokeSecretLeases closes every outstanding lease on one secret.
//
// It does NOT stop the next read from opening a fresh lease — that would be removing the
// policy or revoking the grant — and the response says so, because an operator reaching
// for this during an incident needs to know it resets allowances rather than locking the
// secret.
func (s *Server) revokeSecretLeases(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	var req api.SecretAddress
	if !decode(w, r, &req) {
		return
	}
	revoked, err := s.api.RevokeSecretLeases(r.Context(), c, api.SecretLeaseRef{Address: req})
	if err != nil {
		response.ServiceError(w, r, "could not revoke the secret's leases", err)
		return
	}
	response.OK(w, map[string]any{"revoked": revoked},
		"outstanding leases revoked; a subsequent authorized read opens a fresh lease")
}
