package api

import (
	"context"

	"github.com/maintainerd/secret/internal/platform/apperror"
	"github.com/maintainerd/secret/internal/store"
)

// Bulk operations: reveal N secrets, or write N secrets, in one call.
//
// WHY THEY EXIST. A workload starting up needs twenty values, and twenty round trips
// is twenty chances to be half-configured. A reconciler writes a whole environment
// at once. The batch is a transport optimisation, not a semantic one.
//
// WHICH IS WHY EVERY ITEM IS INDIVIDUALLY AUTHORIZED AND INDIVIDUALLY AUDITED. Each
// element goes through the same single-item path — same MRN resolution, same grant
// check against that MRN, same audit row (and the same reference and import
// resolution). A batch that checked permission once against the scope would be the
// single easiest way to turn a narrow grant into a broad one: ask for the twenty keys
// you may read plus the one you may not.
//
// PARTIAL RESULTS ARE THE CONTRACT, NOT A FAILURE MODE. A batch returns per-item
// outcomes rather than failing wholesale on the first denial. All-or-nothing would
// mean one unauthorized key in a list of twenty tells the caller nothing about the
// other nineteen — and, worse, that a caller could probe its own grants by bisecting
// the list. Per-item errors are also what a consumer needs: "these eighteen are
// yours, these two are not" is actionable, "denied" is not.
//
// BATCH SIZE IS BOUNDED. An unbounded batch is a bulk-decryption endpoint: one
// request that reveals an entire environment, held in memory at once, with a single
// audit timestamp. The bound is what keeps a reveal an event rather than a stream.

// The bound itself lives in internal/api/limits.go (Limits.MaxBatchItems, capped by
// the MaxBatchSize constant) so an operator can lower it and nobody can raise it.

// BatchGetItem is one requested reveal.
type BatchGetItem struct {
	Address SecretAddress `json:"address"`
	// Version pins a specific version; 0 means the current one.
	Version int32 `json:"version,omitempty"`
}

// BatchGetResult is one reveal outcome. Exactly one of Secret or Error is set.
type BatchGetResult struct {
	Address SecretAddress
	Secret  *store.RevealedSecret
	// ReferenceHops mirrors Revealed.ReferenceHops for this item.
	ReferenceHops []string
	Error         error
}

// Zero overwrites this result's decrypted value.
func (r *BatchGetResult) Zero() {
	if r != nil && r.Secret != nil {
		r.Secret.Zero()
	}
}

// BatchGet reveals several secrets. The caller MUST Zero every result.
//
// On an error mid-batch the results collected SO FAR are zeroized before returning,
// so an aborted batch never leaves decrypted values in a slice the caller was not
// given.
func (s *Service) BatchGet(ctx context.Context, c Caller, items []BatchGetItem) ([]BatchGetResult, error) {
	// The whole batch is validated up front — item count AND every item's address —
	// so a malformed item is a 400 for the request rather than a per-item error
	// buried among ninety-nine successful reveals.
	if err := validate(BatchGetInput{Items: items}); err != nil {
		return nil, err
	}

	out := make([]BatchGetResult, 0, len(items))
	for _, item := range items {
		revealed, err := s.Reveal(ctx, c, item.Address, item.Version)
		if err != nil {
			// An audit failure is NOT a per-item error. If the trail cannot be
			// written the whole batch is abandoned, because continuing would produce
			// exactly the unaudited reveals the single-item path refuses to produce.
			if isAuditFailure(err) {
				zeroAll(out)
				return nil, err
			}
			out = append(out, BatchGetResult{Address: item.Address, Error: err})
			continue
		}
		out = append(out, BatchGetResult{
			Address:       item.Address,
			Secret:        revealed.Secret,
			ReferenceHops: revealed.ReferenceHops,
		})
	}
	return out, nil
}

// BatchPutItem is one requested write.
type BatchPutItem struct {
	Address       SecretAddress `json:"address"`
	Value         []byte        `json:"-"`
	ValueType     string        `json:"value_type,omitempty"`
	Description   string        `json:"description,omitempty"`
	Tags          []string      `json:"tags,omitempty"`
	CreateFolders bool          `json:"create_folders,omitempty"`
}

// BatchPutResult is one write outcome.
type BatchPutResult struct {
	Address SecretAddress
	Result  *store.PutResult
	Error   error
}

// BatchPut writes several secrets.
//
// The writes are NOT one transaction, and that is a deliberate choice rather than a
// limitation. Each item is its own transaction in the store (a version insert plus a
// current_version advance plus a retention prune), and wrapping twenty of those in
// one transaction would hold row locks on twenty secrets across twenty seals — long
// enough for an ordinary concurrent write to a single one of them to block on a batch
// it has nothing to do with. Per-item results tell the caller exactly which writes
// landed, which is what a reconciler needs in order to retry the rest.
func (s *Service) BatchPut(ctx context.Context, c Caller, items []BatchPutItem) ([]BatchPutResult, error) {
	if err := validate(BatchPutInput{Items: items}); err != nil {
		return nil, err
	}

	out := make([]BatchPutResult, 0, len(items))
	for _, item := range items {
		result, err := s.PutSecret(ctx, c, PutSecretInput{
			Address:       item.Address,
			Value:         item.Value,
			ValueType:     item.ValueType,
			Description:   item.Description,
			Tags:          item.Tags,
			CreateFolders: item.CreateFolders,
		})
		if err != nil {
			if isAuditFailure(err) {
				return nil, err
			}
			out = append(out, BatchPutResult{Address: item.Address, Error: err})
			continue
		}
		out = append(out, BatchPutResult{Address: item.Address, Result: result})
	}
	return out, nil
}

// isAuditFailure reports whether an error means the trail could not be written, as
// opposed to the operation being refused or the target being absent. Those are the
// only errors that abort a whole batch.
func isAuditFailure(err error) bool {
	if err == nil {
		return false
	}
	if apperror.IsNotFound(err) || apperror.IsValidation(err) ||
		apperror.IsConflict(err) || apperror.IsForbidden(err) || apperror.IsUnavailable(err) {
		return false
	}
	return true
}

func zeroAll(results []BatchGetResult) {
	for i := range results {
		results[i].Zero()
	}
}
