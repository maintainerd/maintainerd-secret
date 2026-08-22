package api

import (
	"fmt"
	"time"

	validation "github.com/go-ozzo/ozzo-validation/v4"

	"github.com/maintainerd/secret/internal/store"
)

// Audit query DTO.
//
// The audit read is a query, not a mutation, but it is the query an attacker who has
// just read a credential makes next — so its page bound matters for the same reason
// every other one does: a caller must not be able to ask for the whole trail in one
// response. Reading it is itself audited (see Service.ListAuditEvents).
//
// THE FILTERS ARE PART OF THE REQUEST, NOT PART OF THE CLIENT. They used to be
// neither: the endpoint paged and the console filtered whatever page it had, which
// answers "no matches" when it means "not on this page". On an access trail those are
// "nobody read that credential" and "nobody read it in the last hundred rows", and an
// incident review cannot tell them apart. Every predicate below is pushed into the
// SQL (store.AuditFilter), so a filtered page is a filtered TRAIL.
//
// The page caps are unchanged and still enforced by Pagination: a filter narrows what
// is counted, never how much one response may carry.

// auditMRNPrefixMaxLength bounds the resource prefix. resource_mrn is unbounded TEXT
// in the schema, but a full MRN is a handful of slugs and a path — a bound two orders
// of magnitude above the longest real one refuses a pathological LIKE pattern without
// ever refusing a real query.
const auditMRNPrefixMaxLength = 512

// auditActorPrefixMaxLength matches audit_log.actor_subject's VARCHAR(255): a prefix
// longer than the column can hold could never match anything.
const auditActorPrefixMaxLength = 255

// ListAuditEventsInput pages and FILTERS the tenant's access trail, newest first.
type ListAuditEventsInput struct {
	Pagination `json:"page"`

	// Action is an EXACT match against one of store.AuditActions. Exact rather than
	// a prefix because it is a closed vocabulary a console renders as a dropdown, and
	// because "secret.read" must not also match a future "secret.reader".
	Action string `json:"action,omitempty"`

	// Outcome is an exact match: success, denied or error. The denied rows are the
	// most interesting ones in the table, which is why filtering to them alone is a
	// first-class query rather than something to scroll for.
	Outcome string `json:"outcome,omitempty"`

	// Actor is a PREFIX of the actor subject — what an operator has to hand during an
	// incident is usually part of a subject, not all of it. Passing the whole subject
	// makes it an exact match, so the looser rule loses nothing.
	Actor string `json:"actor,omitempty"`

	// Resource is a PREFIX of the resource MRN, which is what makes "everything that
	// touched this project" or "everything under prod" expressible:
	// `mrn:secret:acme:billing-app:secret/prod` matches every secret beneath it.
	//
	// Wildcards are NOT honoured. The prefix is escaped before it becomes a LIKE
	// pattern (store.likePrefix), so a `%` or `_` in an MRN is matched literally —
	// otherwise an underscore in a project slug would silently widen the filter.
	Resource string `json:"resource,omitempty"`

	// From and To bound created_at INCLUSIVELY. Either may be nil for an open end, so
	// "since Monday" needs no invented upper bound.
	From *time.Time `json:"from,omitempty"`
	To   *time.Time `json:"to,omitempty"`
}

// Validate checks an audit query.
func (in ListAuditEventsInput) Validate() error {
	return validation.ValidateStruct(&in,
		validation.Field(&in.Pagination),
		// Membership rather than a length bound: an action this service never records
		// is not dangerous, but it is a filter that returns nothing forever, which
		// reads as "nothing happened" on the one screen where that must never be
		// ambiguous. The list comes from the store so the two cannot drift.
		validation.Field(&in.Action, validation.In(anySlice(store.AuditActions())...).
			Error("action must be one of the recorded audit actions")),
		validation.Field(&in.Outcome, validation.In(anySlice(store.AuditOutcomes())...).
			Error(fmt.Sprintf("outcome must be one of %s, %s, %s",
				store.OutcomeSuccess, store.OutcomeDenied, store.OutcomeError))),
		validation.Field(&in.Actor, validation.Length(0, auditActorPrefixMaxLength).
			Error(fmt.Sprintf("actor must be at most %d characters", auditActorPrefixMaxLength))),
		validation.Field(&in.Resource, validation.Length(0, auditMRNPrefixMaxLength).
			Error(fmt.Sprintf("resource must be at most %d characters", auditMRNPrefixMaxLength))),
		// An inverted range is refused rather than silently returning nothing. A
		// console that swapped its two date fields would otherwise render an empty
		// trail, which is the same screen as "no events" and means something else
		// entirely.
		validation.Field(&in.To, validation.By(func(value any) error {
			to, _ := value.(*time.Time)
			if to == nil || in.From == nil || !to.Before(*in.From) {
				return nil
			}
			return validation.NewError("validation_audit_range", "to must not be earlier than from")
		})),
	)
}

// filter renders the DTO's predicates as the store's filter.
func (in ListAuditEventsInput) filter() store.AuditFilter {
	return store.AuditFilter{
		Action:         in.Action,
		Outcome:        in.Outcome,
		ActorPrefix:    in.Actor,
		ResourcePrefix: in.Resource,
		From:           in.From,
		To:             in.To,
	}
}

// auditMetadata renders the filters that were actually set, for the audit row this
// read writes about itself. Absent filters are omitted rather than recorded as empty
// strings, so an unfiltered read produces the same row it always did.
func (in ListAuditEventsInput) auditMetadata() map[string]any {
	out := map[string]any{}
	if in.Action != "" {
		out["filter_action"] = in.Action
	}
	if in.Outcome != "" {
		out["filter_outcome"] = in.Outcome
	}
	if in.Actor != "" {
		out["filter_actor_prefix"] = in.Actor
	}
	if in.Resource != "" {
		out["filter_resource_prefix"] = in.Resource
	}
	if in.From != nil {
		out["filter_from"] = in.From.UTC().Format(time.RFC3339)
	}
	if in.To != nil {
		out["filter_to"] = in.To.UTC().Format(time.RFC3339)
	}
	return out
}

// anySlice widens a string list for validation.In, which takes ...any. It exists so
// the accepted sets stay DERIVED from the store's constants instead of being retyped
// here — a hand-copied list is a list that stops matching.
func anySlice(values []string) []any {
	out := make([]any, 0, len(values))
	for _, v := range values {
		out = append(out, v)
	}
	return out
}
