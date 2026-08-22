package api

import (
	validation "github.com/go-ozzo/ozzo-validation/v4"
)

// Audit query DTO.
//
// The audit read is a query, not a mutation, but it is the query an attacker who has
// just read a credential makes next — so its page bound matters for the same reason
// every other one does: a caller must not be able to ask for the whole trail in one
// response. Reading it is itself audited (see Service.ListAuditEvents).

// ListAuditEventsInput pages the tenant's access trail, newest first.
type ListAuditEventsInput struct {
	Pagination `json:"page"`
}

// Validate checks an audit query.
func (in ListAuditEventsInput) Validate() error {
	return validation.ValidateStruct(&in,
		validation.Field(&in.Pagination),
	)
}
