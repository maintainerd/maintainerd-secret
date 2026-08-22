// Package apperror defines the structured errors the service layer returns, so
// transport layers can map them to a status code without inspecting strings. Same
// contract as core's internal/platform/apperror, trimmed to what this service uses.
//
// One rule is specific to a secret store: NO ERROR IN THIS PACKAGE, AND NO ERROR
// WRAPPED BY IT, MAY CARRY A SECRET VALUE. Errors travel to logs, to traces, and to
// clients. A decrypt failure says "decrypt failed", never what it was decrypting or
// what came out.
package apperror

import (
	"errors"
	"fmt"
)

// NotFoundError means the addressed thing does not exist — or, for a tenant-scoped
// read, exists but not for this tenant. Those two cases are deliberately
// indistinguishable to the caller: a distinct "exists but forbidden" response
// confirms the existence of another tenant's secret, which is itself a leak.
type NotFoundError struct{ Entity string }

func (e *NotFoundError) Error() string { return e.Entity + " not found" }

// ConflictError means a uniqueness or state constraint refused the operation.
type ConflictError struct{ Reason string }

func (e *ConflictError) Error() string { return e.Reason }

// ValidationError means the input was malformed.
type ValidationError struct{ Reason string }

func (e *ValidationError) Error() string { return e.Reason }

// ForbiddenError means the operation is not permitted in this state — a destroy
// inside the recovery window, a move of an environment's root folder.
type ForbiddenError struct{ Reason string }

func (e *ForbiddenError) Error() string { return e.Reason }

// UnavailableError means a dependency this operation needs is not built or not
// reachable — the KMS root-key providers that are registered but not yet
// implemented return this.
type UnavailableError struct{ Reason string }

func (e *UnavailableError) Error() string { return e.Reason }

// InternalError wraps an unexpected failure. Op names the operation for the server
// log; the wrapped cause is never intended for a client.
type InternalError struct {
	Op  string
	Err error
}

func (e *InternalError) Error() string { return fmt.Sprintf("%s: %v", e.Op, e.Err) }
func (e *InternalError) Unwrap() error { return e.Err }

// Constructors.
func NewNotFound(entity string) error   { return &NotFoundError{Entity: entity} }
func NewConflict(reason string) error   { return &ConflictError{Reason: reason} }
func NewValidation(reason string) error { return &ValidationError{Reason: reason} }
func NewForbidden(reason string) error  { return &ForbiddenError{Reason: reason} }

// NewUnavailable reports a dependency that is absent rather than broken.
func NewUnavailable(reason string) error { return &UnavailableError{Reason: reason} }

// NewInternal wraps cause with the operation that failed.
func NewInternal(op string, cause error) error { return &InternalError{Op: op, Err: cause} }

// Predicates, for callers that need to branch without a type switch.
func IsNotFound(err error) bool {
	var t *NotFoundError
	return errors.As(err, &t)
}

func IsConflict(err error) bool {
	var t *ConflictError
	return errors.As(err, &t)
}

func IsValidation(err error) bool {
	var t *ValidationError
	return errors.As(err, &t)
}

func IsForbidden(err error) bool {
	var t *ForbiddenError
	return errors.As(err, &t)
}

func IsUnavailable(err error) bool {
	var t *UnavailableError
	return errors.As(err, &t)
}
