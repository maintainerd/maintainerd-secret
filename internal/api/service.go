// Package api is the application service both transports sit on: the REST handlers
// (internal/httpapi) and the gRPC service (internal/grpcserver) are thin adapters
// over the methods here.
//
// WHY THERE IS A LAYER BETWEEN THE TRANSPORTS AND THE STORE. Three things have to
// happen on every operation, in order, and none of them belongs in a handler:
//
//  1. RESOLVE THE TARGET'S MRN. Authorization is MRN-level, so the target has to be
//     named before it can be checked — including for a create, where the target does
//     not exist yet and the check is against the MRN it will have.
//  2. CHECK THE CALLER'S GRANTS AGAINST THAT MRN, and AUDIT A DENIAL.
//  3. AUDIT THE OUTCOME.
//
// Duplicating that across two transports is how one of them ends up missing a step.
// Worse, the step most likely to be missed is the audit, and an unaudited reveal is
// precisely the thing this service exists to make impossible. So the transports
// carry no authorization logic at all: they parse, they call, they render.
//
// EVERY METHOD HERE TAKES A Caller. That is not ceremony — it is what makes the
// audit trail complete by construction, because there is no way to reach an
// operation without supplying the identity that will be recorded against it.
package api

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/maintainerd/secret/internal/audit"
	"github.com/maintainerd/secret/internal/platform/apperror"
	"github.com/maintainerd/secret/internal/platform/authz"
	"github.com/maintainerd/secret/internal/store"
)

// Notifier announces a secret change to a project's webhook endpoints. It is an
// interface rather than a concrete dependency so the service is constructible
// without the outbound HTTP path (tests, and a deployment that disables webhooks).
//
// A nil Notifier is a documented no-op: notification is best-effort by nature — a
// consumer that misses an announcement re-reads on its next cycle — so a delivery
// failure must never fail the write that triggered it. The write is the durable
// fact; the webhook is a courtesy.
type Notifier interface {
	Notify(ctx context.Context, n Notification)
}

// Notification is what a webhook announces. NOTE WHAT IS ABSENT: there is no value
// field, and there cannot be one. See internal/webhook for why a payload that
// carried a credential would move it outside encrypted custody for no gain.
type Notification struct {
	TenantUUID  uuid.UUID
	Project     string
	Event       string
	ResourceMRN string
	Version     int32
	Actor       audit.Actor
}

// Options tunes the service.
type Options struct {
	// ReferenceMaxDepth bounds how many hops a reference chain may be followed
	// before the resolver gives up. See resolveReferences for why a bound is a
	// correctness requirement and not a tuning knob.
	ReferenceMaxDepth int
	// DefaultTenant is the tenant a request that names none is resolved to. It is
	// what makes a standalone install usable without every caller knowing a tenant
	// slug.
	DefaultTenant string
}

// DefaultReferenceMaxDepth is the fallback bound on reference chains.
const DefaultReferenceMaxDepth = 8

// Service is the application service.
type Service struct {
	store    *store.Service
	auditor  *audit.Auditor
	notifier Notifier
	opts     Options
}

// New builds the service.
//
// The auditor is REQUIRED and its absence is a construction error rather than a
// degraded mode. That is the structural half of "no unaudited path": there is no way
// to obtain a *Service that can reveal a secret without also being able to record
// that it did.
func New(st *store.Service, auditor *audit.Auditor, notifier Notifier, opts Options) (*Service, error) {
	if st == nil {
		return nil, errors.New("api: store is required")
	}
	if auditor == nil {
		return nil, audit.ErrNoAuditor
	}
	if opts.ReferenceMaxDepth < 1 {
		opts.ReferenceMaxDepth = DefaultReferenceMaxDepth
	}
	return &Service{store: st, auditor: auditor, notifier: notifier, opts: opts}, nil
}

// Store exposes the underlying store for the paths that legitimately need it — the
// setup surface (which runs before any caller exists) and the boot-time root-key
// registration. It is NOT a back door for handlers: an operation reached through
// here performs no permission check and writes no audit row, which is why the only
// callers are the two that have no caller identity to check.
func (s *Service) Store() *store.Service { return s.store }

// Caller is the authenticated principal of one request, resolved into everything the
// service needs: the grants to check, the identity to record, and the tenant the
// request is scoped to.
type Caller struct {
	Claims *authz.Claims
	Actor  audit.Actor
	// TenantUUID and TenantName are the resolved tenant. Both are carried because
	// the query layer scopes on the UUID and the MRN is built from the name.
	TenantUUID uuid.UUID
	TenantName string
}

// tenantPtr returns the tenant for an audit row.
func (c Caller) tenantPtr() *uuid.UUID {
	if c.TenantUUID == uuid.Nil {
		return nil
	}
	id := c.TenantUUID
	return &id
}

// mrn builds an MRN in this caller's tenant.
func (c Caller) mrn(project, resourcePath string) string {
	return store.MRN(c.TenantName, project, resourcePath)
}

// ResolveCaller turns verified claims plus a requested tenant into a Caller.
//
// TENANT PRECEDENCE: the explicit request hint, then the token's own tenant claim,
// then the configured default. The hint is trusted only as a SELECTOR, never as an
// authorization: naming a tenant gets you an MRN in that tenant, and the grant check
// then decides whether you may touch it. That is why a caller may ask for any tenant
// slug — asking is free, and the answer for a tenant you hold no grant in is a
// denial (audited) rather than a data leak.
func (s *Service) ResolveCaller(ctx context.Context, claims *authz.Claims, actor audit.Actor, tenantHint string) (Caller, error) {
	name := tenantHint
	if name == "" && claims != nil {
		name = claims.Tenant
	}
	if name == "" {
		name = s.opts.DefaultTenant
	}
	if name == "" {
		return Caller{}, apperror.NewValidation("no tenant was named and no default tenant is configured")
	}
	tenant, err := s.store.GetTenantByName(ctx, name)
	if err != nil {
		return Caller{}, err
	}
	if actor.Subject == "" && claims != nil {
		actor.Subject = claims.Subject
	}
	if actor.Kind == "" && claims != nil {
		actor.Kind = claims.Kind
	}
	return Caller{
		Claims:     claims,
		Actor:      actor,
		TenantUUID: tenant.UUID,
		TenantName: tenant.Name,
	}, nil
}

// guard is the single authorization gate.
//
// Every operation goes through it, and it does three things that must always happen
// together: it refuses to run at all without an auditor, it checks the caller's
// grants against the CONCRETE target MRN, and it writes an audit row for a denial
// before returning the error. A denied attempt is the most interesting row in the
// table — it is how an over-reaching or compromised principal is spotted — so the
// denial path is the one place where "we forgot to audit" would be most costly and
// least visible.
//
// The returned error names the permission and the resource. That is deliberate and
// it is not an information leak worth avoiding: the caller already supplied the
// address, so the only new fact is "you lack this grant", which is exactly what an
// operator debugging a 403 needs. It says nothing about whether the resource exists.
func (s *Service) guard(ctx context.Context, c Caller, permission, action, resourceMRN string) error {
	if s.auditor == nil {
		return audit.ErrNoAuditor
	}
	if c.Claims.Allows(permission, resourceMRN) {
		return nil
	}
	s.auditor.RecordDenied(ctx, c.Actor, audit.Event{
		TenantUUID:  c.tenantPtr(),
		Action:      action,
		ResourceMRN: resourceMRN,
		Reason:      "missing permission " + permission,
	})
	return apperror.NewForbidden(fmt.Sprintf("requires permission %s on %s", permission, resourceMRN))
}

// recordSuccess writes the success row and returns any write failure.
//
// Callers on a MUTATION or a REVEAL path propagate the error: an operation that
// could not be audited must not report success. That is the strict reading, and it
// is the right one for a vault — an unaudited reveal that the caller believes
// succeeded is strictly worse than a failed reveal, because the value is out and
// nothing records it.
func (s *Service) recordSuccess(ctx context.Context, c Caller, ev audit.Event) error {
	if s.auditor == nil {
		return audit.ErrNoAuditor
	}
	ev.TenantUUID = c.tenantPtr()
	ev.Outcome = store.OutcomeSuccess
	if err := s.auditor.Record(ctx, c.Actor, ev); err != nil {
		return apperror.NewInternal("record audit event", err)
	}
	return nil
}

// recordFailure writes an error row for an operation that failed for a
// non-authorization reason. Errorless, like the denial path: the caller is already
// returning a failure and a second one would replace a useful message with a useless
// one.
func (s *Service) recordFailure(ctx context.Context, c Caller, action, resourceMRN string, cause error) {
	if s.auditor == nil {
		return
	}
	s.auditor.RecordError(ctx, c.Actor, audit.Event{
		TenantUUID:  c.tenantPtr(),
		Action:      action,
		ResourceMRN: resourceMRN,
		Reason:      redactedReason(cause),
	})
}

// redactedReason renders a cause for the audit trail.
//
// An InternalError's wrapped cause is deliberately NOT included: it is a database
// message describing the store's structure, and audit_log is readable by anyone with
// secret:ReadAudit — a broader audience than the operator reading the server log. The
// typed errors are safe because they are the service's own words.
func redactedReason(err error) string {
	if err == nil {
		return ""
	}
	var internal *apperror.InternalError
	if errors.As(err, &internal) {
		return internal.Op + " failed"
	}
	return err.Error()
}

// notify fans a change out to the project's webhook endpoints, if a notifier is
// configured. Best-effort by contract — see Notifier.
func (s *Service) notify(ctx context.Context, c Caller, project, event, resourceMRN string, version int32) {
	if s.notifier == nil {
		return
	}
	s.notifier.Notify(ctx, Notification{
		TenantUUID:  c.TenantUUID,
		Project:     project,
		Event:       event,
		ResourceMRN: resourceMRN,
		Version:     version,
		Actor:       c.Actor,
	})
}

// int32Ptr is a local helper; audit events take *int32 so "no version" is
// distinguishable from "version 0", which is a real state (a secret before its first
// write).
func int32Ptr(v int32) *int32 { return &v }
