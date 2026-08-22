// Package audit is the API boundary's access trail.
//
// WHY IT LIVES HERE AND NOT IN THE STORE. The store knows what happened; only the
// boundary knows WHO asked and HOW — the authenticated subject, the principal kind,
// the client address, the user agent, the request id. An audit row written from
// inside the store would have to invent or thread all five, and the ones it
// invented would be the ones an incident review needs most. So the store owns the
// durable append (store.RecordAudit, append-only at the database level) and this
// package owns the decision to call it, with the request context in hand.
//
// WHY THE AUDITOR IS A REQUIRED DEPENDENCY RATHER THAN AN OPTIONAL HOOK. For a
// secret store the read IS the sensitive event, so "no unaudited get path" has to be
// a structural property, not a convention someone remembers. The reveal path takes
// an *Auditor and FAILS CLOSED when it is absent: a nil auditor is not "skip
// auditing", it is ErrNoAuditor and the reveal does not happen. That is the
// difference between a guarantee and a habit — a future refactor that constructs the
// service without an auditor gets a broken reveal (loudly, in tests) instead of a
// silently unaudited one.
//
// A DENIED ATTEMPT IS AUDITED TOO. A refused access is the most interesting row in
// the table: it is how a compromised or over-reaching principal is spotted. The
// denial path therefore writes before it returns the error, and a failure to write
// the denial does not turn the denial into an allow.
//
// NO EVENT IN THIS PACKAGE CAN CARRY A SECRET VALUE. There is no field for one, on
// purpose — a stronger guarantee than remembering not to fill one in. Metadata is a
// string map and every writer of it passes structural facts (version numbers, key
// counts, reference hops), never a payload.
package audit

import (
	"context"
	"errors"
	"log/slog"

	"github.com/google/uuid"

	"github.com/maintainerd/secret/internal/store"
)

// ErrNoAuditor is returned by any audited operation reached without an auditor. It
// is a programming error surfaced at runtime rather than a condition to handle: the
// only correct response is to construct the service properly.
var ErrNoAuditor = errors.New("audit: no auditor configured; audited operations refuse to run unaudited")

// Recorder is the durable sink. *store.Service satisfies it.
type Recorder interface {
	RecordAudit(ctx context.Context, ev store.AuditEvent) error
}

// Actor is the request-scoped identity and provenance of one caller. Every field is
// what the boundary observed, never what the caller claimed about itself beyond its
// verified token.
type Actor struct {
	// Subject is the verified principal. Empty is permitted only on the setup
	// surface, which runs before any principal exists.
	Subject string
	// Kind is user | service | setup (store.ActorKind*).
	Kind string
	// IP is the client address, already stripped of the port.
	IP string
	// UserAgent and RequestID come from the request; both are advisory and both are
	// what makes a row correlatable with an HTTP access log.
	UserAgent string
	RequestID string
}

// Event is one audited operation.
type Event struct {
	// TenantUUID is nil for platform-scoped events — notably the setup call that
	// creates the first tenant, which cannot reference one yet.
	TenantUUID *uuid.UUID
	Action     string
	// ResourceMRN is the full MRN as evaluated. It is denormalized into the row so
	// the trail still reads correctly after the folder moves or the secret is
	// destroyed.
	ResourceMRN string
	SecretUUID  *uuid.UUID
	Version     *int32
	Outcome     string
	Reason      string
	Metadata    map[string]any
}

// Auditor writes the trail. Build one with New; the zero value is unusable by
// design, and a nil *Auditor refuses every write.
type Auditor struct {
	rec Recorder
}

// New builds an auditor over a recorder.
func New(rec Recorder) (*Auditor, error) {
	if rec == nil {
		return nil, ErrNoAuditor
	}
	return &Auditor{rec: rec}, nil
}

// Record appends one event.
//
// A failure to write is returned AND logged. Callers on the success path propagate
// it — an operation that could not be audited must not report success, because the
// only thing worse than an unaudited reveal is an unaudited reveal nobody knows
// happened. Callers on a denial path log and keep denying (see RecordDenied).
func (a *Auditor) Record(ctx context.Context, actor Actor, ev Event) error {
	if a == nil || a.rec == nil {
		return ErrNoAuditor
	}
	if ev.Action == "" {
		return errors.New("audit: action is required")
	}
	outcome := ev.Outcome
	if outcome == "" {
		outcome = store.OutcomeSuccess
	}
	kind := actor.Kind
	if kind == "" {
		kind = store.ActorKindService
	}
	return a.rec.RecordAudit(ctx, store.AuditEvent{
		TenantUUID:   ev.TenantUUID,
		ActorSubject: actor.Subject,
		ActorKind:    kind,
		Action:       ev.Action,
		ResourceMRN:  ev.ResourceMRN,
		SecretUUID:   ev.SecretUUID,
		Version:      ev.Version,
		Outcome:      outcome,
		Reason:       ev.Reason,
		IPAddress:    actor.IP,
		UserAgent:    actor.UserAgent,
		RequestID:    actor.RequestID,
		Metadata:     ev.Metadata,
	})
}

// RecordDenied writes a denial and returns nothing.
//
// The signature is deliberately errorless: a denial is already the answer, and there
// is no version of "the denial could not be recorded" that should turn into an
// allow, a 500, or a different message to the caller. The write failure is logged at
// error level because a store that cannot record denials has lost its most valuable
// signal, and that is an operational alarm rather than a request-scoped problem.
func (a *Auditor) RecordDenied(ctx context.Context, actor Actor, ev Event) {
	ev.Outcome = store.OutcomeDenied
	if err := a.Record(ctx, actor, ev); err != nil {
		slog.Error("audit: recording a DENIED attempt failed",
			"action", ev.Action, "resource", ev.ResourceMRN, "actor", actor.Subject, "error", err)
	}
}

// RecordError writes a failed-operation row. Same errorless contract as
// RecordDenied and for the same reason: the caller is already returning a failure.
func (a *Auditor) RecordError(ctx context.Context, actor Actor, ev Event) {
	ev.Outcome = store.OutcomeError
	if err := a.Record(ctx, actor, ev); err != nil {
		slog.Error("audit: recording a failed operation failed",
			"action", ev.Action, "resource", ev.ResourceMRN, "actor", actor.Subject, "error", err)
	}
}
