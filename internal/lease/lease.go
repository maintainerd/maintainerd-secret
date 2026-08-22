// Package lease is the TTL and use-count policy for reads of a static secret, and
// nothing else. It holds no storage, no clock of its own and no knowledge of the
// database — the store owns the rows and the api layer owns the audit trail; this
// package owns the DECISION.
//
// WHY THE DECISION IS A PACKAGE. "May this read be served?" has five inputs (the
// policy, the lease's expiry, its remaining use count, the secret's own expiry, and
// now) and four distinct answers, one of which — refused-because-exhausted — is a
// security-relevant refusal that has to produce a precise, auditable reason. Written
// inline in the reveal path it would be a nest of conditionals nobody can unit-test
// without a database and a stopwatch; here it is a pure function over a struct, and
// the table test beside it enumerates every boundary.
//
// # What a lease is, and what it is not
//
// A lease is NOT authorization. A grant decides who MAY read a secret (see
// internal/platform/permissions); a lease decides how much reading an already
// authorized principal may do before it has to come back. The two are independent and
// both apply: a caller with no grant is refused by the guard and never reaches a
// lease, and a caller with a valid grant and an exhausted lease is refused here.
//
// The point of having it at all is that a static secret cannot answer "who is
// currently reading the production database password, and how often". A lease can, and
// a max_reads cap turns an exfiltration loop — the same valid token pulling one value
// ten thousand times — from an invisible read pattern into a refusal an operator sees.
//
// # The window semantics, stated plainly
//
// max_reads is "this many reads per TTL window, per requester". A lease is issued on
// first read, consumed on each subsequent one, and superseded by a fresh lease once
// its TTL runs out. So an exhausted lease refuses reads until its window closes, and
// then the next read starts a new window with a full allowance.
//
// That is deliberately NOT a lifetime budget. A lifetime cap sounds stricter and is
// worse: it eventually refuses a correctly behaving consumer forever, at an
// unpredictable moment, with no operator action having caused it — which is an outage
// wearing a security control's clothes. A per-window cap bounds the damage of a stolen
// token to max_reads per window while leaving a legitimate consumer working
// indefinitely.
package lease

import (
	"fmt"
	"time"
)

// DefaultTTL is the lease lifetime used when a policy names a TTL of zero. It exists
// so a policy can never produce a lease that is already expired.
const DefaultTTL = time.Hour

// Policy is a secret's lease configuration, as stored on the secret row.
//
// The ZERO VALUE MEANS "NO POLICY", which is what makes leases opt-in per secret: a
// secret nobody configured behaves exactly as it did before this package existed.
// That is checked by Enabled and is the single most important property here — a
// feature that silently started gating every read in the store would be an outage,
// not a feature.
type Policy struct {
	// TTL is the lifetime of an issued lease. Zero means there is no policy at all.
	TTL time.Duration
	// MaxTTL is the ceiling on a caller-requested TTL. Zero means "the default is
	// also the maximum" — an absent ceiling must never be read as an unbounded one.
	MaxTTL time.Duration
	// MaxReads is how many reads one lease may serve. Zero means unlimited within
	// the TTL, which is the useful default for a workload that re-reads on boot.
	MaxReads int32
}

// Enabled reports whether this secret is lease-governed.
func (p Policy) Enabled() bool { return p.TTL > 0 }

// ResolveTTL returns the lifetime to issue, given what the caller asked for.
//
// A request for zero (or for anything the policy does not permit) yields the default.
// An over-long request is REFUSED rather than clamped, for the same reason an
// over-large page limit is: a caller that asked for a 24-hour lease and silently got
// an hour believes it has 24 hours, and will discover otherwise mid-shift.
func (p Policy) ResolveTTL(requested time.Duration) (time.Duration, error) {
	ttl := p.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	if requested <= 0 {
		return ttl, nil
	}
	ceiling := p.MaxTTL
	if ceiling <= 0 {
		ceiling = ttl
	}
	if requested > ceiling {
		return 0, fmt.Errorf("a lease of %s was requested but this secret's maximum is %s",
			requested.Round(time.Second), ceiling.Round(time.Second))
	}
	return requested, nil
}

// State is an issued lease as the enforcement path sees it.
type State struct {
	// ExpiresAt is when this lease stops being usable.
	ExpiresAt time.Time
	// MaxReads is the cap SNAPSHOT AT ISSUE. Zero means unlimited. It is a snapshot
	// rather than a live read of the policy because an operator who tightens the cap
	// should not retroactively invalidate a lease already handed out — the tightened
	// cap applies to the next lease, which is at most one TTL away.
	MaxReads int32
	// ReadsUsed is how many reads have already been served against it.
	ReadsUsed int32
}

// Remaining reports the reads left, and whether the lease is capped at all.
func (s State) Remaining() (remaining int32, capped bool) {
	if s.MaxReads <= 0 {
		return 0, false
	}
	left := s.MaxReads - s.ReadsUsed
	if left < 0 {
		left = 0
	}
	return left, true
}

// Decision is what the enforcement path does next.
type Decision int

const (
	// Issue means there is no usable lease and one must be created.
	Issue Decision = iota
	// Consume means the existing lease is live and has an allowance left.
	Consume
	// Supersede means the existing lease's TTL has run out: retire it and issue a
	// successor. Distinct from Issue because the old row has to be closed, and
	// distinct from Refuse because an expired lease is a routine renewal rather than
	// a violation.
	Supersede
	// Refuse means the read is not permitted.
	Refuse
)

// String renders a Decision for a log or a test failure.
func (d Decision) String() string {
	switch d {
	case Issue:
		return "issue"
	case Consume:
		return "consume"
	case Supersede:
		return "supersede"
	case Refuse:
		return "refuse"
	default:
		return "unknown"
	}
}

// Request is everything Evaluate needs. Every field is supplied by the caller,
// including Now — this package has no clock, so a test needs no stopwatch and a
// production path cannot disagree with the database about what time it is by using a
// second time source.
type Request struct {
	Policy Policy
	// Existing is the requester's current lease, or nil if it has none.
	Existing *State
	// SecretExpiresAt is the secret's own expires_at, or nil if it has none. See
	// Evaluate for why it is a hard gate here and advisory elsewhere.
	SecretExpiresAt *time.Time
	Now             time.Time
}

// Evaluate decides what happens to one read.
//
// THE ORDER OF THE CHECKS IS THE POLICY, and it is arranged so that the most
// authoritative refusal wins:
//
//  1. The secret's own expiry. A credential its owner has declared dead is not served
//     regardless of what any lease says, and no lease can be issued against it.
//  2. No lease yet, or a lease whose TTL has run out — issue or supersede.
//  3. The use-count cap on a live lease — refuse.
//  4. Otherwise consume.
//
// WHY expires_at IS A HARD GATE HERE AND ADVISORY ELSEWHERE. The column has always
// been documented as advisory (see migrations/00006), and every consumer that reads an
// unleased secret today relies on that: turning it into a global gate would break
// working deployments the moment this code shipped, silently, for secrets whose owners
// set an expiry as a reminder rather than as a rule. But a secret that carries a lease
// policy has been explicitly opted into lease-governed reads by an operator, and
// serving a value that operator already declared expired would defeat the point of the
// opt-in. So the gate follows the opt-in: enabled policy, hard expiry; no policy,
// unchanged behaviour.
func Evaluate(req Request) (Decision, string) {
	if !req.Policy.Enabled() {
		// Not lease-governed. The caller should not have asked, and the honest answer
		// is "consume nothing" rather than a refusal.
		return Consume, ""
	}

	if req.SecretExpiresAt != nil && !req.SecretExpiresAt.After(req.Now) {
		return Refuse, fmt.Sprintf("this secret expired at %s and its value is no longer served",
			req.SecretExpiresAt.UTC().Format(time.RFC3339))
	}

	if req.Existing == nil {
		return Issue, ""
	}
	if !req.Existing.ExpiresAt.After(req.Now) {
		return Supersede, ""
	}
	if remaining, capped := req.Existing.Remaining(); capped && remaining <= 0 {
		return Refuse, fmt.Sprintf(
			"this lease has served its %d permitted reads and is refused until it expires at %s",
			req.Existing.MaxReads, req.Existing.ExpiresAt.UTC().Format(time.RFC3339))
	}
	return Consume, ""
}

// Refusal is the typed refusal a caller can test for.
//
// It exists so the api layer can map "the lease said no" to a precise HTTP/gRPC status
// and an audit reason WITHOUT string-matching an error message, and so a refusal can
// never be confused with an internal failure — the difference between "you may not
// read this" and "we could not read this" matters to an operator at three in the
// morning.
type Refusal struct {
	// Reason is the human-readable, caller-safe explanation. It describes the
	// caller's own lease and says nothing about the value.
	Reason string
}

func (e *Refusal) Error() string { return e.Reason }

// NewRefusal builds a Refusal.
func NewRefusal(reason string) error { return &Refusal{Reason: reason} }
