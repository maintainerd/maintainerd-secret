// Package rotator is the scheduled-rotation loop: its own goroutine, a ticker, and
// no path that ends the process.
//
// It mirrors the shape of core's internal/supervisor deliberately, because the
// operational contract is the same: a background loop that keeps the platform in the
// state an operator asked for must never be the reason the service goes down. So
// every pass is best-effort, a panic is recovered, a failing pass is an ordinary
// condition (the database blips, setup has not run yet, one root key is missing), and
// the loop keeps ticking.
//
// It holds no rotation logic of its own. Deciding what is due, generating a value,
// writing the version and recording the audit row all live in the API service; this
// package only decides WHEN to ask. That split is what makes the interesting part
// testable without a clock and this part testable without a store.
//
// ============================================================================
// IT IS LEADER-ONLY, AND THAT IS A CORRECTNESS REQUIREMENT
// ============================================================================
//
// Every other surface in this service is safe on N replicas. This loop is not.
// Two replicas ticking the same schedule find the same due secret and rotate it
// twice: two new versions, two webhook fan-outs, two audit rows, and a consumer
// that re-read after the first notification now holding a value that is already
// superseded. Nothing is corrupted — a secret with two extra versions is still a
// valid secret — but the store's history and every downstream consumer have been
// told something untrue.
//
// So a pass runs only on the replica that holds the leader lock (see
// internal/leader). A follower ticks, finds it is not the leader, and does
// nothing. The gate is checked on EVERY pass rather than once at start-up,
// because leadership can change under a running loop — that is the whole point of
// it — and a loop that cached the answer would keep rotating for as long as it
// lived after losing the lock.
//
// A nil Leader means "there is no election, so this process is the only one",
// which is the correct reading for a single-replica deployment and for a test.
package rotator

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/maintainerd/secret/internal/api"
	"github.com/maintainerd/secret/internal/leader"
)

// Defaults for Options.
const (
	// DefaultInterval is how often a pass runs. Rotation intervals are measured in
	// days, so a scan every five minutes is already two orders of magnitude finer
	// than the thing it is scheduling — fine enough that a rotation is never
	// meaningfully late, coarse enough to be invisible in load.
	DefaultInterval = 5 * time.Minute
	// DefaultBatch bounds one pass. A store where a thousand secrets come due at
	// once (a policy applied in bulk) must not attempt a thousand writes in one
	// tick; the remainder is picked up by the next pass moments later.
	DefaultBatch = 50
)

// Engine is the rotation work one pass performs. *api.Service satisfies it.
type Engine interface {
	RotateDueSecrets(ctx context.Context, limit int) (api.RotationResult, error)
}

// Options tunes the loop. A zero Options is a working configuration.
type Options struct {
	Interval time.Duration
	Batch    int
	// Enabled turns the loop off without removing the policies. An operator disabling
	// rotation during an incident wants the schedules preserved, not deleted.
	Enabled bool
	// Leader gates every pass: a follower replica must not rotate. Nil means no
	// election is configured, which is read as "this is the only process" — see the
	// package comment and leader.Holds.
	//
	// It is an INTERFACE rather than a *leader.Elector so this loop can be tested
	// with a two-line fake, and so any other periodic worker in this service adopts
	// the same gate without depending on how the lock is taken.
	Leader leader.Election
}

func (o Options) withDefaults() Options {
	if o.Interval <= 0 {
		o.Interval = DefaultInterval
	}
	if o.Batch <= 0 {
		o.Batch = DefaultBatch
	}
	return o
}

// Rotator is the loop.
type Rotator struct {
	engine Engine
	opts   Options
	// active tracks whether the last pass was allowed to run, so the change of
	// leadership is logged once instead of "skipping, not leader" on every tick.
	// A log line that repeats every interval forever is a log line an operator
	// learns to filter out, and this one is worth reading when it changes.
	//
	// It starts true so the FIRST skip on a follower still reports the transition:
	// a replica that comes up as a follower must say so once, or an operator
	// looking for "why is nothing rotating" finds silence on every replica.
	active atomic.Bool
}

// New builds the loop.
func New(engine Engine, opts Options) *Rotator {
	r := &Rotator{engine: engine, opts: opts.withDefaults()}
	r.active.Store(true)
	return r
}

// IsLeaderGated reports whether an election governs this loop. Used by the boot
// log so an operator can see, in one line, whether running a second replica would
// double-rotate.
func (r *Rotator) IsLeaderGated() bool { return r != nil && r.opts.Leader != nil }

// Run ticks until ctx is cancelled.
//
// The first pass runs IMMEDIATELY rather than after one interval. The most likely
// moment for a rotation to be overdue is right after the service was down, and
// waiting a full interval would extend that for no reason.
func (r *Rotator) Run(ctx context.Context) {
	if r == nil || r.engine == nil || !r.opts.Enabled {
		slog.Info("rotator: disabled — scheduled rotation policies will not fire")
		return
	}
	slog.Info("rotator: started",
		"interval", r.opts.Interval.String(), "batch", r.opts.Batch,
		"leader_gated", r.IsLeaderGated())
	if !r.IsLeaderGated() {
		// Said once, loudly, because the failure it warns about is invisible: two
		// replicas both rotating looks like a working service right up until
		// somebody reads the version history.
		slog.Warn("rotator: no leader election configured — every replica will rotate",
			"effect", "with more than one replica the same secret is rotated once per replica, "+
				"each producing a version and a webhook fan-out",
			"fix", "SECRET_LEADER_ELECTION_ENABLED=true")
	}
	ticker := time.NewTicker(r.opts.Interval)
	defer ticker.Stop()
	for {
		r.Tick(ctx)
		select {
		case <-ctx.Done():
			slog.Info("rotator: stopped")
			return
		case <-ticker.C:
		}
	}
}

// Tick runs one pass. Exported so a test (and a future on-demand endpoint) can drive
// it without a ticker.
//
// The recover is not defensive clutter: this runs on its own goroutine, and an
// unrecovered panic there takes the whole process down — so a bug in the loop that
// rotates credentials would become the thing that takes the vault offline.
func (r *Rotator) Tick(ctx context.Context) {
	defer func() {
		if rec := recover(); rec != nil {
			slog.Error("rotator: pass panicked — the loop continues", "panic", rec)
		}
	}()
	if ctx.Err() != nil {
		return
	}
	// THE LEADER GATE, checked on every pass rather than cached at start-up:
	// leadership changes under a running loop, and that is the point of it.
	if !leader.Holds(r.opts.Leader) {
		if r.active.CompareAndSwap(true, false) {
			slog.Info("rotator: paused — this replica is not the leader",
				"detail", "scheduled rotation runs on exactly one replica; this one will resume if it is promoted")
		}
		return
	}
	if r.active.CompareAndSwap(false, true) {
		slog.Info("rotator: resumed — this replica is now the leader")
	}

	result, err := r.engine.RotateDueSecrets(ctx, r.opts.Batch)
	if err != nil {
		slog.Warn("rotator: pass failed — retrying on the next tick", "error", err)
		return
	}
	if result.Due == 0 {
		return
	}
	slog.Info("rotator: pass complete",
		"due", result.Due, "rotated", result.Rotated, "failed", result.Failed, "skipped", result.Skipped)
}
