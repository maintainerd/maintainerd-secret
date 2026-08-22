package dynamic

import (
	"context"
	"log/slog"
	"time"
)

// The reaper: the background loop that revokes expired dynamic leases.
//
// WHY IT EXISTS AT ALL, GIVEN 'VALID UNTIL'. A creation template can say
// `VALID UNTIL '{{expiration}}'`, and when it does, PostgreSQL itself stops accepting
// the login at the right moment. That is a good belt and it is NOT sufficient:
//
//   - The template is OPERATOR-WRITTEN. One that omits VALID UNTIL — by oversight, by
//     copy-paste, or because the author did not know about it — produces a permanent
//     database account from an API call whose whole contract was "expiring
//     credential". Nothing in the request path can detect that, because the statement
//     succeeded.
//   - VALID UNTIL expires the LOGIN, not the ROLE. The account stays in pg_roles
//     forever, owning objects and holding memberships, and a store that issues a
//     thousand credentials a day accumulates a thousand dead roles a day.
//   - An expiry the TARGET database enforces cannot be audited by this service. "The
//     credential was revoked" has to be a fact this store recorded, not an inference
//     from a setting on a database it does not own.
//
// So the lease row is the record of truth and this loop is the enforcement: an
// orphaned role cannot outlive its lease, whatever the template did or did not say.
//
// The shape mirrors internal/rotator deliberately, because the operational contract is
// identical — a background loop that keeps the platform in the state an operator asked
// for must never be the reason the service goes down. Every pass is best-effort, a
// panic is recovered, a failing pass is an ordinary condition (the target database is
// down, a root key is missing, setup has not run), and the loop keeps ticking.
//
// It holds NO revocation logic of its own. Resolving the DSN, rendering the revocation
// template, running it and recording the outcome all live in the api service; this
// package only decides WHEN to ask.

// Reaper defaults.
const (
	// DefaultReapInterval is how often a pass runs. Lease TTLs are measured in hours,
	// so a sweep every minute is two orders of magnitude finer than the thing it is
	// enforcing — fine enough that a credential is never meaningfully overdue, coarse
	// enough to be invisible in load.
	//
	// It is much tighter than the rotator's five minutes on purpose: a late rotation
	// is a policy drifting, while a late revocation is a live credential outliving its
	// lease, and those are not the same kind of late.
	DefaultReapInterval = time.Minute
	// DefaultReapBatch bounds one pass. A store where a thousand leases expire at once
	// (a deploy that issued a thousand credentials an hour ago) must not open a
	// thousand connections to target databases in one tick; the remainder is picked up
	// by the next pass moments later.
	DefaultReapBatch = 25
)

// ReapReport is the outcome of one pass.
type ReapReport struct {
	// Due is how many expired leases the pass found.
	Due int
	// Revoked is how many were successfully revoked and closed.
	Revoked int
	// Failed is how many could not be revoked. THE LEASES STAY OPEN — see
	// internal/store: a revocation the target database refused has not happened, and
	// marking it done would lose the only record that a live account needs dropping.
	// A non-zero Failed that persists across passes is the signal that an account has
	// been orphaned by an outage.
	Failed int
	// Skipped counts leases the pass could not even attempt — a role config whose DSN
	// secret has been deleted, a provisioner that is not configured. Distinct from
	// Failed because the target database was never contacted, so there is nothing to
	// retry until an operator fixes the configuration.
	Skipped int
}

// ReapEngine is the work one pass performs. *api.Service satisfies it.
//
// It is declared HERE rather than taking an api type so that internal/api can import
// this package for the Provisioner seam without an import cycle — the same reason
// internal/rotator declares its own Engine.
type ReapEngine interface {
	ReapExpiredDynamicLeases(ctx context.Context, limit int) (ReapReport, error)
}

// ReaperOptions tunes the loop. A zero value is a working configuration except for
// Enabled, which is opt-in.
type ReaperOptions struct {
	Interval time.Duration
	Batch    int
	// Enabled turns the loop off without removing the leases.
	//
	// AN OPERATOR WHO DISABLES IT IS ACCEPTING THAT ISSUED CREDENTIALS OUTLIVE THEIR
	// LEASES, and the boot log says so in those words. It is a real switch because a
	// reaper hammering an unreachable target database during an incident is a
	// legitimate thing to want to stop; it is not a switch anybody should leave off.
	Enabled bool
}

func (o ReaperOptions) withDefaults() ReaperOptions {
	if o.Interval <= 0 {
		o.Interval = DefaultReapInterval
	}
	if o.Batch <= 0 {
		o.Batch = DefaultReapBatch
	}
	return o
}

// Reaper is the loop.
type Reaper struct {
	engine ReapEngine
	opts   ReaperOptions
}

// NewReaper builds the loop.
func NewReaper(engine ReapEngine, opts ReaperOptions) *Reaper {
	return &Reaper{engine: engine, opts: opts.withDefaults()}
}

// Interval is the resolved sweep cadence. Exported so a caller driving Tick through a
// shared scheduler (leader.RunPeriodic) uses the same cadence Run would have.
func (r *Reaper) Interval() time.Duration {
	if r == nil {
		return DefaultReapInterval
	}
	return r.opts.Interval
}

// Enabled reports whether this reaper would do work. A nil engine counts as disabled:
// there is nothing to sweep with, and reporting enabled would produce a worker that
// logs a started line and then does nothing every interval forever.
func (r *Reaper) Enabled() bool { return r != nil && r.engine != nil && r.opts.Enabled }

// Run ticks until ctx is cancelled.
//
// The first pass runs IMMEDIATELY rather than after one interval, and here that
// matters more than it does for the rotator: the most likely moment for a lease to be
// overdue is right after the service was down, which is exactly when a credential has
// been sitting live past its expiry with nothing watching.
func (r *Reaper) Run(ctx context.Context) {
	if r == nil || r.engine == nil || !r.opts.Enabled {
		slog.Warn("dynamic reaper: DISABLED — issued dynamic credentials will not be revoked when their leases expire")
		return
	}
	slog.Info("dynamic reaper: started", "interval", r.opts.Interval.String(), "batch", r.opts.Batch)
	ticker := time.NewTicker(r.opts.Interval)
	defer ticker.Stop()
	for {
		r.Tick(ctx)
		select {
		case <-ctx.Done():
			slog.Info("dynamic reaper: stopped")
			return
		case <-ticker.C:
		}
	}
}

// Tick runs one pass. Exported so a test — and an operator-triggered sweep — can drive
// it without a ticker.
//
// The recover is not defensive clutter: this runs on its own goroutine, and an
// unrecovered panic there takes the whole process down, so a bug in the loop that
// revokes credentials would become the thing that takes the vault offline.
func (r *Reaper) Tick(ctx context.Context) {
	defer func() {
		if rec := recover(); rec != nil {
			slog.Error("dynamic reaper: pass panicked — the loop continues", "panic", rec)
		}
	}()
	if ctx.Err() != nil {
		return
	}
	report, err := r.engine.ReapExpiredDynamicLeases(ctx, r.opts.Batch)
	if err != nil {
		slog.Warn("dynamic reaper: pass failed — retrying on the next tick", "error", err)
		return
	}
	if report.Due == 0 {
		return
	}
	// A failure here is logged at WARN rather than INFO because the consequence is a
	// live database credential past its expiry. It is not an error for the process —
	// the retry is automatic — but it is not routine either.
	level := slog.LevelInfo
	if report.Failed > 0 || report.Skipped > 0 {
		level = slog.LevelWarn
	}
	slog.Log(ctx, level, "dynamic reaper: pass complete",
		"due", report.Due, "revoked", report.Revoked, "failed", report.Failed, "skipped", report.Skipped)
}
