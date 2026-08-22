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
package rotator

import (
	"context"
	"log/slog"
	"time"

	"github.com/maintainerd/secret/internal/api"
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
}

// New builds the loop.
func New(engine Engine, opts Options) *Rotator {
	return &Rotator{engine: engine, opts: opts.withDefaults()}
}

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
	slog.Info("rotator: started", "interval", r.opts.Interval.String(), "batch", r.opts.Batch)
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
