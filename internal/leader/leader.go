// Package leader is single-writer election for this service's background work.
//
// ============================================================================
// THE PROBLEM IT EXISTS FOR
// ============================================================================
//
// Every request surface in this service is safe to run on N replicas: reads are
// reads, and writes are serialized by the database. The BACKGROUND WORK is not.
// A periodic worker assumes it is the only one of its kind, and with two replicas
// that assumption is simply false:
//
//   - The ROTATOR scans for due secrets and rotates them. Two replicas ticking the
//     same schedule rotate the same secret twice — two new versions, two webhook
//     fan-outs, two audit rows, and a consumer that re-read after the first
//     notification holding a value that is already superseded. Nothing is
//     corrupted, but the store's history and every downstream consumer are lied to.
//   - Any FUTURE periodic worker (webhook re-drive, lease reaper, version-retention
//     pruning) has the same shape and the same failure.
//
// So the periodic work needs exactly one owner at a time, and the ownership has to
// survive a replica being killed without warning.
//
// ============================================================================
// WHY A POSTGRES ADVISORY LOCK
// ============================================================================
//
// A session-scoped advisory lock (pg_try_advisory_lock) is the right primitive
// here, and the reasons are specific rather than aesthetic:
//
//   - NO NEW DEPENDENCY. This service already requires PostgreSQL and cannot serve
//     a single secret without it. Electing through the database it must already
//     reach adds no new failure domain — contrast etcd, ZooKeeper, Consul or Redis,
//     each of which would make "the vault has a leader" depend on a second system
//     that can be down while Postgres is up.
//   - IT DIES WITH THE CONNECTION. This is the property that matters most. The lock
//     is held by a SESSION, not by a row, so when a leader is SIGKILLed, its
//     container is evicted, or its network partitions, the backend goes away and
//     PostgreSQL releases the lock itself. There is nothing to time out and nothing
//     to clean up.
//   - CONTRAST A LEASE TABLE. The obvious alternative — a `leader` row with an
//     `expires_at` an owner renews — needs a REAPER to expire the row of a leader
//     that died, and the reaper is itself work that needs a leader, or a clock
//     comparison that is wrong whenever two replicas' clocks disagree. It also
//     leaves a window (up to one lease duration) in which no replica will act
//     because a dead one still nominally owns the lease. The advisory lock has no
//     lease duration, no clock dependency, and no reaper.
//   - IT IS MUTUALLY EXCLUSIVE BY CONSTRUCTION. `pg_try_advisory_lock` returns
//     false rather than blocking, so a follower learns it is a follower in one round
//     trip and never queues behind the leader.
//
// THE ONE COST, STATED PLAINLY: holding a session-scoped lock means holding one
// pooled connection for as long as this process is the leader. That is one
// connection out of DB_MAX_OPEN_CONNS, permanently, on exactly one replica. A
// lease table would not hold a connection — that is the trade, and one connection
// is cheaper than a reaper that has to be correct about clocks.
//
// ============================================================================
// WHAT IT DOES NOT CLAIM
// ============================================================================
//
// This is NOT a consensus protocol and it is NOT a fencing token. There is a
// theoretical window in which a leader has lost its lock (its session died) but has
// not yet noticed, while a new leader has taken it — the classic
// distributed-lock-is-not-a-fence problem. Every worker gated by this election must
// therefore still be safe to run twice; the election reduces duplicate work from
// "always" to "a heartbeat interval after an abrupt failure", it does not make
// duplicate work impossible. The rotator satisfies that: a double rotation is
// wasteful, not corrupting.
package leader

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// Defaults for Options. Both are deliberately short relative to the interval of
// the work they gate (the rotator scans every 5m by default), so a promotion after
// a leader dies costs at most one heartbeat rather than one work interval.
const (
	// DefaultRetryInterval is how often a FOLLOWER re-campaigns. It is the upper
	// bound on how long the periodic work is unowned after a leader disappears.
	DefaultRetryInterval = 10 * time.Second
	// DefaultHeartbeatInterval is how often a LEADER checks that it still holds the
	// lock. It is not a lease renewal — the lock needs no renewing — it is how
	// quickly this process notices that its session died and stops acting as leader.
	DefaultHeartbeatInterval = 10 * time.Second
	// DefaultResignTimeout bounds the unlock on shutdown. It is short because the
	// fallback is correct: if the unlock cannot complete, the connection is
	// destroyed instead, and killing the session releases the lock anyway.
	DefaultResignTimeout = 5 * time.Second
	// DefaultLockName is the lock every periodic worker in this service shares.
	//
	// ONE LOCK FOR ALL BACKGROUND WORK, not one per worker. Two reasons: a single
	// owner means two periodic workers can never race each other across replicas
	// (the retention pruner and the rotator both touch version rows), and N locks
	// would mean N pooled connections held open forever instead of one.
	DefaultLockName = "background-workers"
)

// Election is the contract a leader-gated worker depends on.
//
// IT IS DELIBERATELY ONE METHOD. Any background worker in this service — the
// rotator today, a webhook re-drive worker, a lease reaper or a version-retention
// pruner tomorrow — needs to answer exactly one question before it does work:
// "am I the replica that owns this?" Everything else (how the lock is taken, how
// loss is detected, how it is released) is this package's problem and must not
// leak into a worker.
//
// A worker takes an Election, never a *Elector, so it can be tested with a
// two-line fake:
//
//	type fakeElection struct{ leader bool }
//	func (f fakeElection) IsLeader() bool { return f.leader }
//
// Prefer Holds(e) over e.IsLeader() at a call site: it is nil-safe, and nil is a
// supported configuration (see Holds).
type Election interface {
	// IsLeader reports whether this process currently owns the leader lock.
	//
	// It is a cheap, non-blocking read of a cached flag — safe to call on every
	// tick of every worker. It never touches the database.
	IsLeader() bool
}

// Holds reports whether a worker gated by e may do work right now.
//
// A NIL ELECTION MEANS YES, and that is a deliberate, documented default rather
// than a nil-check convenience: it makes "no election configured" mean "this is
// the only process", which is the correct reading for a single-replica deployment
// and for every unit test that does not care about election. A worker that took
// the opposite default would silently stop rotating the moment an operator ran
// without an elector.
//
// The consequence is stated where it belongs, in the boot log: running more than
// one replica with election DISABLED is the configuration in which duplicate
// rotation comes back.
func Holds(e Election) bool {
	return e == nil || e.IsLeader()
}

// Wrap converts a possibly-nil *Elector into an Election, and every caller that
// holds a *Elector must use it.
//
// ============================================================================
// THIS EXISTS TO PREVENT A SILENT, SEVERE BUG
// ============================================================================
//
// Assigning a nil *Elector straight into an Election field does NOT produce a nil
// interface — it produces a non-nil interface holding a nil pointer. Holds would
// then call IsLeader on it, get false (the nil receiver is handled), and conclude
// that this replica is a follower. Every leader-gated worker would stop.
//
// The result is a service that silently never rotates a secret whenever election
// is turned OFF — the exact opposite of what disabling election is supposed to do,
// with no error anywhere. Wrap collapses the nil pointer to a nil interface so
// "no election" means "no election".
//
//	// WRONG: opts.Leader is non-nil even when elector is nil.
//	opts.Leader = elector
//	// RIGHT:
//	opts.Leader = leader.Wrap(elector)
func Wrap(e *Elector) Election {
	if e == nil {
		return nil
	}
	return e
}

// Options tunes an Elector. A zero Options is a working configuration.
type Options struct {
	// Name identifies the lock. It is hashed into the advisory-lock key, so it must
	// be stable across releases: changing it elects a SECOND leader that believes it
	// owns the same work. Defaults to DefaultLockName.
	Name string
	// RetryInterval is how often a follower re-campaigns. Defaults to
	// DefaultRetryInterval.
	RetryInterval time.Duration
	// HeartbeatInterval is how often a leader verifies its session. Defaults to
	// DefaultHeartbeatInterval.
	HeartbeatInterval time.Duration
	// ResignTimeout bounds the unlock on shutdown. Defaults to DefaultResignTimeout.
	ResignTimeout time.Duration
}

func (o Options) withDefaults() Options {
	if o.Name == "" {
		o.Name = DefaultLockName
	}
	if o.RetryInterval <= 0 {
		o.RetryInterval = DefaultRetryInterval
	}
	if o.HeartbeatInterval <= 0 {
		o.HeartbeatInterval = DefaultHeartbeatInterval
	}
	if o.ResignTimeout <= 0 {
		o.ResignTimeout = DefaultResignTimeout
	}
	return o
}

// Elector campaigns for, holds, and releases the leader lock.
//
// It satisfies Election, so it is passed directly to any leader-gated worker.
type Elector struct {
	locker Locker
	key    int64
	opts   Options

	// mu guards session. It is NOT held while IsLeader is read: the flag below is
	// the hot path (every worker tick) and must never contend with a heartbeat
	// round trip to the database.
	mu      sync.Mutex
	session Session

	leader atomic.Bool
	// promotions counts elections won, for the test that asserts a follower is
	// actually promoted rather than merely reporting true.
	promotions atomic.Int64
}

// New builds an Elector over a Locker.
//
// The Locker seam is what makes this package testable without a database: the
// production implementation is NewPgLocker, and a test supplies an in-memory one
// that behaves the way PostgreSQL does (one holder at a time, loss on session
// death). That matters because the properties worth testing here — only one
// replica rotates, a follower is promoted when the leader's session dies — are
// properties of the ELECTION, not of PostgreSQL's lock manager.
func New(locker Locker, opts Options) *Elector {
	opts = opts.withDefaults()
	return &Elector{
		locker: locker,
		key:    LockKey(opts.Name),
		opts:   opts,
	}
}

// Name returns the lock name this Elector campaigns for.
func (e *Elector) Name() string { return e.opts.Name }

// Key returns the advisory-lock key, for a boot log line an operator can match
// against pg_locks.
func (e *Elector) Key() int64 { return e.key }

// IsLeader implements Election.
func (e *Elector) IsLeader() bool { return e != nil && e.leader.Load() }

// Promotions reports how many times this process has won an election.
func (e *Elector) Promotions() int64 {
	if e == nil {
		return 0
	}
	return e.promotions.Load()
}

// Elect makes ONE attempt to take the lock.
//
// It reports (true, nil) when this process is the leader — including when it
// already was, so Elect is idempotent — and (false, nil) when another replica
// holds it. A (false, non-nil) return is a database problem, NOT a lost election:
// the caller must not treat it as "someone else is leader", because the honest
// state is "unknown", and the loop simply retries.
func (e *Elector) Elect(ctx context.Context) (bool, error) {
	if e == nil {
		return false, errors.New("leader: nil elector")
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.session != nil {
		return true, nil
	}
	session, acquired, err := e.locker.TryLock(ctx, e.key)
	if err != nil {
		return false, fmt.Errorf("leader: campaign for %q: %w", e.opts.Name, err)
	}
	if !acquired {
		return false, nil
	}
	e.session = session
	e.leader.Store(true)
	e.promotions.Add(1)
	slog.Info("leader: elected — this replica owns the background workers",
		"lock", e.opts.Name, "lock_key", e.key)
	return true, nil
}

// Resign releases the lock and stops reporting leadership.
//
// THE FLAG IS CLEARED BEFORE THE UNLOCK, deliberately. The two orderings fail
// differently and only one of them fails safely: clearing first means there is a
// brief window in which nobody acts as leader, and clearing last would mean a
// window in which this process still claims leadership after the lock is
// available for another replica to take. For background work, a gap is free and an
// overlap duplicates rotations.
//
// Resign is idempotent and safe to call on a process that never won.
func (e *Elector) Resign(ctx context.Context) error {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.releaseLocked(ctx, "resigned")
}

// releaseLocked drops the session. Caller holds mu.
func (e *Elector) releaseLocked(ctx context.Context, why string) error {
	e.leader.Store(false)
	session := e.session
	if session == nil {
		return nil
	}
	e.session = nil

	if err := session.Release(ctx); err != nil {
		// Not fatal and not silent. The fallback is sound: Session.Release destroys
		// the connection rather than returning it to the pool when the unlock
		// itself fails, and killing the session is what releases a session-scoped
		// advisory lock — so a failed unlock still ends with the lock free.
		slog.Warn("leader: releasing the lock reported an error; the session was destroyed instead",
			"lock", e.opts.Name, "reason", why, "error", err)
		return err
	}
	slog.Info("leader: released the lock", "lock", e.opts.Name, "reason", why)
	return nil
}

// Run campaigns until ctx is cancelled, then resigns.
//
// It never returns an error, for the same reason the rotator does not: a service
// that refuses to serve secrets because it could not decide who runs the
// background work has turned a degradation into an outage. A replica that cannot
// reach the database to campaign is a follower — which is exactly the safe answer.
//
// Run is the whole lifecycle in one call, so cmd/secretd hands it to the same
// errgroup that supervises the two servers and SIGTERM drains it with them.
func (e *Elector) Run(ctx context.Context) {
	if e == nil {
		return
	}
	slog.Info("leader: campaigning for the background-worker lock",
		"lock", e.opts.Name, "lock_key", e.key,
		"retry", e.opts.RetryInterval.String(), "heartbeat", e.opts.HeartbeatInterval.String())

	defer func() {
		// context.WithoutCancel: ctx is already cancelled by the time this runs, and
		// an unlock on a cancelled context fails immediately — which would leave the
		// lock held until PostgreSQL noticed the backend was gone. A bounded fresh
		// context gives the clean release a chance and still cannot hang shutdown.
		resignCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), e.opts.ResignTimeout)
		defer cancel()
		_ = e.Resign(resignCtx)
	}()

	for {
		e.step(ctx)

		wait := e.opts.RetryInterval
		if e.IsLeader() {
			wait = e.opts.HeartbeatInterval
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// step is one iteration of the campaign loop: campaign if a follower, verify if a
// leader. Exported behaviour is tested through Elect/Heartbeat; this exists so Run
// stays readable.
func (e *Elector) step(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	if !e.IsLeader() {
		if _, err := e.Elect(ctx); err != nil {
			// Warn, not error: a replica that cannot campaign is a follower, and a
			// follower is the safe state.
			slog.Warn("leader: campaign failed — remaining a follower and retrying",
				"lock", e.opts.Name, "retry_in", e.opts.RetryInterval.String(), "error", err)
		}
		return
	}
	if err := e.Heartbeat(ctx); err != nil {
		slog.Warn("leader: lock session lost — standing down so another replica can take over",
			"lock", e.opts.Name, "error", err)
	}
}

// Heartbeat verifies that this process still holds the lock, and stands down if it
// does not.
//
// This is NOT a lease renewal. A session-scoped advisory lock needs no renewing —
// it is held for as long as the session lives. What this detects is the session
// having DIED (the backend was terminated, the connection dropped, the database
// restarted), because in that case PostgreSQL has already handed the lock to
// whoever asks next while this process still believes it is the leader.
//
// Standing down on failure is the whole point: it is what turns "leader crashed"
// into "another replica is promoted within one heartbeat".
func (e *Elector) Heartbeat(ctx context.Context) error {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	session := e.session
	if session == nil {
		e.leader.Store(false)
		return nil
	}
	if err := session.Ping(ctx); err != nil {
		// Do not report the release error over the ping error: the ping error is the
		// cause and the one an operator needs.
		_ = e.releaseLocked(ctx, "session lost")
		return err
	}
	return nil
}

// RunPeriodic runs fn on an interval, but ONLY while e reports leadership.
//
// This is the adoption point for every background worker in this service — the
// webhook re-drive worker, a lease reaper, a version-retention pruner — so that
// making a new worker multi-replica-safe is one call rather than a re-derivation
// of the gating, the transition logging and the panic recovery:
//
//	go leader.RunPeriodic(ctx, elector, "webhook-redrive", time.Minute, func(c context.Context) error {
//	    return redriver.Drain(c)
//	})
//
// The contract it provides, and the reasons each part is not optional:
//
//   - LEADER-GATED. fn is not called at all on a follower. A worker must not
//     implement this check itself, because the interesting part is the TRANSITION
//     logging below and every worker would get it subtly differently.
//   - TRANSITIONS ARE LOGGED ONCE. "skipping, not leader" on every tick of every
//     worker is noise that trains an operator to ignore the log. The change of
//     state is logged; the steady state is not.
//   - A PANIC IS RECOVERED. This runs on its own goroutine, where an unrecovered
//     panic takes the whole process down — so a bug in a maintenance loop would
//     become the reason the vault stopped serving secrets.
//   - AN ERROR IS NEVER FATAL. A failing pass is an ordinary condition (the
//     database blips, a row is locked) and is retried on the next tick.
//   - THE FIRST PASS IS NOT IMMEDIATE. Unlike the rotator, maintenance work has no
//     "it might be overdue right now" property worth a burst at boot, and every
//     replica starting at once would put every first pass in the same instant.
//
// It returns only when ctx is cancelled.
func RunPeriodic(ctx context.Context, e Election, name string, interval time.Duration, fn func(context.Context) error) {
	if fn == nil {
		return
	}
	if interval <= 0 {
		interval = time.Minute
	}
	slog.Info("periodic worker: started", "worker", name, "interval", interval.String(),
		"leader_gated", e != nil)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	wasLeader := true // so the first skip logs the transition to follower
	for {
		select {
		case <-ctx.Done():
			slog.Info("periodic worker: stopped", "worker", name)
			return
		case <-ticker.C:
		}
		if ctx.Err() != nil {
			continue
		}

		if !Holds(e) {
			if wasLeader {
				slog.Info("periodic worker: paused — this replica is not the leader", "worker", name)
				wasLeader = false
			}
			continue
		}
		if !wasLeader {
			slog.Info("periodic worker: resumed — this replica is the leader", "worker", name)
			wasLeader = true
		}
		runOnce(ctx, name, fn)
	}
}

// runOnce isolates the recover, so a panic cannot skip the ticker.
func runOnce(ctx context.Context, name string, fn func(context.Context) error) {
	defer func() {
		if rec := recover(); rec != nil {
			slog.Error("periodic worker: pass panicked — the loop continues",
				"worker", name, "panic", rec)
		}
	}()
	if err := fn(ctx); err != nil {
		slog.Warn("periodic worker: pass failed — retrying on the next tick",
			"worker", name, "error", err)
	}
}
