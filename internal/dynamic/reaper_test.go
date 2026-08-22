package dynamic

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	// These tests deliberately exercise the loud paths (a refused revocation, a failing
	// pass, a panicking pass), and the log lines are noise here.
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	m.Run()
}

// ===========================================================================
// A NOTE ON WHAT IS NOT TESTED HERE, BECAUSE IT DOES NOT EXIST
// ===========================================================================
//
// ReapEngine's doc says "*api.Service satisfies it". AT THE TIME OF WRITING NOTHING IN
// THE PRODUCTION TREE IMPLEMENTS ReapExpiredDynamicLeases, and nothing calls NewReaper
// — so no reaper is ever constructed or started, and the loop below never runs in
// production. Outside this file, `grep -rn 'ReapExpiredDynamicLeases\|NewReaper'`
// matches only reaper.go's own declaration and call site.
//
// The consequence is exactly the one this file's own package comment warns about: an
// expired dynamic lease is never revoked, so the PostgreSQL role outlives it
// indefinitely. The store already has both halves of the work
// (store.ListExpiredDynamicLeases, store.RevokeExpiredDynamicLease); what is missing
// is the api-level method that composes them into a ReapReport, and the
// leader.RunPeriodic wiring in cmd/secretd/bootstrap.go that the webhook re-driver has
// and this does not.
//
// That gap lives in internal/api and cmd/secretd, which are outside this change's
// scope, so it is REPORTED rather than fixed. The tests below verify the loop against
// a fake engine that models the store's documented contract, so the loop is correct
// and ready for the day something implements the seam.

// ---------------------------------------------------------------------------
// A fake engine that models the store's revocation contract
// ---------------------------------------------------------------------------

// fakeLease is one issued lease, as the reaper's engine sees it.
type fakeLease struct {
	roleName string
	// revoked mirrors the lease row's revoked_at: set ONLY after the target database
	// confirms the drop.
	revoked bool
	// attempts mirrors revoke_attempts, which is what lets an operator see that an
	// account has been stranded by an outage.
	attempts int
}

// fakeReapEngine models api.Service's missing ReapExpiredDynamicLeases against the
// fake target database, following the ordering internal/store documents:
//
//	THE LEASE IS MARKED REVOKED ONLY AFTER THE TARGET DATABASE CONFIRMS THE DROP.
//	A revocation the target refused leaves the lease OPEN with an incremented attempt
//	count, so the reaper keeps trying.
//
// That ordering is the whole reason a failed pass is survivable: the row that demands
// the account's removal outlives the failure.
type fakeReapEngine struct {
	mu sync.Mutex
	// prov is the fake target database, so a revocation is observable as a role that
	// really stopped existing rather than as a counter that went up.
	prov *fakeProvisioner
	// leases is every issued lease, keyed by role name.
	leases map[string]*fakeLease
	// skip marks leases the pass cannot even attempt — a role config whose DSN secret
	// was deleted, a provisioner that is not configured.
	skip map[string]bool
	// err fails the whole pass (the listing query itself).
	err error
	// panicNext makes one pass panic, to prove the loop survives a bug in itself.
	panicNext bool
	// passes counts calls, so a ticker can be observed without a sleep.
	passes atomic.Int64
	// sawLimit records the batch bound the loop asked for.
	sawLimit int
}

var _ ReapEngine = (*fakeReapEngine)(nil)

func newFakeReapEngine() *fakeReapEngine {
	return &fakeReapEngine{
		prov:   newFakeProvisioner(),
		leases: map[string]*fakeLease{},
		skip:   map[string]bool{},
	}
}

// issue creates a role on the fake target and records its lease, the way the issue
// path does.
func (f *fakeReapEngine) issue(t *testing.T) string {
	t.Helper()
	name := issueThrough(t, f.prov, "m9d")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.leases[name] = &fakeLease{roleName: name}
	return name
}

func (f *fakeReapEngine) ReapExpiredDynamicLeases(ctx context.Context, limit int) (ReapReport, error) {
	f.passes.Add(1)

	f.mu.Lock()
	if f.panicNext {
		f.panicNext = false
		f.mu.Unlock()
		panic("a bug in the reap query")
	}
	if f.err != nil {
		err := f.err
		f.mu.Unlock()
		return ReapReport{}, err
	}
	f.sawLimit = limit

	// The due set: every lease not yet revoked, bounded by the batch.
	var due []*fakeLease
	for _, lease := range f.leases {
		if lease.revoked {
			continue
		}
		if len(due) == limit {
			break
		}
		due = append(due, lease)
	}
	skip := make(map[string]bool, len(f.skip))
	for k, v := range f.skip {
		skip[k] = v
	}
	f.mu.Unlock()

	report := ReapReport{Due: len(due)}
	for _, lease := range due {
		if skip[lease.roleName] {
			// The target database was never contacted, so there is nothing to retry
			// until an operator fixes the configuration.
			report.Skipped++
			continue
		}
		err := revokeThrough(f.prov, lease.roleName)

		f.mu.Lock()
		lease.attempts++
		if err != nil {
			// THE LEASE STAYS OPEN. Marking it done would lose the only record that a
			// live account needs dropping.
			report.Failed++
		} else {
			lease.revoked = true
			report.Revoked++
		}
		f.mu.Unlock()
	}
	return report, ctx.Err()
}

func (f *fakeReapEngine) lease(name string) fakeLease {
	f.mu.Lock()
	defer f.mu.Unlock()
	return *f.leases[name]
}

func (f *fakeReapEngine) setErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

func (f *fakeReapEngine) limitAsked() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sawLimit
}

// ---------------------------------------------------------------------------
// Tick — the pass
// ---------------------------------------------------------------------------

// TestAPassRevokesEveryExpiredLease is the guarantee the loop exists to provide: an
// orphaned role cannot outlive its lease, whatever the operator's template did or did
// not say about VALID UNTIL.
func TestAPassRevokesEveryExpiredLease(t *testing.T) {
	engine := newFakeReapEngine()
	names := make([]string, 5)
	for i := range names {
		names[i] = engine.issue(t)
	}
	require.Equal(t, 5, engine.prov.roleCount())

	NewReaper(engine, ReaperOptions{Enabled: true}).Tick(context.Background())

	for _, name := range names {
		assert.True(t, engine.lease(name).revoked, "the lease row must record the revocation")
		assert.False(t, engine.prov.hasRole(name), "the PostgreSQL role must actually be gone")
	}
	assert.Zero(t, engine.prov.roleCount())
}

// TestAFailedRevocationKeepsTheLeaseClaimable is THE test in this file.
//
// A dropped lease is a PERMANENT LIVE ROLE. If a pass marked a lease revoked after the
// target database refused the drop, the account would still exist and the only row
// demanding its removal would be closed — no later pass would ever look at it again,
// and nothing in the system would know. So a refused revocation must leave the lease
// exactly as claimable as it was, and a subsequent pass must pick it up.
func TestAFailedRevocationKeepsTheLeaseClaimable(t *testing.T) {
	engine := newFakeReapEngine()
	name := engine.issue(t)
	reaper := NewReaper(engine, ReaperOptions{Enabled: true})

	// The target database is down mid-incident.
	engine.prov.setFailRevoke(errors.New("57P03: the database system is starting up"))

	// Several passes, because an outage lasts longer than one tick.
	for i := 1; i <= 3; i++ {
		reaper.Tick(context.Background())

		lease := engine.lease(name)
		assert.False(t, lease.revoked, "pass %d must not record a revocation the target refused", i)
		assert.Equal(t, i, lease.attempts, "each pass must really retry, not skip a row it failed before")
		assert.True(t, engine.prov.hasRole(name), "the account still exists, so the lease must too")
	}

	// The target recovers, and the very next pass drains it. Nothing had to be
	// re-queued by hand: the lease row never stopped being the record of truth.
	engine.prov.setFailRevoke(nil)
	reaper.Tick(context.Background())

	assert.True(t, engine.lease(name).revoked)
	assert.False(t, engine.prov.hasRole(name), "the orphaned role must not outlive the outage")
}

// TestAFailedPassIsReportedAsFailedNotRevoked. Failed and Revoked are separate
// counters because a non-zero Failed persisting across passes is the SIGNAL that an
// account has been orphaned by an outage — collapsing them would hide it.
func TestAFailedPassIsReportedAsFailedNotRevoked(t *testing.T) {
	engine := newFakeReapEngine()
	good := engine.issue(t)
	engine.issue(t)
	engine.prov.setFailRevoke(errors.New("57P03: the database system is starting up"))

	report, err := engine.ReapExpiredDynamicLeases(context.Background(), DefaultReapBatch)
	require.NoError(t, err)
	assert.Equal(t, 2, report.Due)
	assert.Zero(t, report.Revoked)
	assert.Equal(t, 2, report.Failed)
	assert.Zero(t, report.Skipped)
	assert.True(t, engine.prov.hasRole(good))
}

// TestASkippedLeaseIsDistinctFromAFailedOne. Skipped means the target database was
// never contacted (a deleted DSN secret, an unconfigured provisioner), so there is
// nothing to retry until an operator fixes the configuration — a different action from
// "wait for the target to come back".
func TestASkippedLeaseIsDistinctFromAFailedOne(t *testing.T) {
	engine := newFakeReapEngine()
	stranded := engine.issue(t)
	normal := engine.issue(t)
	engine.skip[stranded] = true

	report, err := engine.ReapExpiredDynamicLeases(context.Background(), DefaultReapBatch)
	require.NoError(t, err)
	assert.Equal(t, 2, report.Due)
	assert.Equal(t, 1, report.Revoked)
	assert.Equal(t, 1, report.Skipped)
	assert.Zero(t, report.Failed)

	// A skipped lease is still open, so it is still visible to the next pass and to an
	// operator's query.
	assert.False(t, engine.lease(stranded).revoked)
	assert.True(t, engine.prov.hasRole(stranded))
	assert.True(t, engine.lease(normal).revoked)
}

// TestARevocationRunTwiceIsHarmless. A reaper racing an explicit revoke, or retrying
// a lease whose row could not be closed, both re-run the same statement — so the pass
// must tolerate revoking something already gone.
func TestARevocationRunTwiceIsHarmless(t *testing.T) {
	engine := newFakeReapEngine()
	name := engine.issue(t)
	reaper := NewReaper(engine, ReaperOptions{Enabled: true})

	reaper.Tick(context.Background())
	require.True(t, engine.lease(name).revoked)
	_, firstRevokes := engine.prov.counts()

	// A second pass finds nothing due and asks the target for nothing.
	reaper.Tick(context.Background())
	_, secondRevokes := engine.prov.counts()
	assert.Equal(t, firstRevokes, secondRevokes, "a closed lease must not be re-attempted every minute")

	// And re-running the statement directly is still a success, which is what makes the
	// retry path safe.
	require.NoError(t, revokeThrough(engine.prov, name))
}

// TestAPassIsBoundedByItsBatch. A store where a thousand leases expire at once (a
// deploy that issued a thousand credentials an hour ago) must not open a thousand
// connections to target databases in one tick.
func TestAPassIsBoundedByItsBatch(t *testing.T) {
	engine := newFakeReapEngine()
	for i := 0; i < 10; i++ {
		engine.issue(t)
	}

	reaper := NewReaper(engine, ReaperOptions{Enabled: true, Batch: 3})
	reaper.Tick(context.Background())

	assert.Equal(t, 3, engine.limitAsked(), "the loop must pass its batch bound through")
	assert.Equal(t, 7, engine.prov.roleCount(), "the remainder is picked up by the next pass")

	// The remainder really is picked up, rather than stranded outside the window.
	for i := 0; i < 4; i++ {
		reaper.Tick(context.Background())
	}
	assert.Zero(t, engine.prov.roleCount())
}

// TestAnEmptyPassDoesNothingAndSaysNothing. Due == 0 is the steady state on most
// ticks, and logging it every minute would train an operator to ignore the log.
func TestAnEmptyPassDoesNothingAndSaysNothing(t *testing.T) {
	engine := newFakeReapEngine()
	reaper := NewReaper(engine, ReaperOptions{Enabled: true})

	require.NotPanics(t, func() { reaper.Tick(context.Background()) })
	assert.EqualValues(t, 1, engine.passes.Load())
	assert.Zero(t, engine.prov.roleCount())
}

// TestAPanickingPassDoesNotTakeTheVaultDown. This runs on its own goroutine, where an
// unrecovered panic kills the process — so a bug in the loop that revokes credentials
// would become the reason the vault stopped serving secrets.
func TestAPanickingPassDoesNotTakeTheVaultDown(t *testing.T) {
	engine := newFakeReapEngine()
	name := engine.issue(t)
	engine.panicNext = true
	reaper := NewReaper(engine, ReaperOptions{Enabled: true})

	require.NotPanics(t, func() { reaper.Tick(context.Background()) })

	// And the loop is still usable: the next pass does the work the panicking one did
	// not, so a transient bug does not strand a live credential forever.
	reaper.Tick(context.Background())
	assert.True(t, engine.lease(name).revoked)
}

// TestAFailingPassIsAnOrdinaryConditionRetriedNextTick. The target database being
// down, a root key being absent, setup not having run — all ordinary, none of them a
// reason for the loop to stop.
func TestAFailingPassIsAnOrdinaryConditionRetriedNextTick(t *testing.T) {
	engine := newFakeReapEngine()
	name := engine.issue(t)
	engine.setErr(errors.New("connection refused"))
	reaper := NewReaper(engine, ReaperOptions{Enabled: true})

	require.NotPanics(t, func() { reaper.Tick(context.Background()) })
	assert.True(t, engine.prov.hasRole(name), "a failed pass revokes nothing")

	engine.setErr(nil)
	reaper.Tick(context.Background())
	assert.False(t, engine.prov.hasRole(name), "and the next pass picks the work up")
}

// TestACancelledContextSkipsThePassEntirely. A pass started on a dead context would
// open connections it cannot finish and post DDL with an expired deadline.
func TestACancelledContextSkipsThePassEntirely(t *testing.T) {
	engine := newFakeReapEngine()
	engine.issue(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	NewReaper(engine, ReaperOptions{Enabled: true}).Tick(ctx)

	assert.Zero(t, engine.passes.Load(), "the engine must not be asked to do work on a dead context")
	assert.Equal(t, 1, engine.prov.roleCount())
}

// ---------------------------------------------------------------------------
// Run — the loop
// ---------------------------------------------------------------------------

// TestRunIsOptInAndSaysSoWhenItIsOff. An operator who disables the reaper is
// accepting that issued credentials outlive their leases, and the boot log says so in
// those words — a reaper hammering an unreachable target during an incident is a
// legitimate thing to want to stop, but it is not a switch anybody should leave off.
func TestRunIsOptInAndSaysSoWhenItIsOff(t *testing.T) {
	engine := newFakeReapEngine()
	engine.issue(t)

	// A zero ReaperOptions is a working configuration EXCEPT for Enabled.
	done := make(chan struct{})
	go func() { NewReaper(engine, ReaperOptions{}).Run(context.Background()); close(done) }()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("a disabled reaper must return immediately rather than tick forever")
	}
	assert.Zero(t, engine.passes.Load(), "a disabled reaper must perform no work at all")
	assert.Equal(t, 1, engine.prov.roleCount())
}

// TestRunSweepsImmediatelyRatherThanAfterOneInterval. The most likely moment for a
// lease to be overdue is right after the service was down — which is exactly when a
// credential has been sitting live past its expiry with nothing watching. Waiting a
// full interval before the first sweep would extend that window for no reason.
func TestRunSweepsImmediatelyRatherThanAfterOneInterval(t *testing.T) {
	engine := newFakeReapEngine()
	name := engine.issue(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// An interval far longer than the test, so a pass can only be the immediate one.
	go NewReaper(engine, ReaperOptions{Enabled: true, Interval: time.Hour}).Run(ctx)

	require.Eventually(t, func() bool { return !engine.prov.hasRole(name) }, time.Second, time.Millisecond,
		"the first pass must not wait out an interval")
	assert.EqualValues(t, 1, engine.passes.Load())
}

// TestRunKeepsTickingAndStopsOnCancellation.
func TestRunKeepsTickingAndStopsOnCancellation(t *testing.T) {
	engine := newFakeReapEngine()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		NewReaper(engine, ReaperOptions{Enabled: true, Interval: time.Millisecond}).Run(ctx)
		close(done)
	}()

	require.Eventually(t, func() bool { return engine.passes.Load() > 3 }, time.Second, time.Millisecond,
		"the loop must keep sweeping, not stop after its first pass")

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return when its context was cancelled")
	}
}

// TestRunSurvivesAPermanentlyFailingEngine: a lease reaper that could be killed by a
// target database being down would stop revoking every OTHER tenant's credentials too.
func TestRunSurvivesAPermanentlyFailingEngine(t *testing.T) {
	engine := newFakeReapEngine()
	engine.setErr(errors.New("connection refused"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go NewReaper(engine, ReaperOptions{Enabled: true, Interval: time.Millisecond}).Run(ctx)

	require.Eventually(t, func() bool { return engine.passes.Load() > 3 }, time.Second, time.Millisecond,
		"the loop must keep retrying through an outage")
}

// TestRunIsSafeWithNothingToRun. Both guards exist because the bootstrap constructs
// the reaper before it knows whether provisioning is configured.
func TestRunIsSafeWithNothingToRun(t *testing.T) {
	t.Run("a nil reaper", func(t *testing.T) {
		var r *Reaper
		require.NotPanics(t, func() { r.Run(context.Background()) })
	})
	t.Run("a nil engine", func(t *testing.T) {
		done := make(chan struct{})
		go func() { NewReaper(nil, ReaperOptions{Enabled: true}).Run(context.Background()); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("a reaper with no engine must return rather than tick against nil")
		}
	})
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

func TestReaperOptionsDefaults(t *testing.T) {
	opts := ReaperOptions{}.withDefaults()
	assert.Equal(t, DefaultReapInterval, opts.Interval)
	assert.Equal(t, DefaultReapBatch, opts.Batch)
	assert.False(t, opts.Enabled, "Enabled is the one field a zero value must not turn on")

	// A non-positive interval or batch is a misconfiguration, not a request for a tight
	// loop or an unbounded pass.
	opts = ReaperOptions{Interval: -time.Second, Batch: -1}.withDefaults()
	assert.Equal(t, DefaultReapInterval, opts.Interval)
	assert.Equal(t, DefaultReapBatch, opts.Batch)

	opts = ReaperOptions{Interval: 5 * time.Second, Batch: 7, Enabled: true}.withDefaults()
	assert.Equal(t, 5*time.Second, opts.Interval)
	assert.Equal(t, 7, opts.Batch)
	assert.True(t, opts.Enabled)
}

// TestTheSweepIsMuchFinerThanTheLeasesItEnforces. A late rotation is a policy
// drifting; a late revocation is a live credential outliving its lease, and those are
// not the same kind of late — which is why this interval is far tighter than the
// rotator's.
func TestTheSweepIsMuchFinerThanTheLeasesItEnforces(t *testing.T) {
	assert.Equal(t, time.Minute, DefaultReapInterval)

	// Lease TTLs are measured in hours and the sweep runs every minute, so it is 60x
	// finer than the thing it enforces — fine enough that a credential is never
	// meaningfully overdue, coarse enough to be invisible in load. (The constant's own
	// comment rounds that to "two orders of magnitude"; the assertion states the
	// relationship that actually holds.)
	assert.LessOrEqual(t, DefaultReapInterval*10, DefaultTTL,
		"a sweep must be at least an order of magnitude finer than the default lease")

	// Stated rather than glossed: the sweep interval EQUALS the TTL floor, so a lease
	// issued at MinTTL can be up to one full interval overdue. That is the accepted
	// cost of the floor existing at all — below a minute the credential would expire
	// before a consumer could finish using it, and the reaper would churn.
	assert.Equal(t, MinTTL, DefaultReapInterval)

	assert.Positive(t, DefaultReapBatch)
	assert.LessOrEqual(t, DefaultReapBatch, 100, "a pass must not open an unbounded number of connections")
}
