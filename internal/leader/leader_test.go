package leader

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
	// These tests deliberately exercise the loud paths (a lost lock, a failed
	// campaign, a panicking worker), and the log lines are noise here.
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	m.Run()
}

// ---------------------------------------------------------------------------
// A fake lock manager that behaves the way PostgreSQL does
// ---------------------------------------------------------------------------

// fakeLocks models the properties of a session-scoped advisory lock that the
// election's correctness actually rests on:
//
//	MUTUAL EXCLUSION  one holder per key at a time; a second TryLock returns false
//	                  rather than blocking.
//	DEATH RELEASES    killing a session frees the key with no reaper and no
//	                  timeout — which is the whole reason the advisory lock was
//	                  chosen over a lease table, so it is the property under test.
//
// Modelling those rather than talking to a real database is what makes "only one
// replica rotates" and "a follower is promoted when the leader dies" testable in
// milliseconds. They are properties of the ELECTION; PostgreSQL's lock manager is
// not the thing that could be wrong here.
type fakeLocks struct {
	mu       sync.Mutex
	held     map[int64]*fakeSession
	failWith error
	// attempts counts TryLock calls, so a test can prove a follower is really
	// re-campaigning rather than reporting a cached answer.
	attempts atomic.Int64
}

func newFakeLocks() *fakeLocks {
	return &fakeLocks{held: map[int64]*fakeSession{}}
}

func (f *fakeLocks) TryLock(_ context.Context, key int64) (Session, bool, error) {
	f.attempts.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failWith != nil {
		return nil, false, f.failWith
	}
	if _, taken := f.held[key]; taken {
		return nil, false, nil
	}
	s := &fakeSession{locks: f, key: key}
	f.held[key] = s
	return s, true, nil
}

// fail makes every subsequent campaign report a database problem.
func (f *fakeLocks) fail(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failWith = err
}

// holder reports which session currently owns key.
func (f *fakeLocks) holder(key int64) *fakeSession {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.held[key]
}

// fakeSession is one held lock.
type fakeSession struct {
	locks *fakeLocks
	key   int64
	dead  atomic.Bool
}

// kill simulates the backend going away — a SIGKILLed replica, an evicted
// container, a terminated backend, a database restart. The lock is released with no
// cooperation from the owner, which is exactly what a session-scoped advisory lock
// does and exactly what a lease table cannot do without a reaper.
func (s *fakeSession) kill() {
	s.dead.Store(true)
	s.locks.mu.Lock()
	defer s.locks.mu.Unlock()
	if s.locks.held[s.key] == s {
		delete(s.locks.held, s.key)
	}
}

func (s *fakeSession) Ping(context.Context) error {
	if s.dead.Load() {
		return errors.New("advisory-lock session is not alive: connection closed")
	}
	return nil
}

func (s *fakeSession) Release(context.Context) error {
	if s.dead.Load() {
		return errors.New("session already gone")
	}
	s.dead.Store(true)
	s.locks.mu.Lock()
	defer s.locks.mu.Unlock()
	if s.locks.held[s.key] == s {
		delete(s.locks.held, s.key)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Lock keys
// ---------------------------------------------------------------------------

// TestLockKeyIsStableAndNamespaced. Stability is load-bearing: the key is derived
// from a name, so if the derivation changed between releases a rolling deploy would
// have the old and new replicas holding two DIFFERENT locks and both believing they
// own the background work — the exact double-rotation the election exists to stop.
func TestLockKeyIsStableAndNamespaced(t *testing.T) {
	assert.Equal(t, LockKey(DefaultLockName), LockKey(DefaultLockName), "the derivation must be deterministic")
	assert.NotEqual(t, LockKey("background-workers"), LockKey("something-else"))

	// Non-negative, so a log line matches a pg_locks row without a sign to explain.
	assert.GreaterOrEqual(t, LockKey(DefaultLockName), int64(0))
	assert.GreaterOrEqual(t, LockKey("a"), int64(0))
	assert.GreaterOrEqual(t, LockKey(""), int64(0))

	// Namespaced, so another maintainerd service sharing the database cannot collide
	// on a short generic name. Advisory locks are scoped to the DATABASE, not to a
	// schema or table, so this is the only thing separating them.
	assert.NotEqual(t, LockKey("background-workers"), LockKey(LockNamespace+"background-workers"),
		"the namespace must be applied by LockKey, not expected from the caller")
}

// ---------------------------------------------------------------------------
// Holds / Wrap — the nil semantics
// ---------------------------------------------------------------------------

// TestHoldsTreatsNoElectionAsSoleOwner. A nil Election means "no election is
// configured", which must read as "this is the only process" — otherwise a
// single-replica deployment, and every test that does not care about election,
// would silently stop doing background work.
func TestHoldsTreatsNoElectionAsSoleOwner(t *testing.T) {
	assert.True(t, Holds(nil), "no election configured must mean this process may work")
}

func TestHoldsDelegatesToTheElection(t *testing.T) {
	locks := newFakeLocks()
	e := New(locks, Options{})
	assert.False(t, Holds(e), "a process that has not won must not work")

	won, err := e.Elect(context.Background())
	require.NoError(t, err)
	require.True(t, won)
	assert.True(t, Holds(e))
}

// asElection performs the bare, unwrapped assignment that production code must never
// do — storing a *Elector directly in an Election field. It is the mistake Wrap exists
// to prevent, reproduced here so the test can assert what it actually costs.
func asElection(e *Elector) Election { return e }

// TestWrapCollapsesATypedNil is the regression test for a silent, severe bug.
//
// Assigning a nil *Elector straight into an Election field yields a NON-nil
// interface holding a nil pointer. Holds would then call IsLeader, get false, and
// conclude this replica is a follower — so every leader-gated worker would stop
// whenever an operator DISABLED election, which is the exact opposite of what
// disabling it should do, with no error anywhere.
func TestWrapCollapsesATypedNil(t *testing.T) {
	var nilElector *Elector

	// The trap itself, asserted so the reason Wrap exists cannot be dismissed as
	// redundant by a future reader.
	//
	// The comparison is written as a bare `!= nil` rather than assert.NotNil,
	// deliberately: testify's NotNil uses reflection and reports an interface holding
	// a nil pointer as nil, which is precisely the distinction under test here. Go's
	// own interface comparison is the thing production code performs, so it is the
	// thing this asserts.
	//
	// It goes through asElection rather than a direct assignment so the conversion is
	// opaque to static analysis. Given a local of known concrete type, staticcheck
	// reports the comparison as always true (SA4023) — which is correct, and is exactly
	// the bug: "always true" is what makes the bare assignment silently break every
	// leader-gated worker. Suppressing the check would hide the assertion's reason; a
	// function boundary keeps the assertion real.
	trap := asElection(nilElector)
	assert.True(t, trap != nil, "a nil *Elector in an interface field is NOT a nil interface")
	assert.False(t, Holds(trap), "which is why the bare assignment stops all background work")

	// Wrap is the fix.
	wrapped := Wrap(nilElector)
	assert.True(t, wrapped == nil, "Wrap must collapse a nil pointer to a nil interface")
	assert.True(t, Holds(wrapped), "wrapped nil must mean no election, so work proceeds")

	elected := New(newFakeLocks(), Options{})
	assert.True(t, Wrap(elected) != nil, "a real elector must survive Wrap unchanged")
	assert.False(t, Holds(Wrap(elected)), "a real elector that has not won is still a follower")
}

// ---------------------------------------------------------------------------
// Election
// ---------------------------------------------------------------------------

// TestOnlyOneOfTwoInstancesWins is the core guarantee: two replicas campaign for
// the same lock and exactly one of them may act.
func TestOnlyOneOfTwoInstancesWins(t *testing.T) {
	locks := newFakeLocks()
	a := New(locks, Options{})
	b := New(locks, Options{})

	wonA, err := a.Elect(context.Background())
	require.NoError(t, err)
	wonB, err := b.Elect(context.Background())
	require.NoError(t, err)

	assert.True(t, wonA)
	assert.False(t, wonB, "the second replica must lose rather than block")
	assert.True(t, a.IsLeader())
	assert.False(t, b.IsLeader())

	// Losing an election is not an error condition, so nothing was reported.
	assert.Equal(t, int64(1), a.Promotions())
	assert.Equal(t, int64(0), b.Promotions())
}

// TestBothInstancesCampaigningConcurrentlyElectExactlyOneLeader. The interesting
// case is the race at startup, when N replicas come up together.
func TestBothInstancesCampaigningConcurrentlyElectExactlyOneLeader(t *testing.T) {
	locks := newFakeLocks()
	const instances = 8

	electors := make([]*Elector, instances)
	for i := range electors {
		electors[i] = New(locks, Options{})
	}

	var wg sync.WaitGroup
	for _, e := range electors {
		wg.Add(1)
		go func(e *Elector) {
			defer wg.Done()
			_, _ = e.Elect(context.Background())
		}(e)
	}
	wg.Wait()

	leaders := 0
	for _, e := range electors {
		if e.IsLeader() {
			leaders++
		}
	}
	assert.Equal(t, 1, leaders, "exactly one replica may hold the lock")
}

// TestElectIsIdempotent: a leader re-campaigning must not take a second lock or
// count a second promotion.
func TestElectIsIdempotent(t *testing.T) {
	locks := newFakeLocks()
	e := New(locks, Options{})

	for i := 0; i < 3; i++ {
		won, err := e.Elect(context.Background())
		require.NoError(t, err)
		assert.True(t, won)
	}
	assert.Equal(t, int64(1), e.Promotions())
	assert.Equal(t, int64(1), locks.attempts.Load(), "an existing leader must not re-ask for the lock")
}

// TestACampaignErrorIsNotALostElection. A database problem means the answer is
// UNKNOWN, not "somebody else is leader". Conflating the two would report a healthy
// follower when what this process actually has is no answer.
func TestACampaignErrorIsNotALostElection(t *testing.T) {
	locks := newFakeLocks()
	locks.fail(errors.New("connection refused"))
	e := New(locks, Options{})

	won, err := e.Elect(context.Background())
	require.Error(t, err)
	assert.False(t, won)
	assert.False(t, e.IsLeader(), "a failed campaign must never report leadership")
	assert.Contains(t, err.Error(), DefaultLockName, "the error must name the lock being campaigned for")
}

// TestResignReleasesTheLockForAnotherReplica.
func TestResignReleasesTheLockForAnotherReplica(t *testing.T) {
	locks := newFakeLocks()
	a := New(locks, Options{})
	b := New(locks, Options{})

	require.NoError(t, must(a.Elect(context.Background())))
	require.False(t, must2(b.Elect(context.Background())))

	require.NoError(t, a.Resign(context.Background()))
	assert.False(t, a.IsLeader())

	won, err := b.Elect(context.Background())
	require.NoError(t, err)
	assert.True(t, won, "the lock must be available once the holder resigns")
}

// TestResignIsIdempotentAndSafeOnANonLeader.
func TestResignIsIdempotentAndSafeOnANonLeader(t *testing.T) {
	e := New(newFakeLocks(), Options{})
	assert.NoError(t, e.Resign(context.Background()), "a process that never won must resign cleanly")

	require.NoError(t, must(e.Elect(context.Background())))
	require.NoError(t, e.Resign(context.Background()))
	assert.NoError(t, e.Resign(context.Background()))
}

// TestHeartbeatDetectsALostSessionAndStandsDown is the promotion mechanism.
//
// A session-scoped advisory lock needs no renewal — it is held for as long as the
// session lives. What the heartbeat detects is the session having DIED, because at
// that moment PostgreSQL has already made the lock available to whoever asks next
// while this process still believes it is the leader. Standing down is what turns
// "the leader crashed" into "another replica is promoted".
func TestHeartbeatDetectsALostSessionAndStandsDown(t *testing.T) {
	locks := newFakeLocks()
	e := New(locks, Options{})
	require.NoError(t, must(e.Elect(context.Background())))
	require.NoError(t, e.Heartbeat(context.Background()), "a live session heartbeats cleanly")
	require.True(t, e.IsLeader())

	locks.holder(e.Key()).kill()

	err := e.Heartbeat(context.Background())
	require.Error(t, err)
	assert.False(t, e.IsLeader(), "a leader that lost its session must stop claiming leadership")
}

// TestLeaderLossPromotesTheOtherInstance. End to end: A leads, A dies abruptly
// (nothing is released cooperatively), B is promoted.
//
// THIS IS THE PROPERTY THE ADVISORY LOCK WAS CHOSEN FOR. There is no lease to
// expire and no reaper to run: the lock is gone the instant A's session is, so B's
// next campaign succeeds.
func TestLeaderLossPromotesTheOtherInstance(t *testing.T) {
	locks := newFakeLocks()
	a := New(locks, Options{})
	b := New(locks, Options{})

	require.NoError(t, must(a.Elect(context.Background())))
	require.False(t, must2(b.Elect(context.Background())), "B starts as a follower")

	// A is SIGKILLed: its backend disappears without unlocking anything.
	locks.holder(a.Key()).kill()

	// B's next campaign wins. Note B needed no knowledge of A at all.
	won, err := b.Elect(context.Background())
	require.NoError(t, err)
	assert.True(t, won, "a follower must be promoted once the leader's session dies")
	assert.True(t, b.IsLeader())

	// And A discovers it is no longer the leader on its next heartbeat.
	require.Error(t, a.Heartbeat(context.Background()))
	assert.False(t, a.IsLeader())
}

// TestRunCampaignsUntilCancelledThenResigns.
func TestRunCampaignsUntilCancelledThenResigns(t *testing.T) {
	locks := newFakeLocks()
	e := New(locks, Options{RetryInterval: 5 * time.Millisecond, HeartbeatInterval: 5 * time.Millisecond})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.Run(ctx); close(done) }()

	require.Eventually(t, e.IsLeader, time.Second, time.Millisecond, "Run must campaign without being asked twice")

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return when its context was cancelled")
	}
	assert.False(t, e.IsLeader(), "Run must resign on the way out")
	assert.Nil(t, locks.holder(e.Key()), "the lock must be free for another replica immediately after shutdown")
}

// TestRunPromotesAFollowerAfterTheLeaderDies exercises the loop rather than a
// single Elect: a follower whose campaigns are failing must keep trying, and take
// the lock as soon as it is free.
func TestRunPromotesAFollowerAfterTheLeaderDies(t *testing.T) {
	locks := newFakeLocks()
	a := New(locks, Options{})
	b := New(locks, Options{RetryInterval: 5 * time.Millisecond, HeartbeatInterval: 5 * time.Millisecond})

	require.NoError(t, must(a.Elect(context.Background())))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go b.Run(ctx)

	// B is losing elections, repeatedly. Proving it is really re-asking (rather than
	// caching a lost campaign) is the point of counting attempts.
	require.Eventually(t, func() bool { return locks.attempts.Load() > 3 }, time.Second, time.Millisecond)
	require.False(t, b.IsLeader(), "B must not lead while A holds the lock")

	locks.holder(a.Key()).kill()

	require.Eventually(t, b.IsLeader, time.Second, time.Millisecond,
		"B must be promoted within a retry interval of the leader dying")
}

// TestRunStandsDownWhenItsOwnSessionDies: the leader side of the same event.
func TestRunStandsDownWhenItsOwnSessionDies(t *testing.T) {
	locks := newFakeLocks()
	e := New(locks, Options{RetryInterval: time.Hour, HeartbeatInterval: 5 * time.Millisecond})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)

	require.Eventually(t, e.IsLeader, time.Second, time.Millisecond)
	locks.holder(e.Key()).kill()

	require.Eventually(t, func() bool { return !e.IsLeader() }, time.Second, time.Millisecond,
		"a leader must stop claiming leadership within a heartbeat of losing its session")
}

// TestRunSurvivesADatabaseOutage: a replica that cannot campaign is a follower, and
// the loop must keep running rather than returning.
func TestRunSurvivesADatabaseOutage(t *testing.T) {
	locks := newFakeLocks()
	locks.fail(errors.New("connection refused"))
	e := New(locks, Options{RetryInterval: 5 * time.Millisecond, HeartbeatInterval: 5 * time.Millisecond})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.Run(ctx); close(done) }()

	require.Eventually(t, func() bool { return locks.attempts.Load() > 3 }, time.Second, time.Millisecond,
		"the loop must keep campaigning through an outage")
	assert.False(t, e.IsLeader())

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after an outage")
	}
}

func TestDefaultsMakeAZeroOptionsWorkable(t *testing.T) {
	e := New(newFakeLocks(), Options{})
	assert.Equal(t, DefaultLockName, e.Name())
	assert.Equal(t, DefaultRetryInterval, e.opts.RetryInterval)
	assert.Equal(t, DefaultHeartbeatInterval, e.opts.HeartbeatInterval)
	assert.Equal(t, DefaultResignTimeout, e.opts.ResignTimeout)
}

// ---------------------------------------------------------------------------
// RunPeriodic — the adoption point for other background workers
// ---------------------------------------------------------------------------

// TestRunPeriodicDoesNotRunOnAFollower is the guarantee every worker that adopts
// this helper is buying.
func TestRunPeriodicDoesNotRunOnAFollower(t *testing.T) {
	locks := newFakeLocks()
	holder := New(locks, Options{})
	require.NoError(t, must(holder.Elect(context.Background())))

	follower := New(locks, Options{}) // lost the lock, so never a leader

	var passes atomic.Int64
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go RunPeriodic(ctx, follower, "test-worker", time.Millisecond, func(context.Context) error {
		passes.Add(1)
		return nil
	})

	time.Sleep(50 * time.Millisecond)
	assert.Zero(t, passes.Load(), "a follower must not perform the work")
}

// TestRunPeriodicRunsOnTheLeaderAndResumesOnPromotion. The gate is re-checked every
// tick, deliberately: leadership changes under a running loop, and a worker that
// cached the answer would keep working after losing the lock (or never start after
// gaining it).
func TestRunPeriodicRunsOnTheLeaderAndResumesOnPromotion(t *testing.T) {
	election := &togglableElection{}

	var passes atomic.Int64
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go RunPeriodic(ctx, election, "test-worker", time.Millisecond, func(context.Context) error {
		passes.Add(1)
		return nil
	})

	time.Sleep(30 * time.Millisecond)
	require.Zero(t, passes.Load(), "no work while a follower")

	election.set(true)
	require.Eventually(t, func() bool { return passes.Load() > 0 }, time.Second, time.Millisecond,
		"work must start when this replica is promoted")

	election.set(false)
	stopped := passes.Load()
	time.Sleep(30 * time.Millisecond)
	// Allow one in-flight pass that had already been admitted.
	assert.LessOrEqual(t, passes.Load()-stopped, int64(1),
		"work must stop when leadership is lost, not merely at the next restart")
}

// TestRunPeriodicWithNoElectionAlwaysRuns: nil means single-process, so the work
// proceeds. A worker that stopped here would be broken on every single-replica
// deployment.
func TestRunPeriodicWithNoElectionAlwaysRuns(t *testing.T) {
	var passes atomic.Int64
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go RunPeriodic(ctx, nil, "test-worker", time.Millisecond, func(context.Context) error {
		passes.Add(1)
		return nil
	})
	require.Eventually(t, func() bool { return passes.Load() > 0 }, time.Second, time.Millisecond)
}

// TestRunPeriodicRecoversAPanic. This runs on its own goroutine, where an
// unrecovered panic takes the whole process down — a bug in a maintenance loop must
// not become the reason the vault stopped serving secrets.
func TestRunPeriodicRecoversAPanic(t *testing.T) {
	var passes atomic.Int64
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NotPanics(t, func() {
		go RunPeriodic(ctx, nil, "test-worker", time.Millisecond, func(context.Context) error {
			passes.Add(1)
			panic("worker exploded")
		})
		require.Eventually(t, func() bool { return passes.Load() > 2 }, time.Second, time.Millisecond,
			"the loop must keep ticking after a panicking pass")
	})
}

// TestRunPeriodicTreatsAnErrorAsOrdinary.
func TestRunPeriodicTreatsAnErrorAsOrdinary(t *testing.T) {
	var passes atomic.Int64
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go RunPeriodic(ctx, nil, "test-worker", time.Millisecond, func(context.Context) error {
		passes.Add(1)
		return errors.New("the database blipped")
	})
	require.Eventually(t, func() bool { return passes.Load() > 2 }, time.Second, time.Millisecond,
		"a failing pass must be retried on the next tick, not end the loop")
}

func TestRunPeriodicStopsOnContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		RunPeriodic(ctx, nil, "test-worker", time.Millisecond, func(context.Context) error { return nil })
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("RunPeriodic did not stop when its context was cancelled")
	}
}

func TestRunPeriodicWithNoWorkReturnsImmediately(t *testing.T) {
	done := make(chan struct{})
	go func() {
		RunPeriodic(context.Background(), nil, "test-worker", time.Millisecond, nil)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("RunPeriodic with a nil function must return rather than tick forever")
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// togglableElection is the two-line fake the Election interface exists to make
// possible.
type togglableElection struct{ leader atomic.Bool }

func (t *togglableElection) IsLeader() bool { return t.leader.Load() }
func (t *togglableElection) set(v bool)     { t.leader.Store(v) }

// must adapts (bool, error) for require.NoError when only the error matters.
func must(_ bool, err error) error { return err }

// must2 adapts (bool, error) for an assertion on the bool, failing loudly on error.
func must2(won bool, err error) bool {
	if err != nil {
		panic(err)
	}
	return won
}
