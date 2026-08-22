package rotator

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/maintainerd/secret/internal/api"
)

// fakeEngine records passes and can be told to fail or panic.
type fakeEngine struct {
	mu     sync.Mutex
	passes int
	err    error
	panics bool
	result api.RotationResult
}

func (f *fakeEngine) RotateDueSecrets(_ context.Context, limit int) (api.RotationResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.passes++
	if f.panics {
		panic("engine exploded")
	}
	return f.result, f.err
}

func (f *fakeEngine) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.passes
}

// election is the two-line fake that leader.Election exists to make possible.
type election struct{ leader atomic.Bool }

func (e *election) IsLeader() bool { return e.leader.Load() }
func (e *election) set(v bool)     { e.leader.Store(v) }

func TestDefaultsMakeAZeroOptionsWorkable(t *testing.T) {
	r := New(&fakeEngine{}, Options{Enabled: true})
	assert.Equal(t, DefaultInterval, r.opts.Interval)
	assert.Equal(t, DefaultBatch, r.opts.Batch)
}

// ---------------------------------------------------------------------------
// Multi-replica safety: the leader gate
// ---------------------------------------------------------------------------

// TestOnlyTheLeaderRotates is the multi-replica guarantee, stated as the failure it
// prevents: two replicas ticking the same schedule would find the same due secret
// and rotate it twice — two versions, two webhook fan-outs, two audit rows, and a
// consumer that re-read after the first notification holding a value that is
// already superseded.
func TestOnlyTheLeaderRotates(t *testing.T) {
	shared := &election{}
	shared.set(true)
	follower := &election{} // never promoted

	leaderEngine := &fakeEngine{}
	followerEngine := &fakeEngine{}

	leaderRotator := New(leaderEngine, Options{Enabled: true, Leader: shared})
	followerRotator := New(followerEngine, Options{Enabled: true, Leader: follower})

	// Both replicas tick the same number of times, as they would in production.
	for i := 0; i < 5; i++ {
		leaderRotator.Tick(context.Background())
		followerRotator.Tick(context.Background())
	}

	assert.Equal(t, 5, leaderEngine.count(), "the leader must rotate on every pass")
	assert.Zero(t, followerEngine.count(), "a follower must never rotate")
}

// TestLeaderLossStopsRotationMidLoop. The gate is re-read on EVERY pass rather than
// cached at start-up, because leadership changes under a running loop — that is the
// entire point of it — and a loop that cached the answer would keep rotating for as
// long as it lived after losing the lock.
func TestLeaderLossStopsRotationMidLoop(t *testing.T) {
	e := &election{}
	e.set(true)
	engine := &fakeEngine{}
	r := New(engine, Options{Enabled: true, Leader: e})

	r.Tick(context.Background())
	r.Tick(context.Background())
	require.Equal(t, 2, engine.count())

	e.set(false) // the session died; another replica has been promoted
	r.Tick(context.Background())
	r.Tick(context.Background())
	assert.Equal(t, 2, engine.count(), "a demoted replica must stop rotating immediately")
}

// TestPromotionStartsRotation: the other half of the same event. A replica that
// comes up as a follower must begin rotating when it wins the lock, without a
// restart.
func TestPromotionStartsRotation(t *testing.T) {
	e := &election{}
	engine := &fakeEngine{}
	r := New(engine, Options{Enabled: true, Leader: e})

	r.Tick(context.Background())
	require.Zero(t, engine.count(), "a follower does no work")

	e.set(true) // the previous leader died and this replica won the campaign
	r.Tick(context.Background())
	assert.Equal(t, 1, engine.count(), "a promoted replica must start rotating without a restart")
}

// TestNoElectionMeansThisIsTheOnlyProcess. A nil Leader is a supported
// configuration — a single-replica deployment, or an operator who set
// SECRET_LEADER_ELECTION_ENABLED=false — and it must ROTATE. A rotator that stopped
// here would silently never rotate anything the moment election was turned off,
// which is the opposite of what turning it off should do.
func TestNoElectionMeansThisIsTheOnlyProcess(t *testing.T) {
	engine := &fakeEngine{}
	r := New(engine, Options{Enabled: true})
	require.False(t, r.IsLeaderGated())

	r.Tick(context.Background())
	r.Tick(context.Background())
	assert.Equal(t, 2, engine.count(), "with no election configured this process is the sole owner")
}

// TestLeaderGateIsReportedForTheBootLog, so an operator can see in one line whether
// adding a second replica would double-rotate.
func TestLeaderGateIsReportedForTheBootLog(t *testing.T) {
	assert.False(t, New(&fakeEngine{}, Options{Enabled: true}).IsLeaderGated())
	assert.True(t, New(&fakeEngine{}, Options{Enabled: true, Leader: &election{}}).IsLeaderGated())
}

// TestDisabledLoopDoesNothing: turning rotation off must preserve every policy, which
// means the loop simply does not run — it does not disable or delete anything.
func TestDisabledLoopDoesNothing(t *testing.T) {
	engine := &fakeEngine{}
	New(engine, Options{Enabled: false}).Run(context.Background())
	assert.Equal(t, 0, engine.count())
}

// TestAFailingPassIsNotFatal is the operational contract: a failing pass is an
// ordinary condition (the database blips, setup has not run yet), and the loop keeps
// ticking.
func TestAFailingPassIsNotFatal(t *testing.T) {
	engine := &fakeEngine{err: errors.New("database is unreachable")}
	r := New(engine, Options{Enabled: true})
	r.Tick(context.Background())
	r.Tick(context.Background())
	assert.Equal(t, 2, engine.count(), "a failed pass must not stop the loop")
}

// TestAPanickingPassIsRecovered: this runs on its own goroutine, where an unrecovered
// panic takes the whole process down — so a bug in the loop that rotates credentials
// would become the thing that takes the vault offline.
func TestAPanickingPassIsRecovered(t *testing.T) {
	engine := &fakeEngine{panics: true}
	r := New(engine, Options{Enabled: true})
	assert.NotPanics(t, func() { r.Tick(context.Background()) })
	assert.Equal(t, 1, engine.count())
}

// TestTickIsANoOpOnACancelledContext so shutdown does not start work it cannot finish.
func TestTickIsANoOpOnACancelledContext(t *testing.T) {
	engine := &fakeEngine{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	New(engine, Options{Enabled: true}).Tick(ctx)
	assert.Equal(t, 0, engine.count())
}

// TestRunPerformsTheFirstPassImmediately. The most likely moment for a rotation to be
// overdue is right after the service was down; waiting a full interval would extend
// that for no reason.
func TestRunPerformsTheFirstPassImmediately(t *testing.T) {
	engine := &fakeEngine{result: api.RotationResult{Due: 1, Rotated: 1}}
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		New(engine, Options{Enabled: true, Interval: time.Hour}).Run(ctx)
		close(done)
	}()

	require.Eventually(t, func() bool { return engine.count() >= 1 }, time.Second, 5*time.Millisecond,
		"the first pass must not wait for the first tick")
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("the loop did not stop when its context was cancelled")
	}
}
