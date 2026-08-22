package rotator

import (
	"context"
	"errors"
	"sync"
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

func TestDefaultsMakeAZeroOptionsWorkable(t *testing.T) {
	r := New(&fakeEngine{}, Options{Enabled: true})
	assert.Equal(t, DefaultInterval, r.opts.Interval)
	assert.Equal(t, DefaultBatch, r.opts.Batch)
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
