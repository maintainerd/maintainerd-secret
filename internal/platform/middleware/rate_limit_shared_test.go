package middleware

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

// Tests for the SHARED side of the limiter — the part that makes one budget span
// every replica instead of being multiplied by the replica count.

// ---------------------------------------------------------------------------
// A fake reservation store that behaves the way the SQL does
// ---------------------------------------------------------------------------

// fakeStore models the one property the limiter's bound rests on: the total granted
// for a (key, window), summed over every caller, never exceeds the limit. That is
// what LEAST(...) in reserveSQL enforces under a row lock, and modelling it here is
// what makes "the budget is shared, not multiplied" testable without a database.
type fakeStore struct {
	mu       sync.Mutex
	reserved map[string]int64
	failWith error
	// calls counts round trips, so a test can prove the in-process fast path is
	// actually avoiding them.
	calls atomic.Int64
}

func newFakeStore() *fakeStore {
	return &fakeStore{reserved: map[string]int64{}}
}

func (f *fakeStore) Reserve(_ context.Context, key string, windowStart time.Time, _ time.Duration, limit, slice int64) (int64, error) {
	f.calls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failWith != nil {
		return 0, f.failWith
	}
	// The row is keyed by (bucket_key, window_start), exactly as the primary key is.
	rowKey := key + "@" + windowStart.UTC().Format(time.RFC3339Nano)
	have := f.reserved[rowKey]
	if have >= limit {
		return 0, nil
	}
	grant := slice
	if have+grant > limit {
		grant = limit - have
	}
	f.reserved[rowKey] = have + grant
	return grant, nil
}

func (f *fakeStore) fail(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failWith = err
}

func (f *fakeStore) heal() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failWith = nil
}

// sharedLimiter builds a limiter wired to store, with a controllable clock.
func sharedLimiter(window time.Duration, store ReservationStore, now func() time.Time) *Limiter {
	l := NewLimiter(window)
	l.now = now
	return l.WithStore(context.Background(), store)
}

// countAllowed drives n requests against one key and reports how many were admitted.
func countAllowed(l *Limiter, key string, limit, n int) int {
	allowed := 0
	for i := 0; i < n; i++ {
		if ok, _ := l.Allow(key, limit); ok {
			allowed++
		}
	}
	return allowed
}

// ---------------------------------------------------------------------------
// The headline property
// ---------------------------------------------------------------------------

// TestTheBudgetIsSharedRatherThanMultiplied is the whole point of the shared store.
//
// THE BUG IT PREVENTS: with a per-process counter, two replicas each admit `limit`
// requests, so a client that spreads its traffic gets 2x the configured budget —
// and the reveal budget is the exfiltration bound on a compromised token, so
// silently multiplying it by the replica count is precisely the number that must not
// drift.
func TestTheBudgetIsSharedRatherThanMultiplied(t *testing.T) {
	const limit = 100
	fixed := time.Now()
	clock := func() time.Time { return fixed }
	store := newFakeStore()

	// Two replicas, each with its own in-memory limiter, sharing one store.
	a := sharedLimiter(time.Minute, store, clock)
	b := sharedLimiter(time.Minute, store, clock)

	// Each replica is offered the full budget's worth of traffic. Per-process
	// metering would admit all 200.
	allowed := countAllowed(a, "reveal|sub:abc", limit, limit) +
		countAllowed(b, "reveal|sub:abc", limit, limit)

	assert.LessOrEqual(t, allowed, limit,
		"the fleet must not admit more than the configured budget")
	assert.Greater(t, allowed, 0, "the budget must actually be usable")
}

// TestTheSharedBudgetHoldsAcrossManyReplicas: the bound must not loosen as replicas
// are added, which is the failure mode of a per-process counter.
func TestTheSharedBudgetHoldsAcrossManyReplicas(t *testing.T) {
	const (
		limit    = 300
		replicas = 5
	)
	fixed := time.Now()
	clock := func() time.Time { return fixed }
	store := newFakeStore()

	total := 0
	for i := 0; i < replicas; i++ {
		l := sharedLimiter(time.Minute, store, clock)
		total += countAllowed(l, "reveal|sub:abc", limit, limit)
	}

	assert.LessOrEqual(t, total, limit,
		"five replicas must share one budget, not hold five of them")
}

// TestTheSharedBudgetHoldsUnderConcurrency. The reservation is atomic in the store,
// so concurrent reservers each get a slice or nothing — they never both believe they
// got the same units.
func TestTheSharedBudgetHoldsUnderConcurrency(t *testing.T) {
	const (
		limit    = 200
		replicas = 8
		each     = 100
	)
	fixed := time.Now()
	clock := func() time.Time { return fixed }
	store := newFakeStore()

	var allowed atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < replicas; i++ {
		l := sharedLimiter(time.Minute, store, clock)
		wg.Add(1)
		go func(l *Limiter) {
			defer wg.Done()
			for j := 0; j < each; j++ {
				if ok, _ := l.Allow("reveal|sub:abc", limit); ok {
					allowed.Add(1)
				}
			}
		}(l)
	}
	wg.Wait()

	assert.LessOrEqual(t, allowed.Load(), int64(limit),
		"concurrent reservations must not oversubscribe the window")
}

// TestASingleReplicaStillGetsItsWholeBudget. The shared ceiling must not become a
// lower ceiling in the common single-replica case: an operator who configures 300
// reveals a minute and runs one replica must get 300, not a slice of them.
func TestASingleReplicaStillGetsItsWholeBudget(t *testing.T) {
	const limit = 100
	fixed := time.Now()
	store := newFakeStore()
	l := sharedLimiter(time.Minute, store, func() time.Time { return fixed })

	assert.Equal(t, limit, countAllowed(l, "reveal|sub:abc", limit, limit),
		"one replica must be able to spend the entire budget")

	ok, retryAfter := l.Allow("reveal|sub:abc", limit)
	assert.False(t, ok, "the request after the budget is spent must be refused")
	assert.Positive(t, retryAfter, "a refusal must tell the client when to come back")
}

// ---------------------------------------------------------------------------
// The fast path
// ---------------------------------------------------------------------------

// TestTheFastPathAvoidsARoundTripPerRequest. A naive shared limiter increments a row
// on every request, which puts a database write in front of every reveal — the
// hot path of the thing the limiter is protecting. This one reserves a slice and
// spends it from memory.
func TestTheFastPathAvoidsARoundTripPerRequest(t *testing.T) {
	const limit = 300
	fixed := time.Now()
	store := newFakeStore()
	l := sharedLimiter(time.Minute, store, func() time.Time { return fixed })

	require.Equal(t, limit, countAllowed(l, "reveal|sub:abc", limit, limit))

	// A slice is limit/DefaultReservationDivisor = 30, so 300 requests must cost
	// about 10 reservations — not 300.
	calls := store.calls.Load()
	assert.LessOrEqual(t, calls, int64(limit/DefaultReservationDivisor)+2,
		"the fast path must amortize the round trip across a slice of requests")
	assert.Less(t, calls, int64(limit)/2, "a round trip per request defeats the purpose")
}

// TestARefusedKeyStopsQueryingTheStore. Once the window's budget is fully reserved
// there is nothing left to ask for, so continuing to ask would turn a rate-limited
// client into a source of database load — which is a denial-of-service amplifier
// rather than a limiter.
func TestARefusedKeyStopsQueryingTheStore(t *testing.T) {
	const limit = 10
	fixed := time.Now()
	store := newFakeStore()
	l := sharedLimiter(time.Minute, store, func() time.Time { return fixed })

	countAllowed(l, "setup|ip:203.0.113.7", limit, limit)
	callsAfterBudget := store.calls.Load()

	// Hammer the refused key.
	for i := 0; i < 200; i++ {
		ok, _ := l.Allow("setup|ip:203.0.113.7", limit)
		require.False(t, ok)
	}
	assert.Equal(t, callsAfterBudget, store.calls.Load(),
		"a key whose shared budget is exhausted must not keep querying the store")
}

// TestTheSetupBudgetReservesOneAtATime. A tenth of 10 rounds to 1, so the setup
// surface reserves a single unit per attempt. That is the CORRECT answer for the one
// path reachable without an Auth-minted credential: it compares a bootstrap token,
// so an exact shared count matters far more than a saved query.
func TestTheSetupBudgetReservesOneAtATime(t *testing.T) {
	l := NewLimiter(time.Minute)
	assert.Equal(t, 1, l.sliceFor(10), "the setup budget must be metered exactly")
	assert.Equal(t, 30, l.sliceFor(300), "the reveal budget amortizes across a slice")
	assert.Equal(t, 12, l.sliceFor(120))
	assert.Equal(t, 1, l.sliceFor(1), "a slice is never zero, or nothing would ever be granted")
}

// ---------------------------------------------------------------------------
// Degradation
// ---------------------------------------------------------------------------

// TestAStoreOutageDegradesToPerReplicaMeteringRatherThanFailingOpen.
//
// The two alternatives are both worse. Failing OPEN removes the meter exactly when
// something is already wrong. Failing SHUT turns a limiter outage into a vault
// outage on top of the database outage the service is already suffering. So it
// degrades to the per-process ceiling — which is what this service had before the
// shared store existed — and says so.
func TestAStoreOutageDegradesToPerReplicaMeteringRatherThanFailingOpen(t *testing.T) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	const limit = 50
	fixed := time.Now()
	store := newFakeStore()
	store.fail(errors.New("connection refused"))
	l := sharedLimiter(time.Minute, store, func() time.Time { return fixed })

	// It must NOT fail open: the per-process ceiling is still the configured limit.
	allowed := countAllowed(l, "reveal|sub:abc", limit, limit*3)
	assert.Equal(t, limit, allowed,
		"a store outage must degrade to the per-replica ceiling, never to no limit")
	assert.True(t, l.IsDegraded(), "the degradation must be observable, not silent")
}

// TestDegradationBacksOffRatherThanQueryingEveryRequest. A failing store must not
// add a timing-out query to every request; that would make a database blip far worse
// than it is.
func TestDegradationBacksOffRatherThanQueryingEveryRequest(t *testing.T) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	const limit = 100
	fixed := time.Now()
	store := newFakeStore()
	store.fail(errors.New("connection refused"))
	l := sharedLimiter(time.Minute, store, func() time.Time { return fixed })

	countAllowed(l, "reveal|sub:abc", limit, limit)
	assert.LessOrEqual(t, store.calls.Load(), int64(2),
		"a failed reservation must suppress further attempts for the backoff period")
}

// TestTheStoreRecoveringRestoresSharedMetering, so a transient outage does not leave
// the fleet on per-replica budgets until the next restart.
func TestTheStoreRecoveringRestoresSharedMetering(t *testing.T) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	const limit = 100
	now := time.Now()
	clock := func() time.Time { return now }
	store := newFakeStore()
	store.fail(errors.New("connection refused"))
	l := sharedLimiter(time.Minute, store, clock)

	l.Allow("reveal|sub:abc", limit)
	require.True(t, l.IsDegraded())

	store.heal()
	// Move past the backoff so the limiter is willing to try again.
	now = now.Add(DefaultStoreBackoff + time.Second)
	l.Allow("reveal|sub:abc", limit)
	assert.False(t, l.IsDegraded(), "shared metering must resume once the store answers again")
}

// TestNoStoreIsPerProcessAndUnchanged. A limiter with no store must behave exactly
// as it did before the shared store existed: no round trips, no table, no
// dependency. That is the single-replica deployment and every existing test.
func TestNoStoreIsPerProcessAndUnchanged(t *testing.T) {
	const limit = 5
	fixed := time.Now()
	l := NewLimiter(time.Minute)
	l.now = func() time.Time { return fixed }

	assert.False(t, l.IsShared())
	assert.Equal(t, limit, countAllowed(l, "reveal|sub:abc", limit, limit*2))
	ok, _ := l.Allow("reveal|sub:abc", limit)
	assert.False(t, ok)
}

// ---------------------------------------------------------------------------
// Windows and keys
// ---------------------------------------------------------------------------

// TestANewWindowGrantsAFreshSharedBudget.
func TestANewWindowGrantsAFreshSharedBudget(t *testing.T) {
	const limit = 20
	now := time.Now()
	clock := func() time.Time { return now }
	store := newFakeStore()
	l := sharedLimiter(time.Minute, store, clock)

	require.Equal(t, limit, countAllowed(l, "reveal|sub:abc", limit, limit))
	ok, _ := l.Allow("reveal|sub:abc", limit)
	require.False(t, ok)

	now = now.Add(2 * time.Minute)
	ok, _ = l.Allow("reveal|sub:abc", limit)
	assert.True(t, ok, "a closed window must not hold a client out forever")
}

// TestReplicasWithSkewedClocksShareOneWindowRow. The window boundary is truncated to
// the second before it becomes part of the row key. Without that, two replicas
// computing the boundary from their own clocks would land on two different rows and
// each reserve a full budget — the per-replica bug, reintroduced by sub-second
// skew.
func TestReplicasWithSkewedClocksShareOneWindowRow(t *testing.T) {
	const limit = 60
	base := time.Now().Truncate(time.Minute)
	store := newFakeStore()

	// Two replicas whose clocks differ by a few hundred milliseconds.
	a := sharedLimiter(time.Minute, store, func() time.Time { return base })
	b := sharedLimiter(time.Minute, store, func() time.Time { return base.Add(300 * time.Millisecond) })

	total := countAllowed(a, "reveal|sub:abc", limit, limit) +
		countAllowed(b, "reveal|sub:abc", limit, limit)

	assert.LessOrEqual(t, total, limit,
		"sub-second clock skew must not split one window into two budgets")
}

// TestDifferentClassesAndPrincipalsHaveSeparateSharedBudgets. A workload writing at
// its full write budget must not be unable to read, and one principal must not be
// able to spend another's allowance.
func TestDifferentClassesAndPrincipalsHaveSeparateSharedBudgets(t *testing.T) {
	const limit = 10
	fixed := time.Now()
	store := newFakeStore()
	l := sharedLimiter(time.Minute, store, func() time.Time { return fixed })

	require.Equal(t, limit, countAllowed(l, "reveal|sub:abc", limit, limit))
	refused, _ := l.Allow("reveal|sub:abc", limit)
	require.False(t, refused)

	ok, _ := l.Allow("write|sub:abc", limit)
	assert.True(t, ok, "a spent reveal budget must not consume the write budget")

	ok, _ = l.Allow("reveal|sub:xyz", limit)
	assert.True(t, ok, "one principal must not spend another's allowance")
}

// TestWithStoreIsANoOpOnANilStore keeps the bootstrap call site a single expression
// rather than a branch.
func TestWithStoreIsANoOpOnANilStore(t *testing.T) {
	l := NewLimiter(time.Minute).WithStore(context.Background(), nil)
	require.NotNil(t, l)
	assert.False(t, l.IsShared())

	var nilLimiter *Limiter
	assert.Nil(t, nilLimiter.WithStore(context.Background(), newFakeStore()))
	assert.False(t, nilLimiter.IsShared())
	assert.False(t, nilLimiter.IsDegraded())
}
