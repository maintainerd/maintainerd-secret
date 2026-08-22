package middleware

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	sdkauthz "github.com/maintainerd/sdk/authz"
	"github.com/maintainerd/secret/internal/platform/response"
)

// The rate limiter.
//
// ============================================================================
// IT IS A SHARED QUOTA WHEN A STORE IS CONFIGURED, AND PER-PROCESS WHEN NOT
// ============================================================================
//
// maintainerd-auth meters through Redis, so its budget is a real cluster-wide quota.
// This service has no Redis — but it does have PostgreSQL, which it cannot serve a
// single secret without, so metering through the database it already requires adds no
// new failure domain. That is what ReservationStore is.
//
// The problem being solved is concrete. A PER-PROCESS counter is not a budget once
// there is more than one replica: a client that spreads its requests across N
// replicas gets N times the configured allowance, so `SECRET_RATE_LIMIT_REVEAL=300`
// on three replicas is a reveal budget of 900. The reveal budget is the exfiltration
// bound on a compromised token, so multiplying it by the replica count is exactly the
// number that must not silently drift.
//
// ============================================================================
// HOW IT IS BOTH SHARED AND FAST: RESERVATIONS, NOT COUNTERS
// ============================================================================
//
// The naive shared limiter increments a database row on EVERY request. That is a
// round trip in front of every reveal, which puts the database on the hot path of the
// thing the limiter is supposed to protect, and turns a database blip into a total
// outage of a service that was merely being metered.
//
// So this limiter does not count in the database. It RESERVES in the database and
// SPENDS in memory:
//
//  1. A replica asks the shared row for a SLICE of the window's budget — by default a
//     tenth of it (ReservationDivisor). One round trip.
//  2. It then serves requests from that slice out of memory, with NO round trip, until
//     the slice is spent.
//  3. When the slice runs out it asks for another. When the row reports the window's
//     budget is fully reserved, it refuses locally for the rest of the window and stops
//     asking.
//
// THE BOUND THIS GIVES IS A REAL ONE, and it is worth being precise about the
// direction of the error. Total RESERVED across all replicas can never exceed the
// limit, because the row's increment is clamped to it. Total SPENT can never exceed
// total reserved. Therefore total spend across every replica is <= the configured
// limit — the budget is shared, not multiplied.
//
// THE HONEST TRADE-OFF, IN THE OTHER DIRECTION: a replica that reserves a slice and
// then goes idle STRANDS the unspent remainder for the rest of the window. So the
// effective ceiling is the configured limit, but the effective FLOOR is lower than a
// perfect global counter's — under a badly skewed load balancer, honest clients can be
// refused while up to (replicas - 1) x slice units sit unused. That is the price of
// not putting a query in front of every request, and it is the right price for this
// service: a limiter is a dampener, and refusing slightly early is a far better
// failure than either allowing N times the budget or making every reveal wait on a
// write.
//
// The divisor is the dial between the two. A larger slice means fewer round trips and
// more stranding; a smaller slice means the opposite. A tenth was chosen because it
// makes the round trip amortized to nothing on the reveal budget (300/10 = one query
// per 30 requests) while stranding at most 10% of the budget per idle replica.
//
// ============================================================================
// WHAT HAPPENS WHEN THE STORE IS UNAVAILABLE
// ============================================================================
//
// It DEGRADES TO THE PER-PROCESS BUDGET rather than failing open or failing shut,
// and both alternatives are worse:
//
//   - Failing open (ignore the limit) would remove the meter exactly when something is
//     wrong, which is when it is most needed.
//   - Failing shut (refuse everything) would turn a limiter outage into a vault
//     outage, on top of a database outage the service is already suffering.
//
// The in-process fixed window below is ALWAYS applied, store or no store, and it is a
// hard per-replica ceiling of the same configured limit. So a store outage degrades the
// guarantee from "<= limit across the fleet" to "<= limit per replica" — precisely the
// behaviour this service had before the store existed — and it says so in the log. It
// cannot degrade to "no limit". Note also what an attacker gains from that degradation:
// nothing they can use, because every request the limiter would have refused was going
// to hit the same unavailable database for its actual work.
//
// With NO store configured at all (a single-replica deployment, or a test), the
// behaviour is exactly the in-process fixed window and nothing else — no round trips,
// no table, no dependency.

// Limiter is a fixed-window counter keyed by an arbitrary string, optionally backed by
// a shared reservation store.
//
// A fixed window rather than a token bucket, deliberately: the failure mode of a fixed
// window is that a client can spend two budgets across a window boundary, which for a
// dampener is acceptable and easy to reason about. A token bucket's failure mode is a
// refill-rate bug that silently grants more than intended, which is not.
type Limiter struct {
	window time.Duration
	// maxKeys bounds memory. Every distinct key is a map entry, and the setup surface
	// is keyed by client IP — an address an attacker chooses — so an unbounded map is
	// a memory-exhaustion primitive reachable without a credential.
	maxKeys int

	// store is the shared budget. Nil is a supported configuration and means
	// per-process metering, unchanged from before this service had a store.
	store ReservationStore
	// storeCtx bounds every store call to the process lifetime, so a reservation in
	// flight at SIGTERM is cancelled with everything else rather than outliving the
	// drain. Allow has no context parameter of its own — deliberately, because
	// changing its signature would change every call site for a detail none of them
	// can act on — so the base context is held here and a per-call timeout derived
	// from it.
	storeCtx     context.Context
	storeTimeout time.Duration
	// divisor sets the reservation slice as a fraction of the limit.
	divisor int
	// storeBackoff is how long a failed store call suppresses further attempts, so a
	// database outage does not add a timing-out query to every request.
	storeBackoff time.Duration

	mu      sync.Mutex
	buckets map[string]*bucket
	// now is injectable so the tests do not sleep.
	now func() time.Time

	// degraded reports, for the tests and for a single log line, whether the limiter
	// has fallen back to per-process metering.
	degraded atomic.Bool
}

type bucket struct {
	// count is the per-process hit count for this window. It is the hard per-replica
	// ceiling and is applied whether or not a store is configured.
	count int
	// windowStart and resetAt bound the window as the half-open interval
	// [windowStart, resetAt). windowStart is ALIGNED TO ABSOLUTE TIME — see
	// bucketLocked for why that alignment is what makes the shared budget shared.
	windowStart time.Time
	resetAt     time.Time

	// --- shared-quota bookkeeping; untouched when no store is configured ---

	// granted is how many units of the shared budget this replica has reserved for
	// this window, and spent is how many of them it has handed out.
	granted int
	spent   int
	// exhausted records that the shared row reported the window's budget fully
	// reserved, so there is nothing left to ask for and no reason to ask again.
	exhausted bool
	// backoffAt suppresses store calls after a failure.
	backoffAt time.Time
}

const (
	// DefaultMaxKeys bounds the tracked key set. 50k entries is a few megabytes and far
	// more than any real deployment's concurrent principal count.
	DefaultMaxKeys = 50000
	// DefaultReservationDivisor makes one reservation a tenth of the window's budget.
	// See the trade-off discussion above.
	DefaultReservationDivisor = 10
	// DefaultStoreTimeout bounds one reservation round trip. It is short because the
	// fallback is correct and cheap: exceeding it degrades this replica to its own
	// per-process ceiling for one backoff period.
	DefaultStoreTimeout = 750 * time.Millisecond
	// DefaultStoreBackoff is how long a failed reservation suppresses the next attempt.
	DefaultStoreBackoff = 5 * time.Second
)

// NewLimiter builds a per-process limiter over the given window.
//
// Call WithStore to make its budget shared across replicas.
func NewLimiter(window time.Duration) *Limiter {
	if window <= 0 {
		window = time.Minute
	}
	return &Limiter{
		window:       window,
		maxKeys:      DefaultMaxKeys,
		divisor:      DefaultReservationDivisor,
		storeTimeout: DefaultStoreTimeout,
		storeBackoff: DefaultStoreBackoff,
		buckets:      make(map[string]*bucket),
		now:          time.Now,
	}
}

// WithStore makes this limiter's budget shared across replicas.
//
// ctx is the PROCESS context, not a request's: it exists so a reservation in flight
// when SIGTERM arrives is cancelled with the rest of the service. Passing a
// request-scoped context here would cancel other requests' reservations.
//
// It returns the limiter so bootstrap can chain, and is a no-op on a nil store — which
// keeps the "no shared store configured" path a single expression at the call site
// rather than a branch.
func (l *Limiter) WithStore(ctx context.Context, store ReservationStore) *Limiter {
	if l == nil || store == nil {
		return l
	}
	if ctx == nil {
		ctx = context.Background()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.store = store
	l.storeCtx = ctx
	return l
}

// IsShared reports whether a shared store is configured, for the boot log.
func (l *Limiter) IsShared() bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.store != nil
}

// IsDegraded reports whether the shared store has failed and this limiter has fallen
// back to per-process metering.
func (l *Limiter) IsDegraded() bool { return l != nil && l.degraded.Load() }

// Allow records a hit against key and reports whether it is within limit, along with
// how long the caller should wait if it is not.
//
// THE SIGNATURE IS UNCHANGED by the shared store, on purpose. Every call site — the
// HTTP middleware and the gRPC interceptor — asks the same question it always asked,
// and neither of them can do anything useful with a store, a context or a reservation.
// Where the counter lives is this type's business.
//
// A limit of zero or less is treated as "unlimited" only because a caller that wants no
// limit should not install the middleware at all; the config layer refuses a
// non-positive budget, so this branch is unreachable from a running server.
func (l *Limiter) Allow(key string, limit int) (bool, time.Duration) {
	if l == nil || limit <= 0 {
		return true, 0
	}

	l.mu.Lock()
	now := l.now()
	b := l.bucketLocked(key, now)

	// STEP 1: the per-replica ceiling, always applied. It is sound to refuse on this
	// alone: a local count can never exceed the global one, so local > limit proves
	// global > limit. It is also what makes a store outage degrade rather than open.
	b.count++
	if b.count > limit {
		retryAfter := retryAfterFor(b, now)
		l.mu.Unlock()
		return false, retryAfter
	}

	// STEP 2: with no shared store, the local window IS the budget.
	if l.store == nil {
		l.mu.Unlock()
		return true, 0
	}

	// STEP 3: the fast path — spend from the slice already reserved. No round trip.
	if b.spent < b.granted {
		b.spent++
		l.mu.Unlock()
		return true, 0
	}

	// STEP 4: the shared budget for this window is gone. Refuse without asking again.
	if b.exhausted {
		retryAfter := retryAfterFor(b, now)
		l.mu.Unlock()
		return false, retryAfter
	}

	// STEP 5: a recent store failure. Degraded to the per-replica ceiling, which this
	// request has already passed.
	if now.Before(b.backoffAt) {
		l.mu.Unlock()
		return true, 0
	}

	windowStart := b.windowStart
	windowEnd := b.resetAt
	slice := l.sliceFor(limit)
	store := l.store
	baseCtx := l.storeCtx
	timeout := l.storeTimeout
	// THE MUTEX IS RELEASED ACROSS THE ROUND TRIP. Holding it would serialize every
	// request on every key behind one query — including the fast-path requests that
	// need no query at all.
	l.mu.Unlock()

	if baseCtx == nil {
		baseCtx = context.Background()
	}
	ctx, cancel := context.WithTimeout(baseCtx, timeout)
	granted, err := store.Reserve(ctx, key, windowStart, l.window, int64(limit), int64(slice))
	cancel()

	l.mu.Lock()
	defer l.mu.Unlock()

	// The window may have rotated while this call was in the database. A grant that
	// belongs to a window that is over is discarded rather than applied to the new
	// one, which would let a reservation from the past fund the present.
	cur, ok := l.buckets[key]
	if !ok || !cur.resetAt.Equal(windowEnd) {
		return true, 0
	}

	if err != nil {
		cur.backoffAt = l.now().Add(l.storeBackoff)
		if l.degraded.CompareAndSwap(false, true) {
			slog.Warn("rate limiter: the shared budget is unreachable — metering per replica until it returns",
				"effect", "the effective ceiling is the configured limit PER REPLICA rather than across the fleet",
				"backoff", l.storeBackoff.String(), "error", err)
		}
		return true, 0
	}
	if l.degraded.CompareAndSwap(true, false) {
		slog.Info("rate limiter: the shared budget is reachable again — metering across the fleet")
	}

	cur.granted += int(granted)
	// A grant SHORTER than the slice asked for means the row hit the limit, so this is
	// the last of the shared budget for this window. Recording it here is what stops a
	// refused key from re-querying on every subsequent request.
	if granted < int64(slice) {
		cur.exhausted = true
	}
	if cur.spent < cur.granted {
		cur.spent++
		return true, 0
	}
	return false, retryAfterFor(cur, l.now())
}

// bucketLocked returns the live bucket for key, rotating an expired one. Caller holds
// mu.
//
// ============================================================================
// THE WINDOW IS ALIGNED TO ABSOLUTE TIME, AND THAT IS LOAD-BEARING
// ============================================================================
//
// The obvious implementation anchors the window at the moment a key is first seen
// (resetAt = now + window). That is fine for a per-process limiter and WRONG for a
// shared one, because each replica sees a given principal's first request at a
// different instant — so replica A's window for "reveal|sub:abc" might run
// 12:00:03-12:01:03 while replica B's runs 12:00:41-12:01:41. They would then
// reserve from two DIFFERENT rows, each get a full budget, and the fleet-wide
// ceiling would quietly be two budgets again. That is the exact bug the shared
// store exists to remove, reintroduced by the window boundary.
//
// Truncating to the window aligns every replica to the same absolute grid (Go's
// Truncate is relative to the zero time, so it is an absolute anchor and not a
// process-relative one). Every replica computes the same windowStart for the same
// instant, so they contend for the same row, and the ceiling holds.
//
// The interval is HALF-OPEN, [windowStart, resetAt): an instant exactly on the
// boundary belongs to the new window, which is the only reading under which two
// adjacent windows do not overlap by an instant.
func (l *Limiter) bucketLocked(key string, now time.Time) *bucket {
	b, ok := l.buckets[key]
	if ok && now.Before(b.resetAt) {
		return b
	}
	l.sweep(now)
	start := now.Truncate(l.window)
	b = &bucket{windowStart: start, resetAt: start.Add(l.window)}
	l.buckets[key] = b
	return b
}

// sliceFor is how much of the budget one reservation asks for.
//
// It is clamped to at least 1 so a small budget still works: the setup budget is 10 a
// minute, a tenth of which rounds to 1, which means the setup surface reserves one unit
// at a time — a round trip per attempt. That is the correct answer for the one surface
// reachable without an Auth-minted token, where a shared count matters far more than a
// saved query.
func (l *Limiter) sliceFor(limit int) int {
	d := l.divisor
	if d < 1 {
		d = DefaultReservationDivisor
	}
	s := limit / d
	if s < 1 {
		s = 1
	}
	if s > limit {
		s = limit
	}
	return s
}

// retryAfterFor is measured against the limiter's own clock, not time.Now(): the two are
// the same in production and only the injected one is right under test, and a
// Retry-After computed from the wrong clock is worse than none.
func retryAfterFor(b *bucket, now time.Time) time.Duration {
	retryAfter := b.resetAt.Sub(now).Round(time.Second)
	if retryAfter < time.Second {
		retryAfter = time.Second
	}
	return retryAfter
}

// sweep drops expired buckets, and hard-resets if the map is still over its bound.
//
// The hard reset is the deliberate choice for the pathological case (an attacker
// rotating source addresses to grow the map): it costs one window of unmetered traffic
// for everyone, once, and it bounds memory absolutely. Evicting selectively would let
// the attacker choose whose counter is discarded, which is worse.
func (l *Limiter) sweep(now time.Time) {
	if len(l.buckets) < l.maxKeys {
		// Cheap path: only sweep when the map is actually growing.
		if len(l.buckets) < l.maxKeys/2 {
			return
		}
		for key, b := range l.buckets {
			if now.After(b.resetAt) {
				delete(l.buckets, key)
			}
		}
		return
	}
	for key, b := range l.buckets {
		if now.After(b.resetAt) {
			delete(l.buckets, key)
		}
	}
	if len(l.buckets) >= l.maxKeys {
		slog.Warn("rate limiter: tracked-key bound reached, resetting every counter",
			"max_keys", l.maxKeys,
			"effect", "one window of unmetered traffic; suspect a source-address rotation")
		l.buckets = make(map[string]*bucket)
	}
}

// KeyFunc derives a limiter key from a request.
type KeyFunc func(*http.Request) string

// ByPrincipal keys on the authenticated subject, falling back to the peer address when
// there is none.
//
// Keying on the PRINCIPAL rather than the IP is what makes the reveal budget mean
// something: a workload behind a NAT shares one address with every other workload
// there, so an IP-keyed reveal budget would either be too small for the honest ones or
// too large for the compromised one. The IP fallback covers the pre-auth window.
func ByPrincipal(r *http.Request) string {
	if claims, ok := sdkauthz.FromContext(r.Context()); ok && claims != nil && claims.Subject != "" {
		return "sub:" + claims.Subject
	}
	return "ip:" + PeerIP(r)
}

// ByClientIP keys on the peer address. Used for the setup surface, which runs before
// any principal exists.
func ByClientIP(r *http.Request) string { return "ip:" + PeerIP(r) }

// PeerIP returns the peer address with the port stripped.
//
// Forwarding headers are NOT consulted, matching httpapi.clientIP and the gRPC
// interceptor. A caller-supplied X-Forwarded-For would let anyone reset their own rate
// limit by rotating a header value, which is not a limiter.
func PeerIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// RateLimit meters requests under one budget.
//
// class names the budget in the log line and in the limiter key, so the reveal budget
// and the write budget are separate counters for the same principal — a workload
// writing at its full write budget must not be unable to read.
func RateLimit(l *Limiter, class string, limit int, key KeyFunc) Middleware {
	return func(next http.Handler) http.Handler {
		if l == nil || limit <= 0 {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			allowed, retryAfter := l.Allow(class+"|"+key(r), limit)
			if !allowed {
				if retryAfter < time.Second {
					retryAfter = time.Second
				}
				// Logged at warn with the class and the principal, because a client
				// sitting on its limit is either misconfigured or hostile and both
				// are worth seeing. The key is NOT logged verbatim when it is an
				// address-derived one — PeerIP is already in the request line.
				response.LoggerFromContext(r.Context()).Warn("rate limit exceeded",
					"class", class, "limit", limit, "window_retry_after_s", int(retryAfter.Seconds()))
				w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())))
				response.ErrorWithCode(w, http.StatusTooManyRequests, "rate_limited",
					"rate limit exceeded — try again later")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
