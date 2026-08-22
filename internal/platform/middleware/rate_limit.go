package middleware

import (
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	sdkauthz "github.com/maintainerd/sdk/authz"
	"github.com/maintainerd/secret/internal/platform/response"
)

// The rate limiter.
//
// ============================================================================
// THE HONEST LIMITATION, STATED FIRST: THIS LIMITER IS PER-PROCESS.
// ============================================================================
//
// maintainerd-auth meters through Redis (internal/platform/middleware/rate_limit.go
// there), so its counters are shared across replicas and its budget is a real
// cluster-wide quota. This service has no Redis and no other shared store it could use
// without inventing a dependency, so the counters here live in this process's memory.
//
// THE CONSEQUENCE, PRECISELY: with N replicas behind a load balancer, a client that
// spreads its requests across them gets up to N times the configured budget. This is a
// burst dampener and a brute-force dampener. It is NOT a quota, and it must not be
// described as one in a control document.
//
// WHY IT IS STILL WORTH HAVING:
//
//   - The setup surface is the one path reachable WITHOUT an Auth-minted token, and it
//     compares a bootstrap token. Metering it per IP turns an online guess of that token
//     from "as fast as the network allows" into "10 a minute per address per replica",
//     which is the difference between hours and centuries for any token worth the name.
//   - A compromised token with broad reveal grants is metered on how fast it can walk
//     the store. N times a small number is still a small number, and every one of those
//     reveals writes an audit row, so the limiter buys the time the trail needs to be
//     noticed.
//   - The alternative — no limit at all until this service grows a Redis dependency —
//     is strictly worse in every deployment, including the single-node one that is the
//     common case for a standalone vault.
//
// IT FAILS CLOSED WITHIN ITS SCOPE. There is no dependency to be unavailable: an
// in-memory map cannot time out, so there is no "limiter outage → allow" path of the
// kind Auth has to reason about. Turning the limiter off is an explicit configuration
// (SECRET_RATE_LIMIT_ENABLED=false), not a failure mode.
//
// If this service later gains a shared store, replace Limiter's internals and leave
// this interface alone — the middleware and its call sites do not care where the
// counter lives.

// Limiter is a fixed-window counter keyed by an arbitrary string.
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

	mu      sync.Mutex
	buckets map[string]*bucket
	// now is injectable so the tests do not sleep.
	now func() time.Time
}

type bucket struct {
	count   int
	resetAt time.Time
}

// DefaultMaxKeys bounds the tracked key set. 50k entries is a few megabytes and far
// more than any real deployment's concurrent principal count.
const DefaultMaxKeys = 50000

// NewLimiter builds a limiter over the given window.
func NewLimiter(window time.Duration) *Limiter {
	if window <= 0 {
		window = time.Minute
	}
	return &Limiter{
		window:  window,
		maxKeys: DefaultMaxKeys,
		buckets: make(map[string]*bucket),
		now:     time.Now,
	}
}

// Allow records a hit against key and reports whether it is within limit, along with
// how long the caller should wait if it is not.
//
// A limit of zero or less is treated as "unlimited" only because a caller that wants no
// limit should not install the middleware at all; the config layer refuses a
// non-positive budget, so this branch is unreachable from a running server.
func (l *Limiter) Allow(key string, limit int) (bool, time.Duration) {
	if l == nil || limit <= 0 {
		return true, 0
	}
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[key]
	if !ok || now.After(b.resetAt) {
		l.sweep(now)
		b = &bucket{resetAt: now.Add(l.window)}
		l.buckets[key] = b
	}
	b.count++
	if b.count > limit {
		// Measured against the limiter's own clock, not time.Now(): the two are the
		// same in production and only the injected one is right under test, and a
		// Retry-After computed from the wrong clock is worse than none.
		retryAfter := b.resetAt.Sub(now).Round(time.Second)
		if retryAfter < time.Second {
			retryAfter = time.Second
		}
		return false, retryAfter
	}
	return true, 0
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
