package middleware

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sdkauthz "github.com/maintainerd/sdk/authz"
)

// clock is an injectable time source, so the limiter's window behaviour is tested
// without sleeping.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func testLimiter(window time.Duration) (*Limiter, *clock) {
	c := &clock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	l := NewLimiter(window)
	l.now = c.Now
	return l, c
}

func TestLimiterCountsWithinAWindow(t *testing.T) {
	l, _ := testLimiter(time.Minute)

	for i := 1; i <= 3; i++ {
		allowed, _ := l.Allow("k", 3)
		assert.True(t, allowed, "request %d should be inside the budget", i)
	}

	allowed, retryAfter := l.Allow("k", 3)
	assert.False(t, allowed, "the fourth request exceeds a budget of three")
	assert.Positive(t, retryAfter, "a refused caller is told when to come back")
}

func TestLimiterResetsAfterTheWindow(t *testing.T) {
	l, c := testLimiter(time.Minute)

	require.True(t, first(l.Allow("k", 1)))
	require.False(t, first(l.Allow("k", 1)))

	c.advance(61 * time.Second)
	assert.True(t, first(l.Allow("k", 1)), "the window rolled and the budget refilled")
}

func TestLimiterKeysAreIndependent(t *testing.T) {
	l, _ := testLimiter(time.Minute)

	require.True(t, first(l.Allow("sub:a", 1)))
	require.False(t, first(l.Allow("sub:a", 1)))
	assert.True(t, first(l.Allow("sub:b", 1)), "one principal must not spend another's budget")
}

// TestLimiterBoundsItsMemory: the setup surface is keyed by client IP, an address an
// attacker chooses, so an unbounded map would be a memory-exhaustion primitive
// reachable without a credential.
func TestLimiterBoundsItsMemory(t *testing.T) {
	l, _ := testLimiter(time.Minute)
	l.maxKeys = 64

	for i := 0; i < 500; i++ {
		l.Allow("ip:10.0.0."+strconv.Itoa(i), 100)
	}

	l.mu.Lock()
	size := len(l.buckets)
	l.mu.Unlock()
	assert.LessOrEqual(t, size, l.maxKeys,
		"the tracked-key set must stay bounded regardless of how many keys arrive")
}

func TestLimiterIsSafeUnderConcurrency(t *testing.T) {
	l, _ := testLimiter(time.Minute)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l.Allow("shared", 1000)
		}()
	}
	wg.Wait()

	l.mu.Lock()
	count := l.buckets["shared"].count
	l.mu.Unlock()
	assert.Equal(t, 50, count, "every concurrent hit must be counted exactly once")
}

func TestNilLimiterAndNonPositiveLimitAllow(t *testing.T) {
	var nilLimiter *Limiter
	allowed, _ := nilLimiter.Allow("k", 5)
	assert.True(t, allowed)

	l, _ := testLimiter(time.Minute)
	allowed, _ = l.Allow("k", 0)
	assert.True(t, allowed)
}

// ---------------------------------------------------------------------------
// The middleware
// ---------------------------------------------------------------------------

func TestRateLimitMiddleware(t *testing.T) {
	l, _ := testLimiter(time.Minute)
	handler := RateLimit(l, "reveal", 2, ByPrincipal)(okHandler())

	call := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets/reveal", nil)
		req.RemoteAddr = "203.0.113.7:5000"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w
	}

	assert.Equal(t, http.StatusOK, call().Code)
	assert.Equal(t, http.StatusOK, call().Code)

	refused := call()
	assert.Equal(t, http.StatusTooManyRequests, refused.Code)
	assert.NotEmpty(t, refused.Header().Get("Retry-After"))
	assert.Contains(t, refused.Body.String(), "rate_limited")
}

// TestRateLimitClassesAreSeparateBudgets: a workload writing at its full write budget
// must not be unable to read.
func TestRateLimitClassesAreSeparateBudgets(t *testing.T) {
	l, _ := testLimiter(time.Minute)
	write := RateLimit(l, "write", 1, ByPrincipal)(okHandler())
	reveal := RateLimit(l, "reveal", 1, ByPrincipal)(okHandler())

	req := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/secrets", nil)
		r.RemoteAddr = "203.0.113.7:5000"
		return r
	}

	w := httptest.NewRecorder()
	write.ServeHTTP(w, req())
	require.Equal(t, http.StatusOK, w.Code)

	w = httptest.NewRecorder()
	write.ServeHTTP(w, req())
	require.Equal(t, http.StatusTooManyRequests, w.Code, "the write budget is spent")

	w = httptest.NewRecorder()
	reveal.ServeHTTP(w, req())
	assert.Equal(t, http.StatusOK, w.Code, "the reveal budget is a separate counter")
}

// TestRateLimitKeysOnThePrincipalNotTheAddress: a workload behind a NAT shares one
// address with every other workload there, so an IP-keyed reveal budget would be too
// small for the honest ones or too large for the compromised one.
func TestRateLimitKeysOnThePrincipalNotTheAddress(t *testing.T) {
	l, _ := testLimiter(time.Minute)
	handler := RateLimit(l, "reveal", 1, ByPrincipal)(okHandler())

	as := func(subject string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets/reveal", nil)
		req.RemoteAddr = "203.0.113.7:5000" // the same NAT for both
		req = req.WithContext(sdkauthz.NewContext(req.Context(), &sdkauthz.Claims{Subject: subject}))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w.Code
	}

	assert.Equal(t, http.StatusOK, as("svc-a"))
	assert.Equal(t, http.StatusTooManyRequests, as("svc-a"))
	assert.Equal(t, http.StatusOK, as("svc-b"), "a second principal has its own budget")
}

// TestByClientIPIgnoresForwardingHeaders: a caller-supplied X-Forwarded-For would let
// anyone reset their own limit by rotating a header value, which is not a limiter.
func TestByClientIPIgnoresForwardingHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/setup", nil)
	req.RemoteAddr = "203.0.113.7:5000"
	req.Header.Set("X-Forwarded-For", "10.0.0.1")

	assert.Equal(t, "ip:203.0.113.7", ByClientIP(req))
	assert.Equal(t, "203.0.113.7", PeerIP(req))
}

func TestByPrincipalFallsBackToTheAddress(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/setup", nil)
	req.RemoteAddr = "203.0.113.7:5000"
	assert.Equal(t, "ip:203.0.113.7", ByPrincipal(req),
		"before authentication there is no principal to key on")
}

func TestRateLimitIsAPassThroughWhenDisabled(t *testing.T) {
	handler := RateLimit(nil, "write", 1, ByPrincipal)(okHandler())
	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/", nil))
		assert.Equal(t, http.StatusOK, w.Code)
	}
}

func first(allowed bool, _ time.Duration) bool { return allowed }
