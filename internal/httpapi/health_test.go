package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/maintainerd/secret/internal/platform/authz"
)

func probeRouter(t *testing.T, opts Options) http.Handler {
	t.Helper()
	return NewServer(nil, nil, authz.Guard{
		Mode:   authz.ModeUnavailable,
		Reason: "AUTH_JWKS_URL not set",
	}, opts).Router()
}

func probe(t *testing.T, router http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
	return w
}

// TestLivenessIsCheapAndUnconditional. An orchestrator RESTARTS a container whose
// liveness probe fails, so this endpoint must not depend on anything: a liveness probe
// that touches Postgres turns a database blip into a rolling restart of every replica.
//
// Note the guard is in ModeUnavailable here — the whole API is refusing traffic — and
// /healthz still answers 200, which is exactly right: the process is alive.
func TestLivenessIsCheapAndUnconditional(t *testing.T) {
	failing := []ReadinessCheck{{
		Name:  "database",
		Probe: func(context.Context) error { return errors.New("connection refused") },
	}}
	w := probe(t, probeRouter(t, Options{Readiness: failing}), "/healthz")

	assert.Equal(t, http.StatusOK, w.Code,
		"liveness must not depend on a readiness check")
	assert.Contains(t, w.Body.String(), `"status":"ok"`)
}

func TestReadinessPassesWhenEveryDependencyIsHealthy(t *testing.T) {
	checks := []ReadinessCheck{
		{Name: "database", Probe: func(context.Context) error { return nil }},
		{Name: "auth", Probe: func(context.Context) error { return nil }},
	}
	w := probe(t, probeRouter(t, Options{Readiness: checks}), "/readyz")

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"status":"ready"`)
	assert.Contains(t, w.Body.String(), `"database":"ok"`)
	assert.Contains(t, w.Body.String(), `"auth":"ok"`)
}

// TestReadinessFailsClosed is the property: while a dependency is down this replica
// reports not-ready and the load balancer stops sending it work. For a vault the
// fail-closed direction is the only defensible one.
func TestReadinessFailsClosed(t *testing.T) {
	checks := []ReadinessCheck{
		{Name: "database", Probe: func(context.Context) error { return errors.New("dial tcp 10.0.0.5:5432: connection refused") }},
		{Name: "auth", Probe: func(context.Context) error { return nil }},
	}
	w := probe(t, probeRouter(t, Options{Readiness: checks}), "/readyz")

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Contains(t, w.Body.String(), `"status":"not_ready"`)
	assert.Contains(t, w.Body.String(), `"database":"unhealthy"`)
	assert.Contains(t, w.Body.String(), `"auth":"ok"`,
		"a failing check must not mask a healthy one")
}

// TestReadinessDisclosesOnlyTheDependencyName. The probes are unauthenticated, so what
// they say is bounded on purpose: a NAME, never an address, a driver message or a
// version.
func TestReadinessDisclosesOnlyTheDependencyName(t *testing.T) {
	checks := []ReadinessCheck{{
		Name: "database",
		Probe: func(context.Context) error {
			return errors.New("dial tcp 10.0.0.5:5432: connect: connection refused (user=secret_app db=secretdb)")
		},
	}}
	body := probe(t, probeRouter(t, Options{Readiness: checks}), "/readyz").Body.String()

	assert.NotContains(t, body, "10.0.0.5")
	assert.NotContains(t, body, "secret_app")
	assert.NotContains(t, body, "secretdb")
	assert.NotContains(t, body, "connection refused")
}

// TestReadinessBoundsAHangingProbe: a readiness endpoint that never answers is read as
// healthy by some orchestrators and unhealthy by others, which is the one answer worse
// than either.
func TestReadinessBoundsAHangingProbe(t *testing.T) {
	checks := []ReadinessCheck{{
		Name: "database",
		Probe: func(ctx context.Context) error {
			<-make(chan struct{}) // never returns, and never looks at ctx
			return nil
		},
	}}
	router := probeRouter(t, Options{Readiness: checks, ReadinessTimeout: 25 * time.Millisecond})

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- probe(t, router, "/readyz") }()

	select {
	case w := <-done:
		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
		assert.Contains(t, w.Body.String(), `"database":"unhealthy"`)
	case <-time.After(2 * time.Second):
		t.Fatal("/readyz hung on a probe that ignores its context")
	}
}

// TestProbesAreUnauthenticatedAndOutsideTheGuardedGroup. They are mounted outside
// /api/v1, which is what makes them exempt by construction rather than by an exception
// inside the guard — and they are the only unauthenticated surface on this transport
// apart from the self-guarded setup wizard.
func TestProbesAreUnauthenticatedAndOutsideTheGuardedGroup(t *testing.T) {
	router := probeRouter(t, Options{})

	require.Equal(t, http.StatusOK, probe(t, router, "/healthz").Code)
	require.Equal(t, http.StatusOK, probe(t, router, "/readyz").Code,
		"with no checks configured, readiness is equivalent to liveness")

	// Everything under /api/v1 is refused by the guard, including paths that do not
	// exist — an unconfigured API does not enumerate its routes.
	assert.Equal(t, http.StatusServiceUnavailable, probe(t, router, "/api/v1/healthz").Code)
}

// TestProbeResponsesAreNotCached. A metadata listing naming every credential in
// production does not belong in a proxy cache, and neither does a readiness answer an
// orchestrator is about to act on.
func TestProbeResponsesAreNotCached(t *testing.T) {
	router := probeRouter(t, Options{})
	for _, path := range []string{"/healthz", "/readyz"} {
		w := probe(t, router, path)
		assert.Equal(t, "no-store", w.Header().Get("Cache-Control"), path)
		assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"), path)
	}
}
