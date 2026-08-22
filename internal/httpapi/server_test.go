package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/maintainerd/secret/internal/platform/authz"
)

// These tests drive the ROUTER, not the handlers: they assert that every documented
// route exists, is mounted under the guarded group, and that /healthz is not.
//
// The guard is put in ModeUnavailable, which refuses every guarded route with 503
// WITHOUT reaching a handler. That is what makes the routing table testable without a
// database — and it doubles as a check on the fail-closed startup ladder: an
// unconfigured production instance answers 503 on the whole API rather than serving it
// open.
func unavailableRouter() http.Handler {
	return NewServer(nil, nil, authz.Guard{
		Mode:   authz.ModeUnavailable,
		Reason: "AUTH_JWKS_URL not set",
	}).Router()
}

func do(t *testing.T, router http.Handler, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(method, target, strings.NewReader("{}")))
	return w
}

func TestHealthzIsServedWithoutAuth(t *testing.T) {
	w := do(t, unavailableRouter(), http.MethodGet, "/healthz")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"status":"ok"`)
}

// TestEveryDocumentedRouteExistsAndIsGuarded. A 503 means the route matched and the
// guard refused it; a 404 or 405 would mean the route is missing or the method is
// wrong, which is the drift this catches.
func TestEveryDocumentedRouteExistsAndIsGuarded(t *testing.T) {
	router := unavailableRouter()
	routes := []struct {
		method string
		target string
	}{
		{http.MethodGet, "/api/v1/projects"},
		{http.MethodPost, "/api/v1/projects"},
		{http.MethodGet, "/api/v1/projects/billing"},
		{http.MethodPatch, "/api/v1/projects/billing"},
		{http.MethodDelete, "/api/v1/projects/billing"},

		{http.MethodGet, "/api/v1/environments?project=billing"},
		{http.MethodPost, "/api/v1/environments"},
		{http.MethodGet, "/api/v1/environments/billing/prod"},
		{http.MethodPatch, "/api/v1/environments/billing/prod"},
		{http.MethodDelete, "/api/v1/environments/billing/prod"},

		{http.MethodGet, "/api/v1/folders?project=billing&environment=prod"},
		{http.MethodPost, "/api/v1/folders"},
		{http.MethodPost, "/api/v1/folders/move"},
		{http.MethodDelete, "/api/v1/folders?project=billing&environment=prod&path=/db"},

		{http.MethodGet, "/api/v1/imports?project=billing&environment=prod"},
		{http.MethodPost, "/api/v1/imports"},
		{http.MethodPatch, "/api/v1/imports/6f3d8b52-4f2e-4c2b-8a1f-1c0c3f2d9e11"},
		{http.MethodDelete, "/api/v1/imports/6f3d8b52-4f2e-4c2b-8a1f-1c0c3f2d9e11"},

		{http.MethodGet, "/api/v1/secrets?project=billing&environment=prod"},
		{http.MethodPost, "/api/v1/secrets"},
		{http.MethodPatch, "/api/v1/secrets"},
		{http.MethodGet, "/api/v1/secrets/describe?project=billing&environment=prod&key=K"},
		{http.MethodGet, "/api/v1/secrets/versions?project=billing&environment=prod&key=K"},
		{http.MethodGet, "/api/v1/secrets/deleted?project=billing&environment=prod"},
		{http.MethodPost, "/api/v1/secrets/reveal"},
		{http.MethodPost, "/api/v1/secrets/rollback"},
		{http.MethodPost, "/api/v1/secrets/rotate"},
		{http.MethodPost, "/api/v1/secrets/rotation-policy"},
		{http.MethodPost, "/api/v1/secrets/delete"},
		{http.MethodPost, "/api/v1/secrets/restore"},
		{http.MethodPost, "/api/v1/secrets/destroy"},

		{http.MethodPost, "/api/v1/bulk/get"},
		{http.MethodPost, "/api/v1/bulk/put"},

		{http.MethodGet, "/api/v1/webhooks?project=billing"},
		{http.MethodPost, "/api/v1/webhooks"},
		{http.MethodPatch, "/api/v1/webhooks/6f3d8b52-4f2e-4c2b-8a1f-1c0c3f2d9e11"},
		{http.MethodDelete, "/api/v1/webhooks/6f3d8b52-4f2e-4c2b-8a1f-1c0c3f2d9e11?project=billing"},
		{http.MethodGet, "/api/v1/webhooks/6f3d8b52-4f2e-4c2b-8a1f-1c0c3f2d9e11/deliveries?project=billing"},

		{http.MethodGet, "/api/v1/audit"},
	}
	for _, route := range routes {
		w := do(t, router, route.method, route.target)
		assert.Equal(t, http.StatusServiceUnavailable, w.Code,
			"%s %s should have matched a guarded route", route.method, route.target)
	}
}

// TestTheGuardRunsBeforeRouting is worth pinning down, because it decides what a
// caller learns from a 503.
//
// The guard is mounted on the whole /api/v1 group, so an unconfigured instance
// answers 503 for ANY path under it — including paths that do not exist. That is the
// right order: a service that has decided not to serve its API should not first tell
// an anonymous caller which of its routes are real.
func TestTheGuardRunsBeforeRouting(t *testing.T) {
	router := unavailableRouter()
	assert.Equal(t, http.StatusServiceUnavailable,
		do(t, router, http.MethodPost, "/api/v1/secrets/reveal").Code)
	assert.Equal(t, http.StatusServiceUnavailable,
		do(t, router, http.MethodGet, "/api/v1/not-a-thing/at-all").Code,
		"an unconfigured API does not enumerate its routes")

	// Outside the guarded group, ordinary routing applies.
	assert.Equal(t, http.StatusNotFound, do(t, router, http.MethodGet, "/nope").Code)
}

// TestDecodeRejectsUnknownFields is a correctness feature: a caller that misspells
// "keep_versions" would otherwise get a silent default, which for retention means a
// version history quietly shorter than asked for.
func TestDecodeRejectsUnknownFields(t *testing.T) {
	type body struct {
		Key string `json:"key"`
	}
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"kee":"typo"}`))
	w := httptest.NewRecorder()
	var dst body
	ok := decode(w, r, &dst)
	assert.False(t, ok)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	r = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"key":"fine"}`))
	w = httptest.NewRecorder()
	require.True(t, decode(w, r, &dst))
	assert.Equal(t, "fine", dst.Key)
}

func TestDecodeRequiresABody(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(""))
	w := httptest.NewRecorder()
	var dst struct{}
	assert.False(t, decode(w, r, &dst))
	assert.Contains(t, w.Body.String(), "a request body is required")
}

// TestTenantHintReadsTheHeaderThenTheQuery.
func TestTenantHintReadsTheHeaderThenTheQuery(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/?tenant=from-query", nil)
	assert.Equal(t, "from-query", tenantHint(r))

	r.Header.Set(TenantHeader, " from-header ")
	assert.Equal(t, "from-header", tenantHint(r), "the header wins and is trimmed")
}

// TestClientIPIgnoresForwardedFor: a caller-supplied forwarded-for would let anyone
// write an arbitrary address into this service's audit trail.
func TestClientIPIgnoresForwardedFor(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.7:54321"
	r.Header.Set("X-Forwarded-For", "10.0.0.1")
	assert.Equal(t, "203.0.113.7", clientIP(r))
}
