package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sdkauthz "github.com/maintainerd/sdk/authz"
	mw "github.com/maintainerd/secret/internal/platform/middleware"
	"github.com/maintainerd/secret/internal/platform/permissions"
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
	return NewServer(nil, nil, sdkauthz.Guard{
		Mode:   sdkauthz.ModeUnavailable,
		Reason: "AUTH_JWKS_URL not set",
	}, Options{}).Router()
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

// ---------------------------------------------------------------------------
// The guard's denials wear this API's envelope
// ---------------------------------------------------------------------------

// TestGuardDenialsUseTheServiceEnvelope.
//
// The guard is the SDK's, and the SDK's default denial body is a compact
// {"error","code"} object — right for a library that cannot know its consumer's
// contract, wrong here. Every other failure this API produces is a
// response.Envelope, and a client that has to parse one shape for a 403 from the
// guard and another for a 403 from a handler will get one of them wrong. This
// pins the wiring in httpapi.NewServer that makes them the same.
func TestGuardDenialsUseTheServiceEnvelope(t *testing.T) {
	// ModeUnavailable — the fail-closed startup posture.
	w := do(t, unavailableRouter(), http.MethodGet, "/api/v1/secrets")
	require.Equal(t, http.StatusServiceUnavailable, w.Code)

	var body struct {
		Success bool   `json:"success"`
		Error   string `json:"error"`
		Code    string `json:"code"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.False(t, body.Success, "the envelope's success flag must be present and false")
	assert.Equal(t, "auth_unavailable", body.Code)
	assert.Contains(t, body.Error, "AUTH_JWKS_URL not set",
		"the reason names the variable, so an operator is not left guessing")
	assert.Contains(t, body.Error, "disabled outside development")
}

// TestUnauthenticatedDenialsUseTheServiceEnvelope covers the other two denial
// kinds an enforcing instance produces: no token, and a token without the
// permission.
func TestUnauthenticatedDenialsUseTheServiceEnvelope(t *testing.T) {
	metadataOnly := &sdkauthz.Claims{
		Subject: "op-a",
		// A USER principal, so this test measures the PERMISSION denial rather than
		// the actor one: /projects writes are user-only, and a service principal would
		// be refused a step earlier with a different code. The actor path has its own
		// test — see TestServicePrincipalIsRefusedOnTheConsoleSurfaces.
		Kind:   sdkauthz.ActorKindUser,
		Grants: []sdkauthz.Grant{{Action: permissions.PermReadMetadata}},
	}
	router := NewServer(nil, nil, sdkauthz.Guard{
		Mode: sdkauthz.ModeEnforced,
		Verify: func(_ context.Context, token string) (*sdkauthz.Claims, error) {
			if token != "good" {
				return nil, errors.New("bad token")
			}
			return metadataOnly, nil
		},
	}, Options{}).Router()

	decodeBody := func(w *httptest.ResponseRecorder) (bool, string, string) {
		t.Helper()
		var body struct {
			Success bool   `json:"success"`
			Error   string `json:"error"`
			Code    string `json:"code"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
		return body.Success, body.Error, body.Code
	}

	t.Run("no bearer token", func(t *testing.T) {
		w := do(t, router, http.MethodGet, "/api/v1/secrets")
		require.Equal(t, http.StatusUnauthorized, w.Code)
		success, message, code := decodeBody(w)
		assert.False(t, success)
		assert.Equal(t, "missing_token", code)
		assert.Equal(t, "missing bearer token", message)
	})

	t.Run("a forged token never says which check failed", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets", nil)
		req.Header.Set("Authorization", "Bearer forged")
		router.ServeHTTP(w, req)

		require.Equal(t, http.StatusUnauthorized, w.Code)
		success, message, code := decodeBody(w)
		assert.False(t, success)
		assert.Equal(t, "invalid_token", code)
		assert.Equal(t, "invalid token", message)
		assert.NotContains(t, w.Body.String(), "bad token",
			"which check a forged token failed is oracle material")
	})

	t.Run("a valid token without the permission", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/projects", strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer good")
		router.ServeHTTP(w, req)

		require.Equal(t, http.StatusForbidden, w.Code)
		success, message, code := decodeBody(w)
		assert.False(t, success)
		assert.Equal(t, "insufficient_permission", code)
		assert.Contains(t, message, permissions.PermManageProject)
	})

	t.Run("an unmapped route is denied even to a valid token", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/debug/dump", nil)
		req.Header.Set("Authorization", "Bearer good")
		router.ServeHTTP(w, req)

		require.Equal(t, http.StatusForbidden, w.Code)
		_, _, code := decodeBody(w)
		assert.Equal(t, "no_permission_mapping", code,
			"the Map is an allowlist: an unmapped surface fails closed")
	})
}

// TestDevOpenAttachesABlanketPrincipal.
//
// A development-open instance has no way to tell one caller from another, so it
// attributes every request to a named blanket principal — and the NAME is the
// point: "development-open" in an audit row on a real deployment is a sentence
// that reads as wrong. Attaching no principal at all would be worse: the audit
// trail would record an empty actor for every write.
func TestDevOpenAttachesABlanketPrincipal(t *testing.T) {
	var seen *sdkauthz.Claims
	server := NewServer(nil, nil, sdkauthz.Guard{Mode: sdkauthz.ModeDevOpen}, Options{})

	handler := server.guard.HTTPMiddleware()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		claims, ok := sdkauthz.FromContext(r.Context())
		require.True(t, ok, "dev-open must still place a principal, or audit rows lose their actor")
		seen = claims
	}))

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/secrets", nil))

	require.NotNil(t, seen)
	assert.Equal(t, "development-open", seen.Subject)
	assert.True(t, seen.HasAction(permissions.PermGetSecret),
		"a dev-open caller is treated as blanket-granted — which is exactly what the boot banner shouts about")
}

// TestTheSetupWizardStaysReachableWhileAuthIsUnavailable. Provisioning is what
// makes tokens mintable at all, so the one surface that must survive
// ModeUnavailable is the self-guarded first-run wizard. A 503 here would leave a
// fresh install with no way to become configured.
func TestTheSetupWizardStaysReachableWhileAuthIsUnavailable(t *testing.T) {
	w := do(t, unavailableRouter(), http.MethodGet, "/api/v1/setup/status")
	assert.NotEqual(t, http.StatusServiceUnavailable, w.Code,
		"the setup surface is exempt from the guard by construction")
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

// TestTheBodyCapIsWiredIntoTheRouter. The cap lives in middleware.BodyLimit rather than
// in decode, so this asserts it is actually mounted — and that it applies OUTSIDE the
// guard, on a route the guard is refusing, because the setup surface is reachable
// before any token exists and the body arrives before any check can run.
func TestTheBodyCapIsWiredIntoTheRouter(t *testing.T) {
	router := NewServer(nil, nil, sdkauthz.Guard{
		Mode:   sdkauthz.ModeUnavailable,
		Reason: "AUTH_JWKS_URL not set",
	}, Options{MaxBodyBytes: 64}).Router()

	oversized := strings.NewReader(strings.Repeat("a", 4096))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/setup", oversized)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// The setup segment is exempt from the guard, so the request reaches a handler and
	// the capped reader is what refuses it.
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// TestTheConfiguredCapIsTheOneEnforced. decode no longer wraps the body a second time
// with a constant; an operator who raises the limit must actually get it.
func TestTheConfiguredCapIsTheOneEnforced(t *testing.T) {
	body := strings.Repeat("a", 8192)

	server := NewServer(nil, nil, sdkauthz.Guard{Mode: sdkauthz.ModeDevOpen}, Options{MaxBodyBytes: 16384})
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()

	var dst map[string]any
	mwHandler := mw.BodyLimit(server.opts.MaxBodyBytes)(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			// The body is not JSON, so decode fails — but it must fail on the CONTENT,
			// not on the size, which is what proves the larger configured cap applied.
			decode(w, r, &dst)
		}))
	mwHandler.ServeHTTP(w, req)

	assert.Contains(t, w.Body.String(), "invalid request body")
	assert.NotContains(t, w.Body.String(), "too large")
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

// ---------------------------------------------------------------------------
// Service-to-service vs browser-to-backend, over the real router
// ---------------------------------------------------------------------------

// guardedRouterFor builds the real mux with an enforcing guard that verifies exactly
// one token into the given principal. It is the shortest path from "a token of this
// class arrives" to "the real route table decided", which is what these tests are
// about — the SDK's Check has its own unit tests.
func guardedRouterFor(p *sdkauthz.Claims) http.Handler {
	return NewServer(nil, nil, sdkauthz.Guard{
		Mode: sdkauthz.ModeEnforced,
		Verify: func(_ context.Context, token string) (*sdkauthz.Claims, error) {
			if token != "good" {
				return nil, errors.New("bad token")
			}
			return p, nil
		},
	}, Options{}).Router()
}

func callAs(t *testing.T, p *sdkauthz.Claims, method, target string) (int, string) {
	t.Helper()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(method, target, strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer good")
	guardedRouterFor(p).ServeHTTP(w, req)

	var body struct {
		Code string `json:"code"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	return w.Code, body.Code
}

// admin returns a principal of the given class holding secret:Admin — the widest
// grant this service has. That is the point of these tests: the caller is refused
// with EVERY permission, so the refusal can only be about which CLASS of caller it is.
func admin(kind string) *sdkauthz.Claims {
	return &sdkauthz.Claims{
		Subject:        "principal-1",
		Kind:           kind,
		Grants:         []sdkauthz.Grant{{Action: permissions.PermAdmin}},
		BlanketActions: permissions.BlanketActions(),
	}
}

// TestServicePrincipalIsRefusedOnTheConsoleSurfaces is the stolen-m2m-credential
// case, end to end over the real routing table: the token verifies, it carries
// secret:Admin, and a workload still has no business creating a project, rewiring a
// webhook, destroying a secret or reading the access trail.
func TestServicePrincipalIsRefusedOnTheConsoleSurfaces(t *testing.T) {
	consoleSurfaces := []struct {
		method string
		target string
		why    string
	}{
		{http.MethodPost, "/api/v1/projects", "creating a project is console work"},
		{http.MethodPatch, "/api/v1/projects/billing", "so is renaming one"},
		{http.MethodDelete, "/api/v1/projects/billing", "and deleting one"},
		{http.MethodPost, "/api/v1/environments", "environments are the same shape"},
		{http.MethodPost, "/api/v1/folders", "so are folders"},
		{http.MethodDelete, "/api/v1/folders", "a folder delete also deletes the secrets under it"},
		{http.MethodPost, "/api/v1/imports", "an import makes another scope's values readable through this one"},
		{http.MethodPost, "/api/v1/webhooks", "a webhook endpoint is where change announcements are sent"},
		{http.MethodDelete, "/api/v1/webhooks/" + testUUID, "and unwiring one is how you silence them"},
		{http.MethodPost, "/api/v1/secrets/rotation-policy", "the policy decides when every future value is replaced"},
		{http.MethodPost, "/api/v1/secrets/restore", "restore is authorized at TENANT scope"},
		{http.MethodPost, "/api/v1/secrets/destroy", "destroy is irreversible and tenant-scoped"},
		{http.MethodGet, "/api/v1/audit", "the access trail is what an incident review reads"},
	}

	workload := admin(sdkauthz.ActorKindService)
	operator := admin(sdkauthz.ActorKindUser)

	for _, s := range consoleSurfaces {
		t.Run(s.method+" "+s.target, func(t *testing.T) {
			status, code := callAs(t, workload, s.method, s.target)
			assert.Equal(t, http.StatusForbidden, status,
				"a service principal must be refused here: %s", s.why)
			assert.Equal(t, "actor_kind_not_permitted", code,
				"and the refusal must be distinguishable from a missing grant — "+
					"widening permissions is not the fix for a workload on the console surface")

			// The same surface, driven by a human, is not blocked by the actor check.
			// It reaches the handler (and fails on the nil dependencies these router
			// tests use), which is enough to prove the guard let it past.
			status, code = callAs(t, operator, s.method, s.target)
			assert.NotEqual(t, "actor_kind_not_permitted", code,
				"a user principal must not be refused by the ACTOR check on %s %s (status %d)",
				s.method, s.target, status)
		})
	}
}

// TestBothClassesReachTheWorkloadSurfaces is the other half, and the one that would
// break the product if it regressed: a workload fetching its own secrets is the core
// service-to-service case this vault exists for, and an operator does exactly the
// same things from the console. Neither class may be refused on these.
func TestBothClassesReachTheWorkloadSurfaces(t *testing.T) {
	workloadSurfaces := []struct {
		method string
		target string
	}{
		{http.MethodPost, "/api/v1/secrets/reveal"},
		{http.MethodPost, "/api/v1/bulk/get"},
		{http.MethodPost, "/api/v1/bulk/put"},
		{http.MethodGet, "/api/v1/secrets"},
		{http.MethodGet, "/api/v1/secrets/describe"},
		{http.MethodGet, "/api/v1/secrets/versions"},
		{http.MethodGet, "/api/v1/secrets/deleted"},
		{http.MethodPost, "/api/v1/secrets"},
		{http.MethodPatch, "/api/v1/secrets"},
		{http.MethodPost, "/api/v1/secrets/rollback"},
		{http.MethodPost, "/api/v1/secrets/rotate"},
		{http.MethodPost, "/api/v1/secrets/delete"},
		{http.MethodGet, "/api/v1/projects"},
		{http.MethodGet, "/api/v1/folders"},
		{http.MethodGet, "/api/v1/webhooks"},
	}

	for _, kind := range []string{sdkauthz.ActorKindService, sdkauthz.ActorKindUser} {
		p := admin(kind)
		for _, s := range workloadSurfaces {
			t.Run(kind+" "+s.method+" "+s.target, func(t *testing.T) {
				_, code := callAs(t, p, s.method, s.target)
				assert.NotEqual(t, "actor_kind_not_permitted", code,
					"%s principals must reach %s %s", kind, s.method, s.target)
			})
		}
	}
}

// TestAnUnclassifiedPrincipalIsRefusedOnAConstrainedSurface. "We could not tell what
// this caller is" is not a reason to admit it to the console surface.
func TestAnUnclassifiedPrincipalIsRefusedOnAConstrainedSurface(t *testing.T) {
	status, code := callAs(t, admin(""), http.MethodPost, "/api/v1/projects")
	assert.Equal(t, http.StatusForbidden, status)
	assert.Equal(t, "actor_kind_not_permitted", code)
}

// testUUID is a syntactically valid path parameter; no handler runs in these tests.
const testUUID = "11111111-1111-1111-1111-111111111111"
