package authz

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const prodPassword = "mrn:secret:acme:billing:secret/prod/db/PASSWORD"

// ---------------------------------------------------------------------------
// Grants
// ---------------------------------------------------------------------------

func TestParseGrant(t *testing.T) {
	g := ParseGrant("secret:GetSecret")
	assert.Equal(t, PermGetSecret, g.Action)
	assert.Empty(t, g.Resource)

	g = ParseGrant("secret:GetSecret=mrn:secret:acme:billing:secret/staging/*")
	assert.Equal(t, PermGetSecret, g.Action)
	assert.Equal(t, "mrn:secret:acme:billing:secret/staging/*", g.Resource,
		"only the FIRST '=' splits, so a pattern containing one survives")
}

// TestUnqualifiedGrantIsServiceWide states the one compatibility trade in the design,
// as a test, so it cannot change silently.
func TestUnqualifiedGrantIsServiceWide(t *testing.T) {
	c := &Claims{Grants: []Grant{{Action: PermGetSecret}}}
	assert.True(t, c.Allows(PermGetSecret, prodPassword))
	assert.True(t, c.Allows(PermGetSecret, "mrn:secret:other:other:secret/dev/X"))
}

// TestScopedGrantIsConfinedToItsPattern is the point of MRN-level authorization.
func TestScopedGrantIsConfinedToItsPattern(t *testing.T) {
	c := &Claims{Grants: []Grant{{
		Action:   PermGetSecret,
		Resource: "mrn:secret:acme:billing:secret/staging/*",
	}}}
	assert.True(t, c.Allows(PermGetSecret, "mrn:secret:acme:billing:secret/staging/db/PASSWORD"))
	assert.False(t, c.Allows(PermGetSecret, prodPassword))
}

// TestMetadataGrantIsNotARevealGrant is the split the contract requires.
func TestMetadataGrantIsNotARevealGrant(t *testing.T) {
	c := &Claims{Grants: []Grant{{Action: PermReadMetadata}}}
	assert.True(t, c.Allows(PermReadMetadata, prodPassword))
	assert.False(t, c.Allows(PermGetSecret, prodPassword),
		"metadata browsing and value reveal are different privileges")
}

// TestAdminImpliesEveryAction but not a wider resource scope.
func TestAdminImpliesEveryActionButNotAWiderScope(t *testing.T) {
	c := &Claims{Grants: []Grant{{Action: PermAdmin, Resource: "mrn:secret:acme:*:*"}}}
	assert.True(t, c.Allows(PermGetSecret, prodPassword))
	assert.True(t, c.Allows(PermDeleteSecret, prodPassword))
	assert.False(t, c.Allows(PermGetSecret, "mrn:secret:other:billing:secret/prod/X"),
		"an admin grant written for one tenant stays in that tenant")
}

// TestDenyByDefault covers every fail-closed path in one place.
func TestDenyByDefault(t *testing.T) {
	var nilClaims *Claims
	assert.False(t, nilClaims.Allows(PermGetSecret, prodPassword))

	empty := &Claims{}
	assert.False(t, empty.Allows(PermGetSecret, prodPassword))

	// A malformed grant pattern is treated as no grant, never as a wildcard.
	broken := &Claims{Grants: []Grant{{Action: PermGetSecret, Resource: "not-an-mrn"}}}
	assert.False(t, broken.Allows(PermGetSecret, prodPassword))

	// A resource this service could not render as a valid MRN is refused rather than
	// matched loosely.
	wide := &Claims{Grants: []Grant{{Action: PermGetSecret}}}
	assert.False(t, wide.Allows(PermGetSecret, "not-an-mrn"))
	assert.False(t, wide.Allows("", prodPassword))
}

// TestNoActionPrefixMatching: "secret:Get*" must not be a grant whose blast radius
// changes every time an RPC is added.
func TestNoActionPrefixMatching(t *testing.T) {
	c := &Claims{Grants: []Grant{{Action: "secret:Get*"}}}
	assert.False(t, c.Allows(PermGetSecret, prodPassword))
}

// ---------------------------------------------------------------------------
// Declared permissions
// ---------------------------------------------------------------------------

// TestDeclaredPermissionsCoversEveryRoutePermission is the anti-drift check.
// Registration and enforcement are two halves of one fact: when they drift the
// failure is silent and total, because the guard demands a permission that exists
// nowhere in Auth.
func TestDeclaredPermissionsCoversEveryRoutePermission(t *testing.T) {
	declared := DeclaredPermissions()
	for segment, p := range routePermissions {
		assert.True(t, slices.Contains(declared, p.Read),
			"segment %q read permission %q is not declared", segment, p.Read)
		assert.True(t, slices.Contains(declared, p.Write),
			"segment %q write permission %q is not declared", segment, p.Write)
	}
}

func TestDeclaredPermissionsIsSortedAndComplete(t *testing.T) {
	declared := DeclaredPermissions()
	assert.True(t, slices.IsSorted(declared), "an unsorted list makes setup logs and diffs unreadable")
	assert.Len(t, declared, len(allPermissions))
	for _, want := range []string{
		PermReadMetadata, PermGetSecret, PermPutSecret, PermDeleteSecret,
		PermRotateSecret, PermListSecrets, PermManageProject, PermManageEnvironment,
		PermManageFolder, PermManageRotation, PermReadAudit, PermAdmin,
	} {
		assert.True(t, slices.Contains(declared, want), "%q must be declared", want)
	}
}

// ---------------------------------------------------------------------------
// The HTTP surface guard
// ---------------------------------------------------------------------------

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
}

func request(method, path, token string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

func verifier(claims *Claims) VerifyFunc {
	return func(_ context.Context, token string) (*Claims, error) {
		if token != "good" {
			return nil, errors.New("bad token")
		}
		return claims, nil
	}
}

// TestUnmappedRouteIsDenied is the allowlist property: mounting a router without
// deciding its permissions fails closed instead of shipping an open surface.
func TestUnmappedRouteIsDenied(t *testing.T) {
	g := Guard{Mode: ModeEnforced, Verify: verifier(&Claims{Grants: []Grant{{Action: PermAdmin}}})}
	w := httptest.NewRecorder()
	g.Middleware(okHandler()).ServeHTTP(w, request(http.MethodGet, "/api/v1/brand-new-thing", "good"))
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "no permission mapping")
}

func TestMissingAndInvalidTokensAreUnauthorized(t *testing.T) {
	g := Guard{Mode: ModeEnforced, Verify: verifier(&Claims{})}

	w := httptest.NewRecorder()
	g.Middleware(okHandler()).ServeHTTP(w, request(http.MethodGet, "/api/v1/projects", ""))
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	w = httptest.NewRecorder()
	g.Middleware(okHandler()).ServeHTTP(w, request(http.MethodGet, "/api/v1/projects", "forged"))
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "invalid token")
	assert.NotContains(t, w.Body.String(), "bad token",
		"the verify error is never echoed — it is oracle material")
}

func TestBaselinePermissionIsEnforcedPerMethod(t *testing.T) {
	metadataOnly := &Claims{Grants: []Grant{{Action: PermReadMetadata}}}
	g := Guard{Mode: ModeEnforced, Verify: verifier(metadataOnly)}

	w := httptest.NewRecorder()
	g.Middleware(okHandler()).ServeHTTP(w, request(http.MethodGet, "/api/v1/projects", "good"))
	assert.Equal(t, http.StatusTeapot, w.Code, "a read is allowed by the read baseline")

	w = httptest.NewRecorder()
	g.Middleware(okHandler()).ServeHTTP(w, request(http.MethodPost, "/api/v1/projects", "good"))
	assert.Equal(t, http.StatusForbidden, w.Code, "a write needs the write baseline")
	assert.Contains(t, w.Body.String(), PermManageProject)
}

// TestModeUnavailableRefusesEverythingButSetup: outside development a missing auth
// configuration disables the API rather than quietly serving it open — and the setup
// surface stays reachable so a fresh install can be provisioned at all.
func TestModeUnavailableRefusesEverythingButSetup(t *testing.T) {
	g := Guard{Mode: ModeUnavailable, Reason: "AUTH_JWKS_URL not set"}

	w := httptest.NewRecorder()
	g.Middleware(okHandler()).ServeHTTP(w, request(http.MethodGet, "/api/v1/secrets", ""))
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Contains(t, w.Body.String(), "AUTH_JWKS_URL not set")

	w = httptest.NewRecorder()
	g.Middleware(okHandler()).ServeHTTP(w, request(http.MethodPost, "/api/v1/setup", ""))
	assert.Equal(t, http.StatusTeapot, w.Code, "the setup surface guards itself and stays reachable")
}

// TestModeDevOpenAttachesBlanketClaims so downstream audit rows are attributed to a
// subject that looks wrong if it is ever seen on a real deployment.
func TestModeDevOpenAttachesBlanketClaims(t *testing.T) {
	var seen *Claims
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, ok := FromContext(r.Context())
		require.True(t, ok)
		seen = c
		w.WriteHeader(http.StatusTeapot)
	})
	g := Guard{Mode: ModeDevOpen, Reason: "AUTH_JWKS_URL not set"}

	w := httptest.NewRecorder()
	g.Middleware(handler).ServeHTTP(w, request(http.MethodPost, "/api/v1/secrets", ""))
	assert.Equal(t, http.StatusTeapot, w.Code)
	require.NotNil(t, seen)
	assert.Equal(t, "development-open", seen.Subject)
	assert.True(t, seen.Allows(PermGetSecret, prodPassword))
}

func TestHealthzIsOutsideTheGuardedGroup(t *testing.T) {
	// apiSegment returns "" for anything not under /api/v1, and an empty segment is
	// not in routePermissions — but the route never reaches the middleware because it
	// is mounted outside the group. This asserts the segment extraction that makes
	// that arrangement correct.
	assert.Equal(t, "", apiSegment("/healthz"))
	assert.Equal(t, "secrets", apiSegment("/api/v1/secrets"))
	assert.Equal(t, "secrets", apiSegment("/api/v1/secrets/reveal"))
	assert.Equal(t, "setup", apiSegment("/api/v1/setup/status"))
}

func TestBearerParsing(t *testing.T) {
	assert.Equal(t, "abc", bearer("Bearer abc"))
	assert.Equal(t, "abc", bearer("bearer abc"))
	assert.Equal(t, "", bearer("Basic abc"))
	assert.Equal(t, "", bearer(""))
}
