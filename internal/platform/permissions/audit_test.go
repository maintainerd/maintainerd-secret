package permissions_test

import (
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	sdkauthz "github.com/maintainerd/sdk/authz"
	secretv1 "github.com/maintainerd/secret/gen/maintainerd/secret/v1"
	"github.com/maintainerd/secret/internal/httpapi"
	"github.com/maintainerd/secret/internal/platform/permissions"
)

// THE GAP AUDIT.
//
// Every other test in this repo checks that a surface behaves correctly. This one
// checks that no surface was FORGOTTEN — which is the failure mode that actually
// ships, because a forgotten route does not throw, does not log and does not look
// wrong in review. It looks like a handler.
//
// The property is: for every REST route the chi router serves and every gRPC
// method the generated descriptors register, permissions.Map either (a) demands a
// non-empty permission for it, or (b) exempts it — and every exemption is on a
// short list with a written reason.
//
// BOTH SIDES ARE DERIVED FROM THE LIVE SURFACE, never from a hand-kept list. The
// routes come from walking the real router this service mounts (chi.Walk), and
// the methods come from the protoc-generated grpc.ServiceDesc values that
// grpc.Server dispatches on. A hand-kept list would drift silently and the test
// would keep passing, which is worse than no test: it would report "no gaps"
// about a surface it had stopped reading.
//
// The Map is an ALLOWLIST, so an unmapped surface already fails CLOSED at runtime
// — a 403 to every caller, valid token or not. This test converts that from a
// production incident with a baffling symptom into a red CI run naming the route.

// ---------------------------------------------------------------------------
// The exemptions, and why each one exists
// ---------------------------------------------------------------------------

// justifiedExemptPaths is every HTTP path served with NO permission check, with
// the argument for it. A path that appears in permissions.Map().ExemptPaths and
// not here fails this test: adding an unguarded route must require writing down
// why, in a file a reviewer reads.
var justifiedExemptPaths = map[string]string{
	permissions.HealthzPath: "liveness. An orchestrator must be able to probe before it holds a " +
		"credential, and the body is the literal string ok.",
	permissions.ReadyzPath: "readiness. Same argument; it discloses a dependency NAME " +
		"(database, auth) and never an address, a driver message or a version.",
	permissions.SetupPath: "the first-run wizard. It must work BEFORE Auth exists, because " +
		"provisioning is what makes tokens mintable at all. Self-guarded by " +
		"SETUP_BOOTSTRAP_TOKEN compared in constant time, rate-limited per client IP, " +
		"and refused outright once an orchestrator owns the instance or " +
		"MAINTAINERD_MODE=core declares one will.",
}

// justifiedExemptMethods is the same for gRPC, matched EXACTLY. A prefix
// exemption would mean the next RPC added to one of these services inherits
// somebody else's argument.
var justifiedExemptMethods = map[string]string{
	permissions.HealthServicePrefix + "Check": "the standard health protocol, for the reason /healthz is exempt.",
	permissions.HealthServicePrefix + "Watch": "the streaming health probe. Exempt for the same reason as Check, " +
		"and the reason the STREAM interceptor has to be installed at all.",
	permissions.SecretServicePrefix + "Ping": "answers {ok, setup_complete} and nothing else — the same single bit " +
		"the anonymous REST setup status returns. An orchestrator has to be able to ask " +
		"\"is this instance provisioned yet\" before it has provisioned the thing that mints tokens.",
	permissions.SecretServicePrefix + "Setup": "the legacy flat-surface setup RPC, gated by the bootstrap token " +
		"compared in constant time inside the handler.",
	permissions.SetupServicePrefix + "GetSetupStatus": "the controlled setup surface. Discloses one bit to an " +
		"unprivileged caller; the full payload needs the setup token or a verified secret:Admin.",
	permissions.SetupServicePrefix + "Setup":         "the controlled setup surface, gated by the x-setup-token metadata header.",
	permissions.SetupServicePrefix + "CompleteSetup": "the controlled setup surface, gated by the x-setup-token metadata header.",
}

// ---------------------------------------------------------------------------
// REST
// ---------------------------------------------------------------------------

// router builds the real mux. NewServer tolerates nil dependencies because the
// routing table is fixed at construction and no handler runs here.
func router(t *testing.T) chi.Routes {
	t.Helper()
	handler := httpapi.NewServer(nil, nil, sdkauthz.Guard{
		Mode:   sdkauthz.ModeUnavailable,
		Reason: "gap audit",
	}, httpapi.Options{}).Router()

	routes, ok := handler.(chi.Routes)
	require.True(t, ok, "Router() must stay walkable — the audit depends on enumerating it")
	return routes
}

type restRoute struct {
	method  string
	pattern string
}

func walkREST(t *testing.T) []restRoute {
	t.Helper()
	var out []restRoute
	err := chi.Walk(router(t), func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		out = append(out, restRoute{method: method, pattern: route})
		return nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, out, "walking the router produced nothing; the audit would pass vacuously")
	return out
}

// TestEveryRESTRouteIsGuardedOrJustified is the REST half of the audit.
func TestEveryRESTRouteIsGuardedOrJustified(t *testing.T) {
	m := permissions.Map()

	for _, r := range walkREST(t) {
		t.Run(r.method+" "+r.pattern, func(t *testing.T) {
			surface := sdkauthz.Surface{Path: r.pattern, HTTPMethod: r.method}

			if m.IsExempt(surface) {
				_, justified := matchJustifiedPath(r.pattern)
				assert.True(t, justified,
					"%s %s is served with NO permission check and has no written justification in "+
						"justifiedExemptPaths", r.method, r.pattern)
				return
			}

			required, mapped := m.Required(surface)
			require.True(t, mapped,
				"%s %s has no permission mapping. It is DENIED to every caller at runtime "+
					"(the Map is an allowlist), which ships as a 403 nobody can explain. Add its "+
					"segment to permissions.Map().Routes.", r.method, r.pattern)
			assert.NotEmpty(t, required,
				"%s %s is mapped to an EMPTY permission, which means any authenticated caller may "+
					"call it. That is only ever correct for a surface deliberately opened, and this "+
					"service has none.", r.method, r.pattern)
		})
	}
}

// TestEveryMappedRouteSegmentIsLive is the other direction: a segment in the
// table that no route serves is dead weight, and dead weight is what makes an
// authorization table stop being read.
func TestEveryMappedRouteSegmentIsLive(t *testing.T) {
	live := map[string]bool{}
	for _, r := range walkREST(t) {
		if segment := sdkauthz.FirstSegment(permissions.APIPrefix, r.pattern); segment != "" {
			live[segment] = true
		}
	}
	for segment := range permissions.Map().Routes {
		assert.True(t, live[segment], "route segment %q is mapped but no route serves it", segment)
	}
}

// TestEveryExemptPathIsJustified catches an exemption added to the Map without a
// reason written beside it.
func TestEveryExemptPathIsJustified(t *testing.T) {
	for _, path := range permissions.Map().ExemptPaths {
		reason, ok := justifiedExemptPaths[path]
		assert.True(t, ok, "exempt path %q has no justification", path)
		assert.NotEmpty(t, reason)
	}
	assert.Len(t, permissions.Map().ExemptPaths, len(justifiedExemptPaths),
		"the justification list and the exemption list must be the same set")
}

// TestTheGuardedGroupHasNoUnexpectedExemptions. Exactly three HTTP paths are
// served unguarded, and two of them are probes. If that count moves, somebody has
// opened a door.
func TestTheGuardedGroupHasNoUnexpectedExemptions(t *testing.T) {
	var exempt []string
	for _, r := range walkREST(t) {
		if permissions.Map().IsExempt(sdkauthz.Surface{Path: r.pattern, HTTPMethod: r.method}) {
			exempt = append(exempt, r.method+" "+r.pattern)
		}
	}
	sort.Strings(exempt)
	assert.Equal(t, []string{
		"GET /healthz",
		"GET /readyz",
		"GET /api/v1/setup/status",
		"POST /api/v1/setup/",
	}, sortedLikeExpected(exempt), "the unguarded HTTP surface changed")
}

// ---------------------------------------------------------------------------
// gRPC
// ---------------------------------------------------------------------------

// registeredServices are the descriptors the bootstrap hands to grpc.Server.
// Enumerating THESE rather than the .proto text is what makes the audit follow
// the code that actually dispatches.
func registeredServices() []*grpc.ServiceDesc {
	return []*grpc.ServiceDesc{
		&secretv1.SecretService_ServiceDesc,
		&secretv1.SetupService_ServiceDesc,
	}
}

// grpcMethods flattens every registered descriptor into full method names,
// INCLUDING streams. Streams are the ones that were invisible: they dispatch
// through a different interceptor chain, so a unary-only guard never sees them.
func grpcMethods() []string {
	var out []string
	for _, desc := range registeredServices() {
		prefix := "/" + desc.ServiceName + "/"
		for _, m := range desc.Methods {
			out = append(out, prefix+m.MethodName)
		}
		for _, s := range desc.Streams {
			out = append(out, prefix+s.StreamName)
		}
	}
	sort.Strings(out)
	return out
}

// TestEveryGRPCMethodIsGuardedOrJustified is the gRPC half of the audit.
func TestEveryGRPCMethodIsGuardedOrJustified(t *testing.T) {
	m := permissions.Map()
	methods := grpcMethods()
	require.NotEmpty(t, methods)

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			surface := sdkauthz.Surface{FullMethod: method}

			if m.IsExempt(surface) {
				reason, justified := justifiedExemptMethods[method]
				assert.True(t, justified,
					"%s is served with NO permission check and has no written justification in "+
						"justifiedExemptMethods", method)
				assert.NotEmpty(t, reason)
				return
			}

			required, mapped := m.Required(surface)
			require.True(t, mapped,
				"%s has no permission mapping. It is DENIED to every caller at runtime, which "+
					"ships as a PermissionDenied nobody can explain. Add it to "+
					"permissions.Map().Methods.", method)
			assert.NotEmpty(t, required,
				"%s is mapped to an EMPTY permission, so any authenticated caller may call it", method)
		})
	}
}

// TestEveryMappedMethodIsRegistered is the stale-entry direction.
func TestEveryMappedMethodIsRegistered(t *testing.T) {
	live := map[string]bool{}
	for _, method := range grpcMethods() {
		live[method] = true
	}
	for mapped := range permissions.Map().Methods {
		assert.True(t, live[mapped], "%s is mapped but no registered service serves it", mapped)
	}
}

// TestEveryExemptMethodIsJustifiedAndReal. Health lives outside these
// descriptors (grpc-go registers it), so it is checked for a justification but
// not for registration here.
func TestEveryExemptMethodIsJustifiedAndReal(t *testing.T) {
	live := map[string]bool{}
	for _, method := range grpcMethods() {
		live[method] = true
	}
	for _, method := range permissions.Map().ExemptMethods {
		reason, ok := justifiedExemptMethods[method]
		assert.True(t, ok, "exempt method %q has no justification", method)
		assert.NotEmpty(t, reason)

		if strings.HasPrefix(method, permissions.HealthServicePrefix) {
			continue // registered by grpc-go's health package, not by a descriptor here
		}
		assert.True(t, live[method], "exempt method %q is not registered by any service", method)
	}
	assert.Len(t, permissions.Map().ExemptMethods, len(justifiedExemptMethods),
		"the justification list and the exemption list must be the same set")
}

// TestReflectionIsNeitherMappedNorExempt. That combination is deliberate and load
// bearing: it makes reflection reachable ONLY in ModeDevOpen, where the guard
// admits every caller before it consults the map. Mapping it would make it
// reachable with a grant in production, and exempting it would make it reachable
// with nothing at all.
func TestReflectionIsNeitherMappedNorExempt(t *testing.T) {
	const method = "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo"
	m := permissions.Map()
	surface := sdkauthz.Surface{FullMethod: method}

	assert.False(t, m.IsExempt(surface))
	_, mapped := m.Required(surface)
	assert.False(t, mapped)
}

// TestTheAuditWouldCatchANewSurface is the audit's own vacuity check.
//
// A test that enumerates a surface and finds no problem is indistinguishable, at
// a glance, from a test that enumerates nothing. This exercises the exact
// predicate the two audits above use against surfaces that do NOT exist, and
// requires it to report them as gaps. If somebody weakens Map.Required — say by
// making an unknown segment fall back to a default permission — this fails and
// the audits stop being decorative.
func TestTheAuditWouldCatchANewSurface(t *testing.T) {
	m := permissions.Map()

	t.Run("an unmapped REST segment", func(t *testing.T) {
		surface := sdkauthz.Surface{Path: "/api/v1/debug/dump", HTTPMethod: http.MethodGet}
		assert.False(t, m.IsExempt(surface))
		_, mapped := m.Required(surface)
		assert.False(t, mapped, "a brand-new segment must read as UNMAPPED, or the audit proves nothing")
	})

	t.Run("a route outside the API prefix", func(t *testing.T) {
		surface := sdkauthz.Surface{Path: "/internal/metrics", HTTPMethod: http.MethodGet}
		assert.False(t, m.IsExempt(surface))
		_, mapped := m.Required(surface)
		assert.False(t, mapped)
	})

	t.Run("a near-miss on an exempt prefix", func(t *testing.T) {
		// Segment-aware matching is what stops /api/v1/setup from exempting a
		// neighbour whose name merely starts with it.
		assert.False(t, m.IsExempt(sdkauthz.Surface{
			Path: "/api/v1/setup-admin", HTTPMethod: http.MethodPost,
		}))
	})

	t.Run("an unmapped gRPC method", func(t *testing.T) {
		surface := sdkauthz.Surface{FullMethod: permissions.SecretServicePrefix + "ExportEverything"}
		assert.False(t, m.IsExempt(surface))
		_, mapped := m.Required(surface)
		assert.False(t, mapped)
	})

	t.Run("a new RPC on a service whose neighbours are exempt", func(t *testing.T) {
		surface := sdkauthz.Surface{FullMethod: permissions.SetupServicePrefix + "ResetEverything"}
		assert.False(t, m.IsExempt(surface),
			"the setup exemption is an exact method list, not a service prefix")
		_, mapped := m.Required(surface)
		assert.False(t, mapped)
	})
}

// ---------------------------------------------------------------------------
// The permission vocabulary
// ---------------------------------------------------------------------------

// TestDeclaredPermissionsMatchesTheConstants. Setup registers exactly
// DeclaredPermissions() in Auth. If the Map can demand a permission the constant
// list does not contain — or the reverse — registration and enforcement have
// drifted, and the failure is silent and total: the guard demands something no
// token can carry, and every call is 403 with nothing in any log saying why.
func TestDeclaredPermissionsMatchesTheConstants(t *testing.T) {
	want := append([]string(nil), permissions.All()...)
	sort.Strings(want)
	assert.Equal(t, want, permissions.DeclaredPermissions())
}

// TestRevealIsADistinctGrantFromReadMetadata is the one permission split this
// service cannot lose. Browsing metadata is safe to hand out broadly; revealing a
// value is reading the production database password. Collapsed, every principal
// who can render a console page could exfiltrate every credential on it, and the
// audit trail could no longer separate "who looked at the list" from "who read
// the value".
func TestRevealIsADistinctGrantFromReadMetadata(t *testing.T) {
	assert.NotEqual(t, permissions.PermReadMetadata, permissions.PermGetSecret)

	m := permissions.Map().Methods
	assert.Equal(t, permissions.PermGetSecret, m[permissions.SecretServicePrefix+"GetSecret"])
	assert.Equal(t, permissions.PermReadMetadata, m[permissions.SecretServicePrefix+"DescribeSecret"])

	// And the REST reveal is NOT covered by its segment's baseline: /secrets
	// carries metadata on both verbs, and the reveal privilege is enforced per
	// operation against the target MRN in internal/api.
	required, mapped := permissions.Map().Required(sdkauthz.Surface{
		Path: "/api/v1/secrets/reveal", HTTPMethod: http.MethodPost,
	})
	require.True(t, mapped)
	assert.Equal(t, permissions.PermReadMetadata, required,
		"the surface baseline is metadata; GetSecret is checked against the target MRN in the api layer")
	assert.Contains(t, permissions.Map().OperationPermissions, permissions.PermGetSecret,
		"a permission enforced only per-operation must still be DECLARED, or Auth never registers it")
}

// TestAdminIsTheOnlyBlanketAction. A second blanket action is a second key to the
// whole vault, and the SDK honours whatever is on this list without further
// argument.
func TestAdminIsTheOnlyBlanketAction(t *testing.T) {
	assert.Equal(t, []string{permissions.PermAdmin}, permissions.Map().BlanketActions)
	assert.Equal(t, []string{permissions.PermAdmin}, permissions.BlanketActions())
}

// TestAdminImpliesEveryActionButNotAWiderScope.
//
// secret:Admin is a blanket over ACTIONS, never over RESOURCES. An admin grant
// written for one tenant stays confined to that tenant's MRNs — which is what
// makes "administrator of the acme tenant" a thing that can exist at all. If
// blanket ever leaked into the resource dimension, every tenant admin would
// silently become an admin of every tenant.
//
// The check is here rather than in the SDK because secret:Admin is this service's
// vocabulary: the SDK only knows it is blanket because Map.BlanketActions says so.
func TestAdminImpliesEveryActionButNotAWiderScope(t *testing.T) {
	tenantAdmin := &sdkauthz.Principal{
		Grants: []sdkauthz.Grant{
			{Action: permissions.PermAdmin, Resource: "mrn:secret:acme:*:*"},
		},
		BlanketActions: permissions.BlanketActions(),
	}

	assert.True(t, tenantAdmin.Allows(permissions.PermGetSecret, "mrn:secret:acme:billing:secret/prod/db/PASSWORD"),
		"admin covers every action inside its own scope")
	assert.True(t, tenantAdmin.Allows(permissions.PermDeleteSecret, "mrn:secret:acme:billing:secret/prod/db/PASSWORD"))

	assert.False(t, tenantAdmin.Allows(permissions.PermReadMetadata, "mrn:secret:other:billing:secret/prod/db/PASSWORD"),
		"admin must NOT reach another tenant")
	assert.False(t, tenantAdmin.Allows(permissions.PermGetSecret, "mrn:secret:acmecorp:billing:secret/prod/x"),
		"a wildcard must not run across a segment boundary into a similarly named tenant")
}

// TestAMetadataGrantIsNotARevealGrant, at the grant level rather than the table
// level. This is the property the whole ReadMetadata/GetSecret split exists for.
func TestAMetadataGrantIsNotARevealGrant(t *testing.T) {
	reader := &sdkauthz.Principal{
		Grants:         []sdkauthz.Grant{{Action: permissions.PermReadMetadata}},
		BlanketActions: permissions.BlanketActions(),
	}
	const target = "mrn:secret:acme:billing:secret/prod/db/PASSWORD"

	assert.True(t, reader.Allows(permissions.PermReadMetadata, target))
	assert.False(t, reader.Allows(permissions.PermGetSecret, target),
		"browsing what exists must never imply reading a value")
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// matchJustifiedPath finds the justification covering a route, matching on a
// segment boundary exactly as the SDK's exemption does.
func matchJustifiedPath(pattern string) (string, bool) {
	for prefix, reason := range justifiedExemptPaths {
		trimmed := strings.TrimSuffix(prefix, "/")
		if pattern == trimmed || strings.HasPrefix(pattern, trimmed+"/") {
			return reason, true
		}
	}
	return "", false
}

// sortedLikeExpected keeps the assertion readable by comparing sets rather than
// orderings; the expected slice above is written in the order a reader expects to
// see the surface, not in byte order.
func sortedLikeExpected(got []string) []string {
	out := append([]string(nil), got...)
	order := map[string]int{
		"GET /healthz":             0,
		"GET /readyz":              1,
		"GET /api/v1/setup/status": 2,
		"POST /api/v1/setup/":      3,
	}
	sort.SliceStable(out, func(i, j int) bool {
		oi, oki := order[out[i]]
		oj, okj := order[out[j]]
		if oki && okj {
			return oi < oj
		}
		return out[i] < out[j]
	})
	return out
}
