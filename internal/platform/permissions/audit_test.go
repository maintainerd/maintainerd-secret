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

// THE GAP AUDIT — and, now, THE SPECIFICATION.
//
// Every other test in this repo checks that a surface behaves correctly. This one
// checks that no surface was FORGOTTEN, and that every surface demands what its
// handler actually does — the two failure modes that actually ship, because
// neither throws, neither logs and neither looks wrong in review. They look like
// a handler.
//
// The property has two halves:
//
//  1. NO GAPS. For every REST route the chi router serves and every gRPC method
//     the generated descriptors register, permissions.Map either demands a rule
//     for it or exempts it — and every exemption is on a short list with a
//     written reason.
//
//  2. NO WEAK GUARDS. Every surface resolves to EXACTLY the permission and actor
//     class written down for it in restSpec / grpcSpec below, and no surface
//     whose handler performs a WRITE resolves to a read-only permission.
//
// THE SPEC TABLES ARE WRITTEN INDEPENDENTLY OF THE MAP, and that is what makes
// them a specification rather than a mirror. Each row was derived by reading the
// handler in internal/httpapi or internal/grpcserver, following it to its
// internal/api method, and recording the permission that method's s.guard call
// actually demands. A row that merely restated permissions.Map would pass forever
// and prove nothing; these rows disagree with the Map loudly if either moves. The
// `mutates` column is likewise a fact about the HANDLER, not about the HTTP verb —
// a reveal is a POST and is not a mutation, a rollback is a POST and is.
//
// THE SURFACE LISTS ARE DERIVED FROM THE LIVE SURFACE, never from a hand-kept
// list. The routes come from walking the real router this service mounts
// (chi.Walk), and the methods come from the protoc-generated grpc.ServiceDesc
// values that grpc.Server dispatches on. So a NEW surface fails the spec (it has
// no row) and a REMOVED surface fails it too (its row is stale) — the table
// cannot quietly stop describing the service.
//
// The Map is an ALLOWLIST, so an unmapped surface already fails CLOSED at runtime
// — a 403 to every caller, valid token or not. This test converts that from a
// production incident with a baffling symptom into a red CI run naming the route.

// ---------------------------------------------------------------------------
// The specification
// ---------------------------------------------------------------------------

// surfaceSpec is what ONE surface must demand.
type surfaceSpec struct {
	// permission is the exact permission the surface guard must require. It is the
	// permission the handler's operation performs, read off the s.guard call in
	// internal/api — never a weaker baseline, because the surface guard runs FIRST.
	permission string
	// actor is the class of caller allowed to reach the surface at all.
	actor sdkauthz.Actor
	// mutates is a fact about the HANDLER: does reaching it change durable state?
	// It is deliberately not derived from the HTTP verb — reveal and batch-get are
	// POSTs carrying reads (a secret's address belongs in a body, not in an access
	// log), and a GET is never a mutation. A mutating surface may not be guarded by
	// a read-only permission; see TestNoMutatingSurfaceIsGuardedByAReadPermission.
	mutates bool
	// alsoEnforces are the permissions the OPERATION layer checks in addition,
	// against the concrete target MRN, inside internal/api. The route guard demands
	// the primary permission above; these are the second layer, and they are written
	// down here so the pairing is visible to a reader of the specification rather
	// than only to a reader of internal/api.
	alsoEnforces []string
	// why records the reasoning for a row a reader would otherwise question.
	why string
}

// restSpec is the REST surface, keyed by "METHOD <chi pattern>".
//
// ACTOR CLASSIFICATION, in one sentence per group: hierarchy and webhook WRITES,
// rotation-policy management, tenant-scoped restore/destroy and the audit trail are
// user-only, because they are things a human does from a console and a workload
// doing one is the signal rather than the workflow; everything else — every fetch,
// every metadata read, and the ordinary write/rotate/delete of a secret a workload
// owns — is open to both classes, because that IS the service-to-service story this
// vault exists for and an operator does exactly the same things from the console.
var restSpec = map[string]surfaceSpec{
	// --- projects ----------------------------------------------------------
	"GET /api/v1/projects/":             {permission: permissions.PermReadMetadata},
	"GET /api/v1/projects/{project}":    {permission: permissions.PermReadMetadata},
	"POST /api/v1/projects/":            {permission: permissions.PermManageProject, actor: sdkauthz.ActorUserOnly, mutates: true},
	"PATCH /api/v1/projects/{project}":  {permission: permissions.PermManageProject, actor: sdkauthz.ActorUserOnly, mutates: true},
	"DELETE /api/v1/projects/{project}": {permission: permissions.PermManageProject, actor: sdkauthz.ActorUserOnly, mutates: true},

	// --- environments ------------------------------------------------------
	"GET /api/v1/environments/":                           {permission: permissions.PermReadMetadata},
	"GET /api/v1/environments/{project}/{environment}":    {permission: permissions.PermReadMetadata},
	"POST /api/v1/environments/":                          {permission: permissions.PermManageEnvironment, actor: sdkauthz.ActorUserOnly, mutates: true},
	"PATCH /api/v1/environments/{project}/{environment}":  {permission: permissions.PermManageEnvironment, actor: sdkauthz.ActorUserOnly, mutates: true},
	"DELETE /api/v1/environments/{project}/{environment}": {permission: permissions.PermManageEnvironment, actor: sdkauthz.ActorUserOnly, mutates: true},

	// --- folders -----------------------------------------------------------
	"GET /api/v1/folders/":      {permission: permissions.PermReadMetadata},
	"POST /api/v1/folders/":     {permission: permissions.PermManageFolder, actor: sdkauthz.ActorUserOnly, mutates: true},
	"POST /api/v1/folders/move": {permission: permissions.PermManageFolder, actor: sdkauthz.ActorUserOnly, mutates: true, why: "api.MoveFolder checks ManageFolder against BOTH the source and the destination MRN"},
	"DELETE /api/v1/folders/": {
		permission: permissions.PermManageFolder, actor: sdkauthz.ActorUserOnly, mutates: true,
		alsoEnforces: []string{permissions.PermDeleteSecret},
		why:          "removing a folder removes the secrets under it, so folder management alone must not be a way to delete values",
	},

	// --- scope imports -----------------------------------------------------
	"GET /api/v1/imports/": {permission: permissions.PermReadMetadata},
	"POST /api/v1/imports/": {
		permission: permissions.PermManageFolder, actor: sdkauthz.ActorUserOnly, mutates: true,
		alsoEnforces: []string{permissions.PermGetSecret},
		why:          "an import makes another scope's values readable through this one, so creating it also requires GetSecret on the SOURCE",
	},
	"PATCH /api/v1/imports/{importUUID}":  {permission: permissions.PermManageFolder, actor: sdkauthz.ActorUserOnly, mutates: true},
	"DELETE /api/v1/imports/{importUUID}": {permission: permissions.PermManageFolder, actor: sdkauthz.ActorUserOnly, mutates: true},

	// --- secrets: reads ----------------------------------------------------
	"GET /api/v1/secrets/":         {permission: permissions.PermListSecrets, why: "api.ListSecrets authorizes a whole SCOPE against the folder MRN — a broader capability than describing one secret"},
	"GET /api/v1/secrets/deleted":  {permission: permissions.PermListSecrets},
	"GET /api/v1/secrets/describe": {permission: permissions.PermReadMetadata},
	"GET /api/v1/secrets/versions": {permission: permissions.PermReadMetadata, why: "version history is numbers, key ids and checksums — never payloads"},

	// --- secrets: reveal ---------------------------------------------------
	"POST /api/v1/secrets/reveal": {
		permission: permissions.PermGetSecret,
		why: "a POST because a secret's address belongs in a body rather than an access log, " +
			"but a REVEAL permission because that is what it does. Not a mutation.",
	},
	"POST /api/v1/bulk/get": {
		permission: permissions.PermGetSecret,
		why:        "a batch get is a reveal; every item is ADDITIONALLY authorized on its own MRN in api.BatchGet",
	},

	// --- secrets: writes ---------------------------------------------------
	"POST /api/v1/secrets/":  {permission: permissions.PermPutSecret, mutates: true},
	"PATCH /api/v1/secrets/": {permission: permissions.PermPutSecret, mutates: true, why: "retention and expiry decide when a value is destroyed, so editing them is a write"},
	"POST /api/v1/secrets/rollback": {
		permission: permissions.PermPutSecret, mutates: true,
		alsoEnforces: []string{permissions.PermGetSecret},
		why: "a rollback republishes a value the caller did not supply, so a principal that may " +
			"write but not read could otherwise use it as a read primitive",
	},
	"POST /api/v1/secrets/rotate": {permission: permissions.PermRotateSecret, mutates: true},
	"POST /api/v1/bulk/put":       {permission: permissions.PermPutSecret, mutates: true},

	// --- secrets: lifecycle ------------------------------------------------
	"POST /api/v1/secrets/delete": {
		permission: permissions.PermDeleteSecret, mutates: true,
		why: "a soft delete opens a recovery window and is scoped to the target's own MRN, so a " +
			"workload decommissioning a secret it owns is legitimate",
	},
	"POST /api/v1/secrets/restore": {
		permission: permissions.PermDeleteSecret, actor: sdkauthz.ActorUserOnly, mutates: true,
		why: "authorized at TENANT scope (the project and environment are unknown until the row is " +
			"read), so it needs a grant wider than any single workload's",
	},
	"POST /api/v1/secrets/destroy": {
		permission: permissions.PermDeleteSecret, actor: sdkauthz.ActorUserOnly, mutates: true,
		why: "tenant-scoped like restore, and irreversible",
	},

	// --- rotation policy ---------------------------------------------------
	"POST /api/v1/secrets/rotation-policy": {
		permission: permissions.PermManageRotation, actor: sdkauthz.ActorUserOnly, mutates: true,
		why: "setting the policy administers the machinery — it decides when every FUTURE value is replaced",
	},

	// --- webhooks ----------------------------------------------------------
	"GET /api/v1/webhooks/":                          {permission: permissions.PermReadMetadata},
	"GET /api/v1/webhooks/{endpointUUID}/deliveries": {permission: permissions.PermReadMetadata},
	"POST /api/v1/webhooks/":                         {permission: permissions.PermManageRotation, actor: sdkauthz.ActorUserOnly, mutates: true},
	"PATCH /api/v1/webhooks/{endpointUUID}":          {permission: permissions.PermManageRotation, actor: sdkauthz.ActorUserOnly, mutates: true},
	"DELETE /api/v1/webhooks/{endpointUUID}":         {permission: permissions.PermManageRotation, actor: sdkauthz.ActorUserOnly, mutates: true},

	// --- audit -------------------------------------------------------------
	"GET /api/v1/audit": {
		permission: permissions.PermReadAudit, actor: sdkauthz.ActorUserOnly,
		why: "the access trail is what an incident review reads; a workload reading it is reconnaissance, not work",
	},
}

// grpcSpec is the same specification for the RPC surface. It must AGREE with
// restSpec surface by surface — the two transports are thin adapters over one api
// service, so a rule that held on one and not the other would be no rule at all: a
// caller refused over REST would simply open a gRPC channel. See
// TestTheTwoTransportsAgree.
var grpcSpec = map[string]surfaceSpec{
	// Legacy flat-key surface — the kit secret-provider client's contract. The
	// permissions are the real ones for the operation, not a compatibility exemption.
	"Put":    {permission: permissions.PermPutSecret, mutates: true},
	"Get":    {permission: permissions.PermGetSecret, why: "the legacy flat Get calls api.Reveal"},
	"List":   {permission: permissions.PermListSecrets},
	"Delete": {permission: permissions.PermDeleteSecret, mutates: true},

	// Hierarchy.
	"CreateProject":     {permission: permissions.PermManageProject, actor: sdkauthz.ActorUserOnly, mutates: true},
	"ListProjects":      {permission: permissions.PermReadMetadata},
	"GetProject":        {permission: permissions.PermReadMetadata},
	"UpdateProject":     {permission: permissions.PermManageProject, actor: sdkauthz.ActorUserOnly, mutates: true},
	"DeleteProject":     {permission: permissions.PermManageProject, actor: sdkauthz.ActorUserOnly, mutates: true},
	"CreateEnvironment": {permission: permissions.PermManageEnvironment, actor: sdkauthz.ActorUserOnly, mutates: true},
	"ListEnvironments":  {permission: permissions.PermReadMetadata},
	"GetEnvironment":    {permission: permissions.PermReadMetadata},
	"UpdateEnvironment": {permission: permissions.PermManageEnvironment, actor: sdkauthz.ActorUserOnly, mutates: true},
	"DeleteEnvironment": {permission: permissions.PermManageEnvironment, actor: sdkauthz.ActorUserOnly, mutates: true},
	"CreateFolder":      {permission: permissions.PermManageFolder, actor: sdkauthz.ActorUserOnly, mutates: true},
	"ListFolders":       {permission: permissions.PermReadMetadata},
	"MoveFolder":        {permission: permissions.PermManageFolder, actor: sdkauthz.ActorUserOnly, mutates: true},
	"DeleteFolder": {
		permission: permissions.PermManageFolder, actor: sdkauthz.ActorUserOnly, mutates: true,
		alsoEnforces: []string{permissions.PermDeleteSecret},
	},
	"CreateImport": {
		permission: permissions.PermManageFolder, actor: sdkauthz.ActorUserOnly, mutates: true,
		alsoEnforces: []string{permissions.PermGetSecret},
	},
	"ListImports":  {permission: permissions.PermReadMetadata},
	"UpdateImport": {permission: permissions.PermManageFolder, actor: sdkauthz.ActorUserOnly, mutates: true},
	"DeleteImport": {permission: permissions.PermManageFolder, actor: sdkauthz.ActorUserOnly, mutates: true},

	// Secrets.
	"GetSecret":            {permission: permissions.PermGetSecret},
	"DescribeSecret":       {permission: permissions.PermReadMetadata},
	"ListSecrets":          {permission: permissions.PermListSecrets},
	"ListSecretVersions":   {permission: permissions.PermReadMetadata},
	"ListDeletedSecrets":   {permission: permissions.PermListSecrets},
	"PutSecret":            {permission: permissions.PermPutSecret, mutates: true},
	"UpdateSecretMetadata": {permission: permissions.PermPutSecret, mutates: true},
	"RollbackSecret": {
		permission: permissions.PermPutSecret, mutates: true,
		alsoEnforces: []string{permissions.PermGetSecret},
	},
	"RotateSecret":      {permission: permissions.PermRotateSecret, mutates: true},
	"SetRotationPolicy": {permission: permissions.PermManageRotation, actor: sdkauthz.ActorUserOnly, mutates: true},
	"DeleteSecret":      {permission: permissions.PermDeleteSecret, mutates: true},
	"RestoreSecret":     {permission: permissions.PermDeleteSecret, actor: sdkauthz.ActorUserOnly, mutates: true},
	"DestroySecret":     {permission: permissions.PermDeleteSecret, actor: sdkauthz.ActorUserOnly, mutates: true},

	// Bulk. A batch is a TRANSPORT optimisation, never a weaker operation.
	"BatchGetSecrets": {permission: permissions.PermGetSecret},
	"BatchPutSecrets": {permission: permissions.PermPutSecret, mutates: true},

	// Webhooks + audit.
	"CreateWebhookEndpoint": {permission: permissions.PermManageRotation, actor: sdkauthz.ActorUserOnly, mutates: true},
	"ListWebhookEndpoints":  {permission: permissions.PermReadMetadata},
	"UpdateWebhookEndpoint": {permission: permissions.PermManageRotation, actor: sdkauthz.ActorUserOnly, mutates: true},
	"DeleteWebhookEndpoint": {permission: permissions.PermManageRotation, actor: sdkauthz.ActorUserOnly, mutates: true},
	"ListWebhookDeliveries": {permission: permissions.PermReadMetadata},
	"ListAuditEvents":       {permission: permissions.PermReadAudit, actor: sdkauthz.ActorUserOnly},
}

// readOnlyPermissions are the permissions that grant NO ability to change anything.
// A surface whose handler writes must never resolve to one of them: the route guard
// runs first, so that would be the check an attacker meets at the door.
var readOnlyPermissions = map[string]bool{
	permissions.PermReadMetadata: true,
	permissions.PermListSecrets:  true,
	permissions.PermReadAudit:    true,
}

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

// TestEveryRESTRouteMatchesItsSpecification is the REST half of the audit, and it
// is now a SPECIFICATION check rather than a presence check.
//
// It used to require only a NON-EMPTY permission, which is a much weaker property
// than it looks: a route mapped to the weakest permission in the vocabulary passes
// "non-empty" exactly as well as a route mapped to the right one. That is how
// /secrets and /bulk came to be guarded by ReadMetadata on every verb — including
// the write, the delete and the destroy — with the real privilege enforced only
// deeper, in internal/api. The route guard runs FIRST, so that made the weakest
// statement in the system the one an attacker met at the door, and it meant a new
// handler on the segment that forgot its deeper check would ship carrying
// ReadMetadata alone.
func TestEveryRESTRouteMatchesItsSpecification(t *testing.T) {
	m := permissions.Map()

	for _, r := range walkREST(t) {
		key := r.method + " " + r.pattern
		t.Run(key, func(t *testing.T) {
			surface := sdkauthz.Surface{Path: r.pattern, HTTPMethod: r.method}

			if m.IsExempt(surface) {
				_, justified := matchJustifiedPath(r.pattern)
				assert.True(t, justified,
					"%s is served with NO permission check and has no written justification in "+
						"justifiedExemptPaths", key)
				return
			}

			spec, specified := restSpec[key]
			require.True(t, specified,
				"%s is a NEW route with no row in restSpec. Read the handler, follow it to its "+
					"internal/api method, and write down the permission that method's s.guard call "+
					"actually demands — plus whether it mutates and which class of caller may reach "+
					"it. Adding the route to permissions.Map() without deciding those is how a "+
					"surface ships guarded by the wrong thing.", key)

			rule, mapped := m.Resolve(surface)
			require.True(t, mapped,
				"%s has no permission mapping. It is DENIED to every caller at runtime "+
					"(the Map is an allowlist), which ships as a 403 nobody can explain.", key)
			assert.NotEmpty(t, rule.Permission,
				"%s is mapped to an EMPTY permission, which means any authenticated caller may "+
					"call it. That is only ever correct for a surface deliberately opened, and this "+
					"service has none.", key)

			assert.Equal(t, spec.permission, rule.Permission,
				"%s must demand the permission its OPERATION performs. %s", key, spec.why)
			assert.Equal(t, spec.actor, rule.Actor,
				"%s must be reachable by exactly the specified class of caller. %s", key, spec.why)
		})
	}
}

// TestTheRESTSpecificationHasNoStaleRows is the other direction: a row describing a
// route that no longer exists is a specification that has quietly stopped describing
// the service, and it would keep the audit above passing while covering less and
// less.
func TestTheRESTSpecificationHasNoStaleRows(t *testing.T) {
	live := map[string]bool{}
	for _, r := range walkREST(t) {
		live[r.method+" "+r.pattern] = true
	}
	for key := range restSpec {
		assert.True(t, live[key], "restSpec describes %q, but no route serves it", key)
	}
}

// TestEveryMappedRouteSurfaceIsLive: a segment or an exact entry in the table that
// no route serves is dead weight, and dead weight is what makes an authorization
// table stop being read.
func TestEveryMappedRouteSurfaceIsLive(t *testing.T) {
	liveSegments := map[string]bool{}
	liveExact := map[string]bool{}
	for _, r := range walkREST(t) {
		if segment := sdkauthz.FirstSegment(permissions.APIPrefix, r.pattern); segment != "" {
			liveSegments[segment] = true
		}
		liveExact[sdkauthz.ExactKey(r.method, r.pattern)] = true
	}
	for segment := range permissions.Map().Routes {
		assert.True(t, liveSegments[segment], "route segment %q is mapped but no route serves it", segment)
	}
	for key := range permissions.Map().Exact {
		assert.True(t, liveExact[key], "exact route %q is mapped but no route serves it", key)
	}
}

// TestNoMutatingSurfaceIsGuardedByAReadPermission is the property the old audit
// could not express, stated over BOTH transports.
//
// A read-only grant is the one an operator hands out broadly — "let the team see
// what exists" — precisely because it cannot change anything. If a surface that
// writes, deletes or destroys resolves to one of those permissions, then the check
// at the door is satisfied by a grant that was issued on the understanding that it
// was harmless, and the only thing standing between it and the write is a deeper
// check some future handler may forget to make.
func TestNoMutatingSurfaceIsGuardedByAReadPermission(t *testing.T) {
	m := permissions.Map()

	t.Run("REST", func(t *testing.T) {
		for _, r := range walkREST(t) {
			key := r.method + " " + r.pattern
			spec, specified := restSpec[key]
			if !specified || !spec.mutates {
				continue
			}
			rule, mapped := m.Resolve(sdkauthz.Surface{Path: r.pattern, HTTPMethod: r.method})
			require.True(t, mapped, "%s is unmapped", key)
			assert.False(t, readOnlyPermissions[rule.Permission],
				"%s CHANGES DURABLE STATE but is guarded by %q, a read-only permission. The route "+
					"guard runs first, so that is the check an attacker meets at the door — and a "+
					"grant issued as harmless would satisfy it.", key, rule.Permission)
		}
	})

	t.Run("gRPC", func(t *testing.T) {
		for _, method := range grpcMethods() {
			spec, specified := grpcSpec[shortMethod(method)]
			if !specified || !spec.mutates {
				continue
			}
			rule, mapped := m.Resolve(sdkauthz.Surface{FullMethod: method})
			require.True(t, mapped, "%s is unmapped", method)
			assert.False(t, readOnlyPermissions[rule.Permission],
				"%s CHANGES DURABLE STATE but is guarded by the read-only permission %q",
				method, rule.Permission)
		}
	})
}

// TestASecondaryPermissionIsStillDeclared. Where the operation layer enforces a
// permission the route guard does not demand, that permission must still be
// registered in Auth — otherwise the deeper check demands something no token can
// ever carry, and the failure is a 403 with nothing in any log explaining it.
func TestASecondaryPermissionIsStillDeclared(t *testing.T) {
	declared := map[string]bool{}
	for _, p := range permissions.DeclaredPermissions() {
		declared[p] = true
	}
	check := func(t *testing.T, key string, spec surfaceSpec) {
		t.Helper()
		for _, p := range spec.alsoEnforces {
			assert.True(t, declared[p],
				"%s additionally enforces %q in internal/api, but it is not in DeclaredPermissions() "+
					"— Auth would never register it and no token could carry it", key, p)
		}
	}
	for key, spec := range restSpec {
		check(t, key, spec)
	}
	for key, spec := range grpcSpec {
		check(t, key, spec)
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

// shortMethod reduces "/maintainerd.secret.v1.SecretService/GetSecret" to
// "GetSecret", which is how grpcSpec is keyed — the service prefix is noise in a
// table where every row shares it.
func shortMethod(fullMethod string) string {
	if i := strings.LastIndexByte(fullMethod, '/'); i >= 0 {
		return fullMethod[i+1:]
	}
	return fullMethod
}

// TestEveryGRPCMethodMatchesItsSpecification is the gRPC half of the audit, held to
// the same specification as REST.
func TestEveryGRPCMethodMatchesItsSpecification(t *testing.T) {
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

			spec, specified := grpcSpec[shortMethod(method)]
			require.True(t, specified,
				"%s is a NEW RPC with no row in grpcSpec. Read the handler, follow it to its "+
					"internal/api method, and write down what that method's s.guard call demands.",
				method)

			rule, mapped := m.Resolve(surface)
			require.True(t, mapped,
				"%s has no permission mapping. It is DENIED to every caller at runtime, which "+
					"ships as a PermissionDenied nobody can explain. Add it to "+
					"permissions.Map().Methods.", method)
			assert.NotEmpty(t, rule.Permission,
				"%s is mapped to an EMPTY permission, so any authenticated caller may call it", method)

			assert.Equal(t, spec.permission, rule.Permission,
				"%s must demand the permission its OPERATION performs. %s", method, spec.why)
			assert.Equal(t, spec.actor, rule.Actor,
				"%s must be reachable by exactly the specified class of caller. %s", method, spec.why)
		})
	}
}

// TestTheGRPCSpecificationHasNoStaleRows mirrors the REST stale-row check.
func TestTheGRPCSpecificationHasNoStaleRows(t *testing.T) {
	live := map[string]bool{}
	for _, method := range grpcMethods() {
		live[shortMethod(method)] = true
	}
	for name := range grpcSpec {
		assert.True(t, live[name], "grpcSpec describes %q, but no registered service serves it", name)
	}
}

// TestEveryMappedMethodIsRegistered is the stale-entry direction for the Map itself,
// including the actor overlay: a MethodActors row keyed by a method that does not
// exist is a constraint nobody is enforcing, and it reads in review as though
// somebody had.
func TestEveryMappedMethodIsRegistered(t *testing.T) {
	live := map[string]bool{}
	for _, method := range grpcMethods() {
		live[method] = true
	}
	for mapped := range permissions.Map().Methods {
		assert.True(t, live[mapped], "%s is mapped but no registered service serves it", mapped)
	}
	for mapped := range permissions.Map().MethodActors {
		assert.True(t, live[mapped],
			"%s has an actor constraint but no registered service serves it", mapped)
		_, hasPermission := permissions.Map().Methods[mapped]
		assert.True(t, hasPermission,
			"%s has an actor constraint but NO permission — an actor-only entry is not in the "+
				"allowlist at all, so the method is denied to everyone", mapped)
	}
}

// TestTheTwoTransportsAgree. The REST handlers and the gRPC service are thin
// adapters over ONE api service, so a rule that held on one transport and not the
// other would be no rule at all: a caller refused over REST would simply open a gRPC
// channel and do the same thing. This pins the pairs where both transports expose the
// same operation.
func TestTheTwoTransportsAgree(t *testing.T) {
	pairs := []struct {
		rest string
		rpc  string
	}{
		{"POST /api/v1/secrets/reveal", "GetSecret"},
		{"GET /api/v1/secrets/describe", "DescribeSecret"},
		{"GET /api/v1/secrets/", "ListSecrets"},
		{"GET /api/v1/secrets/versions", "ListSecretVersions"},
		{"GET /api/v1/secrets/deleted", "ListDeletedSecrets"},
		{"POST /api/v1/secrets/", "PutSecret"},
		{"PATCH /api/v1/secrets/", "UpdateSecretMetadata"},
		{"POST /api/v1/secrets/rollback", "RollbackSecret"},
		{"POST /api/v1/secrets/rotate", "RotateSecret"},
		{"POST /api/v1/secrets/rotation-policy", "SetRotationPolicy"},
		{"POST /api/v1/secrets/delete", "DeleteSecret"},
		{"POST /api/v1/secrets/restore", "RestoreSecret"},
		{"POST /api/v1/secrets/destroy", "DestroySecret"},
		{"POST /api/v1/bulk/get", "BatchGetSecrets"},
		{"POST /api/v1/bulk/put", "BatchPutSecrets"},
		{"POST /api/v1/projects/", "CreateProject"},
		{"GET /api/v1/projects/", "ListProjects"},
		{"POST /api/v1/environments/", "CreateEnvironment"},
		{"POST /api/v1/folders/", "CreateFolder"},
		{"POST /api/v1/folders/move", "MoveFolder"},
		{"DELETE /api/v1/folders/", "DeleteFolder"},
		{"POST /api/v1/imports/", "CreateImport"},
		{"GET /api/v1/imports/", "ListImports"},
		{"POST /api/v1/webhooks/", "CreateWebhookEndpoint"},
		{"GET /api/v1/webhooks/", "ListWebhookEndpoints"},
		{"GET /api/v1/webhooks/{endpointUUID}/deliveries", "ListWebhookDeliveries"},
		{"GET /api/v1/audit", "ListAuditEvents"},
	}

	m := permissions.Map()
	for _, p := range pairs {
		t.Run(p.rest+" == "+p.rpc, func(t *testing.T) {
			method, path, found := strings.Cut(p.rest, " ")
			require.True(t, found)

			restRule, ok := m.Resolve(sdkauthz.Surface{Path: path, HTTPMethod: method})
			require.True(t, ok, "%s is unmapped", p.rest)
			rpcRule, ok := m.Resolve(sdkauthz.Surface{FullMethod: permissions.SecretServicePrefix + p.rpc})
			require.True(t, ok, "%s is unmapped", p.rpc)

			assert.Equal(t, restRule.Permission, rpcRule.Permission,
				"the same operation must demand the same permission on both transports")
			assert.Equal(t, restRule.Actor, rpcRule.Actor,
				"the same operation must accept the same class of caller on both transports — "+
					"otherwise a caller refused over REST just opens a gRPC channel")
		})
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

	// The REST reveal demands the REVEAL permission AT THE DOOR. It used to resolve
	// to the /secrets segment's metadata baseline, with GetSecret checked only deeper
	// against the target MRN. That inverted the layers: a metadata grant satisfied the
	// first check on the one route this whole service exists to protect.
	rule, mapped := permissions.Map().Resolve(sdkauthz.Surface{
		Path: "/api/v1/secrets/reveal", HTTPMethod: http.MethodPost,
	})
	require.True(t, mapped)
	assert.Equal(t, permissions.PermGetSecret, rule.Permission,
		"the route guard for a reveal must be the reveal permission, not a metadata baseline")

	// Describe, on the same segment, still resolves to metadata — which is the proof
	// that the segment is not simply being guarded by its strongest route.
	describe, mapped := permissions.Map().Resolve(sdkauthz.Surface{
		Path: "/api/v1/secrets/describe", HTTPMethod: http.MethodGet,
	})
	require.True(t, mapped)
	assert.Equal(t, permissions.PermReadMetadata, describe.Permission)
}

// ---------------------------------------------------------------------------
// The actor model
// ---------------------------------------------------------------------------

// TestEveryConsoleSurfaceIsUserOnly names the administrative surfaces outright, so
// that removing a constraint requires deleting a line from a list a reviewer reads
// rather than quietly dropping a field from a map literal.
//
// The threat is the one no permission check can catch: a STOLEN m2m credential. Its
// grants are real, so every permission check passes — and a workload creating a
// project, rewiring a webhook, destroying a secret or reading the audit trail is by
// itself the signal.
func TestEveryConsoleSurfaceIsUserOnly(t *testing.T) {
	m := permissions.Map()

	for key, spec := range restSpec {
		if spec.actor != sdkauthz.ActorUserOnly {
			continue
		}
		method, path, _ := strings.Cut(key, " ")
		rule, ok := m.Resolve(sdkauthz.Surface{Path: path, HTTPMethod: method})
		require.True(t, ok, "%s is unmapped", key)
		assert.Equal(t, sdkauthz.ActorUserOnly, rule.Actor,
			"%s is an administrative console surface and must refuse a service principal", key)
	}

	for name, spec := range grpcSpec {
		if spec.actor != sdkauthz.ActorUserOnly {
			continue
		}
		rule, ok := m.Resolve(sdkauthz.Surface{FullMethod: permissions.SecretServicePrefix + name})
		require.True(t, ok, "%s is unmapped", name)
		assert.Equal(t, sdkauthz.ActorUserOnly, rule.Actor,
			"%s is an administrative console surface and must refuse a service principal", name)
	}
}

// TestTheWorkloadPathsAcceptBothClasses is the constraint that protects the PRODUCT
// rather than the vault: a workload fetching its own secrets is the core
// service-to-service case this service exists for, and an operator does exactly the
// same things from the console. Locking either of these to one class would break one
// of the two audiences, silently, at deploy time.
func TestTheWorkloadPathsAcceptBothClasses(t *testing.T) {
	workloadSurfaces := []string{
		"POST /api/v1/secrets/reveal",
		"POST /api/v1/bulk/get",
		"POST /api/v1/bulk/put",
		"GET /api/v1/secrets/",
		"GET /api/v1/secrets/describe",
		"GET /api/v1/secrets/versions",
		"GET /api/v1/secrets/deleted",
		"POST /api/v1/secrets/",
		"PATCH /api/v1/secrets/",
		"POST /api/v1/secrets/rollback",
		"POST /api/v1/secrets/rotate",
		"POST /api/v1/secrets/delete",
		"GET /api/v1/projects/",
		"GET /api/v1/environments/",
		"GET /api/v1/folders/",
		"GET /api/v1/imports/",
		"GET /api/v1/webhooks/",
	}

	m := permissions.Map()
	for _, key := range workloadSurfaces {
		t.Run(key, func(t *testing.T) {
			method, path, _ := strings.Cut(key, " ")
			rule, ok := m.Resolve(sdkauthz.Surface{Path: path, HTTPMethod: method})
			require.True(t, ok, "%s is unmapped", key)
			assert.Equal(t, sdkauthz.ActorAny, rule.Actor,
				"%s must stay reachable by a workload AND by a console operator", key)
		})
	}
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
