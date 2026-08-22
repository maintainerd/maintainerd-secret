// Package permissions is this service's authorization VOCABULARY — and nothing
// else.
//
// The enforcement ENGINE lives in the SDK (github.com/maintainerd/sdk/authz):
// the grant grammar, Principal.Allows, the surface allowlist, the
// Enforced/DevOpen/Unavailable ladder, the HTTP middleware and the gRPC
// interceptors are all there, shared by every maintainerd service and by
// third-party resource servers built beside them. A bug in that code is a
// vulnerability in every service at once, which is exactly why it is written
// once and audited once instead of re-hand-rolled per repo. This package used to
// be a full local copy of it (internal/platform/authz + internal/platform/mrn);
// both are gone.
//
// What the SDK deliberately does NOT know is what a "secret:GetSecret" is, which
// URL segment it guards, or which RPC needs it. That is this service's
// vocabulary, and it is what lives here:
//
//	the secret: permission constants (see All)
//	the REST route table       (exact method+path -> rule; segment pair where uniform)
//	the gRPC method table      (full method -> permission, + actor constraint)
//	the exemption set          (health probes + the self-guarded setup surfaces)
//
// expressed as one authz.Map literal — which is the surface ALLOWLIST as well as
// the table: Map.Resolve reports ok=false for anything not in it and the guard
// denies on ok=false, so mounting a route or registering an RPC without deciding
// its permission fails CLOSED instead of shipping open. See audit_test.go, which
// walks the live chi router and the live gRPC service descriptors, checks each
// surface against a WRITTEN specification of what it should demand, and fails if
// either grows a surface this file does not account for.
//
// # Two layers, two questions — and the route guard is not the weak one
//
// LAYER 1 is the surface guard, this Map: is the caller authenticated, is this a
// surface we decided a rule for, is this CLASS of caller allowed on it, and does
// the caller hold the permission the surface actually performs?
//
// LAYER 2 is the operation check — may THIS principal perform THIS action on THIS
// resource's MRN — and it happens inside internal/api against the concrete
// target. It is the only place "may read staging, must not read prod" can be
// decided, and it is where an operation that needs a SECOND permission enforces
// it (rollback also needs GetSecret; a folder delete also needs DeleteSecret;
// creating a scope import also needs GetSecret on the source).
//
// Both are required, and layer 1 is DEFENCE IN DEPTH rather than the only
// defence. This file used to state the opposite for the /secrets and /bulk
// segments: it carried a metadata BASELINE there and deferred the real privilege
// to internal/api. The reasoning was sound — a reveal is a read carried by a POST
// so a secret's address never lands in an access log — but the ordering was
// inverted. The weak check ran FIRST, the route table stopped saying what a route
// does, and a new handler added on /secrets that forgot its internal/api check
// would have shipped guarded by ReadMetadata alone. Every route now declares the
// permission its operation really performs (authz.Map.Exact), so the route guard
// is correct ON ITS OWN and the MRN check is the second layer.
//
// # The actor model — service-to-service is not browser-to-backend
//
// Two classes of caller reach this vault, through different trust contexts: a
// USER principal signed in to the console through an interactive OAuth2
// authorization-code + PKCE flow, and a SERVICE principal — a machine identity
// carrying Auth's "svc" claim, calling m2m, which is the whole point of a secret
// store. A permission answers "may this principal do X". It cannot answer "should
// this class of caller be doing X at all", and that is the question that catches a
// STOLEN m2m credential: its grants are real, so no permission check will refuse
// it, but a workload creating a project or reading the audit trail is by itself
// the signal.
//
// So every surface also declares an actor constraint (see the table below).
// Administrative surfaces a human drives from the console are ActorUserOnly; the
// fetch and write paths a workload legitimately uses are ActorAny, because an
// operator does exactly the same things from the console. The kind is derived
// from the VERIFIED claims (authz.ActorKindFromClaims) and is recorded on every
// audit row, so an incident review can tell a human reading a value from a
// workload reading it.
package permissions

import (
	sdkauthz "github.com/maintainerd/sdk/authz"
)

// ServiceName is this service's MRN service segment and the name it announces in
// guard banners and logs.
const ServiceName = "secret"

// The permission namespace this service owns. Every action a caller can be
// granted is one of these strings; Auth registers exactly this set (see
// DeclaredPermissions).
const (
	// PermReadMetadata lists and describes secrets and the hierarchy. It NEVER
	// returns a value.
	//
	// PermReadMetadata and PermGetSecret are deliberately DIFFERENT PRIVILEGES, and
	// the split is a requirement rather than a nicety. Browsing metadata — which
	// secrets exist, when they were rotated, what they are for — is what an engineer
	// needs to operate a system, and it is safe to hand out broadly. Revealing a
	// value is seeing the production database password. Collapsing the two would
	// mean every principal who can render a console page can also exfiltrate every
	// credential on it, and the audit trail could no longer distinguish "who looked
	// at the list" from "who read the value" during an incident review.
	PermReadMetadata = "secret:ReadMetadata"

	// PermGetSecret is REVEAL: read a decrypted value. See PermReadMetadata for why
	// this is a separate grant. Every use of it is individually audited, and a
	// reference chain re-checks it at every hop.
	PermGetSecret = "secret:GetSecret"

	// PermPutSecret writes a value (creating the secret, or appending a version).
	PermPutSecret = "secret:PutSecret"
	// PermDeleteSecret soft-deletes, restores and destroys.
	PermDeleteSecret = "secret:DeleteSecret"
	// PermRotateSecret rotates a value on demand.
	PermRotateSecret = "secret:RotateSecret"
	// PermListSecrets lists a scope. Metadata only, like PermReadMetadata; separate
	// because listing a whole environment is a broader capability than describing
	// one secret you already know the name of.
	PermListSecrets = "secret:ListSecrets"

	// PermManageProject creates, updates and deletes projects.
	PermManageProject = "secret:ManageProject"
	// PermManageEnvironment creates, updates and deletes environments.
	PermManageEnvironment = "secret:ManageEnvironment"
	// PermManageFolder creates, moves and deletes folders, and manages scope
	// imports (an import is a property of a folder).
	PermManageFolder = "secret:ManageFolder"
	// PermManageRotation manages rotation policies and webhook endpoints — the
	// machinery that rotates values and announces the change.
	PermManageRotation = "secret:ManageRotation"
	// PermReadAudit reads the access trail.
	PermReadAudit = "secret:ReadAudit"

	// --- dynamic secrets ---------------------------------------------------
	//
	// THE SPLIT BETWEEN THESE TWO IS THE SECURITY MODEL OF DYNAMIC SECRETS, and
	// collapsing it would undo the feature. Configuring a role means choosing which
	// database is targeted and writing the SQL that decides what an issued credential
	// can do — a privileged, reviewable, human act. Issuing one means asking for the
	// short-lived account that configuration already described.

	// PermManageDynamicRole configures a dynamic role: the target DSN reference, the
	// creation and revocation templates, the TTLs. Whoever holds it decides what every
	// credential issued from that role is able to do, which is why its surfaces are
	// user-only.
	PermManageDynamicRole = "secret:ManageDynamicRole"

	// PermIssueDynamicCredential obtains one on-demand credential, and revokes one.
	//
	// It is deliberately open to SERVICE principals: a workload asking for its own
	// short-lived database credential at boot IS the feature, and requiring a human
	// would push consumers back onto a shared static password. The blast radius is
	// bounded by the MRN grant (which roles) and by the role's creation template (what
	// the credential can do) — not by the caller's class.
	//
	// Note what it does NOT imply: any ability to read the target DSN. A holder never
	// sees the administrative connection string on any path, which is the property
	// that makes handing this grant to a workload reasonable.
	PermIssueDynamicCredential = "secret:IssueDynamicCredential"

	// --- transit -----------------------------------------------------------
	//
	// THREE PERMISSIONS RATHER THAN ONE, split by blast radius rather than by verb.
	// Encrypt produces ciphertext and on its own recovers nothing, so a write-only
	// workload — an ingest path that stores encrypted fields and never reads them
	// back — can hold Encrypt alone. Decrypt is the grant that recovers plaintext, so
	// it is the one an incident review cares about. Managing keys decides what both of
	// the others operate on.
	//
	// Collapsing Encrypt and Decrypt would mean every service that WRITES an encrypted
	// column could also READ every encrypted column — the same mistake as collapsing
	// ReadMetadata into GetSecret.

	// PermEncrypt seals a plaintext under a transit key and returns a ciphertext token.
	PermEncrypt = "secret:Encrypt"
	// PermDecrypt recovers a plaintext from a transit ciphertext token. Audited on
	// every use, like a reveal.
	PermDecrypt = "secret:Decrypt"
	// PermManageTransitKey creates, rotates, updates and deletes transit keys. Key
	// LIFECYCLE, never key material: there is no export operation to grant, by design
	// (see internal/transit).
	PermManageTransitKey = "secret:ManageTransitKey"

	// --- leases on static secrets ------------------------------------------

	// PermManageLease sets and clears a secret's lease policy, and revokes outstanding
	// leases.
	//
	// IT IS NOT REQUIRED TO READ A LEASED SECRET — that is still PermGetSecret —
	// because a lease is not authorization: the grant decides who may read, and the
	// lease decides how much reading an already authorized principal may do. Requiring
	// both would make every leased secret unreadable by exactly the consumers the
	// lease was written for.
	//
	// It is administrative, so its surfaces are user-only: deciding a credential may
	// be read ten times an hour is a policy call, and a workload making it is the
	// signal rather than the workflow.
	PermManageLease = "secret:ManageLease"

	// PermAdmin is the blanket grant. It implies every permission above; it does NOT
	// widen resource scope, so an admin grant written for one tenant is still
	// confined to that tenant's MRNs. It is declared to the SDK as a BlanketAction,
	// which is how Principal.HasAction and Principal.Allows learn to honour it.
	PermAdmin = "secret:Admin"
)

// The HTTP surface's fixed paths.
const (
	// APIPrefix is the prefix the route keys below live under. A path outside it
	// yields an empty route key, which is never in the table and is therefore
	// denied.
	APIPrefix = "/api/v1/"
	// SetupPath is the self-guarded first-run wizard (see the exemption set).
	SetupPath = "/api/v1/setup"
	// CapabilitiesPath is the anonymous capability probe (see the exemption set).
	CapabilitiesPath = "/api/v1/capabilities"
	// HealthzPath is the liveness probe and ReadyzPath the readiness probe.
	HealthzPath = "/healthz"
	ReadyzPath  = "/readyz"
)

// The gRPC surface's service prefixes.
const (
	// SecretServicePrefix is the main RPC surface.
	SecretServicePrefix = "/maintainerd.secret.v1.SecretService/"
	// SetupServicePrefix is the CONTROLLED setup surface a controller (Core) drives.
	SetupServicePrefix = "/maintainerd.secret.v1.SetupService/"
	// HealthServicePrefix is the standard gRPC health protocol.
	HealthServicePrefix = "/grpc.health.v1.Health/"
	// ReflectionServicePrefix is server reflection. It is deliberately NOT in the
	// exemption set: reflection enumerates every RPC and message in the service — a
	// map of the vault's API handed to anyone who can open a socket. Left unmapped
	// and unexempt, it is denied by the allowlist in ModeEnforced and reachable only
	// in ModeDevOpen (where the guard admits every caller before it consults the
	// map), which is exactly the development-only posture this service wants. The
	// bootstrap additionally registers the reflection service only in development,
	// so in production there is nothing behind the door either.
	ReflectionServicePrefix = "/grpc.reflection."
)

// Map is this service's surface -> permission table, and the surface allowlist.
//
// A fresh value is returned on every call rather than a package-level variable
// exported by reference: the maps inside are the authorization table, and a
// caller that could mutate them could open a surface at runtime.
//
// WHY /secrets AND /bulk ARE DECLARED ROUTE BY ROUTE AND NOT AS A SEGMENT PAIR.
// A segment pair can only ever be as strong as the WEAKEST route on the segment,
// because one pair guards them all — and /secrets carries a listing, a metadata
// read, a write, a reveal, a rollback, a rotation, a delete and a destroy. The
// pair used to collapse all of that to ReadMetadata on both verbs, with the real
// privilege enforced deeper in internal/api. Those routes are now declared
// exactly, and the two segments are NOT in Routes at all, which is strictly
// stronger than a baseline: a new handler mounted beside them matches no exact
// entry and no segment pair, so it is UNMAPPED and denied to every caller rather
// than inheriting a weak permission.
//
// The POST-carrying-a-read argument still holds and is still why reveal and batch
// get are POSTs — a secret's address in a URL ends up in access logs, proxy logs,
// browser history and referer headers, and a body does not. It was never an
// argument for a weak permission; it was an argument against DERIVING the
// permission from the HTTP verb. Declaring the route exactly settles both.
func Map() sdkauthz.Map {
	return sdkauthz.Map{
		Prefix: APIPrefix,

		// EXACT SURFACES — method + path, winning over any segment pair. Each entry
		// names the permission the handler's operation ACTUALLY performs (verified
		// against internal/api; audit_test.go pins every one of them), and the actor
		// class allowed to reach it.
		//
		// Where a handler enforces MORE than one permission the entry names the
		// PRIMARY one and says so; internal/api keeps enforcing the rest against the
		// concrete target MRN, which is the only place a second, resource-dependent
		// check can be made.
		Exact: map[string]sdkauthz.Rule{
			// --- reads -------------------------------------------------------------
			// Listing a whole scope is a broader capability than describing one secret
			// you already know the name of, which is why ListSecrets is its own grant.
			// api.ListSecrets authorizes against the FOLDER's MRN.
			"GET /api/v1/secrets":          {Permission: PermListSecrets},
			"GET /api/v1/secrets/deleted":  {Permission: PermListSecrets},
			"GET /api/v1/secrets/describe": {Permission: PermReadMetadata},
			// Version history is metadata: numbers, wrapping key ids and checksums, no
			// payloads. Browsing it must never be a way to pull every value a
			// credential has ever held.
			"GET /api/v1/secrets/versions": {Permission: PermReadMetadata},

			// --- reveal ------------------------------------------------------------
			// THE PATH THE WHOLE SERVICE EXISTS TO PROTECT. A POST because its address
			// belongs in a body; a reveal permission because that is what it does.
			// ActorAny: a workload fetching its own secret is the core
			// service-to-service case, and an operator does the same from the console.
			"POST /api/v1/secrets/reveal": {Permission: PermGetSecret},

			// --- writes ------------------------------------------------------------
			// ActorAny on the write paths is a DELIBERATE choice, not an omission. A
			// workload writing or rotating its OWN secret is a first-class case — a
			// rotator replacing the credential it manages, a reconciler converging an
			// environment it owns — and it is exactly the m2m story this service
			// exists for. The blast radius is bounded by the MRN grant, not by the
			// caller's class: a service principal can only write what its grant names.
			// Restricting writes to humans would push rotation back into a person's
			// hands, which is the outcome a secret store is meant to remove.
			"POST /api/v1/secrets":  {Permission: PermPutSecret},
			"PATCH /api/v1/secrets": {Permission: PermPutSecret},
			// Rollback ALSO requires PermGetSecret, enforced in api.Rollback: it reads a
			// value the caller did not supply and republishes it as current, so a
			// principal that may write but not read could otherwise use it as a read
			// primitive. The route guard demands the primary write permission.
			"POST /api/v1/secrets/rollback": {Permission: PermPutSecret},
			"POST /api/v1/secrets/rotate":   {Permission: PermRotateSecret},
			"POST /api/v1/bulk/put":         {Permission: PermPutSecret},
			// Every batch item is additionally authorized INDIVIDUALLY against its own
			// MRN inside api.BatchGet/BatchPut. The route guard is the floor, not the
			// whole check: a batch that checked once against the scope would be the
			// easiest way to turn a narrow grant into a broad one.
			"POST /api/v1/bulk/get": {Permission: PermGetSecret},

			// --- lifecycle ---------------------------------------------------------
			// A soft delete opens a recovery window and is scoped to the target's own
			// MRN, so a workload decommissioning a secret it owns is legitimate.
			"POST /api/v1/secrets/delete": {Permission: PermDeleteSecret},
			// Restore and destroy are NOT: both are authorized at TENANT scope (the
			// target's project and environment are not known until the row is read),
			// so they need a grant far wider than any single workload's, and both are
			// recovery-desk operations a human drives from the console. Destroy is
			// additionally irreversible.
			"POST /api/v1/secrets/restore": {Permission: PermDeleteSecret, Actor: sdkauthz.ActorUserOnly},
			"POST /api/v1/secrets/destroy": {Permission: PermDeleteSecret, Actor: sdkauthz.ActorUserOnly},

			// --- rotation policy ---------------------------------------------------
			// Setting the policy is administration of the machinery, not a rotation:
			// it decides when and how every future value is replaced. Console work.
			"POST /api/v1/secrets/rotation-policy": {Permission: PermManageRotation, Actor: sdkauthz.ActorUserOnly},
		},

		// SEGMENT PAIRS — kept for the segments that genuinely are "browse these,
		// manage these", where one read permission and one write permission say
		// everything true about the whole noun.
		//
		// Keyed by the FIRST path segment under /api/v1. Segments are flat
		// (/projects, /secrets, /audit, …) rather than nested precisely so that this
		// allowlist is meaningful: with everything nested under /projects, one entry
		// would cover the whole API and the allowlist would be a single row saying
		// "yes".
		//
		// The WRITES are user-only: creating a project, moving a folder, rewiring a
		// webhook and reading the access trail are administrative acts a human
		// performs from the console, and a workload doing one is the signal rather
		// than the workflow. The READS stay open to either class — a workload
		// resolving its own scope legitimately browses the hierarchy.
		Routes: map[string]sdkauthz.Perms{
			"projects":     {Read: PermReadMetadata, Write: PermManageProject, WriteActor: sdkauthz.ActorUserOnly},
			"environments": {Read: PermReadMetadata, Write: PermManageEnvironment, WriteActor: sdkauthz.ActorUserOnly},
			// DELETE /folders ALSO requires PermDeleteSecret, enforced in
			// api.DeleteFolder — removing a folder removes the secrets under it, and
			// folder management alone must not be a way to delete values. The route
			// guard demands the primary ManageFolder.
			"folders": {Read: PermReadMetadata, Write: PermManageFolder, WriteActor: sdkauthz.ActorUserOnly},
			// POST /imports ALSO requires PermGetSecret on the SOURCE scope, enforced
			// in api.CreateImport: an import makes another scope's values readable
			// through this one, so creating it must require the ability to read them.
			// The route guard demands the primary ManageFolder.
			"imports":  {Read: PermReadMetadata, Write: PermManageFolder, WriteActor: sdkauthz.ActorUserOnly},
			"webhooks": {Read: PermReadMetadata, Write: PermManageRotation, WriteActor: sdkauthz.ActorUserOnly},
			// The audit trail is user-only on BOTH verbs. It is the record an incident
			// review reads, and a workload reading it is doing reconnaissance rather
			// than work. There is no write route on /audit today; the pair keeps the
			// answer for one that is added.
			"audit": {
				Read: PermReadAudit, Write: PermAdmin,
				ReadActor: sdkauthz.ActorUserOnly, WriteActor: sdkauthz.ActorUserOnly,
			},
		},

		Methods: map[string]string{
			// Legacy flat-key surface — the kit secret-provider client's contract. The
			// permissions are the real ones for the operation, not a compatibility
			// exemption: an old client with a token that cannot read secrets could never
			// read them through the old RPC either.
			SecretServicePrefix + "Put":    PermPutSecret,
			SecretServicePrefix + "Get":    PermGetSecret,
			SecretServicePrefix + "List":   PermListSecrets,
			SecretServicePrefix + "Delete": PermDeleteSecret,

			// Projects / environments / folders / imports.
			SecretServicePrefix + "CreateProject":     PermManageProject,
			SecretServicePrefix + "ListProjects":      PermReadMetadata,
			SecretServicePrefix + "GetProject":        PermReadMetadata,
			SecretServicePrefix + "UpdateProject":     PermManageProject,
			SecretServicePrefix + "DeleteProject":     PermManageProject,
			SecretServicePrefix + "CreateEnvironment": PermManageEnvironment,
			SecretServicePrefix + "ListEnvironments":  PermReadMetadata,
			SecretServicePrefix + "GetEnvironment":    PermReadMetadata,
			SecretServicePrefix + "UpdateEnvironment": PermManageEnvironment,
			SecretServicePrefix + "DeleteEnvironment": PermManageEnvironment,
			SecretServicePrefix + "CreateFolder":      PermManageFolder,
			SecretServicePrefix + "ListFolders":       PermReadMetadata,
			SecretServicePrefix + "MoveFolder":        PermManageFolder,
			SecretServicePrefix + "DeleteFolder":      PermManageFolder,
			SecretServicePrefix + "CreateImport":      PermManageFolder,
			SecretServicePrefix + "ListImports":       PermReadMetadata,
			SecretServicePrefix + "UpdateImport":      PermManageFolder,
			SecretServicePrefix + "DeleteImport":      PermManageFolder,

			// Secrets. GetSecret is the reveal and carries the reveal permission; every
			// metadata operation carries the metadata one. The distinction is the point.
			SecretServicePrefix + "GetSecret":            PermGetSecret,
			SecretServicePrefix + "DescribeSecret":       PermReadMetadata,
			SecretServicePrefix + "ListSecrets":          PermListSecrets,
			SecretServicePrefix + "PutSecret":            PermPutSecret,
			SecretServicePrefix + "UpdateSecretMetadata": PermPutSecret,
			SecretServicePrefix + "ListSecretVersions":   PermReadMetadata,
			SecretServicePrefix + "RollbackSecret":       PermPutSecret,
			SecretServicePrefix + "RotateSecret":         PermRotateSecret,
			SecretServicePrefix + "SetRotationPolicy":    PermManageRotation,
			SecretServicePrefix + "DeleteSecret":         PermDeleteSecret,
			SecretServicePrefix + "ListDeletedSecrets":   PermListSecrets,
			SecretServicePrefix + "RestoreSecret":        PermDeleteSecret,
			SecretServicePrefix + "DestroySecret":        PermDeleteSecret,

			// Bulk. A batch is a TRANSPORT optimisation, not a weaker operation: a batch
			// get is a reveal and a batch put is a write, so each demands the permission
			// its single-item twin does. Every item is ADDITIONALLY authorized on its own
			// MRN inside the api service, which is what stops a batch from turning a
			// narrow grant into a broad one.
			SecretServicePrefix + "BatchGetSecrets": PermGetSecret,
			SecretServicePrefix + "BatchPutSecrets": PermPutSecret,

			// Webhooks + audit.
			SecretServicePrefix + "CreateWebhookEndpoint": PermManageRotation,
			SecretServicePrefix + "ListWebhookEndpoints":  PermReadMetadata,
			SecretServicePrefix + "UpdateWebhookEndpoint": PermManageRotation,
			SecretServicePrefix + "DeleteWebhookEndpoint": PermManageRotation,
			SecretServicePrefix + "ListWebhookDeliveries": PermReadMetadata,
			SecretServicePrefix + "ListAuditEvents":       PermReadAudit,
		},

		// THE ACTOR CONSTRAINT FOR gRPC, method by method. An absent entry means
		// ActorAny — the default, and the right answer for every fetch, write and
		// metadata read, which a workload and a console operator both perform.
		//
		// The list below is the gRPC MIRROR of the user-only REST surfaces, and it has
		// to stay one: the two transports sit on the same api service, so a constraint
		// that held on one and not the other would be no constraint at all — a caller
		// refused over REST would simply open a gRPC channel. audit_test.go asserts
		// the two agree surface by surface.
		MethodActors: map[string]sdkauthz.Actor{
			// Hierarchy management — console work.
			SecretServicePrefix + "CreateProject":     sdkauthz.ActorUserOnly,
			SecretServicePrefix + "UpdateProject":     sdkauthz.ActorUserOnly,
			SecretServicePrefix + "DeleteProject":     sdkauthz.ActorUserOnly,
			SecretServicePrefix + "CreateEnvironment": sdkauthz.ActorUserOnly,
			SecretServicePrefix + "UpdateEnvironment": sdkauthz.ActorUserOnly,
			SecretServicePrefix + "DeleteEnvironment": sdkauthz.ActorUserOnly,
			SecretServicePrefix + "CreateFolder":      sdkauthz.ActorUserOnly,
			SecretServicePrefix + "MoveFolder":        sdkauthz.ActorUserOnly,
			SecretServicePrefix + "DeleteFolder":      sdkauthz.ActorUserOnly,
			SecretServicePrefix + "CreateImport":      sdkauthz.ActorUserOnly,
			SecretServicePrefix + "UpdateImport":      sdkauthz.ActorUserOnly,
			SecretServicePrefix + "DeleteImport":      sdkauthz.ActorUserOnly,

			// Tenant-scoped recovery + the irreversible one.
			SecretServicePrefix + "RestoreSecret": sdkauthz.ActorUserOnly,
			SecretServicePrefix + "DestroySecret": sdkauthz.ActorUserOnly,

			// The machinery that rotates values and announces the change.
			SecretServicePrefix + "SetRotationPolicy":     sdkauthz.ActorUserOnly,
			SecretServicePrefix + "CreateWebhookEndpoint": sdkauthz.ActorUserOnly,
			SecretServicePrefix + "UpdateWebhookEndpoint": sdkauthz.ActorUserOnly,
			SecretServicePrefix + "DeleteWebhookEndpoint": sdkauthz.ActorUserOnly,

			// The access trail.
			SecretServicePrefix + "ListAuditEvents": sdkauthz.ActorUserOnly,
		},

		// Enforced DEEPER than the surface — a SECOND permission checked per
		// operation, against the target MRN, inside internal/api, on top of the
		// primary one the route guard already demanded:
		//
		//	PermGetSecret     rollback (republishes a value the caller did not supply),
		//	                  creating a scope import (on the SOURCE scope), and every
		//	                  hop of a reference chain
		//	PermDeleteSecret  deleting a folder (which deletes the secrets under it)
		//
		// The first two are also primary permissions on routes of their own, so they
		// add nothing to DeclaredPermissions. They stay because the property this list
		// encodes is "a permission this service can demand must be registered in
		// Auth", and that must survive a future where one of them is enforced ONLY as
		// a second check — otherwise the guard would demand something no token could
		// ever carry.
		//
		// THE SIX BELOW THEM ARE THE CASE THAT PROPERTY WAS WRITTEN FOR. Dynamic
		// secrets, transit and static-secret leases are enforced today ONLY inside
		// internal/api — every one of their operations runs through s.guard against a
		// concrete target MRN — because the transports have not mounted their routes
		// and RPCs yet. Without these entries the permissions would be demandable by
		// the api layer and registered nowhere in Auth, which is the exact silent,
		// total failure the DeclaredPermissions doc below describes: a guard asking
		// for something no token can hold, so every call answers 403 and nothing in
		// any log says why.
		//
		// They are listed here rather than in Exact/Methods deliberately: the surface
		// allowlist must describe the surface that EXISTS. An Exact entry for a route
		// nothing serves is a stale row, and audit_test.go's
		// TestEveryMappedRouteSurfaceIsLive fails on it — correctly, because a
		// hand-kept table that can describe imaginary routes has stopped being an
		// allowlist. When the transports mount these surfaces, each one gains its
		// Exact/Methods entry, its actor constraint and its spec row, and the entries
		// here become redundant in the same harmless way the first two are.
		OperationPermissions: []string{
			PermGetSecret,
			PermDeleteSecret,
			PermManageDynamicRole,
			PermIssueDynamicCredential,
			PermEncrypt,
			PermDecrypt,
			PermManageTransitKey,
			PermManageLease,
		},

		// secret:Admin covers every required action. It does NOT widen resource scope.
		BlanketActions: BlanketActions(),

		// EXEMPT PATHS — served with no guard at all. Every entry needs the argument
		// below; nothing is exempt for convenience.
		//
		//	/healthz  liveness. An orchestrator must be able to probe before it holds a
		//	          credential, and the response is the literal string "ok".
		//	/readyz   readiness. Same argument; it discloses a dependency NAME
		//	          ("database", "auth") and never an address or a driver message.
		//	/api/v1/setup
		//	          the first-run wizard. It must work BEFORE Auth exists, because
		//	          provisioning is what makes tokens mintable at all, so it is
		//	          self-guarded by SETUP_BOOTSTRAP_TOKEN compared in constant time,
		//	          IP rate-limited, and refused outright once an orchestrator owns
		//	          the instance (or when MAINTAINERD_MODE=core declares one will).
		//	/api/v1/capabilities
		//	          the capability probe. It answers the questions a client must
		//	          settle BEFORE it can hold a token — is the guard enforced or
		//	          dev-open, is this instance provisioned, and which issuer and
		//	          audience a token must carry — so requiring a token to ask them
		//	          would be circular. It is exempt because it is UNAUTHENTICATABLE,
		//	          not because it is convenient.
		//
		//	          What it discloses is bounded to facts an anonymous caller could
		//	          already obtain from the port it is talking to: the service name
		//	          (a constant), the version (already public as an image tag), the
		//	          guard mode (determinable in one unauthenticated request by
		//	          reading whether a guarded route answers 401 or 200), the setup
		//	          bit (already the documented anonymous disclosure of
		//	          /setup/status and SecretService/Ping), the run mode (named by
		//	          rest_wizard_open today), and — only when the guard is ENFORCED —
		//	          the issuer and audience, both of which appear in the clear in
		//	          every token this service verifies. It has no write path, no
		//	          client secret, no JWKS URL (routinely an internal address), no
		//	          tenant, project or permission list, no file path, and it reads
		//	          nothing per-request that is not memoized in-process.
		//
		// The two probes are ALSO mounted outside the /api/v1 group the guard wraps,
		// so they are exempt by construction as well as by declaration. Listing them
		// here keeps the Map a complete statement of the HTTP surface — which is what
		// the gap-audit test checks itself against — and keeps them reachable if the
		// guard is ever mounted at the root.
		//
		// Prefix matching is segment-aware in the SDK, so "/api/v1/setup" exempts
		// "/api/v1/setup/status" and never "/api/v1/setup-admin".
		ExemptPaths: []string{HealthzPath, ReadyzPath, SetupPath, CapabilitiesPath},

		// EXEMPT METHODS — matched EXACTLY, never by prefix, so a new RPC on any of
		// these services fails closed instead of inheriting an exemption.
		//
		//	Health/Check, Health/Watch
		//	          the standard health protocol, for the reason /healthz is exempt.
		//	          Watch is server-streaming, which is why the bootstrap installs
		//	          the SDK's STREAM interceptor as well as the unary one.
		//	SecretService/Ping
		//	          answers {ok, setup_complete} and nothing else — the same single
		//	          bit the anonymous REST setup status returns. An orchestrator has
		//	          to be able to ask "is this instance provisioned yet" before it has
		//	          provisioned the thing that mints tokens.
		//	SecretService/Setup
		//	          the legacy flat-surface setup RPC, gated by the bootstrap token
		//	          compared in constant time inside the handler.
		//	SetupService/*
		//	          the controlled setup surface, gated by the x-setup-token metadata
		//	          header in the handler, for the same reason the REST wizard is.
		//	          GetSetupStatus discloses one bit to an unprivileged caller and the
		//	          full payload only to the setup token or a verified secret:Admin.
		//
		// Nothing else may be added without the same argument: an entry here is a
		// method no token protects.
		ExemptMethods: []string{
			HealthServicePrefix + "Check",
			HealthServicePrefix + "Watch",
			SecretServicePrefix + "Ping",
			SecretServicePrefix + "Setup",
			SetupServicePrefix + "GetSetupStatus",
			SetupServicePrefix + "Setup",
			SetupServicePrefix + "CompleteSetup",
		},
	}
}

// BlanketActions is this service's own blanket action list — the actions that,
// when granted, cover every required action.
//
// IT MUST BE SET ON EVERY PRINCIPAL, or secret:Admin silently stops meaning
// anything. The SDK cannot infer it (an admin action is a service's vocabulary,
// not the platform's), so authz.Guard copies it from Map.BlanketActions onto
// every principal it verifies. A Principal built ANY OTHER WAY — a test double, a
// custom transport, a decision cache — has to set it from here, and gets
// wildcard-only coverage if it does not. That failure is quiet in exactly the
// wrong direction: an administrator who suddenly cannot read anything.
func BlanketActions() []string { return []string{PermAdmin} }

// DeclaredPermissions returns every permission this service's surfaces can
// demand, deduped and sorted.
//
// SETUP REGISTERS EXACTLY THIS LIST IN AUTH, and it is DERIVED from the Map
// rather than hand-listed at the registration site. Enforcement and registration
// are two halves of one fact, and when they drift the failure is silent and
// total: the guard demands a permission that exists nowhere in Auth, so no token
// can ever carry it and every call answers 403 regardless of who makes it, with
// nothing in any log saying why.
func DeclaredPermissions() []string { return Map().DeclaredPermissions() }

// All is the canonical constant list, in declaration order. It exists so a test
// can assert that the Map demands exactly these and no more — the drift guard in
// the other direction from DeclaredPermissions.
func All() []string {
	return []string{
		PermReadMetadata,
		PermGetSecret,
		PermPutSecret,
		PermDeleteSecret,
		PermRotateSecret,
		PermListSecrets,
		PermManageProject,
		PermManageEnvironment,
		PermManageFolder,
		PermManageRotation,
		PermReadAudit,
		PermManageDynamicRole,
		PermIssueDynamicCredential,
		PermEncrypt,
		PermDecrypt,
		PermManageTransitKey,
		PermManageLease,
		PermAdmin,
	}
}

// DevOpenWarnings are the service-specific consequences appended to the SDK's
// dev-open boot banner.
//
// The banner names every disabled guard INDIVIDUALLY rather than saying "auth
// disabled". A one-line summary is easy to skim past in a startup log; a line
// that says "ANY caller can reveal ANY secret" is not. This is the last warning
// before an unguarded vault starts answering requests.
func DevOpenWarnings() []string {
	return []string{
		"reveal gating — ANY caller can read ANY secret's decrypted value",
		"the setup status surface — the full controller and tenant payload is readable",
	}
}
