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
//	the twelve secret: permission constants
//	the REST route table       (segment -> read/write permission pair)
//	the gRPC method table      (full method -> permission)
//	the exemption set          (health probes + the self-guarded setup surfaces)
//
// expressed as one authz.Map literal — which is the surface ALLOWLIST as well as
// the table: Map.Required reports ok=false for anything not in it and the guard
// denies on ok=false, so mounting a route or registering an RPC without deciding
// its permission fails CLOSED instead of shipping open. See
// permissions_audit_test.go, which walks the live chi router and the live gRPC
// service descriptors and fails if either grows a surface this file does not
// account for.
//
// TWO LAYERS, TWO QUESTIONS. The Map is layer 1 (the surface guard): is the
// caller authenticated, and is this a surface we decided a permission for? Layer
// 2 is the operation check — may THIS principal perform THIS action on THIS
// resource's MRN — and it happens inside internal/api against the concrete
// target. The Map is the allowlist, never the authorization decision. Both are
// required: layer 1 without layer 2 is a vault where anyone who may read one
// secret may read all of them.
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
// WHY "secrets" AND "bulk" CARRY THE SAME PERMISSION ON BOTH VERBS. Several
// routes on those segments are reads carried by a POST (reveal takes a body so a
// secret address never lands in an access log, proxy log or browser history;
// batch get likewise), so a method-derived read/write split would demand a write
// permission for a read. The baseline there is therefore metadata access, and the
// real privilege — GetSecret to reveal, PutSecret to write, DeleteSecret to
// delete — is enforced per operation against the target's MRN in internal/api,
// which is the only place it can be enforced correctly anyway. Those deeper
// permissions are declared in OperationPermissions so they are still registered
// in Auth.
func Map() sdkauthz.Map {
	return sdkauthz.Map{
		Prefix: APIPrefix,

		// Keyed by the FIRST path segment under /api/v1. Segments are flat
		// (/projects, /secrets, /audit, …) rather than nested precisely so that this
		// allowlist is meaningful: with everything nested under /projects, one entry
		// would cover the whole API and the allowlist would be a single row saying
		// "yes".
		Routes: map[string]sdkauthz.Perms{
			"projects":     {Read: PermReadMetadata, Write: PermManageProject},
			"environments": {Read: PermReadMetadata, Write: PermManageEnvironment},
			"folders":      {Read: PermReadMetadata, Write: PermManageFolder},
			"imports":      {Read: PermReadMetadata, Write: PermManageFolder},
			"secrets":      {Read: PermReadMetadata, Write: PermReadMetadata},
			"bulk":         {Read: PermReadMetadata, Write: PermReadMetadata},
			"webhooks":     {Read: PermReadMetadata, Write: PermManageRotation},
			"audit":        {Read: PermReadAudit, Write: PermAdmin},
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

			// Bulk. The baseline is metadata because a batch mixes items whose individual
			// privileges differ; each item is checked with the operation's real permission
			// against its own MRN inside the api service.
			SecretServicePrefix + "BatchGetSecrets": PermReadMetadata,
			SecretServicePrefix + "BatchPutSecrets": PermReadMetadata,

			// Webhooks + audit.
			SecretServicePrefix + "CreateWebhookEndpoint": PermManageRotation,
			SecretServicePrefix + "ListWebhookEndpoints":  PermReadMetadata,
			SecretServicePrefix + "UpdateWebhookEndpoint": PermManageRotation,
			SecretServicePrefix + "DeleteWebhookEndpoint": PermManageRotation,
			SecretServicePrefix + "ListWebhookDeliveries": PermReadMetadata,
			SecretServicePrefix + "ListAuditEvents":       PermReadAudit,
		},

		// Enforced DEEPER than the surface — per operation, against the target MRN,
		// inside internal/api. They demand no route of their own on the REST side
		// (the /secrets and /bulk segments carry a metadata baseline), but Auth must
		// still know they exist or no token could ever carry them.
		OperationPermissions: []string{
			PermGetSecret,
			PermPutSecret,
			PermDeleteSecret,
			PermRotateSecret,
			PermListSecrets,
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
		//
		// The two probes are ALSO mounted outside the /api/v1 group the guard wraps,
		// so they are exempt by construction as well as by declaration. Listing them
		// here keeps the Map a complete statement of the HTTP surface — which is what
		// the gap-audit test checks itself against — and keeps them reachable if the
		// guard is ever mounted at the root.
		//
		// Prefix matching is segment-aware in the SDK, so "/api/v1/setup" exempts
		// "/api/v1/setup/status" and never "/api/v1/setup-admin".
		ExemptPaths: []string{HealthzPath, ReadyzPath, SetupPath},

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
// can assert that the Map demands exactly these twelve and no more — the drift
// guard in the other direction from DeclaredPermissions.
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
