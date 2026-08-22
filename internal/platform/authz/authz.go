// Package authz guards this service's API the way the platform demands of every
// attached service: sdk-verified bearer tokens (Auth's JWKS + issuer + audience)
// plus deny-by-default permission enforcement.
//
// There are TWO layers here, and they answer different questions:
//
//  1. THE SURFACE GUARD (Guard.Middleware / the gRPC interceptor). Is the caller
//     authenticated at all, and is the surface it is calling one this service has
//     decided permissions for? The route/method maps double as allowlists: an
//     unmapped surface is DENIED even to a valid token, so mounting a router or
//     adding an RPC without deciding its permission fails closed instead of
//     shipping open.
//
//  2. THE OPERATION CHECK (Claims.Allows). May THIS principal perform THIS action
//     on THIS resource? This is the one that matters, and it is MRN-level: the
//     caller's grants are matched against the target's
//     mrn:secret:<tenant>:<project>:<resource-path>, which is what makes "may read
//     staging, must not read prod" expressible at all. A permission check that
//     stopped at the route would make every grant environment-wide.
//
// Both are required. Layer 1 without layer 2 is a vault where anyone who may read
// one secret may read all of them; layer 2 without layer 1 is a vault that answers
// unauthenticated callers.
//
// FAIL-CLOSED STARTUP. Outside APP_ENV=development, a missing auth configuration
// (AUTH_JWKS_URL / AUTH_ISSUER / AUTH_AUDIENCE) does not degrade to "open" — REST
// answers 503 and gRPC serves health only. In development it opens with a LOUD boot
// warning naming every guard that is off, because a silent dev-open default is how
// an unguarded vault reaches production.
package authz

import (
	"context"
	"net/http"
	"sort"
	"strings"

	sdkauth "github.com/maintainerd/sdk/auth"

	"github.com/maintainerd/secret/internal/platform/mrn"
	"github.com/maintainerd/secret/internal/platform/response"
)

// The permission namespace this service owns. Every action a caller can be granted
// is one of these strings; Auth registers exactly this set (see DeclaredPermissions).
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
	// confined to that tenant's MRNs.
	PermAdmin = "secret:Admin"
)

// allPermissions is the canonical set — the single list DeclaredPermissions reports
// and the route/method maps are checked against by test. Registration in Auth and
// enforcement here are two halves of one fact: when they drift the failure is
// silent and total, because the guard demands a permission that exists nowhere in
// Auth, so no token can ever carry it and every call is denied regardless of who
// makes it.
var allPermissions = []string{
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

// DeclaredPermissions returns every permission this service's surfaces can demand,
// sorted so setup logs and diffs are stable (map iteration is randomised, and a
// permission list that reorders every boot is unreadable).
//
// Setup registers exactly this list in Auth as the service's resource-API
// permissions. It is derived from the constants above rather than hand-listed at
// the registration site for the reason in allPermissions' comment.
func DeclaredPermissions() []string {
	out := make([]string, len(allPermissions))
	copy(out, allPermissions)
	sort.Strings(out)
	return out
}

// Actor kinds, as recorded on an audit row.
const (
	ActorKindUser    = "user"
	ActorKindService = "service"
)

// Grant is one entitlement: an action, optionally confined to an MRN pattern.
//
// THE GRANT GRAMMAR, as it appears in a token's scope/permissions claim:
//
//	secret:ReadMetadata                                       — action, service-wide
//	secret:GetSecret=mrn:secret:acme:billing:secret/staging/*  — action, scoped
//
// An UNQUALIFIED grant is service-wide (equivalent to `=mrn:secret:*:*:*`). That is
// stated plainly rather than hidden because it is the one place this design trades
// safety for compatibility: a plain permission token minted by an Auth that knows
// nothing about MRNs still works, and the operator narrows it by writing the
// resource form. The narrow form is what makes per-environment grants expressible,
// and it is the form the console and Auth's policy authoring should emit.
//
// The separator is '=' and only the FIRST one splits, because an action never
// contains '=' while a resource pattern theoretically may.
type Grant struct {
	Action string
	// Resource is an MRN pattern, or "" for service-wide.
	Resource string
}

// ParseGrant parses one entry of a scope/permissions claim.
func ParseGrant(raw string) Grant {
	raw = strings.TrimSpace(raw)
	if i := strings.IndexByte(raw, '='); i >= 0 {
		return Grant{Action: strings.TrimSpace(raw[:i]), Resource: strings.TrimSpace(raw[i+1:])}
	}
	return Grant{Action: raw}
}

// Claims is the verified identity of a caller, reduced to what authorization needs.
type Claims struct {
	// Subject is the principal as authenticated — an Auth subject, a service
	// identity, or (for the setup surface) the setup controller. It is what lands in
	// audit_log.actor_subject.
	Subject string
	// Kind is user or service, recorded on the audit row so an incident review can
	// tell a human reading a credential from a workload reading it.
	Kind string
	// Tenant is the tenant slug the token asserts, when it asserts one. It is used
	// only as the DEFAULT tenant for a request that does not name one; it is never a
	// substitute for the grant check, because a token's own tenant claim says who
	// the caller is, not what it may read.
	Tenant string
	// Grants is the parsed entitlement list.
	Grants []Grant
}

// Allows reports whether these claims permit action on resourceMRN.
//
// Deny-by-default at every step: no claims, no grants, an unparseable pattern, an
// unparseable resource — all false. A malformed pattern is treated as no grant
// rather than as a wildcard, which is the only safe reading of "we cannot evaluate
// this".
func (c *Claims) Allows(action, resourceMRN string) bool {
	if c == nil || action == "" || resourceMRN == "" {
		return false
	}
	target, err := mrn.Parse(resourceMRN)
	if err != nil {
		// A resource this service itself could not render as a valid MRN is a bug,
		// and the fail-closed answer is the correct one: better a denied read than
		// an allowed one against an identifier nobody can reason about.
		return false
	}
	for _, g := range c.Grants {
		if !actionCovers(g.Action, action) {
			continue
		}
		if g.Resource == "" {
			return true
		}
		pattern, perr := mrn.ParsePattern(g.Resource)
		if perr != nil {
			continue
		}
		if pattern.Matches(target) {
			return true
		}
	}
	return false
}

// HasAction reports whether the claims carry an action at all, ignoring resource
// scope. It exists for the surface guard (layer 1), which runs before the target
// MRN is known — never for an operation decision, which must always be MRN-level.
func (c *Claims) HasAction(action string) bool {
	if c == nil {
		return false
	}
	for _, g := range c.Grants {
		if actionCovers(g.Action, action) {
			return true
		}
	}
	return false
}

// actionCovers reports whether a granted action covers a required one. "*" and
// secret:Admin are blanket actions; everything else is exact. There is deliberately
// no prefix matching on actions — "secret:Get*" would be a grant whose blast radius
// changes every time a new RPC is added.
func actionCovers(granted, required string) bool {
	switch granted {
	case required, "*", PermAdmin:
		return true
	}
	return false
}

// VerifyFunc validates a bearer token and returns its claims. In production it
// wraps the sdk verifier (JWKS + issuer + audience); tests inject their own.
type VerifyFunc func(ctx context.Context, token string) (*Claims, error)

// SDKVerify adapts the sdk verifier to VerifyFunc, reading grants from both claim
// shapes maintainerd-auth can mint: the space-separated "scope" string and the
// "permissions" array.
func SDKVerify(v *sdkauth.Verifier) VerifyFunc {
	return func(_ context.Context, token string) (*Claims, error) {
		c, err := v.Verify(token)
		if err != nil {
			return nil, err
		}
		out := &Claims{Subject: c.Subject, Tenant: c.Tenant, Kind: ActorKindService}
		for _, s := range c.Scopes {
			out.Grants = append(out.Grants, ParseGrant(s))
		}
		if raw, ok := c.Raw["permissions"].([]any); ok {
			for _, p := range raw {
				if s, ok := p.(string); ok {
					out.Grants = append(out.Grants, ParseGrant(s))
				}
			}
		}
		// sub_type is Auth's principal-kind claim. Anything that is not explicitly a
		// user is recorded as a service: mislabelling a workload as a human in the
		// audit trail is the less misleading direction.
		if st, _ := c.Raw["sub_type"].(string); strings.EqualFold(st, ActorKindUser) {
			out.Kind = ActorKindUser
		}
		if out.Tenant == "" {
			if t, _ := c.Raw["tenant_slug"].(string); t != "" {
				out.Tenant = t
			}
		}
		return out, nil
	}
}

// Mode is the resolved posture of the guard.
type Mode int

const (
	// ModeEnforced verifies tokens and permissions on every guarded surface — the
	// only mode outside development.
	ModeEnforced Mode = iota
	// ModeDevOpen serves without authentication. Permitted ONLY in development, and
	// announced loudly at boot (see Guard.LogBanner).
	ModeDevOpen
	// ModeUnavailable refuses every guarded surface: auth is required
	// (non-development) but not configured. REST answers 503; gRPC serves health
	// only. The setup surface stays reachable because it carries its own
	// SETUP_BOOTSTRAP_TOKEN gate — a fresh install has to be provisionable into a
	// state where tokens exist at all.
	ModeUnavailable
)

func (m Mode) String() string {
	switch m {
	case ModeEnforced:
		return "enforced"
	case ModeDevOpen:
		return "development-open"
	default:
		return "unavailable"
	}
}

// Guard is the resolved posture, decided once at startup by the bootstrap.
type Guard struct {
	Mode   Mode
	Verify VerifyFunc // required when Mode == ModeEnforced
	Reason string     // human-readable cause for DevOpen/Unavailable
}

// DevClaims is the identity attributed to a caller in ModeDevOpen. It carries a
// blanket grant, because a dev-open service by definition has no way to tell one
// caller from another — and it carries a NAME that will look wrong in an audit row
// if it is ever seen on a real deployment, which is the point.
func DevClaims() *Claims {
	return &Claims{
		Subject: "development-open",
		Kind:    ActorKindService,
		Grants:  []Grant{{Action: PermAdmin}},
	}
}

// perms is the read/write permission pair guarding one API segment.
type perms struct {
	Read  string
	Write string
}

// routePermissions maps the first path segment under /api/v1 to the BASELINE
// permission its surface requires: GET/HEAD need Read, every mutating verb needs
// Write. The map is the allowlist — a segment not listed here is DENIED even to a
// valid token.
//
// WHY "secrets" HAS THE SAME PERMISSION ON BOTH VERBS. Several routes on that
// segment are reads carried by a POST (reveal takes a body so a secret address
// never lands in an access log or a browser history; batch get likewise), so a
// method-derived read/write split would demand a write permission for a read and a
// read permission for nothing. The baseline there is therefore metadata access, and
// the real privilege — GetSecret to reveal, PutSecret to write, DeleteSecret to
// delete — is enforced per operation against the target's MRN, which is the only
// place it can be enforced correctly anyway. This map is the surface allowlist, not
// the authorization decision.
//
// "setup" is deliberately absent AND special-cased in Middleware: the setup surface
// must work before Auth exists, so it is self-guarded by SETUP_BOOTSTRAP_TOKEN in
// the setup handler instead of by tokens no one can mint yet. "healthz" lives
// outside /api/v1 and is exempt by construction.
var routePermissions = map[string]perms{
	"projects":     {Read: PermReadMetadata, Write: PermManageProject},
	"environments": {Read: PermReadMetadata, Write: PermManageEnvironment},
	"folders":      {Read: PermReadMetadata, Write: PermManageFolder},
	"imports":      {Read: PermReadMetadata, Write: PermManageFolder},
	"secrets":      {Read: PermReadMetadata, Write: PermReadMetadata},
	"bulk":         {Read: PermReadMetadata, Write: PermReadMetadata},
	"webhooks":     {Read: PermReadMetadata, Write: PermManageRotation},
	"audit":        {Read: PermReadAudit, Write: PermAdmin},
}

// setupSegment is the self-guarded first-run surface (see routePermissions).
const setupSegment = "setup"

type ctxKey struct{}

// FromContext returns the Claims the middleware placed, if any.
func FromContext(ctx context.Context) (*Claims, bool) {
	c, ok := ctx.Value(ctxKey{}).(*Claims)
	return c, ok
}

// NewContext attaches claims to a context. Used by the middleware and by the gRPC
// interceptor, which share the operation-level checks downstream.
func NewContext(ctx context.Context, c *Claims) context.Context {
	return context.WithValue(ctx, ctxKey{}, c)
}

// Middleware enforces the surface guard on every route it wraps. Mount it on the
// /api/v1 group; /healthz lives outside that group and is therefore exempt.
func (g Guard) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		segment := apiSegment(r.URL.Path)
		// The setup surface guards itself — see the routePermissions doc for why it
		// cannot be token-guarded.
		if segment == setupSegment {
			next.ServeHTTP(w, r)
			return
		}
		switch g.Mode {
		case ModeDevOpen:
			next.ServeHTTP(w, r.WithContext(NewContext(r.Context(), DevClaims())))
			return
		case ModeUnavailable:
			response.ErrorWithCode(w, http.StatusServiceUnavailable, "auth_unavailable",
				"API authentication is not configured ("+g.Reason+"); the API is disabled outside development")
			return
		}

		token := bearer(r.Header.Get("Authorization"))
		if token == "" {
			response.Error(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		claims, err := g.Verify(r.Context(), token)
		if err != nil {
			// Deliberately generic: which check a forged token failed is oracle
			// material.
			response.Error(w, http.StatusUnauthorized, "invalid token")
			return
		}
		p, known := routePermissions[segment]
		if !known {
			response.Error(w, http.StatusForbidden, "route has no permission mapping")
			return
		}
		required := p.Write
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			required = p.Read
		}
		if !claims.HasAction(required) {
			response.Error(w, http.StatusForbidden, "requires permission "+required)
			return
		}
		next.ServeHTTP(w, r.WithContext(NewContext(r.Context(), claims)))
	})
}

// apiSegment extracts the first path segment under /api/v1 ("" when the path is
// not under it).
func apiSegment(path string) string {
	const prefix = "/api/v1/"
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	rest := strings.TrimPrefix(path, prefix)
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		rest = rest[:i]
	}
	return rest
}

// bearer extracts a "Bearer <token>" Authorization header value.
func bearer(header string) string {
	if len(header) > 7 && strings.EqualFold(header[:7], "bearer ") {
		return strings.TrimSpace(header[7:])
	}
	return ""
}
