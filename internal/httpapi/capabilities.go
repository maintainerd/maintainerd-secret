package httpapi

import (
	"net/http"
	"sync"
	"time"

	sdkauthz "github.com/maintainerd/sdk/authz"
	"github.com/maintainerd/secret/internal/platform/response"
)

// The capability endpoint: what a client may assume about THIS instance, answerable
// without a credential.
//
// WHY IT IS UNAUTHENTICATED. It answers the questions a client has to settle BEFORE it
// can hold a token: is this vault's guard enforced or open, has it been provisioned
// yet, and — if enforced — which issuer and audience a token must carry. A console
// could not ask any of that with a bearer token, because obtaining one is the thing it
// is trying to work out how to do. The alternative, which is what this replaced, is
// INFERENCE: the console concluded "the guard must be dev-open" from the absence of
// identity settings in its OWN configuration, which is a guess about the server made
// from the client's config file. It is wrong in both directions — an enforced service
// whose console was handed no issuer renders as "no identity configured, calling
// without a token" and then 401s on every call; an actually-open service whose console
// WAS given an issuer sends the operator into an OAuth flow nobody is listening for.
//
// WHAT MAKES IT SAFE. Every field below is either a constant, a single bit already
// disclosed by an existing anonymous surface, or a value that appears in every token
// this service verifies. The field-by-field argument is on each field. The rule for
// adding one: an anonymous caller must learn nothing they could use, and nothing they
// could not have obtained from the port they are already talking to. In particular
// there is no client secret, no JWKS URL, no database or host name, no file path, no
// permission list, no tenant or project name, and no reason (the guard's Reason string
// can name a missing variable, which is operator-facing text, not caller-facing).
//
// WHY IT IS NOT MERELY /setup/status WITH MORE FIELDS. That surface is the setup
// wizard's, gated by the setup rate-limit class, and its full payload is deliberately
// privileged — controller identity, tenant, permission list. Widening it would mean
// widening what the anonymous branch of a privileged endpoint discloses. This is a
// separate, permanently-anonymous, deliberately tiny surface.

// capabilitiesCacheTTL bounds how long the setup bit may be stale.
//
// THE CACHE IS THE RATE LIMIT. This endpoint is anonymous, so without one an attacker
// could turn it into two database reads per request — and unlike the setup wizard
// there is no bootstrap token to key a per-IP budget against a real principal. Caching
// removes the database from the hot path entirely, which is a better answer than a
// budget: a budget would also refuse the console.
//
// A COMPLETED SETUP IS CACHED FOREVER, not for the TTL. The setup lock is a durable
// one-shot (a setup_state row) and never reopens, so "complete" is monotonic and a
// cached true can never become wrong. Only the not-yet-complete answer expires.
const capabilitiesCacheTTL = 5 * time.Second

// CapabilityInfo is the static half of the payload — facts the process knows about
// itself at boot, handed to the server by the bootstrap rather than read from config
// here (httpapi imports no config package, so that both transports and every test
// construct a Server the same way).
type CapabilityInfo struct {
	// Version is this build's version string. The release image stamps its own tag
	// into it at link time.
	Version string
	// RunMode is "standalone" or "core".
	RunMode string
	// AuthIssuer and AuthAudience are the two checks a token must satisfy. They are
	// supplied here rather than read off the guard because the SDK's Guard does not
	// retain them — and they are published ONLY when the guard actually resolved to
	// ModeEnforced, so a leftover pair in the environment of a dev-open instance can
	// never be advertised as if it were being verified.
	AuthIssuer   string
	AuthAudience string
}

// capabilitiesPayload is the wire shape. Field-by-field justification below; it is the
// whole reason this type is written out rather than assembled from a map.
type capabilitiesPayload struct {
	// Service is the constant "secret". It identifies WHICH maintainerd API answered,
	// which a caller already knows from the address it dialled — and which a client
	// pointed at the wrong port needs in order to say so. Safe: a constant, present in
	// every MRN this service emits.
	Service string `json:"service"`

	// Version is the build. Safe because the release images are public and their tags
	// enumerable from the registry, so an anonymous caller can already map an image to
	// a version — and the alternative is a console that cannot tell an operator what
	// they are running, and an operator who has to guess when reading a changelog. It
	// is a version, not a commit: no build path, no branch, no CI identifier.
	Version string `json:"version"`

	// GuardMode is "enforced", "dev-open" or "unavailable" — the SDK's ladder, named.
	//
	// Safe, and honest is safer than coy: a caller can already determine this in one
	// unauthenticated request (call any /api/v1 route with no token and read whether
	// it is 200, 401 or 503), so withholding it protects nothing while forcing the
	// console to guess. Saying it plainly is also what lets the console render the
	// permanent "this vault is answering anonymous callers" banner from the SERVER's
	// posture instead of from its own missing settings. It names the mode and never
	// the reason.
	GuardMode string `json:"guard_mode"`

	// SetupComplete is exactly the single bit GET /setup/status and
	// SecretService/Ping already return to an anonymous caller. It is unavoidable —
	// a client has to know whether to show a wizard — and it is already the
	// documented anonymous disclosure, so this adds no new one.
	SetupComplete bool `json:"setup_complete"`

	// RunMode is "standalone" or "core": who provisions this instance. Safe because
	// it names no host, credential or address — it is the same fact
	// /setup/status.rest_wizard_open already implies to an anonymous caller — and the
	// console needs it to decide whether to offer the REST wizard at all rather than
	// offering it and having the server refuse.
	RunMode string `json:"run_mode"`

	// Auth is present ONLY when GuardMode is "enforced", and holds only the issuer
	// and the audience.
	//
	// Both are safe, and both are necessary. Necessary: they are what a client needs
	// to obtain a token this service will accept, and a console that has them from
	// the server cannot be misconfigured into pointing at a different Auth than the
	// one the service verifies against — which is the single most common way a
	// standalone install ends up 401ing everything. Safe: every token this service
	// verifies carries both in the clear, the issuer is a public OIDC discovery
	// origin by design, and the audience is a resource-API identifier, not a secret.
	//
	// Omitted when NOT enforced because there is nothing true to say: a dev-open or
	// unavailable guard verifies no issuer, and publishing a half-configured one
	// would send a client at an authorize endpoint that cannot help it.
	//
	// The JWKS URL is deliberately NOT here. It is the one identity value that is
	// routinely an internal address (an in-cluster service name), and a client never
	// needs it — the service fetches keys, the client does not.
	Auth *capabilityAuth `json:"auth,omitempty"`

	// Console reports whether this process serves the SPA itself, so a client can
	// tell "the API is here and the UI is elsewhere" from "both are here". A boolean
	// about this process's own routing table; it discloses no path.
	Console bool `json:"console"`
}

type capabilityAuth struct {
	Issuer   string `json:"issuer"`
	Audience string `json:"audience"`
}

// capabilitiesCache memoizes the one field that needs a database read.
type capabilitiesCache struct {
	mu       sync.Mutex
	complete bool
	// checkedAt is zero until the first successful read. Once complete is true the
	// entry never expires — see capabilitiesCacheTTL.
	checkedAt time.Time
}

// capabilities answers the capability probe.
//
// It NEVER fails on a setup-status error. A capability endpoint that 500s because the
// database blipped is a console that cannot render its own sign-in page during an
// incident — so a failed read reports setup_complete=false (the fail-closed direction:
// "we cannot confirm this instance is provisioned") and everything else, which does
// not depend on the database at all.
func (s *Server) capabilities(w http.ResponseWriter, r *http.Request) {
	payload := capabilitiesPayload{
		Service:       capabilityServiceName,
		Version:       orUnknown(s.opts.Capabilities.Version),
		GuardMode:     guardModeName(s.guard.Mode),
		SetupComplete: s.setupComplete(r),
		RunMode:       orUnknown(s.opts.Capabilities.RunMode),
		Console:       s.opts.ConsoleDir != "",
	}
	if s.guard.Mode == sdkauthz.ModeEnforced {
		payload.Auth = &capabilityAuth{
			Issuer:   s.opts.Capabilities.AuthIssuer,
			Audience: s.opts.Capabilities.AuthAudience,
		}
	}

	// no-store rather than a short max-age: guard_mode and setup_complete are exactly
	// the facts a client must not act on a stale copy of, and the cache that matters
	// (the one in front of the database) is this process's own.
	w.Header().Set("Cache-Control", "no-store")
	response.OK(w, payload, "")
}

// capabilityServiceName is the constant this endpoint reports. It is spelled here
// rather than imported from the permissions package so that httpapi's import graph
// does not grow an edge for a string.
const capabilityServiceName = "secret"

// setupComplete reads the cached setup bit, refreshing it at most once per TTL.
func (s *Server) setupComplete(r *http.Request) bool {
	if s.setup == nil {
		return false
	}
	s.capabilityCache.mu.Lock()
	defer s.capabilityCache.mu.Unlock()

	if s.capabilityCache.complete {
		return true // monotonic: the setup lock is a durable one-shot.
	}
	if !s.capabilityCache.checkedAt.IsZero() && time.Since(s.capabilityCache.checkedAt) < capabilitiesCacheTTL {
		return false
	}
	status, err := s.setup.Status(r.Context())
	if err != nil {
		// Logged server-side only. The response says "not complete", which is the
		// fail-closed reading of "we could not confirm".
		response.LoggerFromContext(r.Context()).Warn("capabilities: reading the setup status failed",
			"error", err)
		return false
	}
	s.capabilityCache.checkedAt = time.Now()
	s.capabilityCache.complete = status.Completed
	return status.Completed
}

// guardModeName renders the SDK's posture as a stable string a client can branch on.
//
// The strings are this API's contract and are deliberately NOT the SDK's Go constant
// names: a client parsing them must not break because the library renamed an enum.
// "unavailable" is reported as itself rather than folded into "enforced" — they are
// different states with different correct client behaviour (obtain a token vs. wait,
// this replica cannot verify one).
func guardModeName(mode sdkauthz.Mode) string {
	switch mode {
	case sdkauthz.ModeEnforced:
		return "enforced"
	case sdkauthz.ModeDevOpen:
		return "dev-open"
	default:
		return "unavailable"
	}
}

func orUnknown(v string) string {
	if v == "" {
		return "unknown"
	}
	return v
}
