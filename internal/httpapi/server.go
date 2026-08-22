// Package httpapi is the REST surface: chi routes and handlers over the application
// service (internal/api), following core's handler/route style.
//
// THE HANDLERS CARRY NO AUTHORIZATION LOGIC. They parse a request, call one api
// method, and render the result. Every permission check, every MRN resolution and
// every audit row happens in the api service, so the REST and gRPC surfaces cannot
// drift into enforcing different rules — and so a new handler cannot accidentally
// ship without a check, because there is no check for it to omit.
//
// ROUTE SHAPE. Segments under /api/v1 are FLAT (/projects, /environments, /folders,
// /secrets, /bulk, /imports, /webhooks, /audit, /setup) rather than nested
// (/projects/{p}/environments/{e}/secrets/...). That is what makes the guard's
// first-segment allowlist meaningful: with everything nested under /projects, one map
// entry would cover the whole API and the allowlist would be a single row that says
// "yes".
//
// READS THAT TAKE A BODY. Reveal and batch-get are POSTs despite being reads. A
// secret's address in a URL ends up in access logs, proxy logs, browser history and
// referer headers; a body does not. The permission required is still the read one
// (see the authz route map), because the HTTP verb is a transport detail and the
// privilege is not.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	sdkauthz "github.com/maintainerd/sdk/authz"
	"github.com/maintainerd/secret/internal/api"
	"github.com/maintainerd/secret/internal/audit"
	"github.com/maintainerd/secret/internal/platform/apperror"
	mw "github.com/maintainerd/secret/internal/platform/middleware"
	"github.com/maintainerd/secret/internal/platform/permissions"
	"github.com/maintainerd/secret/internal/platform/response"
	"github.com/maintainerd/secret/internal/setup"
)

// TenantHeader lets a caller select which tenant a request addresses.
//
// It is a SELECTOR, never an authorization: naming a tenant gets you an MRN in that
// tenant, and the grant check then decides whether you may touch it. That is why any
// caller may send any slug — asking is free, and the answer for a tenant you hold no
// grant in is an audited denial.
const TenantHeader = "X-Maintainerd-Tenant"

// SetupTokenHeader carries the bootstrap token on the REST setup wizard.
const SetupTokenHeader = "X-Setup-Token"

// defaultMaxBodyBytes bounds a request body when no Options value is supplied (the
// zero-Options construction used by tests). Generous enough for a 100-item batch put of
// realistic credentials, small enough that an unauthenticated POST cannot be a memory
// exhaustion primitive — the guard runs first on the API, but the setup surface is
// self-guarded and reachable before any token exists.
const defaultMaxBodyBytes = 4 << 20 // 4 MiB

// ReadinessCheck is one dependency /readyz probes.
type ReadinessCheck struct {
	// Name appears in the response and in the log line, so an operator reading a
	// failing probe knows WHICH dependency is down without reading the server log.
	Name string
	// Probe reports the dependency's health. It must respect the context: /readyz
	// bounds every probe, and a probe that ignores the bound makes the readiness
	// endpoint itself the thing that hangs.
	Probe func(context.Context) error
}

// RateLimitOptions configures the in-process limiter's budgets. See
// internal/platform/middleware/rate_limit.go for the single-node caveat.
type RateLimitOptions struct {
	Enabled bool
	Window  time.Duration
	// Reveal budgets the two surfaces that return decrypted values.
	Reveal int
	// Write budgets every mutating surface.
	Write int
	// Setup budgets the self-guarded first-run surface, keyed by client IP.
	Setup int
}

// Options tunes the REST server. The zero value is a working configuration with the
// defaults in this file, so a test can construct a Server without a config package.
type Options struct {
	// Production selects the production security-header posture (HSTS).
	Production bool
	// MaxBodyBytes caps a request body on every route.
	MaxBodyBytes int64
	// RequestTimeout is the per-request context deadline applied to /api/v1.
	RequestTimeout time.Duration
	// ReadinessTimeout bounds each /readyz probe.
	ReadinessTimeout time.Duration
	RateLimit        RateLimitOptions
	// Readiness are the dependency probes /readyz reports on. An empty list makes
	// /readyz equivalent to /healthz, which is the honest answer for a server with no
	// dependencies wired — and never the production configuration.
	Readiness []ReadinessCheck
	// Capabilities are the static facts GET /api/v1/capabilities reports. They are
	// passed in rather than read from a config package so a test constructs a Server
	// the same way the bootstrap does.
	Capabilities CapabilityInfo
	// ConsoleDir is the built SPA's directory, or "" to not serve it from this
	// process. See console.go for the whole argument, including why this is a runtime
	// directory rather than a go:embed.
	ConsoleDir string
}

func (o Options) withDefaults() Options {
	if o.MaxBodyBytes < 1 {
		o.MaxBodyBytes = defaultMaxBodyBytes
	}
	if o.ReadinessTimeout <= 0 {
		o.ReadinessTimeout = 2 * time.Second
	}
	if o.RateLimit.Window <= 0 {
		o.RateLimit.Window = time.Minute
	}
	return o
}

// Server holds the dependencies the handlers need.
type Server struct {
	api     *api.Service
	setup   *setup.Service
	guard   sdkauthz.Guard
	opts    Options
	limiter *mw.Limiter
	// console serves the built SPA, or is nil when this process does not.
	console *consoleHandler
	// capabilityCache memoizes the one database-backed field of the anonymous
	// capability payload. See capabilities.go.
	capabilityCache capabilitiesCache
}

// NewServer builds the REST server.
//
// THE PERMISSION TABLE AND THE ERROR WRITER ARE WIRED ONTO THE GUARD HERE, so a
// Server is correctly guarded however it was constructed — including by a test
// that hands in a bare authz.Guard{Mode: …}. Both are idempotent restatements of
// what the bootstrap already resolved.
//
// The error writer matters for the API's contract. The SDK's default denial body
// is a compact {"error","code"} object, which is right for a library that cannot
// know its consumer's envelope — but every other failure this API produces is a
// response.Envelope ({"success":false,"error":…,"code":…}), and a client that has
// to parse one shape for a 403 from the guard and another for a 403 from a
// handler will get one of them wrong. authz.Guard is a value type, so this
// mutates this Server's copy and never the caller's.
func NewServer(svc *api.Service, setupSvc *setup.Service, guard sdkauthz.Guard, opts Options) *Server {
	resolved := opts.withDefaults()
	guard.Service = permissions.ServiceName
	guard.Permissions = permissions.Map()
	guard.WriteError = response.ErrorWithCode
	s := &Server{api: svc, setup: setupSvc, guard: guard, opts: resolved}
	if resolved.RateLimit.Enabled {
		s.limiter = mw.NewLimiter(resolved.RateLimit.Window)
	}
	// A console directory that cannot be opened is logged and skipped rather than
	// fatal: config already proved the path at boot, so failing here means it changed
	// underneath the process — and the vault must keep serving secrets whether or not
	// its UI is available. The log line names it so the operator is not left guessing
	// why the console 404s.
	if console, err := newConsoleHandler(resolved.ConsoleDir); err != nil {
		slog.Error("console: the configured directory could not be opened; the console will not be served",
			"error", err)
	} else {
		s.console = console
	}
	return s
}

// Close releases resources the server holds open — today, the console's directory
// handle. Safe on a nil Server and safe to call more than once.
func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	return s.console.Close()
}

// UseLimiter replaces the server's own limiter with a shared one.
//
// It exists so the REST and gRPC surfaces spend ONE budget. A per-transport budget is
// not a budget: a client that has exhausted its reveal allowance over REST would
// otherwise open a gRPC channel and spend a second one against the same secrets with
// the same grants. The bootstrap builds one limiter and hands it to both.
//
// Passing nil disables rate limiting on this server, which is what
// SECRET_RATE_LIMIT_ENABLED=false produces.
func (s *Server) UseLimiter(l *mw.Limiter) { s.limiter = l }

// Router builds the full mux, including the health probes.
//
// MIDDLEWARE ORDER IS LOAD-BEARING, outermost first:
//
//	RequestID       so every line below can correlate, including a panic
//	SecurityHeaders set before anything can write a response, including a 413 from the
//	                body cap or a 500 from recovery — a header that is only on the happy
//	                path is a header an attacker routes around
//	Recovery        outside the logger so a panic still produces the request line
//	RequestLogger   seeds the request-scoped logger every handler reports through
//	BodyLimit       before routing, because the setup surface is unauthenticated and the
//	                guard has not run yet
//
// THE HEALTH PROBES ARE MOUNTED OUTSIDE /api/v1, which is what makes them exempt from
// the guard by construction rather than by an exception inside it. They are also
// outside the per-request Timeout: a liveness probe must not inherit a 30-second
// budget. They are the ONLY unauthenticated surface on this transport apart from the
// self-guarded setup wizard.
func (s *Server) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	r.Use(mw.SecurityHeaders(s.opts.Production))
	r.Use(mw.Recovery)
	r.Use(mw.RequestLogger)
	r.Use(mw.BodyLimit(s.opts.MaxBodyBytes))

	r.Get("/healthz", s.healthz)
	r.Get("/readyz", s.readyz)

	r.Route("/api/v1", func(v1 chi.Router) {
		v1.Use(mw.Timeout(s.opts.RequestTimeout))
		// An unknown path UNDER /api/v1 must answer as an API, not as the console.
		// Without this the root NotFound handler below (which chi propagates into
		// mounted subrouters) would hand a mistyped API route the SPA's index.html
		// with a 200, and its client would parse HTML as JSON instead of seeing a 404.
		// The console handler refuses these prefixes too — belt and braces, because
		// getting this wrong is silent.
		v1.NotFound(func(w http.ResponseWriter, _ *http.Request) {
			response.Error(w, http.StatusNotFound, "no such endpoint")
		})
		// The SDK guard — the same decision path the gRPC interceptors run, over the
		// same permissions.Map. It is mounted on the /api/v1 group (rather than at the
		// root) so the probes above are outside it by construction as well as by the
		// Map's exemption list, and it places the verified Principal in the request
		// context for the handlers' MRN-level operation checks.
		v1.Use(s.guard.HTTPMiddleware())

		// The capability probe. UNAUTHENTICATED by declaration (it is in the Map's
		// exemption set, with its justification pinned by the gap-audit test) and it
		// discloses only facts a caller could obtain from the port it is already
		// talking to — see capabilities.go for the field-by-field argument.
		//
		// It carries NO rate-limit class. The one field that costs a database read is
		// memoized in-process, so hammering it cannot amplify into query load, and a
		// budget here would refuse the console's own boot request as readily as an
		// attacker's.
		v1.Get("/capabilities", s.capabilities)

		v1.Route("/setup", func(g chi.Router) {
			// The setup surface carries its OWN rate limit, keyed by client IP,
			// because it is the one path reachable without an Auth-minted token and it
			// compares a bootstrap token. Everything else is keyed by principal, which
			// this surface does not have.
			g.Use(s.rateLimit("setup", s.opts.RateLimit.Setup, mw.ByClientIP))
			g.Get("/status", s.getSetupStatus)
			// chi's Route mounts the subrouter, so "/api/v1/setup" and
			// "/api/v1/setup/" both arrive here as "/". An operator following a runbook
			// types one or the other, and a 404 on the first-run endpoint is a bad
			// first impression of a vault.
			g.Post("/", s.postSetup)
		})

		write := s.rateLimit("write", s.opts.RateLimit.Write, mw.ByPrincipal)
		reveal := s.rateLimit("reveal", s.opts.RateLimit.Reveal, mw.ByPrincipal)

		v1.Route("/projects", func(g chi.Router) {
			g.Get("/", s.listProjects)
			g.With(write).Post("/", s.createProject)
			g.Get("/{project}", s.getProject)
			g.With(write).Patch("/{project}", s.updateProject)
			g.With(write).Delete("/{project}", s.deleteProject)
		})

		v1.Route("/environments", func(g chi.Router) {
			g.Get("/", s.listEnvironments)
			g.With(write).Post("/", s.createEnvironment)
			g.Get("/{project}/{environment}", s.getEnvironment)
			g.With(write).Patch("/{project}/{environment}", s.updateEnvironment)
			g.With(write).Delete("/{project}/{environment}", s.deleteEnvironment)
		})

		v1.Route("/folders", func(g chi.Router) {
			g.Get("/", s.listFolders)
			g.With(write).Post("/", s.createFolder)
			g.With(write).Post("/move", s.moveFolder)
			g.With(write).Delete("/", s.deleteFolder)
		})

		v1.Route("/imports", func(g chi.Router) {
			g.Get("/", s.listImports)
			g.With(write).Post("/", s.createImport)
			g.With(write).Patch("/{importUUID}", s.updateImport)
			g.With(write).Delete("/{importUUID}", s.deleteImport)
		})

		v1.Route("/secrets", func(g chi.Router) {
			g.Get("/", s.listSecrets)
			g.With(write).Post("/", s.putSecret)
			g.With(write).Patch("/", s.updateSecretMeta)
			g.Get("/describe", s.describeSecret)
			g.Get("/versions", s.listVersions)
			g.Get("/deleted", s.listDeletedSecrets)
			// Reveal is a POST because its address belongs in a body, not a URL. It
			// carries the REVEAL budget, not the write one: it is the exfiltration
			// path, and metering it separately means a workload writing at its full
			// write budget is still able to read.
			g.With(reveal).Post("/reveal", s.revealSecret)
			g.With(write).Post("/rollback", s.rollbackSecret)
			g.With(write).Post("/rotate", s.rotateSecret)
			g.With(write).Post("/rotation-policy", s.setRotationPolicy)
			g.With(write).Post("/delete", s.deleteSecret)
			g.With(write).Post("/restore", s.restoreSecret)
			g.With(write).Post("/destroy", s.destroySecret)
		})

		v1.Route("/bulk", func(g chi.Router) {
			g.With(reveal).Post("/get", s.batchGet)
			g.With(write).Post("/put", s.batchPut)
		})

		v1.Route("/webhooks", func(g chi.Router) {
			g.Get("/", s.listWebhooks)
			g.With(write).Post("/", s.createWebhook)
			g.With(write).Patch("/{endpointUUID}", s.updateWebhook)
			g.With(write).Delete("/{endpointUUID}", s.deleteWebhook)
			g.Get("/{endpointUUID}/deliveries", s.listWebhookDeliveries)
		})

		v1.Get("/audit", s.listAudit)
	})

	// THE CONSOLE, MOUNTED AS THE ROOT NOT-FOUND HANDLER — which is what puts it
	// OUTSIDE the guarded /api/v1 group by construction, exactly like the probes
	// above, rather than by an exception inside the guard.
	//
	// NotFound rather than a `/*` route on purpose. A wildcard route at the root would
	// be matched by chi against every request and would need its own precedence
	// reasoning against /api/v1 and the probes; NotFound runs only when nothing else
	// matched, so the API and the probes keep their routing unchanged and the console
	// answers everything left over. That is precisely the SPA contract: any path that
	// is not a real asset is a client-side route and must receive index.html.
	//
	// With no console configured this stays chi's default 404, so the routing table is
	// identical to what it was before this existed.
	if s.console != nil {
		r.NotFound(s.console.ServeHTTP)
		// A method the SPA cannot answer is a 405 from chi by default, which for a
		// browser asking for a deep link with anything but GET/HEAD is the right
		// answer; the handler refuses those too.
	}

	return r
}

// rateLimit returns the limiter middleware for one budget, or a pass-through when the
// limiter is disabled. Returning a pass-through rather than nil keeps the route
// declarations uniform.
func (s *Server) rateLimit(class string, limit int, key mw.KeyFunc) func(http.Handler) http.Handler {
	if s.limiter == nil || limit <= 0 {
		return func(next http.Handler) http.Handler { return next }
	}
	return mw.RateLimit(s.limiter, class, limit, key)
}

// caller resolves the request's authenticated principal into an api.Caller.
//
// A request that reaches a guarded handler always has claims (the guard placed them,
// or DevClaims in development), so a missing one is a routing bug rather than an
// unauthenticated caller — reported as 401 anyway, because failing closed on a bug in
// the guard chain is the only safe direction.
func (s *Server) caller(w http.ResponseWriter, r *http.Request) (api.Caller, bool) {
	claims, ok := sdkauthz.FromContext(r.Context())
	if !ok || claims == nil {
		response.Error(w, http.StatusUnauthorized, "unauthenticated")
		return api.Caller{}, false
	}
	c, err := s.api.ResolveCaller(r.Context(), claims, actorFrom(r), tenantHint(r))
	if err != nil {
		response.ServiceError(w, r, "could not resolve the request tenant", err)
		return api.Caller{}, false
	}
	return c, true
}

// actorFrom builds the audit actor from the request's provenance.
func actorFrom(r *http.Request) audit.Actor {
	return audit.Actor{
		IP:        clientIP(r),
		UserAgent: r.UserAgent(),
		RequestID: chimw.GetReqID(r.Context()),
	}
}

// tenantHint reads the requested tenant from the header or the query string.
func tenantHint(r *http.Request) string {
	if v := strings.TrimSpace(r.Header.Get(TenantHeader)); v != "" {
		return v
	}
	return strings.TrimSpace(r.URL.Query().Get("tenant"))
}

// clientIP returns the peer address with the port stripped.
//
// X-Forwarded-For is deliberately NOT consulted. It is caller-controlled, so trusting
// it here would let anyone write an arbitrary address into this service's audit trail
// — turning the field an incident review depends on into one an attacker chooses. A
// deployment behind a trusted proxy should have the proxy rewrite the peer address, or
// this service should learn a configured trusted-proxy list; guessing is worse than
// recording the real peer.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// decode reads a JSON body with a size bound, rejecting unknown fields.
//
// DisallowUnknownFields is a correctness feature, not strictness for its own sake: a
// caller that misspells "create_folders" or "keep_versions" would otherwise get a
// silent default, which for retention means a version history quietly shorter than
// asked for.
//
// THE SIZE BOUND IS NOT APPLIED HERE. It belongs to middleware.BodyLimit, which wraps
// EVERY route before routing — which is where it has to be, because the setup surface
// is reachable before any token exists and the guard cannot run until the body has
// started arriving.
//
// This function used to wrap the body a second time with a constant, as belt and
// braces. That was a bug waiting to happen rather than defence in depth: an operator
// who RAISED HTTP_MAX_BODY_BYTES would have found JSON bodies still refused at the old
// constant, with nothing in the error saying why. One bound, one place, one number in
// the error.
func decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		if errors.Is(err, io.EOF) {
			response.Error(w, http.StatusBadRequest, "a request body is required")
			return false
		}
		response.Error(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return false
	}
	return true
}

// UUID path parameters are NOT parsed here any more. They are carried into the api
// layer as strings and validated by the DTO's is.UUID rule (internal/api), so the
// message a caller gets for a malformed id is the same one the gRPC surface produces
// rather than a second, transport-local wording.

// requireQuery reads a required query parameter.
func requireQuery(w http.ResponseWriter, r *http.Request, name string) (string, bool) {
	v := strings.TrimSpace(r.URL.Query().Get(name))
	if v == "" {
		response.ServiceError(w, r, "invalid request", apperror.NewValidation(name+" is required"))
		return "", false
	}
	return v, true
}
