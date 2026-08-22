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
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"

	"github.com/maintainerd/secret/internal/api"
	"github.com/maintainerd/secret/internal/audit"
	"github.com/maintainerd/secret/internal/platform/apperror"
	"github.com/maintainerd/secret/internal/platform/authz"
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

// maxBodyBytes bounds a request body. Generous enough for a 100-item batch put of
// realistic credentials, small enough that an unauthenticated POST cannot be a memory
// exhaustion primitive (the guard runs first, but the setup surface does not).
const maxBodyBytes = 4 << 20 // 4 MiB

// Server holds the dependencies the handlers need.
type Server struct {
	api   *api.Service
	setup *setup.Service
	guard authz.Guard
}

// NewServer builds the REST server.
func NewServer(svc *api.Service, setupSvc *setup.Service, guard authz.Guard) *Server {
	return &Server{api: svc, setup: setupSvc, guard: guard}
}

// Router builds the full mux, including /healthz.
//
// /healthz is mounted OUTSIDE the /api/v1 group, which is what makes it exempt from
// the guard by construction rather than by an exception inside it — an orchestrator
// has to be able to probe liveness before it has credentials, and the response leaks
// nothing beyond "serving".
func (s *Server) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)
	r.Use(s.requestLogger)

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	r.Route("/api/v1", func(v1 chi.Router) {
		v1.Use(s.guard.Middleware)

		v1.Route("/setup", func(g chi.Router) {
			g.Get("/status", s.getSetupStatus)
			// chi's Route mounts the subrouter, so "/api/v1/setup" and
			// "/api/v1/setup/" both arrive here as "/". An operator following a runbook
			// types one or the other, and a 404 on the first-run endpoint is a bad
			// first impression of a vault.
			g.Post("/", s.postSetup)
		})

		v1.Route("/projects", func(g chi.Router) {
			g.Get("/", s.listProjects)
			g.Post("/", s.createProject)
			g.Get("/{project}", s.getProject)
			g.Patch("/{project}", s.updateProject)
			g.Delete("/{project}", s.deleteProject)
		})

		v1.Route("/environments", func(g chi.Router) {
			g.Get("/", s.listEnvironments)
			g.Post("/", s.createEnvironment)
			g.Get("/{project}/{environment}", s.getEnvironment)
			g.Patch("/{project}/{environment}", s.updateEnvironment)
			g.Delete("/{project}/{environment}", s.deleteEnvironment)
		})

		v1.Route("/folders", func(g chi.Router) {
			g.Get("/", s.listFolders)
			g.Post("/", s.createFolder)
			g.Post("/move", s.moveFolder)
			g.Delete("/", s.deleteFolder)
		})

		v1.Route("/imports", func(g chi.Router) {
			g.Get("/", s.listImports)
			g.Post("/", s.createImport)
			g.Patch("/{importUUID}", s.updateImport)
			g.Delete("/{importUUID}", s.deleteImport)
		})

		v1.Route("/secrets", func(g chi.Router) {
			g.Get("/", s.listSecrets)
			g.Post("/", s.putSecret)
			g.Patch("/", s.updateSecretMeta)
			g.Get("/describe", s.describeSecret)
			g.Get("/versions", s.listVersions)
			g.Get("/deleted", s.listDeletedSecrets)
			// Reveal is a POST because its address belongs in a body, not a URL.
			g.Post("/reveal", s.revealSecret)
			g.Post("/rollback", s.rollbackSecret)
			g.Post("/rotate", s.rotateSecret)
			g.Post("/rotation-policy", s.setRotationPolicy)
			g.Post("/delete", s.deleteSecret)
			g.Post("/restore", s.restoreSecret)
			g.Post("/destroy", s.destroySecret)
		})

		v1.Route("/bulk", func(g chi.Router) {
			g.Post("/get", s.batchGet)
			g.Post("/put", s.batchPut)
		})

		v1.Route("/webhooks", func(g chi.Router) {
			g.Get("/", s.listWebhooks)
			g.Post("/", s.createWebhook)
			g.Patch("/{endpointUUID}", s.updateWebhook)
			g.Delete("/{endpointUUID}", s.deleteWebhook)
			g.Get("/{endpointUUID}/deliveries", s.listWebhookDeliveries)
		})

		v1.Get("/audit", s.listAudit)
	})

	return r
}

// requestLogger attaches a request-scoped logger seeded with the request id, so an
// internal error logged from anywhere in the stack is correlatable with the client's
// request.
func (s *Server) requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger := slog.With("request_id", middleware.GetReqID(r.Context()), "path", r.URL.Path, "method", r.Method)
		next.ServeHTTP(w, r.WithContext(response.WithLogger(r.Context(), logger)))
	})
}

// caller resolves the request's authenticated principal into an api.Caller.
//
// A request that reaches a guarded handler always has claims (the guard placed them,
// or DevClaims in development), so a missing one is a routing bug rather than an
// unauthenticated caller — reported as 401 anyway, because failing closed on a bug in
// the guard chain is the only safe direction.
func (s *Server) caller(w http.ResponseWriter, r *http.Request) (api.Caller, bool) {
	claims, ok := authz.FromContext(r.Context())
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
		RequestID: middleware.GetReqID(r.Context()),
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
func decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
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

// pathUUID reads a UUID path parameter.
func pathUUID(w http.ResponseWriter, r *http.Request, name string) (uuid.UUID, bool) {
	raw := chi.URLParam(r, name)
	id, err := uuid.Parse(raw)
	if err != nil {
		response.Error(w, http.StatusBadRequest, name+" must be a UUID")
		return uuid.Nil, false
	}
	return id, true
}

// requireQuery reads a required query parameter.
func requireQuery(w http.ResponseWriter, r *http.Request, name string) (string, bool) {
	v := strings.TrimSpace(r.URL.Query().Get(name))
	if v == "" {
		response.ServiceError(w, r, "invalid request", apperror.NewValidation(name+" is required"))
		return "", false
	}
	return v, true
}
