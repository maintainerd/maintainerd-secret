package httpapi

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/maintainerd/secret/internal/api"
	"github.com/maintainerd/secret/internal/platform/response"
)

// Dynamic-secret handlers: role configuration, and the credential lifecycle.
//
// Roles are addressed by FIELDS rather than by a path parameter, for the reason stated
// in handlers_transit.go: the surface guard's Exact table matches a request path, so a
// parameterized route cannot carry a per-route permission and would fall back to a
// segment pair — which could not distinguish "configure a role" (user-only,
// secret:ManageDynamicRole) from "ask for a credential" (either class,
// secret:IssueDynamicCredential).
//
// THE ISSUE RESPONSE IS THE SECOND-AND-LAST SHAPE IN THIS SERVICE THAT CARRIES A
// CREDENTIAL, and like the reveal it is encoded by hand rather than through the shared
// helpers. The helpers take `any`; a generated password must never be handed to a
// generic marshaller, and encoding it here keeps "which responses can contain a
// credential" answerable by grep. There is no read-it-back endpoint and no column
// holding the password, so this response is the only place it ever exists.

// dynamicRoleQuery reads a role reference from the query string.
func dynamicRoleQuery(w http.ResponseWriter, r *http.Request) (api.DynamicRoleRef, bool) {
	project, ok := requireQuery(w, r, "project")
	if !ok {
		return api.DynamicRoleRef{}, false
	}
	name, ok := requireQuery(w, r, "name")
	if !ok {
		return api.DynamicRoleRef{}, false
	}
	return api.DynamicRoleRef{Project: project, Name: name}, true
}

// ---------------------------------------------------------------------------
// Role configuration
// ---------------------------------------------------------------------------

func (s *Server) createDynamicRole(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	var req api.CreateDynamicRoleInput
	if !decode(w, r, &req) {
		return
	}
	role, err := s.api.CreateDynamicRole(r.Context(), c, req)
	if err != nil {
		response.ServiceError(w, r, "could not create the dynamic role", err)
		return
	}
	response.Created(w, role, "dynamic role created")
}

func (s *Server) listDynamicRoles(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	project, ok := requireQuery(w, r, "project")
	if !ok {
		return
	}
	page, limit := response.PageParams(r)
	roles, total, err := s.api.ListDynamicRoles(r.Context(), c, api.ListDynamicRolesInput{
		Project:    project,
		Pagination: api.Pagination{Page: page, Limit: limit},
	})
	if err != nil {
		response.ServiceError(w, r, "could not list dynamic roles", err)
		return
	}
	response.List(w, roles, page, limit, total)
}

func (s *Server) describeDynamicRole(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	ref, ok := dynamicRoleQuery(w, r)
	if !ok {
		return
	}
	role, err := s.api.GetDynamicRole(r.Context(), c, ref)
	if err != nil {
		response.ServiceError(w, r, "could not read the dynamic role", err)
		return
	}
	// The detail carries the SQL templates and the DSN REFERENCE — operator-authored
	// SQL and an address. store.DynamicRoleDetail has no field that could hold the
	// connection string itself.
	response.OK(w, role, "")
}

func (s *Server) updateDynamicRole(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	var req api.UpdateDynamicRoleInput
	if !decode(w, r, &req) {
		return
	}
	role, err := s.api.UpdateDynamicRole(r.Context(), c, req)
	if err != nil {
		response.ServiceError(w, r, "could not update the dynamic role", err)
		return
	}
	response.OK(w, role, "dynamic role updated")
}

func (s *Server) deleteDynamicRole(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	ref, ok := dynamicRoleQuery(w, r)
	if !ok {
		return
	}
	if err := s.api.DeleteDynamicRole(r.Context(), c, ref); err != nil {
		// A 409 here is the store refusing to strand outstanding credentials: the
		// revocation template lives on the config, so deleting it would leave issued
		// accounts unrevokable. The message names the count and says to revoke first.
		response.ServiceError(w, r, "could not delete the dynamic role", err)
		return
	}
	response.NoContent(w)
}

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

// issueCredentialResponse carries the one-time credential disclosure.
type issueCredentialResponse struct {
	Success bool `json:"success"`
	// RoleName is the PostgreSQL role that was created, and Password is its password —
	// shown here and nowhere else, ever.
	RoleName  string `json:"role_name"`
	Password  string `json:"password"`
	ExpiresAt string `json:"expires_at"`
	// LeaseUUID is the handle a revocation takes. It is the durable part of this
	// response: the lease survives, the password does not.
	LeaseUUID string `json:"lease_uuid"`
	Message   string `json:"message"`
}

// issueDynamicCredential mints one short-lived database credential.
//
// A workload reaches this legitimately — it is the feature — so the route is open to
// both classes of caller. What bounds it is the MRN grant (which roles) and the role's
// creation template (what the credential can do), not the caller's class.
func (s *Server) issueDynamicCredential(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	var req api.IssueDynamicCredentialInput
	if !decode(w, r, &req) {
		return
	}
	issued, err := s.api.IssueDynamicCredential(r.Context(), c, req)
	if err != nil {
		// A 503 here means this instance has no provisioner configured, or the target
		// database refused the creation DDL. Neither message quotes the rendered
		// statement, which contains the generated password — the provisioner sanitizes
		// its own errors for exactly that reason.
		response.ServiceError(w, r, "could not issue the credential", err)
		return
	}
	body := issueCredentialResponse{
		Success:   true,
		RoleName:  issued.Credential.RoleName,
		Password:  issued.Credential.Password,
		ExpiresAt: issued.Credential.ExpiresAt.UTC().Format(time.RFC3339),
		LeaseUUID: issued.Lease.UUID.String(),
		Message:   "the password is shown once and cannot be retrieved again; the role is dropped when the lease expires",
	}
	// No-store, for the reason a reveal is: a credential must not land in a shared
	// cache, a disk cache, or a proxy.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(body)
}

// revokeDynamicCredential gives one credential back.
//
// Same grant as issuing, deliberately: a workload returning the credential it asked for
// is the ordinary end of the lifecycle, and requiring the management grant would mean
// credentials get left to expire instead of returned.
func (s *Server) revokeDynamicCredential(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	var req api.RevokeDynamicCredentialInput
	if !decode(w, r, &req) {
		return
	}
	lease, err := s.api.RevokeDynamicCredential(r.Context(), c, req)
	if err != nil {
		response.ServiceError(w, r, "could not revoke the credential", err)
		return
	}
	response.OK(w, lease, "credential revoked and the database role dropped")
}

func (s *Server) listDynamicLeases(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	ref, ok := dynamicRoleQuery(w, r)
	if !ok {
		return
	}
	page, limit := response.PageParams(r)
	leases, total, err := s.api.ListDynamicLeases(r.Context(), c, api.ListDynamicLeasesInput{
		Project:    ref.Project,
		Name:       ref.Name,
		Pagination: api.Pagination{Page: page, Limit: limit},
	})
	if err != nil {
		response.ServiceError(w, r, "could not list dynamic leases", err)
		return
	}
	// leases is []store.DynamicLease — a type with no password field, backed by a table
	// with no password column — so this response cannot carry a credential.
	response.List(w, leases, page, limit, total)
}
