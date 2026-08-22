package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"

	sdkauthz "github.com/maintainerd/sdk/authz"
	"github.com/maintainerd/secret/internal/platform/permissions"
	"github.com/maintainerd/secret/internal/platform/response"
	"github.com/maintainerd/secret/internal/setup"
	"github.com/maintainerd/secret/internal/store"
)

// The standalone setup wizard.
//
// THIS IS THE ONE SURFACE THE TOKEN GUARD DOES NOT COVER, and it has to be: the setup
// endpoints must work before Auth exists, because provisioning is what makes tokens
// mintable at all. They are therefore self-guarded by SETUP_BOOTSTRAP_TOKEN, compared
// in constant time, and refused entirely when no token is configured outside
// development.
//
// AND THEY CLOSE ONCE AN ORCHESTRATOR OWNS THE INSTANCE. If Core provisioned this
// service through the gRPC SetupService, the REST wizard is the same
// "whoever-gets-here-first" race the setup token exists to close — reachable by
// anything on the network. So it refuses, with a message that says where to go
// instead. See internal/setup for why the condition is "orchestrated" rather than
// merely "complete".

// getSetupStatus reports setup state.
//
// An anonymous caller gets ONE BIT: whether setup is complete. That much is
// unavoidable (a client has to know whether to show a wizard) but everything else —
// the controller identity, the tenant, the auth tenant it maps to, the permission
// list — is reconnaissance about an unprovisioned vault, and it requires the setup
// token or secret:Admin.
func (s *Server) getSetupStatus(w http.ResponseWriter, r *http.Request) {
	status, err := s.setup.Status(r.Context())
	if err != nil {
		response.ServiceError(w, r, "could not read the setup status", err)
		return
	}
	if s.setupCallerIsPrivileged(r) {
		response.OK(w, status, "")
		return
	}
	response.OK(w, setup.AnonymousStatus(status), "")
}

// setupCallerIsPrivileged reports whether this request may see the full status.
//
// Two independent ways in, because the two modes have different credentials at
// different times: the bootstrap token (which exists before Auth does) or a verified
// secret:Admin grant (which exists afterwards). Checking the token does NOT go through
// the guard, so this deliberately calls CheckToken directly.
func (s *Server) setupCallerIsPrivileged(r *http.Request) bool {
	if token := strings.TrimSpace(r.Header.Get(SetupTokenHeader)); token != "" {
		if err := s.setup.CheckToken(token); err == nil {
			return true
		}
	}
	// The guard has already run on this route only in development (where it attaches
	// DevClaims) or when a caller happened to send a bearer token; the setup segment
	// is exempt from enforcement, so claims may legitimately be absent.
	if claims, ok := sdkauthz.FromContext(r.Context()); ok && claims.HasAction(permissions.PermAdmin) {
		return true
	}
	return false
}

type setupRequest struct {
	// Tenant, Project and Environment default to the configured defaults, so the
	// minimal standalone bootstrap is a POST with only a controller name.
	Tenant            string `json:"tenant,omitempty"`
	TenantDisplayName string `json:"tenant_display_name,omitempty"`
	Project           string `json:"project,omitempty"`
	Environment       string `json:"environment,omitempty"`
	// AuthTenantUUID links this mirror to an Auth tenant. Optional in standalone
	// mode, which owns its own tenant names.
	AuthTenantUUID string `json:"auth_tenant_uuid,omitempty"`
	// Controller identifies the operator closing the setup window. Recorded on the
	// durable lock and in the audit trail.
	Controller string `json:"controller"`
}

// postSetup provisions the instance and closes the setup window.
func (s *Server) postSetup(w http.ResponseWriter, r *http.Request) {
	orchestrated, err := s.setup.RefuseWhenOrchestrated(r.Context())
	if err != nil {
		response.ServiceError(w, r, "could not read the setup status", err)
		return
	}
	if orchestrated {
		response.ErrorWithCode(w, http.StatusForbidden, "setup_orchestrated",
			"this instance is provisioned by an orchestrator: bootstrap it through the gRPC SetupService with its setup token, not the REST setup wizard")
		return
	}

	token := strings.TrimSpace(r.Header.Get(SetupTokenHeader))
	if err := s.setup.CheckToken(token); err != nil {
		if errors.Is(err, setup.ErrSetupDisabled) {
			response.ErrorWithCode(w, http.StatusForbidden, "setup_disabled", err.Error())
			return
		}
		response.ServiceError(w, r, "setup refused", err)
		return
	}

	var req setupRequest
	if !decode(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Controller) == "" {
		response.Error(w, http.StatusBadRequest, "controller is required")
		return
	}
	var authTenant *uuid.UUID
	if req.AuthTenantUUID != "" {
		parsed, perr := uuid.Parse(req.AuthTenantUUID)
		if perr != nil {
			response.Error(w, http.StatusBadRequest, "auth_tenant_uuid must be a UUID")
			return
		}
		authTenant = &parsed
	}

	actor := actorFrom(r)
	actor.Subject = req.Controller
	actor.Kind = store.ActorKindSetup

	result, status, err := s.setup.ProvisionAndComplete(r.Context(), setup.ProvisionInput{
		Tenant:            req.Tenant,
		TenantDisplayName: req.TenantDisplayName,
		AuthTenantUUID:    authTenant,
		Project:           req.Project,
		Environment:       req.Environment,
		Controller:        req.Controller,
	}, actor)
	if err != nil {
		response.ServiceError(w, r, "could not complete setup", err)
		return
	}
	response.Created(w, map[string]any{
		"provisioned": result,
		"status":      status,
	}, "setup complete")
}
