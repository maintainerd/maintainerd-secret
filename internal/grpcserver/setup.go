package grpcserver

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	secretv1 "github.com/maintainerd/secret/gen/maintainerd/secret/v1"
	"github.com/maintainerd/secret/internal/audit"
	"github.com/maintainerd/secret/internal/platform/authz"
	"github.com/maintainerd/secret/internal/setup"
	"github.com/maintainerd/secret/internal/store"
)

// SetupServer implements maintainerd.secret.v1.SetupService — the CONTROLLED setup
// path a controller (Core) drives.
//
// IT IS SELF-GUARDED, not token-guarded, and it has to be: this surface is what
// provisions the instance, so requiring an Auth-minted token would mean requiring the
// thing that does not exist yet. The gate is the bootstrap token in the x-setup-token
// metadata header, compared in constant time, and refused entirely when no token is
// configured outside development.
//
// ONCE IT COMPLETES SETUP, THE REST WIZARD REFUSES. See internal/setup for the
// reasoning; the short version is that two open first-run paths is a race whose
// winner owns the vault.
type SetupServer struct {
	secretv1.UnimplementedSetupServiceServer
	setup *setup.Service
}

// NewSetupServer builds the controlled setup surface.
func NewSetupServer(setupSvc *setup.Service) *SetupServer {
	return &SetupServer{setup: setupSvc}
}

// GetSetupStatus reports the instance's setup state.
//
// An unauthenticated caller receives ONE BIT — whether setup is complete. The full
// payload (controller, tenant, the auth tenant it maps to, the permission list)
// requires the setup token or a verified secret:Admin grant, because it is
// reconnaissance about an unprovisioned vault.
func (s *SetupServer) GetSetupStatus(ctx context.Context, _ *secretv1.GetSetupStatusRequest) (*secretv1.GetSetupStatusResponse, error) {
	full, err := s.setup.Status(ctx)
	if err != nil {
		return nil, toStatus(err, "read setup status")
	}
	if !s.privileged(ctx) {
		return &secretv1.GetSetupStatusResponse{Completed: full.Completed}, nil
	}
	return &secretv1.GetSetupStatusResponse{
		Completed:      full.Completed,
		Controller:     full.Controller,
		ControllerKind: full.ControllerKind,
		Mode:           full.Mode,
		CompletedAt:    full.CompletedAt,
		Tenant:         full.Tenant,
		AuthTenantUuid: full.AuthTenantUUID,
		Project:        full.Project,
		Environment:    full.Environment,
		Permissions:    full.Permissions,
		RestWizardOpen: full.RESTWizardOpen,
	}, nil
}

// privileged reports whether this caller may see the full status: the setup token, or
// a secret:Admin grant on an already-provisioned instance.
func (s *SetupServer) privileged(ctx context.Context) bool {
	if token := metadataValue(ctx, SetupTokenMetadataKey); token != "" {
		if err := s.setup.CheckToken(token); err == nil {
			return true
		}
	}
	// The setup surface is exempt from the interceptor's bearer requirement, so
	// claims are usually absent here; they are present in development (DevClaims) or
	// when a caller happened to send a token that another path verified.
	if claims, ok := authz.FromContext(ctx); ok && claims.HasAction(authz.PermAdmin) {
		return true
	}
	return false
}

// Setup creates the tenant mirror plus the default project and environment.
//
// It does NOT close the window — CompleteSetup does — because a controller provisions
// several things across several RPCs and must be able to finish before the door
// shuts. It is idempotent: a retry after a lost response converges rather than
// reporting a conflict that reads to Core as "somebody else claimed this instance".
func (s *SetupServer) Setup(ctx context.Context, req *secretv1.SetupServiceSetupRequest) (*secretv1.SetupServiceSetupResponse, error) {
	if err := s.gate(ctx); err != nil {
		return nil, err
	}
	if req.GetController() == "" {
		return nil, status.Error(codes.InvalidArgument, "controller is required")
	}
	var authTenant *uuid.UUID
	if raw := req.GetAuthTenantUuid(); raw != "" {
		parsed, err := uuid.Parse(raw)
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, "auth_tenant_uuid must be a UUID")
		}
		authTenant = &parsed
	}

	result, err := s.setup.Provision(ctx, setup.ProvisionInput{
		Tenant:            req.GetTenant(),
		TenantDisplayName: req.GetTenantDisplayName(),
		AuthTenantUUID:    authTenant,
		Project:           req.GetProject(),
		Environment:       req.GetEnvironment(),
		Controller:        req.GetController(),
		Mode:              setup.ModeControlled,
	}, s.actor(ctx, req.GetController()))
	if err != nil {
		return nil, toStatus(err, "provision")
	}
	return &secretv1.SetupServiceSetupResponse{
		TenantUuid:     result.TenantUUID.String(),
		Tenant:         result.Tenant,
		Project:        result.Project,
		Environment:    result.Environment,
		AlreadyExisted: result.AlreadyExisted,
		Permissions:    result.Permissions,
	}, nil
}

// CompleteSetup closes the one-time window permanently.
func (s *SetupServer) CompleteSetup(ctx context.Context, req *secretv1.CompleteSetupRequest) (*secretv1.CompleteSetupResponse, error) {
	if err := s.gate(ctx); err != nil {
		return nil, err
	}
	if req.GetController() == "" {
		return nil, status.Error(codes.InvalidArgument, "controller is required")
	}
	out, err := s.setup.Complete(ctx, req.GetController(), setup.ModeControlled, s.actor(ctx, req.GetController()))
	if err != nil {
		return nil, toStatus(err, "complete setup")
	}
	return &secretv1.CompleteSetupResponse{
		Completed:      out.Completed,
		Controller:     out.Controller,
		ControllerKind: out.ControllerKind,
	}, nil
}

// gate enforces the bootstrap token on the mutating setup RPCs.
func (s *SetupServer) gate(ctx context.Context) error {
	if err := s.setup.CheckToken(metadataValue(ctx, SetupTokenMetadataKey)); err != nil {
		if errors.Is(err, setup.ErrSetupDisabled) {
			return status.Error(codes.PermissionDenied, err.Error())
		}
		return toStatus(err, "check setup token")
	}
	return nil
}

// actor builds the audit actor for a setup call. The kind is `setup` rather than
// `service`, because the trail must distinguish "the controller provisioned this
// vault" from "a service read a secret".
func (s *SetupServer) actor(ctx context.Context, controller string) audit.Actor {
	return audit.Actor{
		Subject:   controller,
		Kind:      store.ActorKindSetup,
		IP:        peerIP(ctx),
		UserAgent: metadataValue(ctx, "user-agent"),
		RequestID: metadataValue(ctx, "x-request-id"),
	}
}
