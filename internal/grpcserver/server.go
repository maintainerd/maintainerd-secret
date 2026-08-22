// Package grpcserver implements maintainerd.secret.v1.SecretService and
// SetupService over the application service (internal/api).
//
// LIKE THE REST HANDLERS, IT CARRIES NO AUTHORIZATION LOGIC. The interceptor proves
// identity and enforces the surface allowlist; every MRN-level permission check and
// every audit row happens inside the api service. That is what keeps the two
// transports from drifting into enforcing different rules.
//
// THE FIVE LEGACY FLAT-KEY RPCs ARE KEPT AND MAPPED, NOT REIMPLEMENTED. Setup, Put,
// Get, List and Delete are the kit secret-provider client's contract (see
// maintainerd-kit secret/ and maintainerd-sdk secret/client.go); breaking them breaks
// every consumer that selected maintainerd-secret as its provider. They now route
// through the same api methods the hierarchical RPCs use, so a secret written through
// Put is an ordinary secret — permission-checked, versioned, audited, and addressable
// by the hierarchical surface.
package grpcserver

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	secretv1 "github.com/maintainerd/secret/gen/maintainerd/secret/v1"
	"github.com/maintainerd/secret/internal/api"
	"github.com/maintainerd/secret/internal/audit"
	"github.com/maintainerd/secret/internal/platform/apperror"
	"github.com/maintainerd/secret/internal/platform/authz"
	"github.com/maintainerd/secret/internal/setup"
	"github.com/maintainerd/secret/internal/store"
)

// TenantMetadataKey selects the tenant a request addresses. Like the REST header, it
// is a SELECTOR and never an authorization.
const TenantMetadataKey = "x-maintainerd-tenant"

// SetupTokenMetadataKey carries the bootstrap token on the setup surfaces.
const SetupTokenMetadataKey = "x-setup-token"

// Service implements secret.v1.SecretService.
type Service struct {
	secretv1.UnimplementedSecretServiceServer
	api   *api.Service
	setup *setup.Service
	// bootstrapToken gates the legacy Setup RPC. Whether setup has already happened
	// is NOT tracked here — that fact lives in the setup_state table, so it survives
	// a restart.
	bootstrapToken string
	devMode        bool
	// defaultTenant is the scope the legacy flat-key RPCs address, matching the
	// prototype's single-namespace behaviour.
	defaultTenant string
}

// New builds the gRPC service.
func New(svc *api.Service, setupSvc *setup.Service, bootstrapToken string, devMode bool, defaultTenant string) *Service {
	return &Service{
		api:            svc,
		setup:          setupSvc,
		bootstrapToken: bootstrapToken,
		devMode:        devMode,
		defaultTenant:  defaultTenant,
	}
}

// caller resolves the RPC's authenticated principal into an api.Caller.
func (s *Service) caller(ctx context.Context) (api.Caller, error) {
	claims, ok := authz.FromContext(ctx)
	if !ok || claims == nil {
		return api.Caller{}, status.Error(codes.Unauthenticated, "unauthenticated")
	}
	actor := audit.Actor{
		IP:        peerIP(ctx),
		UserAgent: metadataValue(ctx, "user-agent"),
		RequestID: metadataValue(ctx, "x-request-id"),
	}
	c, err := s.api.ResolveCaller(ctx, claims, actor, metadataValue(ctx, TenantMetadataKey))
	if err != nil {
		return api.Caller{}, toStatus(err, "resolve tenant")
	}
	return c, nil
}

// legacyCaller resolves the principal for a flat-key RPC, pinned to the DEFAULT
// tenant. The flat namespace has always meant one scope; letting a token's tenant
// claim redirect it would silently change which secrets an existing consumer reads.
func (s *Service) legacyCaller(ctx context.Context) (api.Caller, error) {
	claims, ok := authz.FromContext(ctx)
	if !ok || claims == nil {
		return api.Caller{}, status.Error(codes.Unauthenticated, "unauthenticated")
	}
	actor := audit.Actor{
		IP:        peerIP(ctx),
		UserAgent: metadataValue(ctx, "user-agent"),
		RequestID: metadataValue(ctx, "x-request-id"),
	}
	c, err := s.api.ResolveCaller(ctx, claims, actor, s.defaultTenant)
	if err != nil {
		return api.Caller{}, toStatus(err, "resolve default tenant")
	}
	return c, nil
}

// Ping reports liveness and whether setup has been completed.
//
// The setup flag is read from the database on every call rather than cached, because
// it answers "is this instance still bootstrappable" — a stale yes there is a
// security answer, not a performance one.
func (s *Service) Ping(ctx context.Context, _ *secretv1.PingRequest) (*secretv1.PingResponse, error) {
	st, err := s.setup.Status(ctx)
	if err != nil {
		return nil, toStatus(err, "read setup state")
	}
	return &secretv1.PingResponse{Ok: true, SetupComplete: st.Completed}, nil
}

// ---------------------------------------------------------------------------
// Legacy flat-key surface
// ---------------------------------------------------------------------------

// flatAddress maps a flat key onto the default scope's hierarchy:
// "db/primary/password" becomes folder /db/primary, key "password".
func (s *Service) flatAddress(ctx context.Context, flat string) (api.SecretAddress, error) {
	ref, err := s.api.Store().FlatRef(ctx, flat)
	if err != nil {
		return api.SecretAddress{}, toStatus(err, "resolve key")
	}
	return api.SecretAddress{
		Project:     ref.Project,
		Environment: ref.Environment,
		FolderPath:  ref.FolderPath,
		Key:         ref.Key,
	}, nil
}

// Setup registers a controller exactly once (the legacy RPC).
//
// It is an alias for SetupService.Setup + CompleteSetup in controlled mode, kept
// because the prototype's clients call it. Two gates, both fail-closed: the bootstrap
// token compared in constant time, and the durable one-shot lock in setup_state.
func (s *Service) Setup(ctx context.Context, req *secretv1.SetupRequest) (*secretv1.SetupResponse, error) {
	if s.bootstrapToken == "" {
		if !s.devMode {
			slog.Error("refusing setup: SETUP_BOOTSTRAP_TOKEN is not configured")
			return nil, status.Error(codes.PermissionDenied, "setup is not available: no bootstrap token is configured")
		}
	} else if subtle.ConstantTimeCompare([]byte(req.GetBootstrapToken()), []byte(s.bootstrapToken)) != 1 {
		return nil, status.Error(codes.PermissionDenied, "invalid bootstrap token")
	}
	if req.GetController() == "" {
		return nil, status.Error(codes.InvalidArgument, "controller is required")
	}

	actor := audit.Actor{
		Subject:   req.GetController(),
		Kind:      store.ActorKindSetup,
		IP:        peerIP(ctx),
		UserAgent: metadataValue(ctx, "user-agent"),
	}
	if _, err := s.setup.Provision(ctx, setup.ProvisionInput{
		Controller: req.GetController(),
		Mode:       setup.ModeControlled,
	}, actor); err != nil {
		return nil, toStatus(err, "provision")
	}
	st, err := s.setup.Complete(ctx, req.GetController(), setup.ModeControlled, actor)
	if err != nil {
		return nil, toStatus(err, "complete setup")
	}
	return &secretv1.SetupResponse{Ok: true, Controller: st.Controller}, nil
}

// Put writes a value into the default scope.
func (s *Service) Put(ctx context.Context, req *secretv1.PutRequest) (*secretv1.PutResponse, error) {
	c, err := s.legacyCaller(ctx)
	if err != nil {
		return nil, err
	}
	addr, err := s.flatAddress(ctx, req.GetKey())
	if err != nil {
		return nil, err
	}
	if _, err := s.api.PutSecret(ctx, c, api.PutSecretInput{
		Address: addr,
		Value:   req.GetValue(),
		// The flat RPC carries no folder-creation flag, so a deep key implies its
		// folders — matching the prototype, in which any key was immediately writable.
		CreateFolders: true,
	}); err != nil {
		return nil, toStatus(err, "put secret")
	}
	return &secretv1.PutResponse{}, nil
}

// Get decrypts and returns the current version from the default scope.
func (s *Service) Get(ctx context.Context, req *secretv1.GetRequest) (*secretv1.GetResponse, error) {
	c, err := s.legacyCaller(ctx)
	if err != nil {
		return nil, err
	}
	addr, err := s.flatAddress(ctx, req.GetKey())
	if err != nil {
		return nil, err
	}
	revealed, err := s.api.Reveal(ctx, c, addr, 0)
	if err != nil {
		return nil, toStatus(err, "get secret")
	}
	defer revealed.Secret.Zero()
	return &secretv1.GetResponse{Value: copyBytes(revealed.Secret.Value.Bytes())}, nil
}

// List returns matching keys and NO VALUES.
func (s *Service) List(ctx context.Context, req *secretv1.ListRequest) (*secretv1.ListResponse, error) {
	c, err := s.legacyCaller(ctx)
	if err != nil {
		return nil, err
	}
	policy := s.api.Store().Policy()
	metas, _, err := s.api.ListSecrets(ctx, c, api.ListSecretsInput{
		Project:     policy.DefaultProject,
		Environment: policy.DefaultEnvironment,
		PathPrefix:  "/",
		Limit:       200,
	})
	if err != nil {
		return nil, toStatus(err, "list secrets")
	}
	// The prototype's prefix was a raw string prefix over flat keys. That semantic is
	// preserved rather than reinterpreted as a folder path, so an existing caller sees
	// the same results it did before.
	prefix := req.GetPrefix()
	keys := make([]string, 0, len(metas))
	for _, m := range metas {
		flat := store.FlatKey(m)
		if prefix == "" || strings.HasPrefix(flat, prefix) {
			keys = append(keys, flat)
		}
	}
	return &secretv1.ListResponse{Keys: keys}, nil
}

// Delete soft-deletes a secret, opening its recovery window.
func (s *Service) Delete(ctx context.Context, req *secretv1.DeleteRequest) (*secretv1.DeleteResponse, error) {
	c, err := s.legacyCaller(ctx)
	if err != nil {
		return nil, err
	}
	addr, err := s.flatAddress(ctx, req.GetKey())
	if err != nil {
		return nil, err
	}
	if _, err := s.api.DeleteSecret(ctx, c, addr, nil); err != nil {
		if apperror.IsNotFound(err) {
			// The prototype's Delete was silent on a missing key; keep that.
			return &secretv1.DeleteResponse{}, nil
		}
		return nil, toStatus(err, "delete secret")
	}
	return &secretv1.DeleteResponse{}, nil
}

// copyBytes copies a plaintext out of the store's buffer so zeroizing the buffer
// cannot blank a value already handed to the response.
func copyBytes(src []byte) []byte {
	out := make([]byte, len(src))
	copy(out, src)
	return out
}

// toStatus maps a service error onto a gRPC status.
//
// Internal errors are logged server-side and reported to the client as a generic
// message. That split matters more here than usual: the detail in an internal error
// describes the store's structure, and a client that cannot read a secret should not
// learn the shape of the thing protecting it.
func toStatus(err error, op string) error {
	switch {
	case apperror.IsNotFound(err):
		return status.Error(codes.NotFound, err.Error())
	case apperror.IsValidation(err):
		return status.Error(codes.InvalidArgument, err.Error())
	case apperror.IsConflict(err):
		return status.Error(codes.FailedPrecondition, err.Error())
	case apperror.IsForbidden(err):
		return status.Error(codes.PermissionDenied, err.Error())
	case apperror.IsUnavailable(err):
		return status.Error(codes.Unavailable, err.Error())
	default:
		slog.Error("secret service error", "op", op, "error", err)
		return status.Error(codes.Internal, "internal error")
	}
}
