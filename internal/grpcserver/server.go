// Package grpcserver implements maintainerd.secret.v1.SecretService over the
// durable store.
//
// The RPC surface is unchanged from the prototype — Ping, Setup, Put, Get, List,
// Delete over a flat string key — but everything behind it is different: values are
// versioned rows in Postgres under envelope encryption, and the setup lock is a
// database fact rather than a process variable. The flat key is mapped onto the real
// hierarchy by store.FlatRef, so a secret written here is an ordinary secret.
//
// The hierarchical API (projects, environments, folders, versions, rotation),
// authorization middleware and the console are the next wave. This file is
// deliberately a thin adapter and should shrink when they land.
package grpcserver

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	secretv1 "github.com/maintainerd/secret/gen/maintainerd/secret/v1"
	"github.com/maintainerd/secret/internal/platform/apperror"
	"github.com/maintainerd/secret/internal/store"
)

// Service implements secret.v1.SecretService.
type Service struct {
	secretv1.UnimplementedSecretServiceServer
	store *store.Service
	// bootstrapToken gates the one-time Setup RPC. Whether setup has already
	// happened is NOT tracked here — that fact lives in the setup_state table, so it
	// survives a restart.
	bootstrapToken string
	// devMode permits an empty bootstrap token. Outside development, config refuses
	// to boot without one, so this is only ever true in development.
	devMode bool
}

// New builds the service over the durable store.
func New(st *store.Service, bootstrapToken string, devMode bool) *Service {
	return &Service{store: st, bootstrapToken: bootstrapToken, devMode: devMode}
}

// Ping reports liveness and whether setup has been completed.
//
// The setup flag is read from the database on every call rather than cached, because
// it answers "is this instance still bootstrappable" — a stale yes there is a
// security answer, not a performance one.
func (s *Service) Ping(ctx context.Context, _ *secretv1.PingRequest) (*secretv1.PingResponse, error) {
	st, err := s.store.SetupState(ctx)
	if err != nil {
		return nil, toStatus(err, "read setup state")
	}
	return &secretv1.PingResponse{Ok: true, SetupComplete: st.Complete}, nil
}

// Setup registers a controller exactly once.
//
// Two gates, both fail-closed:
//
//  1. The bootstrap token, compared in constant time. An EMPTY configured token is
//     refused outside development — the prototype treated empty as "setup is open",
//     which combined with the in-memory lock meant every restart reopened
//     unauthenticated controller registration.
//  2. The durable lock in setup_state, which the database enforces as single-use.
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

	st, err := s.store.CompleteSetup(ctx, req.GetController(), store.ControllerKindService)
	if err != nil {
		return nil, toStatus(err, "complete setup")
	}
	return &secretv1.SetupResponse{Ok: true, Controller: st.Controller}, nil
}

// Put writes a value, creating the secret on first write and appending an immutable
// version afterwards. A write whose value is unchanged succeeds without creating a
// version.
func (s *Service) Put(ctx context.Context, req *secretv1.PutRequest) (*secretv1.PutResponse, error) {
	ref, err := s.store.FlatRef(ctx, req.GetKey())
	if err != nil {
		return nil, toStatus(err, "resolve key")
	}
	if _, err := s.store.PutSecret(ctx, store.PutSecretInput{
		Ref:   ref,
		Value: req.GetValue(),
		// The flat RPC carries no folder-creation flag, so a deep key implies its
		// folders — matching the prototype, in which any key was immediately
		// writable.
		CreateFolders: true,
	}); err != nil {
		return nil, toStatus(err, "put secret")
	}
	return &secretv1.PutResponse{}, nil
}

// Get decrypts and returns the current version.
//
// The plaintext is copied into the response and the store's buffer is zeroized
// immediately; from there the value's lifetime is the gRPC response's.
func (s *Service) Get(ctx context.Context, req *secretv1.GetRequest) (*secretv1.GetResponse, error) {
	ref, err := s.store.FlatRef(ctx, req.GetKey())
	if err != nil {
		return nil, toStatus(err, "resolve key")
	}
	revealed, err := s.store.GetSecret(ctx, ref)
	if err != nil {
		return nil, toStatus(err, "get secret")
	}
	defer revealed.Zero()

	value := make([]byte, revealed.Value.Len())
	copy(value, revealed.Value.Bytes())
	return &secretv1.GetResponse{Value: value}, nil
}

// List returns matching keys and NO VALUES. It reads the metadata-only listing
// query, so no ciphertext is fetched and nothing is decrypted.
func (s *Service) List(ctx context.Context, req *secretv1.ListRequest) (*secretv1.ListResponse, error) {
	tenantUUID, err := s.store.DefaultTenantUUID(ctx)
	if err != nil {
		return nil, toStatus(err, "resolve default tenant")
	}
	policy := s.store.Policy()
	metas, _, err := s.store.ListSecrets(ctx, store.ListSecretsInput{
		TenantUUID:  tenantUUID,
		Project:     policy.DefaultProject,
		Environment: policy.DefaultEnvironment,
		PathPrefix:  "/",
		Limit:       200,
	})
	if err != nil {
		return nil, toStatus(err, "list secrets")
	}

	// The prototype's prefix was a raw string prefix over flat keys. That semantic
	// is preserved rather than reinterpreted as a folder path, so an existing caller
	// sees the same results it did before.
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
//
// This is a deliberate behaviour change from the prototype's immediate map delete.
// The recovery window is the entire delete model, and an RPC that irreversibly
// destroyed a credential in one call would be the wrong default; destruction is a
// separate, explicitly gated operation past the window.
func (s *Service) Delete(ctx context.Context, req *secretv1.DeleteRequest) (*secretv1.DeleteResponse, error) {
	ref, err := s.store.FlatRef(ctx, req.GetKey())
	if err != nil {
		return nil, toStatus(err, "resolve key")
	}
	if _, err := s.store.DeleteSecret(ctx, ref, nil); err != nil {
		if apperror.IsNotFound(err) {
			// The prototype's Delete was silent on a missing key; keep that.
			return &secretv1.DeleteResponse{}, nil
		}
		return nil, toStatus(err, "delete secret")
	}
	return &secretv1.DeleteResponse{}, nil
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
