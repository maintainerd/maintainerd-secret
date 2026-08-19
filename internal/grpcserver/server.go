// Package grpcserver implements secret.v1.SecretService over the encrypted store,
// gated by the kit's one-time setup pattern.
package grpcserver

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/maintainerd/kit/setup"

	secretv1 "github.com/maintainerd/secret/gen/maintainerd/secret/v1"
	"github.com/maintainerd/secret/internal/store"
)

// Service implements secret.v1.SecretService.
type Service struct {
	secretv1.UnimplementedSecretServiceServer
	store *store.Store
	setup *setup.Mode
}

func New(st *store.Store, mode *setup.Mode) *Service {
	return &Service{store: st, setup: mode}
}

func (s *Service) Ping(_ context.Context, _ *secretv1.PingRequest) (*secretv1.PingResponse, error) {
	return &secretv1.PingResponse{Ok: true, SetupComplete: s.setup.IsComplete()}, nil
}

// Setup registers the controller one time; it locks afterward (setup pattern).
func (s *Service) Setup(_ context.Context, req *secretv1.SetupRequest) (*secretv1.SetupResponse, error) {
	if err := s.setup.Authorize(req.GetBootstrapToken()); err != nil {
		if errors.Is(err, setup.ErrSetupComplete) {
			return nil, status.Error(codes.FailedPrecondition, "setup already complete")
		}
		return nil, status.Error(codes.PermissionDenied, "invalid bootstrap token")
	}
	if req.GetController() == "" {
		return nil, status.Error(codes.InvalidArgument, "controller is required")
	}
	if err := s.setup.Complete(req.GetController()); err != nil {
		return nil, status.Error(codes.FailedPrecondition, "setup already complete")
	}
	return &secretv1.SetupResponse{Ok: true, Controller: req.GetController()}, nil
}

func (s *Service) Put(_ context.Context, req *secretv1.PutRequest) (*secretv1.PutResponse, error) {
	if req.GetKey() == "" {
		return nil, status.Error(codes.InvalidArgument, "key is required")
	}
	if err := s.store.Put(req.GetKey(), req.GetValue()); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &secretv1.PutResponse{}, nil
}

func (s *Service) Get(_ context.Context, req *secretv1.GetRequest) (*secretv1.GetResponse, error) {
	v, err := s.store.Get(req.GetKey())
	if errors.Is(err, store.ErrNotFound) {
		return nil, status.Error(codes.NotFound, "secret not found")
	}
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &secretv1.GetResponse{Value: v}, nil
}

func (s *Service) List(_ context.Context, req *secretv1.ListRequest) (*secretv1.ListResponse, error) {
	return &secretv1.ListResponse{Keys: s.store.List(req.GetPrefix())}, nil
}

func (s *Service) Delete(_ context.Context, req *secretv1.DeleteRequest) (*secretv1.DeleteResponse, error) {
	s.store.Delete(req.GetKey())
	return &secretv1.DeleteResponse{}, nil
}
