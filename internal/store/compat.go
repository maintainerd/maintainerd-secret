package store

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/maintainerd/secret/internal/platform/apperror"
	"github.com/maintainerd/secret/internal/storage"
)

// This file is the bridge between the prototype's flat key/value RPC surface and the
// hierarchy the store actually has. It exists so the existing
// maintainerd.secret.v1.SecretService — Put, Get, List, Delete over a single string
// key — keeps working against durable storage while the hierarchical API is built in
// the next wave. It should shrink to nothing when that lands.

// EnsureDefaultScope creates the configured default tenant, project, environment and
// root folder if they are absent, and returns the tenant.
//
// A standalone install needs somewhere to put a secret before anyone has provisioned
// a hierarchy — that is what "adoptable alone" means in practice — and the flat-key
// RPCs address exactly that scope. Idempotent, so it is safe on every boot.
func (s *Service) EnsureDefaultScope(ctx context.Context) (*Tenant, error) {
	name := s.policy.DefaultTenant
	project := s.policy.DefaultProject
	environment := s.policy.DefaultEnvironment
	if name == "" || project == "" || environment == "" {
		return nil, apperror.NewValidation("default tenant, project and environment names are all required")
	}

	tenant, err := s.repo.GetTenantByName(ctx, name)
	if errors.Is(err, pgx.ErrNoRows) {
		// A conflict means another replica won the race to create it, which is a
		// success for our purposes — so the row is re-read either way rather than
		// trusting the create's return value.
		if _, cerr := s.CreateTenant(ctx, CreateTenantInput{Name: name, DisplayName: name}); cerr != nil && !apperror.IsConflict(cerr) {
			return nil, cerr
		}
		tenant, err = s.repo.GetTenantByName(ctx, name)
		if err != nil {
			return nil, mapReadError(err, "tenant")
		}
	} else if err != nil {
		return nil, mapReadError(err, "tenant")
	}

	if _, err := s.repo.GetProjectBySlug(ctx, storage.GetProjectBySlugParams{
		TenantID: tenant.TenantID,
		Slug:     project,
	}); errors.Is(err, pgx.ErrNoRows) {
		if _, cerr := s.CreateProject(ctx, CreateProjectInput{
			TenantUUID: tenant.TenantUuid,
			Slug:       project,
			Name:       project,
		}); cerr != nil && !apperror.IsConflict(cerr) {
			return nil, cerr
		}
	} else if err != nil {
		return nil, mapReadError(err, "project")
	}

	if _, err := s.GetEnvironment(ctx, tenant.TenantUuid, project, environment); err != nil {
		if !apperror.IsNotFound(err) {
			return nil, err
		}
		if _, cerr := s.CreateEnvironment(ctx, CreateEnvironmentInput{
			TenantUUID: tenant.TenantUuid,
			Project:    project,
			Slug:       environment,
			Name:       environment,
		}); cerr != nil && !apperror.IsConflict(cerr) {
			return nil, cerr
		}
	}

	t := toTenant(tenant)
	return &t, nil
}

// FlatRef maps a flat key onto a SecretRef inside the default scope.
//
// The mapping is the obvious one: everything before the last '/' is a folder path,
// the remainder is the key. "db/primary/password" becomes folder /db/primary, key
// "password"; "TOKEN" becomes folder /, key "TOKEN". This makes the prototype's flat
// namespace a projection of the real hierarchy rather than a parallel one, so a
// secret written through the old RPC is a normal secret — visible in the hierarchy,
// versioned, audited, and addressable by the new API when it arrives.
func (s *Service) FlatRef(ctx context.Context, flat string) (SecretRef, error) {
	key := strings.TrimSpace(flat)
	if key == "" {
		return SecretRef{}, apperror.NewValidation("key is required")
	}
	folderPath := "/"
	if i := strings.LastIndexByte(key, '/'); i >= 0 {
		folderPath = key[:i]
		key = key[i+1:]
		if folderPath == "" {
			folderPath = "/"
		}
	}
	normalized, err := NormalizePath(folderPath)
	if err != nil {
		return SecretRef{}, apperror.NewValidation(err.Error())
	}
	if err := ValidateKey(key); err != nil {
		return SecretRef{}, apperror.NewValidation(err.Error())
	}

	tenant, err := s.repo.GetTenantByName(ctx, s.policy.DefaultTenant)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return SecretRef{}, apperror.NewNotFound(fmt.Sprintf("default tenant %q", s.policy.DefaultTenant))
		}
		return SecretRef{}, apperror.NewInternal("read default tenant", err)
	}

	return SecretRef{
		TenantUUID:  tenant.TenantUuid,
		Project:     s.policy.DefaultProject,
		Environment: s.policy.DefaultEnvironment,
		FolderPath:  normalized,
		Key:         key,
	}, nil
}

// FlatKey renders a SecretMeta back into the flat form the legacy List RPC returns.
func FlatKey(m SecretMeta) string {
	if m.FolderPath == "/" {
		return m.Key
	}
	return strings.TrimPrefix(m.FolderPath, "/") + "/" + m.Key
}

// DefaultTenantUUID resolves the default scope's tenant UUID.
func (s *Service) DefaultTenantUUID(ctx context.Context) (uuid.UUID, error) {
	tenant, err := s.repo.GetTenantByName(ctx, s.policy.DefaultTenant)
	if err != nil {
		return uuid.Nil, mapReadError(err, "tenant")
	}
	return tenant.TenantUuid, nil
}
