package store

import (
	"context"
	"strings"

	"github.com/google/uuid"

	"github.com/maintainerd/secret/internal/storage"
)

// This file defines the MRN VOCABULARY of this service: the resource-path shape of
// every kind of thing a caller can be granted access to, and the resolvers that
// turn a request's addressing arguments into one.
//
// It exists because an authorization check needs a CONCRETE MRN — the pattern side
// of the match is the grant, and matching a pattern against another pattern is
// meaningless. So every operation, not just a secret read, has to be able to name
// its target. Without that, scope operations (create a folder, list an environment,
// read the audit trail) would have to fall back to a route-level check, and a grant
// written for staging would silently cover prod for exactly those operations.
//
// THE PATHS ARE DELIBERATELY DISJOINT BY PREFIX:
//
//	project                                  the project named by the MRN's project segment
//	environment/<env>                        one environment
//	folder/<env>                             an environment's root folder
//	folder/<env>/<path...>                   a folder
//	secret/<env>/<path...>/<key>             a secret (the shape stored on secrets.mrn_resource_path)
//	import/<uuid>                            one scope-import edge
//	webhook/<uuid>                           one webhook endpoint
//	dynamic-role                             a project's dynamic-role COLLECTION
//	dynamic-role/<name>                      one dynamic role config (and its leases)
//	transit                                  a project's transit-key COLLECTION
//	transit/<name>                           one transit key
//	audit                                    the tenant's access trail
//	setup                                    the one-time setup surface
//
// DYNAMIC ROLES AND TRANSIT KEYS ARE NAMED BY NAME, NOT BY UUID, unlike imports and
// webhooks. That is not an inconsistency: a caller ISSUES against a role name and
// ENCRYPTS against a key name — the name is the address it holds — so a grant an
// operator writes has to be expressible over names. `dynamic-role/reporting-*` is a
// policy somebody can write; the same grant over UUIDs is not.
//
// A LEASE HAS NO RESOURCE PATH OF ITS OWN. Issuing a credential and revoking it are
// authorized against the ROLE, and reading a secret's leases is authorized against the
// SECRET, because a lease is an instrument of the thing it was issued against rather
// than a resource somebody is granted access to. Giving leases their own prefix would
// invite a grant that could revoke credentials on a role it holds nothing else over.
//
// FOLDERS ARE NOT UNDER `secret/`, and that is on purpose. A grant that lets a
// principal read secrets in staging must not also let it MOVE staging's folders —
// moving a folder rewrites the MRNs of everything beneath it, which is a way to
// bring secrets into the reach of a grant that never covered them. Different
// privilege, different resource prefix, so no wildcard can bridge the two by
// accident.

// ResourceProject is the resource path of a project. The project itself is named by
// the MRN's project segment, so the path is a bare type name — the same reason an
// AWS ARN for a bucket does not repeat the bucket name in its resource part.
const ResourceProject = "project"

// ResourceAudit is the resource path of a tenant's access trail.
const ResourceAudit = "audit"

// ResourceSetup is the resource path of the one-time setup surface.
const ResourceSetup = "setup"

// ResourceWebhook is the resource path of a project's webhook COLLECTION — the scope a
// create and a listing are authorized against, before any endpoint UUID exists.
// WebhookResourcePath names one endpoint under it.
const ResourceWebhook = "webhook"

// ResourceDynamicRole is the resource path of a project's dynamic-role COLLECTION — the
// scope a create and a listing are authorized against, before any role name exists.
// DynamicRoleResourcePath names one role under it.
const ResourceDynamicRole = "dynamic-role"

// ResourceTransit is the resource path of a project's transit-key COLLECTION.
// TransitResourcePath names one key under it.
const ResourceTransit = "transit"

// EnvironmentResourcePath returns the resource path of one environment.
func EnvironmentResourcePath(environmentSlug string) string {
	return "environment/" + environmentSlug
}

// FolderResourcePath returns the resource path of one folder. folderPath must be
// normalized ("/" for the root).
func FolderResourcePath(environmentSlug, folderPath string) string {
	if folderPath == "/" || folderPath == "" {
		return "folder/" + environmentSlug
	}
	return "folder/" + environmentSlug + folderPath
}

// SecretResourcePath returns the resource path of one secret. It delegates to the
// same helper the write path uses, so an authorization check and a stored
// mrn_resource_path can never disagree about the shape.
func SecretResourcePath(environmentSlug, folderPath, key string) string {
	return mrnResourcePath(environmentSlug, folderPath, key)
}

// ImportResourcePath returns the resource path of one scope-import edge.
func ImportResourcePath(importUUID uuid.UUID) string { return "import/" + importUUID.String() }

// WebhookResourcePath returns the resource path of one webhook endpoint.
func WebhookResourcePath(endpointUUID uuid.UUID) string { return "webhook/" + endpointUUID.String() }

// DynamicRoleResourcePath returns the resource path of one dynamic role config.
//
// The name is validated as a slug before it ever reaches here (see
// dynamic.ValidateConfigName), which is what keeps a '/' out of it — a name carrying a
// separator would forge an extra MRN segment and could make a grant match something its
// author never wrote.
func DynamicRoleResourcePath(name string) string { return ResourceDynamicRole + "/" + name }

// TransitResourcePath returns the resource path of one transit key. The name is
// slug-validated for the same reason a dynamic role's is.
func TransitResourcePath(name string) string { return ResourceTransit + "/" + name }

// MRN renders a full MRN from its parts. Exported so the API layer can name a
// target before the target exists (a create is authorized against the MRN the
// created thing WILL have — otherwise a create could not be authorized at all).
func MRN(tenantName, projectSlug, resourcePath string) string {
	return mrn(tenantName, projectSlug, resourcePath)
}

// ScopeNames is the human-readable naming of a resolved tenant/project/environment:
// the three segments an MRN is built from. Every resolver below returns one so the
// caller never has to hold an internal id to name a resource.
type ScopeNames struct {
	Tenant      string
	Project     string
	Environment string
}

// ResolveScopeNames resolves a tenant UUID plus project/environment slugs into the
// names an MRN is built from, verifying each step exists and belongs to the tenant.
//
// It is a READ, and it deliberately runs BEFORE the authorization check on every
// path that needs it. That ordering is worth stating because it looks backwards:
// resolving the address means confirming the project and environment exist, which
// leaks their existence to a caller that may turn out to be unauthorized. The
// alternative is worse — a check against an unresolved address would have to guess
// the MRN, and a guessed MRN either denies legitimate access (wrong slug casing,
// missing environment) or authorizes against a resource that is not the target. The
// leak is bounded to "this project/environment exists in this tenant", which the
// tenant-scoped queries already refuse to answer across tenants.
func (s *Service) ResolveScopeNames(ctx context.Context, tenantUUID uuid.UUID, project, environment string) (ScopeNames, error) {
	if environment == "" {
		tenant, err := s.repo.GetTenantByUUID(ctx, tenantUUID)
		if err != nil {
			return ScopeNames{}, mapReadError(err, "tenant")
		}
		out := ScopeNames{Tenant: tenant.Name}
		if project == "" {
			return out, nil
		}
		proj, err := s.repo.GetProjectBySlug(ctx, storage.GetProjectBySlugParams{
			TenantID: tenant.TenantID,
			Slug:     project,
		})
		if err != nil {
			return ScopeNames{}, mapReadError(err, "project")
		}
		out.Project = proj.Slug
		return out, nil
	}
	sc, err := s.resolveEnvironment(ctx, s.repo, tenantUUID, project, environment)
	if err != nil {
		return ScopeNames{}, err
	}
	return ScopeNames{Tenant: sc.tenant.Name, Project: sc.project.Slug, Environment: sc.environment.Slug}, nil
}

// SecretMRN resolves a SecretRef all the way to the secret's MRN, WITHOUT reading
// the secret itself. That distinction matters for a create: the target does not
// exist yet, so the check has to be made against the MRN it will have.
func (s *Service) SecretMRN(ctx context.Context, ref SecretRef) (string, error) {
	folderPath, err := NormalizePath(ref.FolderPath)
	if err != nil {
		return "", err
	}
	if err := ValidateKey(ref.Key); err != nil {
		return "", err
	}
	names, err := s.ResolveScopeNames(ctx, ref.TenantUUID, ref.Project, ref.Environment)
	if err != nil {
		return "", err
	}
	return MRN(names.Tenant, names.Project, SecretResourcePath(names.Environment, folderPath, ref.Key)), nil
}

// TenantName resolves a tenant UUID to the slug that appears in an MRN.
func (s *Service) TenantName(ctx context.Context, tenantUUID uuid.UUID) (string, error) {
	tenant, err := s.repo.GetTenantByUUID(ctx, tenantUUID)
	if err != nil {
		return "", mapReadError(err, "tenant")
	}
	return tenant.Name, nil
}

// SplitReferencePath splits the "project/environment/folder/.../KEY" address form
// used inside a reference value and returned by the flat compatibility RPCs.
//
// It is here rather than in the reference resolver because the same shape is a
// public part of the API surface (batch get takes it), and one parser means one
// answer to "what does staging/db/PASSWORD mean".
func SplitReferencePath(raw string) (project, environment, folderPath, key string, ok bool) {
	parts := strings.Split(strings.Trim(strings.TrimSpace(raw), "/"), "/")
	// project + environment + key is the minimum: a reference must name the
	// environment explicitly, because the same key exists once per environment and
	// an implicit "same environment as the referrer" would make a copied reference
	// mean something different in its new home.
	if len(parts) < 3 {
		return "", "", "", "", false
	}
	project, environment = parts[0], parts[1]
	key = parts[len(parts)-1]
	folderPath = "/"
	if middle := parts[2 : len(parts)-1]; len(middle) > 0 {
		folderPath = "/" + strings.Join(middle, "/")
	}
	return project, environment, folderPath, key, true
}
