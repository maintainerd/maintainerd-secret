package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/maintainerd/secret/internal/platform/apperror"
	"github.com/maintainerd/secret/internal/storage"
)

// This file holds the store operations the API surfaces need and the storage-engine
// wave did not: metadata-only describe, rollback, hierarchy updates, and the audit
// read. They live apart from secrets.go / service.go so the boundary between "the
// engine" and "what the API asks of it" stays visible.

// ---------------------------------------------------------------------------
// Describe
// ---------------------------------------------------------------------------

// DescribeSecret returns one secret's METADATA and nothing else.
//
// It exists as a separate method rather than as GetSecret-minus-the-value because
// the two are different privileges (secret:ReadMetadata vs secret:GetSecret), and a
// describe implemented by decrypting and discarding would mean every metadata read
// touched the root key and produced a decryption the audit trail would have to
// explain. This path never reaches secret_versions at all.
func (s *Service) DescribeSecret(ctx context.Context, ref SecretRef) (*SecretMeta, error) {
	addr, err := s.resolveAddress(ctx, s.repo, ref)
	if err != nil {
		return nil, err
	}
	row, err := s.repo.GetSecretByAddress(ctx, storage.GetSecretByAddressParams{
		TenantID:      addr.tenant.TenantID,
		EnvironmentID: addr.environment.EnvironmentID,
		FolderID:      addr.folder.FolderID,
		Key:           addr.key,
	})
	if err != nil {
		return nil, mapReadError(err, "secret")
	}
	out := secretRowToMeta(row, addr.folder.Path, s.policy.KeepVersions)
	return &out, nil
}

// ---------------------------------------------------------------------------
// Rollback
// ---------------------------------------------------------------------------

// RollbackSecret makes an older version current again by writing a NEW version that
// carries the old plaintext.
//
// HISTORY IS NEVER MUTATED. The obvious implementation — point current_version back
// at version 3 — is wrong twice over: secret_versions is append-only (the trigger
// would refuse any edit), and a current_version that moves backwards makes version
// numbers non-monotonic, so a consumer pinned to version 5 would find that "5" now
// means something that came after "6". Instead a rollback is an ordinary write of a
// known-good value, and the trail reads exactly as it should: "at 14:02 the value
// was set back to what version 3 held".
//
// The plaintext is decrypted and re-sealed INSIDE this method and zeroized on every
// exit path, so it never crosses the store's boundary. A rollback implemented in the
// API layer (reveal, then put) would put a decrypted credential in a handler's
// locals for no reason, and would need the reveal permission to perform a write.
func (s *Service) RollbackSecret(ctx context.Context, ref SecretRef, version int32) (*PutResult, error) {
	if version < 1 {
		return nil, apperror.NewValidation("version must be at least 1")
	}
	revealed, err := s.getVersion(ctx, ref, version)
	if err != nil {
		return nil, err
	}
	defer revealed.Zero()

	if revealed.Meta.CurrentVersion == version {
		// Not an error: rolling back to the live version is a no-op, and PutSecret's
		// checksum comparison would report Unchanged anyway. Answering directly
		// avoids a pointless decrypt-reseal cycle.
		return &PutResult{
			SecretUUID: revealed.Meta.UUID,
			Version:    version,
			Unchanged:  true,
		}, nil
	}

	return s.PutSecret(ctx, PutSecretInput{
		Ref:       ref,
		Value:     revealed.Value.Bytes(),
		ValueType: revealed.ValueType,
	})
}

// ---------------------------------------------------------------------------
// Hierarchy updates
// ---------------------------------------------------------------------------

// UpdateProjectInput changes a project's descriptive fields. The slug is absent on
// purpose: it is an MRN segment, and renaming it would silently repoint every grant
// written against the old name.
type UpdateProjectInput struct {
	TenantUUID  uuid.UUID
	Slug        string
	Name        string
	Description string
	Status      string
}

// UpdateProject rewrites a project's descriptive fields.
func (s *Service) UpdateProject(ctx context.Context, in UpdateProjectInput) (*Project, error) {
	if err := validateStatus(in.Status); err != nil {
		return nil, err
	}
	tenant, err := s.repo.GetTenantByUUID(ctx, in.TenantUUID)
	if err != nil {
		return nil, mapReadError(err, "tenant")
	}
	existing, err := s.repo.GetProjectBySlug(ctx, storage.GetProjectBySlugParams{
		TenantID: tenant.TenantID,
		Slug:     in.Slug,
	})
	if err != nil {
		return nil, mapReadError(err, "project")
	}
	meta, err := encodeObject(nil)
	if err != nil {
		return nil, apperror.NewInternal("encode project metadata", err)
	}
	name := in.Name
	if name == "" {
		name = existing.Name
	}
	status := in.Status
	if status == "" {
		status = existing.Status
	}
	row, err := s.repo.UpdateProject(ctx, storage.UpdateProjectParams{
		Name:        name,
		Description: in.Description,
		Status:      status,
		Metadata:    meta,
		TenantID:    tenant.TenantID,
		ProjectUuid: existing.ProjectUuid,
	})
	if err != nil {
		return nil, mapWriteError(err, "project", "project could not be updated")
	}
	p := toProject(row)
	return &p, nil
}

// UpdateEnvironmentInput changes an environment's descriptive fields. As with a
// project, the slug is not changeable — environments.slug is reserved forever by
// the schema precisely because it is quoted in MRNs, grants and every consumer's
// configuration.
type UpdateEnvironmentInput struct {
	TenantUUID  uuid.UUID
	Project     string
	Slug        string
	Name        string
	Description string
	Position    int32
	Status      string
}

// UpdateEnvironment rewrites an environment's descriptive fields.
func (s *Service) UpdateEnvironment(ctx context.Context, in UpdateEnvironmentInput) (*Environment, error) {
	if err := validateStatus(in.Status); err != nil {
		return nil, err
	}
	sc, err := s.resolveEnvironment(ctx, s.repo, in.TenantUUID, in.Project, in.Slug)
	if err != nil {
		return nil, err
	}
	meta, err := encodeObject(nil)
	if err != nil {
		return nil, apperror.NewInternal("encode environment metadata", err)
	}
	name := in.Name
	if name == "" {
		name = sc.environment.Name
	}
	status := in.Status
	if status == "" {
		status = sc.environment.Status
	}
	row, err := s.repo.UpdateEnvironment(ctx, storage.UpdateEnvironmentParams{
		Name:            name,
		Description:     in.Description,
		Position:        in.Position,
		Status:          status,
		Metadata:        meta,
		EnvironmentUuid: sc.environment.EnvironmentUuid,
		TenantID:        sc.tenant.TenantID,
	})
	if err != nil {
		return nil, mapWriteError(err, "environment", "environment could not be updated")
	}
	e := toEnvironment(row)
	return &e, nil
}

// validateStatus rejects a status the CHECK constraint would refuse anyway,
// converting a constraint violation into a useful message.
// Resource statuses a project or environment may hold. They are exported so the API
// layer's validation and this check cannot drift: a status the API accepts and the
// store rejects is a 500 where a 400 belongs, and the reverse is a value that reaches
// a column nothing else understands.
const (
	StatusActive    = "active"
	StatusSuspended = "suspended"
	StatusArchived  = "archived"
)

// ResourceStatuses is the closed set, in the order an error message should list it.
var ResourceStatuses = []string{StatusActive, StatusSuspended, StatusArchived}

func validateStatus(status string) error {
	if status == "" {
		return nil
	}
	for _, s := range ResourceStatuses {
		if status == s {
			return nil
		}
	}
	return apperror.NewValidation(fmt.Sprintf("status %q must be one of %s, %s, %s",
		status, StatusActive, StatusSuspended, StatusArchived))
}

// ---------------------------------------------------------------------------
// Audit read
// ---------------------------------------------------------------------------

// AuditEntry is one row of the trail as it leaves this package. It carries no
// value, and there is no field on it that could.
type AuditEntry struct {
	UUID         uuid.UUID      `json:"event_uuid"`
	ActorSubject string         `json:"actor_subject"`
	ActorKind    string         `json:"actor_kind"`
	Action       string         `json:"action"`
	ResourceMRN  string         `json:"resource_mrn"`
	Version      *int32         `json:"version,omitempty"`
	Outcome      string         `json:"outcome"`
	Reason       string         `json:"reason,omitempty"`
	IPAddress    string         `json:"ip_address,omitempty"`
	UserAgent    string         `json:"user_agent,omitempty"`
	RequestID    string         `json:"request_id,omitempty"`
	Metadata     map[string]any `json:"metadata,omitempty"`
	CreatedAt    time.Time      `json:"created_at"`
}

// ListAuditEvents pages a tenant's trail, newest first.
func (s *Service) ListAuditEvents(ctx context.Context, tenantUUID uuid.UUID, page, limit int) ([]AuditEntry, int64, error) {
	tenant, err := s.repo.GetTenantByUUID(ctx, tenantUUID)
	if err != nil {
		return nil, 0, mapReadError(err, "tenant")
	}
	page, limit = normalizePage(page, limit)
	tenantID := pgInt8(tenant.TenantID)
	rows, err := s.repo.ListAuditEventsByTenant(ctx, storage.ListAuditEventsByTenantParams{
		TenantID: tenantID,
		Limit:    int32(limit),
		Offset:   int32((page - 1) * limit),
	})
	if err != nil {
		return nil, 0, apperror.NewInternal("list audit events", err)
	}
	total, err := s.repo.CountAuditEventsByTenant(ctx, tenantID)
	if err != nil {
		return nil, 0, apperror.NewInternal("count audit events", err)
	}
	out := make([]AuditEntry, 0, len(rows))
	for _, r := range rows {
		out = append(out, toAuditEntry(r))
	}
	return out, total, nil
}
