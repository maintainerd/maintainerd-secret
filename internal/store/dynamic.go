package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/maintainerd/secret/internal/crypto"
	"github.com/maintainerd/secret/internal/dynamic"
	"github.com/maintainerd/secret/internal/platform/apperror"
	"github.com/maintainerd/secret/internal/storage"
)

// Dynamic secrets: the durable half. Role CONFIGURATION, issued LEASES, and the
// transaction that ties a lease row to a role created in a target PostgreSQL database.
//
// WHAT LIVES HERE AND WHAT DOES NOT. internal/dynamic owns the naming, the credential
// generation, the template rendering and the outbound connection; internal/api owns
// authorization and the audit trail. This file owns the rows and the ORDERING, which is
// the part that is only correct if it is written once and in one place.
//
// THE DSN IS RESOLVED, NEVER STORED. A role config holds a secret REFERENCE
// ('project/environment[/folder...]/KEY'), and the DSN behind it is read through the
// ordinary reveal path — envelope-decrypted, one call, zeroized by the caller. That is
// what keeps the most privileged credential in the system inside encrypted custody
// instead of in a plaintext configuration column.

// DynamicRoleStatuses is the closed set. Exported for the same reason
// WebhookStatuses is: the API layer's validation lists exactly what this package
// accepts rather than a second copy that can drift.
const (
	DynamicRoleStatusActive   = "active"
	DynamicRoleStatusDisabled = "disabled"
)

// DynamicRoleStatuses is the closed status set.
var DynamicRoleStatuses = []string{DynamicRoleStatusActive, DynamicRoleStatusDisabled}

// Revoke reasons recorded on a dynamic lease.
const (
	// DynamicRevokeExplicit is a caller or operator giving the credential up.
	DynamicRevokeExplicit = "explicit"
	// DynamicRevokeExpired is the reaper acting on the lease's TTL.
	DynamicRevokeExpired = "expired"
)

// DynamicRole is a role configuration as it leaves this package.
//
// NOTE THE ABSENCE of any DSN field: DSNSecretRef is an ADDRESS, and there is no field
// on this type that could hold the connection string itself.
type DynamicRole struct {
	UUID        uuid.UUID `json:"role_uuid"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	// DSNSecretRef is the address of the secret holding the target DSN, in the same
	// 'project/environment[/folder...]/KEY' form a reference value uses.
	DSNSecretRef      string    `json:"dsn_secret_ref"`
	DefaultTTLSeconds int32     `json:"default_ttl_seconds"`
	MaxTTLSeconds     int32     `json:"max_ttl_seconds"`
	RoleNamePrefix    string    `json:"role_name_prefix"`
	Status            string    `json:"status"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// DynamicRoleDetail adds the SQL templates, for the single-role read.
//
// The templates are operator-authored SQL rather than credentials, so returning them is
// safe — and necessary, because an operator editing a role has to see what it currently
// runs. They are omitted from the LISTING only because they are long, not because they
// are sensitive.
type DynamicRoleDetail struct {
	DynamicRole
	CreationSQL   string `json:"creation_sql"`
	RevocationSQL string `json:"revocation_sql"`
}

// DynamicLease is an issued credential's record. THERE IS NO PASSWORD FIELD, and there
// is no column behind one either — see migrations/00012.
type DynamicLease struct {
	UUID           uuid.UUID  `json:"lease_uuid"`
	RoleName       string     `json:"role_name"`
	ResourceMRN    string     `json:"resource_mrn"`
	Requester      string     `json:"requester"`
	RequesterKind  string     `json:"requester_kind"`
	IssuedAt       time.Time  `json:"issued_at"`
	ExpiresAt      time.Time  `json:"expires_at"`
	RevokedAt      *time.Time `json:"revoked_at,omitempty"`
	RevokeReason   string     `json:"revoke_reason,omitempty"`
	RevokeError    string     `json:"revoke_error,omitempty"`
	RevokeAttempts int32      `json:"revoke_attempts"`
}

// CreateDynamicRoleInput registers a role configuration.
type CreateDynamicRoleInput struct {
	TenantUUID     uuid.UUID
	Project        string
	Name           string
	Description    string
	DSNSecretRef   string
	CreationSQL    string
	RevocationSQL  string
	DefaultTTL     time.Duration
	MaxTTL         time.Duration
	RoleNamePrefix string
}

// CreateDynamicRole registers a role configuration.
//
// The templates are validated by internal/dynamic (shape rules: a CREATE ROLE, a DROP
// ROLE, a {{name}} placeholder, a password placeholder on the creation side and none on
// the revocation side) and the DSN reference is validated as an ADDRESS. Neither check
// touches the target database: a config can be written before the target exists, which
// is the order an operator actually works in.
func (s *Service) CreateDynamicRole(ctx context.Context, in CreateDynamicRoleInput) (*DynamicRoleDetail, error) {
	cfg := dynamic.Config{
		Name:           in.Name,
		CreationSQL:    in.CreationSQL,
		RevocationSQL:  in.RevocationSQL,
		DefaultTTL:     in.DefaultTTL,
		MaxTTL:         in.MaxTTL,
		RoleNamePrefix: in.RoleNamePrefix,
	}
	if err := cfg.Validate(); err != nil {
		return nil, apperror.NewValidation(err.Error())
	}
	if err := ValidateDSNSecretRef(in.DSNSecretRef); err != nil {
		return nil, apperror.NewValidation(err.Error())
	}
	meta, err := encodeObject(nil)
	if err != nil {
		return nil, apperror.NewInternal("encode dynamic role metadata", err)
	}

	tenant, project, err := s.resolveProject(ctx, in.TenantUUID, in.Project)
	if err != nil {
		return nil, err
	}
	row, err := s.repo.CreateDynamicRole(ctx, storage.CreateDynamicRoleParams{
		TenantID:          tenant.TenantID,
		ProjectID:         project.ProjectID,
		Name:              cfg.Name,
		Description:       in.Description,
		DsnSecretRef:      in.DSNSecretRef,
		CreationSql:       cfg.CreationSQL,
		RevocationSql:     cfg.RevocationSQL,
		DefaultTtlSeconds: int32(cfg.DefaultTTL.Seconds()),
		MaxTtlSeconds:     int32(cfg.MaxTTL.Seconds()),
		RoleNamePrefix:    cfg.RoleNamePrefix,
		Status:            DynamicRoleStatusActive,
		Metadata:          meta,
	})
	if err != nil {
		return nil, mapWriteError(err, "dynamic role",
			fmt.Sprintf("a dynamic role named %q already exists in this project", cfg.Name))
	}
	out := toDynamicRoleDetail(row)
	return &out, nil
}

// GetDynamicRole reads one role configuration, templates included.
func (s *Service) GetDynamicRole(ctx context.Context, tenantUUID uuid.UUID, project, name string) (*DynamicRoleDetail, error) {
	row, _, err := s.dynamicRoleByName(ctx, s.repo, tenantUUID, project, name)
	if err != nil {
		return nil, err
	}
	out := toDynamicRoleDetail(row)
	return &out, nil
}

// ListDynamicRoles pages a project's role configurations. The listing omits the SQL
// templates; GetDynamicRole returns them.
func (s *Service) ListDynamicRoles(ctx context.Context, tenantUUID uuid.UUID, project string, page, limit int) ([]DynamicRole, int64, error) {
	tenant, proj, err := s.resolveProject(ctx, tenantUUID, project)
	if err != nil {
		return nil, 0, err
	}
	page, limit = normalizePage(page, limit)
	rows, err := s.repo.ListDynamicRoleMetaByProject(ctx, storage.ListDynamicRoleMetaByProjectParams{
		TenantID:  tenant.TenantID,
		ProjectID: proj.ProjectID,
		RowLimit:  int32(limit),
		RowOffset: int32((page - 1) * limit),
	})
	if err != nil {
		return nil, 0, apperror.NewInternal("list dynamic roles", err)
	}
	total, err := s.repo.CountDynamicRolesByProject(ctx, storage.CountDynamicRolesByProjectParams{
		TenantID:  tenant.TenantID,
		ProjectID: proj.ProjectID,
	})
	if err != nil {
		return nil, 0, apperror.NewInternal("count dynamic roles", err)
	}
	out := make([]DynamicRole, 0, len(rows))
	for _, r := range rows {
		out = append(out, DynamicRole{
			UUID:              r.RoleUuid,
			Name:              r.Name,
			Description:       r.Description,
			DSNSecretRef:      r.DsnSecretRef,
			DefaultTTLSeconds: r.DefaultTtlSeconds,
			MaxTTLSeconds:     r.MaxTtlSeconds,
			RoleNamePrefix:    r.RoleNamePrefix,
			Status:            r.Status,
			CreatedAt:         r.CreatedAt,
			UpdatedAt:         r.UpdatedAt,
		})
	}
	return out, total, nil
}

// UpdateDynamicRoleInput rewrites a role configuration.
type UpdateDynamicRoleInput struct {
	TenantUUID    uuid.UUID
	Project       string
	Name          string
	Description   string
	DSNSecretRef  string
	CreationSQL   string
	RevocationSQL string
	DefaultTTL    time.Duration
	MaxTTL        time.Duration
	Status        string
}

// UpdateDynamicRole rewrites a role configuration.
//
// EDITING THE REVOCATION TEMPLATE AFFECTS LEASES ALREADY ISSUED, because the reaper
// renders whatever the config currently says when it comes to revoke. That is the right
// behaviour — it is how an operator FIXES a broken revocation template and lets the
// reaper drain the accounts it stranded — and it is worth stating out loud, because the
// converse (snapshotting the template onto each lease) would make a template bug
// permanent for every credential issued before it was noticed.
func (s *Service) UpdateDynamicRole(ctx context.Context, in UpdateDynamicRoleInput) (*DynamicRoleDetail, error) {
	existing, tenant, err := s.dynamicRoleByName(ctx, s.repo, in.TenantUUID, in.Project, in.Name)
	if err != nil {
		return nil, err
	}
	cfg := dynamic.Config{
		Name:           existing.Name,
		CreationSQL:    in.CreationSQL,
		RevocationSQL:  in.RevocationSQL,
		DefaultTTL:     in.DefaultTTL,
		MaxTTL:         in.MaxTTL,
		RoleNamePrefix: existing.RoleNamePrefix,
	}
	if err := cfg.Validate(); err != nil {
		return nil, apperror.NewValidation(err.Error())
	}
	if err := ValidateDSNSecretRef(in.DSNSecretRef); err != nil {
		return nil, apperror.NewValidation(err.Error())
	}
	status := in.Status
	switch status {
	case DynamicRoleStatusActive, DynamicRoleStatusDisabled:
	case "":
		status = DynamicRoleStatusActive
	default:
		return nil, apperror.NewValidation(fmt.Sprintf("status %q must be %s or %s",
			status, DynamicRoleStatusActive, DynamicRoleStatusDisabled))
	}

	row, err := s.repo.UpdateDynamicRole(ctx, storage.UpdateDynamicRoleParams{
		Description:       in.Description,
		DsnSecretRef:      in.DSNSecretRef,
		CreationSql:       cfg.CreationSQL,
		RevocationSql:     cfg.RevocationSQL,
		DefaultTtlSeconds: int32(cfg.DefaultTTL.Seconds()),
		MaxTtlSeconds:     int32(cfg.MaxTTL.Seconds()),
		Status:            status,
		TenantID:          tenant.TenantID,
		RoleUuid:          existing.RoleUuid,
	})
	if err != nil {
		return nil, mapWriteError(err, "dynamic role", "that dynamic role could not be updated")
	}
	out := toDynamicRoleDetail(row)
	return &out, nil
}

// DeleteDynamicRole soft-deletes a role configuration.
//
// IT REFUSES WHILE CREDENTIALS ARE OUTSTANDING, and that refusal is the whole reason
// this method is not a one-liner. The revocation template lives on the CONFIG; delete
// the config and every issued account becomes unrevokable, because the reaper has
// nothing left to render. So the operator is told to revoke first — which is an
// inconvenience that prevents a permanent one.
func (s *Service) DeleteDynamicRole(ctx context.Context, tenantUUID uuid.UUID, project, name string) error {
	row, tenant, err := s.dynamicRoleByName(ctx, s.repo, tenantUUID, project, name)
	if err != nil {
		return err
	}
	live, err := s.repo.CountLiveDynamicLeasesByRole(ctx, row.RoleID)
	if err != nil {
		return apperror.NewInternal("count outstanding dynamic leases", err)
	}
	if live > 0 {
		return apperror.NewConflict(fmt.Sprintf(
			"%d credential(s) issued from this role are still outstanding; revoke them before deleting the role, "+
				"or the accounts they created can no longer be dropped", live))
	}
	n, err := s.repo.SoftDeleteDynamicRole(ctx, storage.SoftDeleteDynamicRoleParams{
		TenantID: tenant.TenantID,
		RoleUuid: row.RoleUuid,
	})
	if err != nil {
		return apperror.NewInternal("delete dynamic role", err)
	}
	if n == 0 {
		return apperror.NewNotFound("dynamic role")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Issue
// ---------------------------------------------------------------------------

// IssueDynamicLeaseInput describes a credential request.
type IssueDynamicLeaseInput struct {
	TenantUUID uuid.UUID
	Project    string
	RoleName   string
	// RequestedTTL is what the caller asked for; zero takes the role's default. An
	// over-long request is refused rather than clamped.
	RequestedTTL time.Duration
	// Requester and RequesterKind are the authenticated principal, recorded on the
	// lease so "who holds a live credential against this database" is answerable.
	Requester     string
	RequesterKind string
	// ResourceMRN is the role's MRN, denormalized onto the lease so the record still
	// reads correctly after the config is deleted.
	ResourceMRN string
}

// Provisioner is the outbound seam, re-declared as a local alias so callers of this
// package do not have to import internal/dynamic to name it.
type Provisioner = dynamic.Provisioner

// IssueDynamicLease mints one credential.
//
// THE ORDERING IS THE DESIGN, and it is the only part of this feature where a mistake
// is unrecoverable. The lease row lives in THIS PostgreSQL database and the role lives
// in the TARGET one, and no transaction spans both, so the sequence is:
//
//  1. Resolve the config and the DSN (the DSN is revealed from its secret and zeroized
//     on the way out of this function, on every path).
//  2. Generate a name and a password, and render both templates.
//  3. Open a LOCAL transaction and INSERT THE LEASE.
//  4. Run the creation DDL against the target database, inside that open transaction.
//  5. Commit.
//
// Step 4 failing means the deferred rollback removes the lease: no role, no lease, and
// the caller gets the target database's refusal. Step 5 failing leaves a role with no
// lease — the one residual window, and the small side of the trade, because the
// opposite ordering (create, then record) leaves the same orphan for the whole duration
// of the DDL rather than for the duration of one local commit.
//
// The provisioner is injected rather than held on the Service so this package keeps no
// outbound network dependency: the store's job is the transaction, and the network call
// is a callback inside it.
func (s *Service) IssueDynamicLease(ctx context.Context, prov Provisioner, in IssueDynamicLeaseInput) (*dynamic.Credential, *DynamicLease, error) {
	if prov == nil {
		return nil, nil, apperror.NewUnavailable("dynamic credential provisioning is not configured on this instance")
	}

	role, tenant, err := s.dynamicRoleByName(ctx, s.repo, in.TenantUUID, in.Project, in.RoleName)
	if err != nil {
		return nil, nil, err
	}
	if role.Status != DynamicRoleStatusActive {
		return nil, nil, apperror.NewForbidden(fmt.Sprintf("dynamic role %q is %s and will not issue credentials", role.Name, role.Status))
	}

	cfg := dynamic.Config{
		Name:           role.Name,
		CreationSQL:    role.CreationSql,
		RevocationSQL:  role.RevocationSql,
		DefaultTTL:     time.Duration(role.DefaultTtlSeconds) * time.Second,
		MaxTTL:         time.Duration(role.MaxTtlSeconds) * time.Second,
		RoleNamePrefix: role.RoleNamePrefix,
	}
	ttl, err := cfg.ResolveTTL(in.RequestedTTL)
	if err != nil {
		return nil, nil, apperror.NewValidation(err.Error())
	}
	expiresAt := s.now().Add(ttl)

	dsn, err := s.resolveDynamicDSN(ctx, in.TenantUUID, role.DsnSecretRef)
	if err != nil {
		return nil, nil, err
	}
	// The DSN is the most privileged credential this flow touches. Zeroized on EVERY
	// path, which is why the defer is set up here rather than after the last use.
	defer dsn.Zero()

	roleName, err := dynamic.NewRoleName(role.RoleNamePrefix)
	if err != nil {
		return nil, nil, apperror.NewInternal("generate dynamic role name", err)
	}
	password, err := dynamic.NewPassword()
	if err != nil {
		return nil, nil, apperror.NewInternal("generate dynamic credential password", err)
	}
	createSQL, err := dynamic.Render(role.CreationSql, roleName, password, expiresAt)
	if err != nil {
		return nil, nil, apperror.NewValidation(err.Error())
	}

	meta, err := encodeObject(nil)
	if err != nil {
		return nil, nil, apperror.NewInternal("encode dynamic lease metadata", err)
	}

	var lease DynamicLease
	err = s.repo.InTx(ctx, func(tx Repository) error {
		row, err := tx.CreateDynamicLease(ctx, storage.CreateDynamicLeaseParams{
			RoleID:        role.RoleID,
			TenantID:      tenant.TenantID,
			DbRoleName:    roleName,
			ResourceMrn:   in.ResourceMRN,
			Requester:     in.Requester,
			RequesterKind: defaultRequesterKind(in.RequesterKind),
			ExpiresAt:     expiresAt,
			Metadata:      meta,
		})
		if err != nil {
			// A unique violation on db_role_name means the generated name collided,
			// which at 20 random alphanumeric characters is not a thing that happens —
			// so reporting it as a conflict rather than retrying is honest: a collision
			// here means the generator is broken, and a silent retry would hide that.
			return mapWriteError(err, "dynamic lease", "the generated role name collided; retry the request")
		}
		if err := prov.Create(ctx, string(dsn), createSQL); err != nil {
			// Rolls the lease row back. The error is already sanitized by the
			// provisioner — it must never quote the statement, which contains the
			// generated password.
			return apperror.NewUnavailable(err.Error())
		}
		lease = toDynamicLeaseFromRow(row)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	return &dynamic.Credential{
		RoleName:  roleName,
		Password:  password,
		ExpiresAt: expiresAt,
	}, &lease, nil
}

// ---------------------------------------------------------------------------
// Revoke
// ---------------------------------------------------------------------------

// RevokeDynamicLease drops the database role and closes the lease.
//
// THE LEASE IS MARKED REVOKED ONLY AFTER THE TARGET DATABASE CONFIRMS THE DROP, and
// that ordering is the opposite of the issue path's for a reason: on issue, the risk is
// an account nobody knows about, so the record is written first; on revoke, the risk is
// an account everybody believes is gone, so the record is written last. A revocation
// the target refused leaves the lease OPEN with an error and an incremented attempt
// count, so the reaper keeps trying and an operator can see that an account is
// stranded.
//
// `reason` is DynamicRevokeExplicit or DynamicRevokeExpired.
func (s *Service) RevokeDynamicLease(ctx context.Context, prov Provisioner, tenantUUID, leaseUUID uuid.UUID, reason string) (*DynamicLease, error) {
	if prov == nil {
		return nil, apperror.NewUnavailable("dynamic credential provisioning is not configured on this instance")
	}
	tenant, err := s.repo.GetTenantByUUID(ctx, tenantUUID)
	if err != nil {
		return nil, mapReadError(err, "tenant")
	}
	row, err := s.repo.GetDynamicLeaseByUUID(ctx, storage.GetDynamicLeaseByUUIDParams{
		TenantID:  tenant.TenantID,
		LeaseUuid: leaseUUID,
	})
	if err != nil {
		return nil, mapReadError(err, "dynamic lease")
	}
	if row.RevokedAt.Valid {
		// Idempotent rather than an error: a caller retrying a revoke, or a reaper
		// racing an explicit one, should see success. Reporting a conflict would make
		// the safe action (revoke again if unsure) look like a failure.
		out := toDynamicLeaseFromRow(row)
		return &out, nil
	}

	if err := s.revokeDynamicLeaseRow(ctx, prov, dynamicLeaseWork{
		LeaseID:    row.LeaseID,
		RoleID:     row.RoleID,
		TenantUUID: tenantUUID,
		RoleName:   row.DbRoleName,
	}, reason); err != nil {
		return nil, err
	}

	updated, err := s.repo.GetDynamicLeaseByUUID(ctx, storage.GetDynamicLeaseByUUIDParams{
		TenantID:  tenant.TenantID,
		LeaseUuid: leaseUUID,
	})
	if err != nil {
		return nil, mapReadError(err, "dynamic lease")
	}
	out := toDynamicLeaseFromRow(updated)
	return &out, nil
}

// dynamicLeaseWork is the slice of a lease row a revocation needs. Note the absence of
// a password: a revocation takes a NAME, which is the whole reason the password never
// has to be stored.
type dynamicLeaseWork struct {
	LeaseID    int64
	RoleID     int64
	TenantUUID uuid.UUID
	RoleName   string
	// ResourceMRN and Requester travel with the work so the api layer can audit a
	// reaper-driven revocation against the same MRN a caller-driven one uses.
	ResourceMRN string
	Requester   string
}

// ExpiredDynamicLease is one overdue lease, as the reaper sees it.
type ExpiredDynamicLease struct {
	LeaseUUID      uuid.UUID
	TenantUUID     uuid.UUID
	RoleName       string
	ResourceMRN    string
	Requester      string
	ExpiresAt      time.Time
	RevokeAttempts int32

	leaseID int64
	roleID  int64
}

// ListExpiredDynamicLeases returns the leases whose TTL has run out and which have not
// been revoked, oldest overdue first.
//
// now() is the DATABASE's, not this process's: a skewed clock must not be able to reap
// early or late. The tenant UUID is resolved per row because a sweep is cross-tenant by
// nature — it is the platform's housekeeping, not a caller's operation.
func (s *Service) ListExpiredDynamicLeases(ctx context.Context, limit int) ([]ExpiredDynamicLease, error) {
	if limit < 1 {
		limit = dynamic.DefaultReapBatch
	}
	rows, err := s.repo.ListExpiredDynamicLeases(ctx, int32(limit))
	if err != nil {
		return nil, apperror.NewInternal("list expired dynamic leases", err)
	}
	out := make([]ExpiredDynamicLease, 0, len(rows))
	for _, r := range rows {
		tenant, err := s.repo.GetTenantByID(ctx, r.TenantID)
		if err != nil {
			// A lease whose tenant has been erased has nothing left to revoke against;
			// skipping it keeps one bad row from stalling the whole sweep.
			continue
		}
		out = append(out, ExpiredDynamicLease{
			LeaseUUID:      r.LeaseUuid,
			TenantUUID:     tenant.TenantUuid,
			RoleName:       r.DbRoleName,
			ResourceMRN:    r.ResourceMrn,
			Requester:      r.Requester,
			ExpiresAt:      r.ExpiresAt,
			RevokeAttempts: r.RevokeAttempts,
			leaseID:        r.LeaseID,
			roleID:         r.RoleID,
		})
	}
	return out, nil
}

// RevokeExpiredDynamicLease revokes one lease the reaper found. Split from
// RevokeDynamicLease so the sweep does not re-resolve a row it already holds.
func (s *Service) RevokeExpiredDynamicLease(ctx context.Context, prov Provisioner, lease ExpiredDynamicLease) error {
	if prov == nil {
		return apperror.NewUnavailable("dynamic credential provisioning is not configured on this instance")
	}
	return s.revokeDynamicLeaseRow(ctx, prov, dynamicLeaseWork{
		LeaseID:     lease.leaseID,
		RoleID:      lease.roleID,
		TenantUUID:  lease.TenantUUID,
		RoleName:    lease.RoleName,
		ResourceMRN: lease.ResourceMRN,
		Requester:   lease.Requester,
	}, DynamicRevokeExpired)
}

// revokeDynamicLeaseRow is the shared revocation path: resolve the config, resolve the
// DSN, render, run, record.
func (s *Service) revokeDynamicLeaseRow(ctx context.Context, prov Provisioner, work dynamicLeaseWork, reason string) error {
	role, err := s.repo.GetDynamicRoleByID(ctx, work.RoleID)
	if err != nil {
		return mapReadError(err, "dynamic role")
	}
	dsn, err := s.resolveDynamicDSN(ctx, work.TenantUUID, role.DsnSecretRef)
	if err != nil {
		return err
	}
	defer dsn.Zero()

	// The password placeholder is refused on a revocation template at validation time,
	// so the empty string here can never reach a rendered statement. Passing it
	// explicitly rather than restructuring Render keeps ONE renderer, which is what
	// keeps the identifier allowlist on one code path.
	revokeSQL, err := dynamic.Render(role.RevocationSql, work.RoleName, "", s.now())
	if err != nil {
		return apperror.NewValidation(err.Error())
	}

	if err := prov.Revoke(ctx, string(dsn), revokeSQL); err != nil {
		// THE LEASE STAYS OPEN. The account still exists, so the row that demands its
		// revocation must survive; only the error and the attempt count are recorded.
		if _, rerr := s.repo.RecordDynamicLeaseRevokeFailure(ctx, storage.RecordDynamicLeaseRevokeFailureParams{
			RevokeError: truncateError(err.Error()),
			LeaseID:     work.LeaseID,
		}); rerr != nil {
			return apperror.NewInternal("record dynamic revocation failure", rerr)
		}
		return apperror.NewUnavailable(err.Error())
	}

	if _, err := s.repo.MarkDynamicLeaseRevoked(ctx, storage.MarkDynamicLeaseRevokedParams{
		RevokeReason: reason,
		LeaseID:      work.LeaseID,
	}); err != nil {
		// The role IS dropped and the row says otherwise. The next reaper pass will
		// render the revocation again; an operator-written template should therefore
		// use IF EXISTS, and the failure here is loud so the inconsistency is not
		// silent.
		return apperror.NewInternal("close dynamic lease", err)
	}
	return nil
}

// ListDynamicLeases pages one role's lease history, newest first.
func (s *Service) ListDynamicLeases(ctx context.Context, tenantUUID uuid.UUID, project, roleName string, page, limit int) ([]DynamicLease, int64, error) {
	role, tenant, err := s.dynamicRoleByName(ctx, s.repo, tenantUUID, project, roleName)
	if err != nil {
		return nil, 0, err
	}
	page, limit = normalizePage(page, limit)
	rows, err := s.repo.ListDynamicLeasesByRole(ctx, storage.ListDynamicLeasesByRoleParams{
		TenantID:  tenant.TenantID,
		RoleID:    role.RoleID,
		RowLimit:  int32(limit),
		RowOffset: int32((page - 1) * limit),
	})
	if err != nil {
		return nil, 0, apperror.NewInternal("list dynamic leases", err)
	}
	total, err := s.repo.CountDynamicLeasesByRole(ctx, storage.CountDynamicLeasesByRoleParams{
		TenantID: tenant.TenantID,
		RoleID:   role.RoleID,
	})
	if err != nil {
		return nil, 0, apperror.NewInternal("count dynamic leases", err)
	}
	out := make([]DynamicLease, 0, len(rows))
	for _, r := range rows {
		l := DynamicLease{
			UUID:           r.LeaseUuid,
			RoleName:       r.DbRoleName,
			ResourceMRN:    r.ResourceMrn,
			Requester:      r.Requester,
			RequesterKind:  r.RequesterKind,
			IssuedAt:       r.IssuedAt,
			ExpiresAt:      r.ExpiresAt,
			RevokeReason:   r.RevokeReason,
			RevokeError:    r.RevokeError,
			RevokeAttempts: r.RevokeAttempts,
		}
		l.RevokedAt = timePtr(r.RevokedAt)
		out = append(out, l)
	}
	return out, total, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// ValidateDSNSecretRef checks that a role's DSN field is an ADDRESS and not a
// connection string.
//
// It is the Go half of the check constraint in migrations/00012, and both exist: the
// constraint is what makes a plaintext DSN unstorable even through a future code path
// that forgets to validate, and this is what turns the attempt into a 400 with a useful
// message instead of a 500 with a constraint name.
func ValidateDSNSecretRef(raw string) error {
	if raw == "" {
		return fmt.Errorf("dsn_secret_ref is required: the target DSN must be stored as a secret and referenced, never written here literally")
	}
	if len(raw) > 1024 {
		return fmt.Errorf("dsn_secret_ref must be at most 1024 characters")
	}
	// ASCII-lowered rather than strings.ToLower: the markers looked for are ASCII, and
	// Unicode case folding on attacker-chosen input is a larger surface than this check
	// needs. The check constraint in migrations/00012 is the authority either way.
	lower := toLowerASCII(raw)
	for _, marker := range []string{"://", "password=", "host=", "dbname=", "user="} {
		if strings.Contains(lower, marker) {
			return fmt.Errorf("dsn_secret_ref looks like a connection string; it must be a secret address of the form project/environment[/folder...]/KEY")
		}
	}
	project, environment, folderPath, key, ok := SplitReferencePath(raw)
	if !ok {
		return fmt.Errorf("dsn_secret_ref %q must be project/environment[/folder...]/KEY", raw)
	}
	if err := ValidateSlug("dsn_secret_ref project", project); err != nil {
		return err
	}
	if err := ValidateSlug("dsn_secret_ref environment", environment); err != nil {
		return err
	}
	if _, err := NormalizePath(folderPath); err != nil {
		return err
	}
	return ValidateKey(key)
}

// resolveDynamicDSN reveals the DSN behind a role's secret reference.
//
// THE CALLER'S GRANTS ARE NOT CHECKED HERE, DELIBERATELY, and it is the one place in
// this service where a value is decrypted without a caller-scoped permission check on
// that value. The reasoning is the entire point of a credential broker: requiring
// secret:GetSecret on the admin DSN would mean every workload that issues a credential
// could also read the admin DSN, which is the situation dynamic secrets exist to end.
//
// The privilege that gates this is secret:ManageDynamicRole — user-only — on the config
// that names the reference. Whoever writes that config decides which DSN is used and
// what an issued credential can do; a caller holding only
// secret:IssueDynamicCredential can pick an existing role and nothing else, and the DSN
// is never returned to it on any path.
func (s *Service) resolveDynamicDSN(ctx context.Context, tenantUUID uuid.UUID, ref string) (crypto.Plaintext, error) {
	project, environment, folderPath, key, ok := SplitReferencePath(ref)
	if !ok {
		return nil, apperror.NewValidation(fmt.Sprintf("dsn_secret_ref %q must be project/environment[/folder...]/KEY", ref))
	}
	revealed, err := s.GetSecret(ctx, SecretRef{
		TenantUUID:  tenantUUID,
		Project:     project,
		Environment: environment,
		FolderPath:  folderPath,
		Key:         key,
	})
	if err != nil {
		var notFound *apperror.NotFoundError
		if errors.As(err, &notFound) {
			// Naming the reference rather than the underlying secret: the caller may
			// hold no grant on that secret at all, so "the DSN this role points at is
			// missing" is the most it should learn, and it is what the OPERATOR needs.
			return nil, apperror.NewUnavailable(fmt.Sprintf(
				"the secret this dynamic role's dsn_secret_ref points at (%s) does not exist", ref))
		}
		return nil, err
	}
	return revealed.Value, nil
}

// resolveProject walks tenant -> project through tenant-scoped queries.
func (s *Service) resolveProject(ctx context.Context, tenantUUID uuid.UUID, project string) (storage.Tenant, storage.Project, error) {
	tenant, err := s.repo.GetTenantByUUID(ctx, tenantUUID)
	if err != nil {
		return storage.Tenant{}, storage.Project{}, mapReadError(err, "tenant")
	}
	proj, err := s.repo.GetProjectBySlug(ctx, storage.GetProjectBySlugParams{
		TenantID: tenant.TenantID,
		Slug:     project,
	})
	if err != nil {
		return storage.Tenant{}, storage.Project{}, mapReadError(err, "project")
	}
	return tenant, proj, nil
}

// dynamicRoleByName resolves a role config and the tenant it belongs to.
func (s *Service) dynamicRoleByName(ctx context.Context, repo Repository, tenantUUID uuid.UUID, project, name string) (storage.DynamicRole, storage.Tenant, error) {
	tenant, err := repo.GetTenantByUUID(ctx, tenantUUID)
	if err != nil {
		return storage.DynamicRole{}, storage.Tenant{}, mapReadError(err, "tenant")
	}
	proj, err := repo.GetProjectBySlug(ctx, storage.GetProjectBySlugParams{
		TenantID: tenant.TenantID,
		Slug:     project,
	})
	if err != nil {
		return storage.DynamicRole{}, storage.Tenant{}, mapReadError(err, "project")
	}
	row, err := repo.GetDynamicRoleByName(ctx, storage.GetDynamicRoleByNameParams{
		TenantID:  tenant.TenantID,
		ProjectID: proj.ProjectID,
		Name:      name,
	})
	if err != nil {
		return storage.DynamicRole{}, storage.Tenant{}, mapReadError(err, "dynamic role")
	}
	return row, tenant, nil
}

func toDynamicRoleDetail(r storage.DynamicRole) DynamicRoleDetail {
	return DynamicRoleDetail{
		DynamicRole: DynamicRole{
			UUID:              r.RoleUuid,
			Name:              r.Name,
			Description:       r.Description,
			DSNSecretRef:      r.DsnSecretRef,
			DefaultTTLSeconds: r.DefaultTtlSeconds,
			MaxTTLSeconds:     r.MaxTtlSeconds,
			RoleNamePrefix:    r.RoleNamePrefix,
			Status:            r.Status,
			CreatedAt:         r.CreatedAt,
			UpdatedAt:         r.UpdatedAt,
		},
		CreationSQL:   r.CreationSql,
		RevocationSQL: r.RevocationSql,
	}
}

func toDynamicLeaseFromRow(r storage.DynamicLease) DynamicLease {
	l := DynamicLease{
		UUID:           r.LeaseUuid,
		RoleName:       r.DbRoleName,
		ResourceMRN:    r.ResourceMrn,
		Requester:      r.Requester,
		RequesterKind:  r.RequesterKind,
		IssuedAt:       r.IssuedAt,
		ExpiresAt:      r.ExpiresAt,
		RevokeReason:   r.RevokeReason,
		RevokeError:    r.RevokeError,
		RevokeAttempts: r.RevokeAttempts,
	}
	l.RevokedAt = timePtr(r.RevokedAt)
	return l
}

func defaultRequesterKind(kind string) string {
	if kind == "" {
		return ActorKindService
	}
	return kind
}

// truncateError bounds what goes into the revoke_error column. An unbounded driver
// message in a row every listing returns is an unbounded response.
func truncateError(msg string) string {
	const max = 500
	if len(msg) <= max {
		return msg
	}
	return msg[:max] + "…"
}

// toLowerASCII lowercases the ASCII letters in s and leaves every other byte alone.
func toLowerASCII(s string) string {
	out := []byte(s)
	for i := range out {
		if out[i] >= 'A' && out[i] <= 'Z' {
			out[i] += 'a' - 'A'
		}
	}
	return string(out)
}
