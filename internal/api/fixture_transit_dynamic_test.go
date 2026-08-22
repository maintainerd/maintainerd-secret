package api

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/maintainerd/secret/internal/dynamic"
	"github.com/maintainerd/secret/internal/storage"
)

// The transit and dynamic-secret half of the in-memory store, plus a fake provisioner.
//
// These are MODELS, not mocks, exactly like the secret tables in fixture_test.go: the
// tenant scoping, the soft-delete predicate, the uniqueness rules and the
// revoked_at IS NULL guard on a revocation are reproduced, so an api-level test can
// actually fail when the layer under test gets one of them wrong. A query that only
// returned a canned row would make every test below pass for the wrong reason —
// including the tenant-isolation ones, which are the point.

// ---------------------------------------------------------------------------
// Transit keys
// ---------------------------------------------------------------------------

func (f *fakeRepo) CreateTransitKey(_ context.Context, arg storage.CreateTransitKeyParams) (storage.TransitKey, error) {
	for _, k := range f.transitKeys {
		if k.TenantID == arg.TenantID && k.ProjectID == arg.ProjectID &&
			k.Name == arg.Name && !k.DeletedAt.Valid {
			return storage.TransitKey{}, uniqueViolation()
		}
	}
	id := f.id("transit_key")
	row := storage.TransitKey{
		KeyID: id, KeyUuid: uuid.New(), TenantID: arg.TenantID, ProjectID: arg.ProjectID,
		Name: arg.Name, Description: arg.Description, CurrentVersion: 0,
		Status: arg.Status, MinDecryptVersion: arg.MinDecryptVersion, Metadata: arg.Metadata,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	f.transitKeys[id] = &row
	return row, nil
}

func (f *fakeRepo) CreateTransitKeyVersion(_ context.Context, arg storage.CreateTransitKeyVersionParams) (storage.TransitKeyVersion, error) {
	for _, v := range f.transitVersions {
		if v.KeyID == arg.KeyID && v.Version == arg.Version {
			return storage.TransitKeyVersion{}, uniqueViolation()
		}
	}
	id := f.id("transit_version")
	row := storage.TransitKeyVersion{
		VersionID: id, KeyID: arg.KeyID, Version: arg.Version,
		MaterialCiphertext: arg.MaterialCiphertext, MaterialNonce: arg.MaterialNonce,
		MaterialDekWrapped: arg.MaterialDekWrapped, MaterialDekNonce: arg.MaterialDekNonce,
		KekID: arg.KekID, CreatedAt: time.Now(),
	}
	f.transitVersions[id] = &row
	return row, nil
}

func (f *fakeRepo) SetTransitKeyCurrentVersion(_ context.Context, arg storage.SetTransitKeyCurrentVersionParams) (storage.TransitKey, error) {
	k, ok := f.transitKeys[arg.KeyID]
	if !ok || k.TenantID != arg.TenantID || k.DeletedAt.Valid {
		return storage.TransitKey{}, pgx.ErrNoRows
	}
	k.CurrentVersion = arg.CurrentVersion
	k.UpdatedAt = time.Now()
	return *k, nil
}

// findTransitKey reproduces `tenant_id = $1 AND project_id = $2 AND name = $3 AND
// deleted_at IS NULL`. The tenant predicate is what makes the cross-tenant tests real.
func (f *fakeRepo) findTransitKey(tenantID, projectID int64, name string) (storage.TransitKey, error) {
	for _, k := range f.transitKeys {
		if k.TenantID == tenantID && k.ProjectID == projectID &&
			k.Name == name && !k.DeletedAt.Valid {
			return *k, nil
		}
	}
	return storage.TransitKey{}, pgx.ErrNoRows
}

func (f *fakeRepo) GetTransitKeyByName(_ context.Context, arg storage.GetTransitKeyByNameParams) (storage.TransitKey, error) {
	return f.findTransitKey(arg.TenantID, arg.ProjectID, arg.Name)
}

func (f *fakeRepo) GetTransitKeyByNameForUpdate(_ context.Context, arg storage.GetTransitKeyByNameForUpdateParams) (storage.TransitKey, error) {
	return f.findTransitKey(arg.TenantID, arg.ProjectID, arg.Name)
}

func (f *fakeRepo) GetTransitKeyVersion(_ context.Context, arg storage.GetTransitKeyVersionParams) (storage.TransitKeyVersion, error) {
	for _, v := range f.transitVersions {
		if v.KeyID == arg.KeyID && v.Version == arg.Version {
			return *v, nil
		}
	}
	return storage.TransitKeyVersion{}, pgx.ErrNoRows
}

func (f *fakeRepo) ListTransitKeyMetaByProject(_ context.Context, arg storage.ListTransitKeyMetaByProjectParams) ([]storage.ListTransitKeyMetaByProjectRow, error) {
	out := []storage.ListTransitKeyMetaByProjectRow{}
	if arg.RowOffset > 0 {
		return out, nil
	}
	for _, k := range f.transitKeys {
		if k.TenantID != arg.TenantID || k.ProjectID != arg.ProjectID || k.DeletedAt.Valid {
			continue
		}
		// The real query's select list omits every material column. Mirrored here by
		// building the row from the metadata fields only — there is no material field on
		// this row type to fill in even if a future edit wanted one.
		out = append(out, storage.ListTransitKeyMetaByProjectRow{
			KeyUuid: k.KeyUuid, ProjectID: k.ProjectID, Name: k.Name,
			Description: k.Description, CurrentVersion: k.CurrentVersion,
			Status: k.Status, MinDecryptVersion: k.MinDecryptVersion,
			CreatedAt: k.CreatedAt, UpdatedAt: k.UpdatedAt,
		})
	}
	return out, nil
}

func (f *fakeRepo) CountTransitKeysByProject(_ context.Context, arg storage.CountTransitKeysByProjectParams) (int64, error) {
	n := int64(0)
	for _, k := range f.transitKeys {
		if k.TenantID == arg.TenantID && k.ProjectID == arg.ProjectID && !k.DeletedAt.Valid {
			n++
		}
	}
	return n, nil
}

func (f *fakeRepo) ListTransitKeyVersionMeta(_ context.Context, arg storage.ListTransitKeyVersionMetaParams) ([]storage.ListTransitKeyVersionMetaRow, error) {
	out := []storage.ListTransitKeyVersionMetaRow{}
	if arg.Offset > 0 {
		return out, nil
	}
	for _, v := range f.transitVersions {
		if v.KeyID != arg.KeyID {
			continue
		}
		out = append(out, storage.ListTransitKeyVersionMetaRow{
			VersionID: v.VersionID, KeyID: v.KeyID, Version: v.Version,
			KekID: v.KekID, CreatedAt: v.CreatedAt,
		})
	}
	return out, nil
}

func (f *fakeRepo) CountTransitKeyVersions(_ context.Context, keyID int64) (int64, error) {
	n := int64(0)
	for _, v := range f.transitVersions {
		if v.KeyID == keyID {
			n++
		}
	}
	return n, nil
}

func (f *fakeRepo) UpdateTransitKey(_ context.Context, arg storage.UpdateTransitKeyParams) (storage.TransitKey, error) {
	for _, k := range f.transitKeys {
		if k.TenantID == arg.TenantID && k.KeyUuid == arg.KeyUuid && !k.DeletedAt.Valid {
			k.Description = arg.Description
			k.Status = arg.Status
			k.MinDecryptVersion = arg.MinDecryptVersion
			k.UpdatedAt = time.Now()
			return *k, nil
		}
	}
	return storage.TransitKey{}, pgx.ErrNoRows
}

func (f *fakeRepo) SoftDeleteTransitKey(_ context.Context, arg storage.SoftDeleteTransitKeyParams) (int64, error) {
	for _, k := range f.transitKeys {
		if k.TenantID == arg.TenantID && k.KeyUuid == arg.KeyUuid && !k.DeletedAt.Valid {
			k.DeletedAt = pgtype.Timestamptz{Time: time.Now(), Valid: true}
			// The VERSIONS ARE LEFT ALONE, like the real query: a soft-deleted key can
			// be brought back with every version intact, and hard-deleting material as a
			// side-effect of removing a row from a listing would make every ciphertext
			// under it unrecoverable.
			return 1, nil
		}
	}
	return 0, nil
}

// ---------------------------------------------------------------------------
// Dynamic roles and leases
// ---------------------------------------------------------------------------

func (f *fakeRepo) CreateDynamicRole(_ context.Context, arg storage.CreateDynamicRoleParams) (storage.DynamicRole, error) {
	for _, r := range f.dynamicRoles {
		if r.TenantID == arg.TenantID && r.ProjectID == arg.ProjectID &&
			r.Name == arg.Name && !r.DeletedAt.Valid {
			return storage.DynamicRole{}, uniqueViolation()
		}
	}
	id := f.id("dynamic_role")
	row := storage.DynamicRole{
		RoleID: id, RoleUuid: uuid.New(), TenantID: arg.TenantID, ProjectID: arg.ProjectID,
		Name: arg.Name, Description: arg.Description, DsnSecretRef: arg.DsnSecretRef,
		CreationSql: arg.CreationSql, RevocationSql: arg.RevocationSql,
		DefaultTtlSeconds: arg.DefaultTtlSeconds, MaxTtlSeconds: arg.MaxTtlSeconds,
		RoleNamePrefix: arg.RoleNamePrefix, Status: arg.Status, Metadata: arg.Metadata,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	f.dynamicRoles[id] = &row
	return row, nil
}

func (f *fakeRepo) GetDynamicRoleByName(_ context.Context, arg storage.GetDynamicRoleByNameParams) (storage.DynamicRole, error) {
	for _, r := range f.dynamicRoles {
		if r.TenantID == arg.TenantID && r.ProjectID == arg.ProjectID &&
			r.Name == arg.Name && !r.DeletedAt.Valid {
			return *r, nil
		}
	}
	return storage.DynamicRole{}, pgx.ErrNoRows
}

func (f *fakeRepo) GetDynamicRoleByID(_ context.Context, roleID int64) (storage.DynamicRole, error) {
	if r, ok := f.dynamicRoles[roleID]; ok {
		return *r, nil
	}
	return storage.DynamicRole{}, pgx.ErrNoRows
}

// ListExpiredDynamicLeases is the reaper's query.
//
// It reproduces the three properties the sweep's correctness rests on: a REVOKED lease
// is never returned (so a completed revocation is not retried forever), overdue is
// decided by comparing expires_at against the clock rather than by trusting a status
// column, and rows come back oldest-overdue first so a backlog drains in the order it
// accumulated. The real query reads the DATABASE's now(), which is what stops a skewed
// replica from reaping early or stalling; the fake has one clock, so that distinction is
// not modelled here.
func (f *fakeRepo) ListExpiredDynamicLeases(_ context.Context, rowLimit int32) ([]storage.ListExpiredDynamicLeasesRow, error) {
	out := []storage.ListExpiredDynamicLeasesRow{}
	for _, l := range f.dynamicLeases {
		if l.RevokedAt.Valid || !l.ExpiresAt.Before(time.Now()) {
			continue
		}
		out = append(out, storage.ListExpiredDynamicLeasesRow{
			LeaseID: l.LeaseID, LeaseUuid: l.LeaseUuid, RoleID: l.RoleID,
			TenantID: l.TenantID, DbRoleName: l.DbRoleName,
			ResourceMrn: l.ResourceMrn, Requester: l.Requester,
			RequesterKind: l.RequesterKind, ExpiresAt: l.ExpiresAt,
			RevokeAttempts: l.RevokeAttempts,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ExpiresAt.Before(out[j].ExpiresAt) })
	if rowLimit > 0 && len(out) > int(rowLimit) {
		out = out[:rowLimit]
	}
	return out, nil
}

func (f *fakeRepo) GetTenantByID(_ context.Context, tenantID int64) (storage.Tenant, error) {
	if t, ok := f.tenants[tenantID]; ok && !t.DeletedAt.Valid {
		return *t, nil
	}
	return storage.Tenant{}, pgx.ErrNoRows
}

func (f *fakeRepo) ListDynamicRoleMetaByProject(_ context.Context, arg storage.ListDynamicRoleMetaByProjectParams) ([]storage.ListDynamicRoleMetaByProjectRow, error) {
	out := []storage.ListDynamicRoleMetaByProjectRow{}
	if arg.RowOffset > 0 {
		return out, nil
	}
	for _, r := range f.dynamicRoles {
		if r.TenantID != arg.TenantID || r.ProjectID != arg.ProjectID || r.DeletedAt.Valid {
			continue
		}
		// The real query omits the SQL templates; so does this row type.
		out = append(out, storage.ListDynamicRoleMetaByProjectRow{
			RoleUuid: r.RoleUuid, ProjectID: r.ProjectID, Name: r.Name,
			Description: r.Description, DsnSecretRef: r.DsnSecretRef,
			DefaultTtlSeconds: r.DefaultTtlSeconds, MaxTtlSeconds: r.MaxTtlSeconds,
			RoleNamePrefix: r.RoleNamePrefix, Status: r.Status,
			CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
		})
	}
	return out, nil
}

func (f *fakeRepo) CountDynamicRolesByProject(_ context.Context, arg storage.CountDynamicRolesByProjectParams) (int64, error) {
	n := int64(0)
	for _, r := range f.dynamicRoles {
		if r.TenantID == arg.TenantID && r.ProjectID == arg.ProjectID && !r.DeletedAt.Valid {
			n++
		}
	}
	return n, nil
}

func (f *fakeRepo) UpdateDynamicRole(_ context.Context, arg storage.UpdateDynamicRoleParams) (storage.DynamicRole, error) {
	for _, r := range f.dynamicRoles {
		if r.TenantID == arg.TenantID && r.RoleUuid == arg.RoleUuid && !r.DeletedAt.Valid {
			r.Description = arg.Description
			r.DsnSecretRef = arg.DsnSecretRef
			r.CreationSql = arg.CreationSql
			r.RevocationSql = arg.RevocationSql
			r.DefaultTtlSeconds = arg.DefaultTtlSeconds
			r.MaxTtlSeconds = arg.MaxTtlSeconds
			r.Status = arg.Status
			r.UpdatedAt = time.Now()
			return *r, nil
		}
	}
	return storage.DynamicRole{}, pgx.ErrNoRows
}

func (f *fakeRepo) SoftDeleteDynamicRole(_ context.Context, arg storage.SoftDeleteDynamicRoleParams) (int64, error) {
	for _, r := range f.dynamicRoles {
		if r.TenantID == arg.TenantID && r.RoleUuid == arg.RoleUuid && !r.DeletedAt.Valid {
			r.DeletedAt = pgtype.Timestamptz{Time: time.Now(), Valid: true}
			return 1, nil
		}
	}
	return 0, nil
}

func (f *fakeRepo) CountLiveDynamicLeasesByRole(_ context.Context, roleID int64) (int64, error) {
	n := int64(0)
	for _, l := range f.dynamicLeases {
		if l.RoleID == roleID && !l.RevokedAt.Valid {
			n++
		}
	}
	return n, nil
}

func (f *fakeRepo) CreateDynamicLease(_ context.Context, arg storage.CreateDynamicLeaseParams) (storage.DynamicLease, error) {
	for _, l := range f.dynamicLeases {
		if l.DbRoleName == arg.DbRoleName {
			return storage.DynamicLease{}, uniqueViolation()
		}
	}
	id := f.id("dynamic_lease")
	row := storage.DynamicLease{
		LeaseID: id, LeaseUuid: uuid.New(), RoleID: arg.RoleID, TenantID: arg.TenantID,
		DbRoleName: arg.DbRoleName, ResourceMrn: arg.ResourceMrn,
		Requester: arg.Requester, RequesterKind: arg.RequesterKind,
		IssuedAt: time.Now(), ExpiresAt: arg.ExpiresAt, Metadata: arg.Metadata,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	f.dynamicLeases[id] = &row
	return row, nil
}

func (f *fakeRepo) GetDynamicLeaseByUUID(_ context.Context, arg storage.GetDynamicLeaseByUUIDParams) (storage.DynamicLease, error) {
	for _, l := range f.dynamicLeases {
		if l.TenantID == arg.TenantID && l.LeaseUuid == arg.LeaseUuid {
			return *l, nil
		}
	}
	return storage.DynamicLease{}, pgx.ErrNoRows
}

func (f *fakeRepo) MarkDynamicLeaseRevoked(_ context.Context, arg storage.MarkDynamicLeaseRevokedParams) (int64, error) {
	l, ok := f.dynamicLeases[arg.LeaseID]
	// The `revoked_at IS NULL` guard is reproduced: whichever of a concurrent reaper
	// pass and an explicit revoke loses gets zero rows and stops, rather than running
	// DROP ROLE twice.
	if !ok || l.RevokedAt.Valid {
		return 0, nil
	}
	l.RevokedAt = pgtype.Timestamptz{Time: time.Now(), Valid: true}
	l.RevokeReason = arg.RevokeReason
	l.RevokeError = ""
	l.RevokeAttempts++
	l.UpdatedAt = time.Now()
	return 1, nil
}

func (f *fakeRepo) RecordDynamicLeaseRevokeFailure(_ context.Context, arg storage.RecordDynamicLeaseRevokeFailureParams) (int64, error) {
	l, ok := f.dynamicLeases[arg.LeaseID]
	if !ok || l.RevokedAt.Valid {
		return 0, nil
	}
	// THE LEASE STAYS OPEN, like the real query: the account still exists, so the row
	// that demands its revocation must survive.
	l.RevokeError = arg.RevokeError
	l.RevokeAttempts++
	l.UpdatedAt = time.Now()
	return 1, nil
}

func (f *fakeRepo) ListDynamicLeasesByRole(_ context.Context, arg storage.ListDynamicLeasesByRoleParams) ([]storage.ListDynamicLeasesByRoleRow, error) {
	out := []storage.ListDynamicLeasesByRoleRow{}
	if arg.RowOffset > 0 {
		return out, nil
	}
	for _, l := range f.dynamicLeases {
		if l.TenantID != arg.TenantID || l.RoleID != arg.RoleID {
			continue
		}
		out = append(out, storage.ListDynamicLeasesByRoleRow{
			LeaseID: l.LeaseID, LeaseUuid: l.LeaseUuid, RoleID: l.RoleID,
			TenantID: l.TenantID, DbRoleName: l.DbRoleName, ResourceMrn: l.ResourceMrn,
			Requester: l.Requester, RequesterKind: l.RequesterKind,
			IssuedAt: l.IssuedAt, ExpiresAt: l.ExpiresAt, RevokedAt: l.RevokedAt,
			RevokeReason: l.RevokeReason, RevokeError: l.RevokeError,
			RevokeAttempts: l.RevokeAttempts,
		})
	}
	return out, nil
}

func (f *fakeRepo) CountDynamicLeasesByRole(_ context.Context, arg storage.CountDynamicLeasesByRoleParams) (int64, error) {
	n := int64(0)
	for _, l := range f.dynamicLeases {
		if l.TenantID == arg.TenantID && l.RoleID == arg.RoleID {
			n++
		}
	}
	return n, nil
}

// leaseRows returns a snapshot of the dynamic leases, for the assertions that check
// what survived a failure.
func (f *fakeRepo) leaseRows() []storage.DynamicLease {
	out := make([]storage.DynamicLease, 0, len(f.dynamicLeases))
	for _, l := range f.dynamicLeases {
		out = append(out, *l)
	}
	return out
}

// ---------------------------------------------------------------------------
// The provisioner fake
// ---------------------------------------------------------------------------

// fakeProvisioner stands in for the outbound connection to a target PostgreSQL
// database. It records the DSN and the rendered statement it was handed, which is what
// makes "the creation statement carried the generated password and the audit row did
// not" checkable.
type fakeProvisioner struct {
	mu sync.Mutex
	// createSQL and revokeSQL are every statement this provisioner was asked to run.
	createSQL []string
	revokeSQL []string
	// dsns is every connection string it was handed — the most privileged credential in
	// the flow, recorded so a test can assert it never appears anywhere else.
	dsns []string
	// createErr and revokeErr make the target database refuse.
	createErr error
	revokeErr error
}

func (p *fakeProvisioner) Create(_ context.Context, dsn, createSQL string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.dsns = append(p.dsns, dsn)
	p.createSQL = append(p.createSQL, createSQL)
	return p.createErr
}

func (p *fakeProvisioner) Revoke(_ context.Context, dsn, revokeSQL string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.dsns = append(p.dsns, dsn)
	p.revokeSQL = append(p.revokeSQL, revokeSQL)
	return p.revokeErr
}

func (p *fakeProvisioner) revokeCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.revokeSQL)
}

var _ dynamic.Provisioner = (*fakeProvisioner)(nil)

// errTargetDown is the failure injected to make the target database refuse.
var errTargetDown = errors.New("target database refused the statement")
