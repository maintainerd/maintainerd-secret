package api

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/maintainerd/secret/internal/audit"
	"github.com/maintainerd/secret/internal/dynamic"
	"github.com/maintainerd/secret/internal/platform/apperror"
	"github.com/maintainerd/secret/internal/platform/permissions"
	"github.com/maintainerd/secret/internal/store"
)

// Dynamic secrets: role CONFIGURATION, and the credentials issued against it.
//
// THE PERMISSION SPLIT IS THE SECURITY MODEL OF THIS FEATURE, and collapsing it would
// undo it. Configuring a role means choosing which database is targeted and writing the
// SQL that decides what an issued credential can do — a privileged, reviewable, human
// act, so secret:ManageDynamicRole is user-only at the route. Issuing one means asking
// for the short-lived account that configuration already described, so
// secret:IssueDynamicCredential is open to SERVICE principals: a workload asking for its
// own database credential at boot IS the feature, and requiring a human would push
// consumers back onto a shared static password.
//
// WHAT A HOLDER OF secret:IssueDynamicCredential CANNOT DO: read the target DSN. The
// role config holds a secret REFERENCE, and store.resolveDynamicDSN reveals it WITHOUT a
// caller-scoped grant check on that secret — deliberately, because requiring
// secret:GetSecret on the admin connection string would mean every workload that issues
// a credential could also read it, which is the situation dynamic secrets exist to end.
// The DSN is never returned to the caller on any path, and the privilege that gates
// which DSN is used is secret:ManageDynamicRole on the config that names it.
//
// ISSUING IS AUDITED UNCONDITIONALLY, and the audit row is MANDATORY rather than
// best-effort: the credential is disclosed exactly once and the password is stored
// nowhere, so the audit row plus the lease row are the only record that a live database
// account exists and who asked for it. See IssueDynamicCredential.

// ---------------------------------------------------------------------------
// Role configuration
// ---------------------------------------------------------------------------

// CreateDynamicRole registers a role configuration.
//
// Authorized against the project's dynamic-role COLLECTION rather than the role's own
// MRN, because the role does not exist yet — the same reasoning CreateTransitKey and
// CreateWebhookEndpoint make. A grant scoped to one role name therefore does not carry
// the ability to create another, which matters more here than elsewhere: a role config
// IS the definition of what its credentials may do.
func (s *Service) CreateDynamicRole(ctx context.Context, c Caller, in CreateDynamicRoleInput) (*store.DynamicRoleDetail, error) {
	if err := validate(in); err != nil {
		return nil, err
	}
	resourceMRN := c.mrn(in.Project, store.ResourceDynamicRole)
	if err := s.guard(ctx, c, permissions.PermManageDynamicRole, store.ActionDynamicRoleCreate, resourceMRN); err != nil {
		return nil, err
	}
	role, err := s.store.CreateDynamicRole(ctx, store.CreateDynamicRoleInput{
		TenantUUID:     c.TenantUUID,
		Project:        in.Project,
		Name:           in.Name,
		Description:    in.Description,
		DSNSecretRef:   in.DSNSecretRef,
		CreationSQL:    in.CreationSQL,
		RevocationSQL:  in.RevocationSQL,
		DefaultTTL:     time.Duration(in.DefaultTTLSeconds) * time.Second,
		MaxTTL:         time.Duration(in.MaxTTLSeconds) * time.Second,
		RoleNamePrefix: in.RoleNamePrefix,
	})
	if err != nil {
		s.recordFailure(ctx, c, store.ActionDynamicRoleCreate, resourceMRN, err)
		return nil, err
	}
	// The row records the DSN REFERENCE and the TTLs — an address and two numbers, none
	// of which is a credential. The SQL templates are deliberately NOT recorded: they
	// are long, they are readable on the config itself, and audit_log has a broader read
	// audience (secret:ReadAudit) than the config surface.
	if err := s.recordSuccess(ctx, c, audit.Event{
		Action:      store.ActionDynamicRoleCreate,
		ResourceMRN: c.mrn(in.Project, store.DynamicRoleResourcePath(role.Name)),
		Metadata:    dynamicRoleMetadata(role),
	}); err != nil {
		return nil, err
	}
	return role, nil
}

// dynamicRoleMetadata renders a role config for an audit row. Addresses and numbers
// only — there is no field here that could hold a connection string or a password.
func dynamicRoleMetadata(role *store.DynamicRoleDetail) map[string]any {
	return map[string]any{
		"role_uuid":           role.UUID.String(),
		"dsn_secret_ref":      role.DSNSecretRef,
		"default_ttl_seconds": role.DefaultTTLSeconds,
		"max_ttl_seconds":     role.MaxTTLSeconds,
		"status":              role.Status,
	}
}

// GetDynamicRole reads one role configuration, SQL templates included.
//
// Requires secret:ReadMetadata rather than secret:ManageDynamicRole, matching the
// listing: the templates are operator-authored SQL rather than credentials, and
// dsn_secret_ref is an ADDRESS. An operator about to edit a role has to see what it
// currently runs, and the console renders this for anyone who can browse the project.
// There is no field on store.DynamicRoleDetail that can hold the connection string
// itself.
func (s *Service) GetDynamicRole(ctx context.Context, c Caller, in DynamicRoleRef) (*store.DynamicRoleDetail, error) {
	if err := validate(in); err != nil {
		return nil, err
	}
	resourceMRN := c.mrn(in.Project, store.DynamicRoleResourcePath(in.Name))
	if err := s.guard(ctx, c, permissions.PermReadMetadata, store.ActionRead, resourceMRN); err != nil {
		return nil, err
	}
	role, err := s.store.GetDynamicRole(ctx, c.TenantUUID, in.Project, in.Name)
	if err != nil {
		s.recordFailure(ctx, c, store.ActionRead, resourceMRN, err)
		return nil, err
	}
	if err := s.recordSuccess(ctx, c, audit.Event{
		Action:      store.ActionRead,
		ResourceMRN: resourceMRN,
		Metadata:    map[string]any{"read": "dynamic_role", "status": role.Status},
	}); err != nil {
		return nil, err
	}
	return role, nil
}

// ListDynamicRoles pages a project's role configurations. The listing omits the SQL
// templates because they are long, not because they are sensitive.
func (s *Service) ListDynamicRoles(ctx context.Context, c Caller, in ListDynamicRolesInput) ([]store.DynamicRole, int64, error) {
	if err := validate(in); err != nil {
		return nil, 0, err
	}
	page, limit := in.Pagination.resolved()
	resourceMRN := c.mrn(in.Project, store.ResourceDynamicRole)
	if err := s.guard(ctx, c, permissions.PermReadMetadata, store.ActionRead, resourceMRN); err != nil {
		return nil, 0, err
	}
	roles, total, err := s.store.ListDynamicRoles(ctx, c.TenantUUID, in.Project, page, limit)
	if err != nil {
		s.recordFailure(ctx, c, store.ActionRead, resourceMRN, err)
		return nil, 0, err
	}
	if err := s.recordSuccess(ctx, c, audit.Event{
		Action:      store.ActionRead,
		ResourceMRN: resourceMRN,
		Metadata:    map[string]any{"read": "dynamic_roles", "returned": len(roles), "total": total},
	}); err != nil {
		return nil, 0, err
	}
	return roles, total, nil
}

// UpdateDynamicRole rewrites a role configuration.
//
// EDITING THE REVOCATION TEMPLATE AFFECTS CREDENTIALS ALREADY ISSUED, because the
// reaper renders whatever the config currently says when it comes to revoke (see
// store.UpdateDynamicRole). That is how an operator FIXES a broken revocation template
// and lets the reaper drain the accounts it stranded — and it is also why this is a
// management grant: whoever holds it decides what every future credential can do AND
// what happens to every outstanding one.
func (s *Service) UpdateDynamicRole(ctx context.Context, c Caller, in UpdateDynamicRoleInput) (*store.DynamicRoleDetail, error) {
	if err := validate(in); err != nil {
		return nil, err
	}
	resourceMRN := c.mrn(in.Project, store.DynamicRoleResourcePath(in.Name))
	if err := s.guard(ctx, c, permissions.PermManageDynamicRole, store.ActionDynamicRoleUpdate, resourceMRN); err != nil {
		return nil, err
	}
	role, err := s.store.UpdateDynamicRole(ctx, store.UpdateDynamicRoleInput{
		TenantUUID:    c.TenantUUID,
		Project:       in.Project,
		Name:          in.Name,
		Description:   in.Description,
		DSNSecretRef:  in.DSNSecretRef,
		CreationSQL:   in.CreationSQL,
		RevocationSQL: in.RevocationSQL,
		DefaultTTL:    time.Duration(in.DefaultTTLSeconds) * time.Second,
		MaxTTL:        time.Duration(in.MaxTTLSeconds) * time.Second,
		Status:        in.Status,
	})
	if err != nil {
		s.recordFailure(ctx, c, store.ActionDynamicRoleUpdate, resourceMRN, err)
		return nil, err
	}
	if err := s.recordSuccess(ctx, c, audit.Event{
		Action:      store.ActionDynamicRoleUpdate,
		ResourceMRN: resourceMRN,
		Metadata:    dynamicRoleMetadata(role),
	}); err != nil {
		return nil, err
	}
	return role, nil
}

// DeleteDynamicRole soft-deletes a role configuration.
//
// The store REFUSES while credentials are outstanding, and the refusal is the point:
// the revocation template lives on the config, so deleting it would make every issued
// account unrevokable. That surfaces here as a 409 telling the operator to revoke first.
func (s *Service) DeleteDynamicRole(ctx context.Context, c Caller, in DynamicRoleRef) error {
	if err := validate(in); err != nil {
		return err
	}
	resourceMRN := c.mrn(in.Project, store.DynamicRoleResourcePath(in.Name))
	if err := s.guard(ctx, c, permissions.PermManageDynamicRole, store.ActionDynamicRoleDelete, resourceMRN); err != nil {
		return err
	}
	if err := s.store.DeleteDynamicRole(ctx, c.TenantUUID, in.Project, in.Name); err != nil {
		s.recordFailure(ctx, c, store.ActionDynamicRoleDelete, resourceMRN, err)
		return err
	}
	return s.recordSuccess(ctx, c, audit.Event{
		Action:      store.ActionDynamicRoleDelete,
		ResourceMRN: resourceMRN,
	})
}

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

// IssuedCredential is a freshly minted credential leaving the service.
//
// IT IS DISCLOSED EXACTLY ONCE, in the issue response, and there is no read-it-back
// path: no column holds the password (see migrations/00012) and no query selects one.
// Revocation needs only a role name, which is what makes storing the password
// unnecessary rather than merely discouraged.
type IssuedCredential struct {
	// Credential carries the generated role name, the password and the expiry.
	Credential *dynamic.Credential
	// Lease is the durable record — who holds it, until when. No password field.
	Lease *store.DynamicLease
}

// IssueDynamicCredential mints one short-lived database credential.
//
// READ-SHAPED, BUT NOT A READ. It requires only secret:IssueDynamicCredential and it
// creates a live PostgreSQL account plus a lease row, so it carries the reveal path's
// audit contract rather than a listing's:
//
//   - It refuses to run without an auditor. Not "skips the audit" — refuses.
//   - It refuses to SUCCEED without an audit row. If the audit write fails the
//     credential is REVOKED (the account is dropped and the lease closed) and an error
//     is returned, so a caller that receives a password has by construction produced a
//     row in audit_log. An unaudited live database account is the one outcome this
//     surface must not produce.
//
// The caller supplies only a TTL, and it is bounded twice — by the role's ceiling and by
// the service limit. It cannot choose the role name, the password, the target DSN or any
// SQL; all of that was decided by whoever configured the role, which is what makes this
// surface safe to hand to a workload.
func (s *Service) IssueDynamicCredential(ctx context.Context, c Caller, in IssueDynamicCredentialInput) (*IssuedCredential, error) {
	// Checked FIRST, before anything is resolved: an unauditable service must not mint
	// a credential, and must not do the work leading up to one either.
	if s.auditor == nil {
		return nil, audit.ErrNoAuditor
	}
	if err := validate(in); err != nil {
		return nil, err
	}
	resourceMRN := c.mrn(in.Project, store.DynamicRoleResourcePath(in.Name))
	if err := s.guard(ctx, c, permissions.PermIssueDynamicCredential, store.ActionDynamicIssue, resourceMRN); err != nil {
		return nil, err
	}

	cred, lease, err := s.store.IssueDynamicLease(ctx, s.opts.Provisioner, store.IssueDynamicLeaseInput{
		TenantUUID:    c.TenantUUID,
		Project:       in.Project,
		RoleName:      in.Name,
		RequestedTTL:  time.Duration(in.TTLSeconds) * time.Second,
		Requester:     c.Actor.Subject,
		RequesterKind: c.Actor.Kind,
		ResourceMRN:   resourceMRN,
	})
	if err != nil {
		s.recordFailure(ctx, c, store.ActionDynamicIssue, resourceMRN, err)
		return nil, err
	}

	if err := s.recordSuccess(ctx, c, audit.Event{
		Action:      store.ActionDynamicIssue,
		ResourceMRN: resourceMRN,
		Metadata:    dynamicLeaseMetadata(lease),
	}); err != nil {
		// THE ACCOUNT EXISTS AND NOTHING RECORDS IT. Returning the credential would
		// leave a live database role whose issuance is unprovable; returning an error
		// while leaving it live would leave one nobody knows to revoke. So it is revoked
		// here, which is the only outcome that ends with no unaccounted account.
		//
		// The revocation's own failure is deliberately swallowed into the audit error
		// rather than replacing it: the caller needs to know the issue did not succeed,
		// and the lease row survives with an incremented attempt count and an error, so
		// the reaper keeps trying and an operator can see the stranded account. Reporting
		// the revoke failure instead would hide the reason the issue was abandoned.
		if _, rerr := s.store.RevokeDynamicLease(ctx, s.opts.Provisioner, c.TenantUUID, lease.UUID, store.DynamicRevokeExplicit); rerr != nil {
			s.recordFailure(ctx, c, store.ActionDynamicRevoke, resourceMRN, rerr)
		}
		return nil, err
	}
	return &IssuedCredential{Credential: cred, Lease: lease}, nil
}

// dynamicLeaseMetadata renders a lease for an audit row.
//
// db_role_name IS recorded and the password is NOT. That pairing is the whole point:
// the role name is what a revocation needs and what an operator greps pg_roles for, and
// it discloses nothing on its own — the account it names cannot be logged into without
// the password, which exists in exactly one response and nowhere else.
func dynamicLeaseMetadata(lease *store.DynamicLease) map[string]any {
	if lease == nil {
		return nil
	}
	return map[string]any{
		"lease_uuid":     lease.UUID.String(),
		"db_role_name":   lease.RoleName,
		"requester":      lease.Requester,
		"requester_kind": lease.RequesterKind,
		"expires_at":     lease.ExpiresAt.UTC().Format(time.RFC3339),
	}
}

// RevokeDynamicCredential drops the database role and closes the lease.
//
// It requires secret:IssueDynamicCredential, the SAME grant as issuing, and that is
// deliberate: a workload giving back the credential it asked for is the ordinary end of
// the lifecycle, and putting revocation behind the management grant would mean the only
// principal able to clean up is one no workload holds — so credentials would be left to
// expire instead of being returned. Revoking is strictly the safe direction.
//
// The store is idempotent on an already-revoked lease, so a retry reports success rather
// than a conflict: making the safe action look like a failure teaches callers not to
// take it.
func (s *Service) RevokeDynamicCredential(ctx context.Context, c Caller, in RevokeDynamicCredentialInput) (*store.DynamicLease, error) {
	if err := validate(in); err != nil {
		return nil, err
	}
	// Parsed after validation, so the is.UUID rule owns the message both transports
	// return. The error is unreachable — the rule already proved the shape.
	leaseUUID, err := uuid.Parse(in.LeaseUUID)
	if err != nil {
		return nil, apperror.NewValidation("lease_uuid must be a valid UUID")
	}
	// Authorized against the ROLE, not the lease: a lease has no resource path of its
	// own (see internal/store/resources.go), because it is an instrument of the role it
	// was issued against. The lease is additionally resolved inside the caller's own
	// tenant by the store's tenant-scoped query, so naming another tenant's lease UUID
	// is a not-found rather than a cross-tenant revoke.
	resourceMRN := c.mrn(in.Project, store.DynamicRoleResourcePath(in.Name))
	if err := s.guard(ctx, c, permissions.PermIssueDynamicCredential, store.ActionDynamicRevoke, resourceMRN); err != nil {
		return nil, err
	}
	lease, err := s.store.RevokeDynamicLease(ctx, s.opts.Provisioner, c.TenantUUID, leaseUUID, store.DynamicRevokeExplicit)
	if err != nil {
		s.recordFailure(ctx, c, store.ActionDynamicRevoke, resourceMRN, err)
		return nil, err
	}
	if err := s.recordSuccess(ctx, c, audit.Event{
		Action:      store.ActionDynamicRevoke,
		ResourceMRN: resourceMRN,
		Metadata: map[string]any{
			"lease_uuid":   lease.UUID.String(),
			"db_role_name": lease.RoleName,
			"reason":       store.DynamicRevokeExplicit,
		},
	}); err != nil {
		return nil, err
	}
	return lease, nil
}

// ListDynamicLeases pages one role's lease history, newest first.
//
// Requires secret:ReadMetadata. The rows are metadata — who holds a credential, until
// when, whether a revocation is stranded — and that IS the answer to "which accounts
// this service created are live against the production database right now", which
// nothing else can give. store.DynamicLease has no password field and no column behind
// one, so this cannot leak a credential structurally rather than by filtering.
func (s *Service) ListDynamicLeases(ctx context.Context, c Caller, in ListDynamicLeasesInput) ([]store.DynamicLease, int64, error) {
	if err := validate(in); err != nil {
		return nil, 0, err
	}
	page, limit := in.Pagination.resolved()
	resourceMRN := c.mrn(in.Project, store.DynamicRoleResourcePath(in.Name))
	if err := s.guard(ctx, c, permissions.PermReadMetadata, store.ActionRead, resourceMRN); err != nil {
		return nil, 0, err
	}
	leases, total, err := s.store.ListDynamicLeases(ctx, c.TenantUUID, in.Project, in.Name, page, limit)
	if err != nil {
		s.recordFailure(ctx, c, store.ActionRead, resourceMRN, err)
		return nil, 0, err
	}
	if err := s.recordSuccess(ctx, c, audit.Event{
		Action:      store.ActionRead,
		ResourceMRN: resourceMRN,
		Metadata:    map[string]any{"read": "dynamic_leases", "returned": len(leases), "total": total},
	}); err != nil {
		return nil, 0, err
	}
	return leases, total, nil
}

// ---------------------------------------------------------------------------
// The reaper's engine
// ---------------------------------------------------------------------------

// reaperActor is the identity an expiry-driven revocation is recorded under. It is a
// service actor for the same reason scheduledActor is: no principal asked for this.
var reaperActor = audit.Actor{
	Subject: "maintainerd-secret/dynamic-reaper",
	Kind:    store.ActorKindService,
}

// ReapExpiredDynamicLeases revokes every dynamic lease whose TTL has run out, and is
// what makes a dynamic credential actually short-lived.
//
// WITHOUT IT THE TTL IS A COMMENT. Issuing a credential creates a real PostgreSQL role;
// the lease row records when it must stop existing, but a row expiring does not drop a
// role. This sweep is the only thing that does, so a service running without it
// accumulates live database accounts forever — the precise failure the feature exists to
// prevent, and an invisible one, because every issue and every read keeps working.
//
// IT PERFORMS NO PERMISSION CHECK, and like RotateDueSecrets that is correct rather than
// an omission: there is no caller. The authorization decision was made when an authorized
// principal configured the role and when a principal holding
// secret:IssueDynamicCredential issued against it. What it does do unconditionally is
// write an audit row per revocation, attributed to the reaper — so "this account was
// dropped by expiry" and "a human revoked it" stay distinguishable during a review.
//
// A FAILED REVOCATION LEAVES THE LEASE OPEN. The store increments an attempt counter and
// does not mark the row revoked, because a revocation the target database refused has not
// happened, and recording it as done would destroy the only record that a live account
// still needs dropping. That is why Failed is reported separately from Skipped: Failed is
// retried on the next pass, Skipped needs an operator.
func (s *Service) ReapExpiredDynamicLeases(ctx context.Context, limit int) (dynamic.ReapReport, error) {
	var out dynamic.ReapReport
	if s.auditor == nil {
		return out, audit.ErrNoAuditor
	}
	// Reported as Skipped rather than as an error: an instance with no provisioner
	// configured cannot have issued anything, so there is nothing overdue to chase, and
	// failing the pass would log an error every interval forever.
	if s.opts.Provisioner == nil {
		return out, nil
	}
	due, err := s.store.ListExpiredDynamicLeases(ctx, limit)
	if err != nil {
		return out, err
	}
	out.Due = len(due)

	for _, lease := range due {
		tenantUUID := lease.TenantUUID
		if rerr := s.store.RevokeExpiredDynamicLease(ctx, s.opts.Provisioner, lease); rerr != nil {
			// FAILED VERSUS SKIPPED IS "WAS THE TARGET CONTACTED", which is the
			// distinction ReapReport documents, and it is not the same as the error's HTTP
			// class: the store maps a provisioner REFUSAL to Unavailable as well, so
			// keying on Unavailable would file every refused DROP ROLE under "an operator
			// must fix the configuration" and the retry signal would be lost in it.
			//
			// A missing role config or a deleted DSN secret (NotFound) and a template that
			// no longer renders (Validation) both fail BEFORE the target is dialled, and
			// no number of retries changes that — those are Skipped. Everything else got
			// as far as the database, so it is Failed and worth retrying next pass.
			if apperror.IsNotFound(rerr) || apperror.IsValidation(rerr) {
				out.Skipped++
			} else {
				out.Failed++
			}
			slog.Warn("dynamic reaper: a credential is live past its expiry",
				"mrn", lease.ResourceMRN, "lease_uuid", lease.LeaseUUID.String(),
				"attempts", lease.RevokeAttempts, "error", rerr)
			s.auditor.RecordError(ctx, reaperActor, audit.Event{
				TenantUUID:  &tenantUUID,
				Action:      store.ActionDynamicRevoke,
				ResourceMRN: lease.ResourceMRN,
				Reason:      redactedReason(rerr),
				Metadata: map[string]any{
					"lease_uuid": lease.LeaseUUID.String(),
					"reason":     store.DynamicRevokeExpired,
					"attempts":   lease.RevokeAttempts,
				},
			})
			continue
		}
		out.Revoked++
		// Unlike a caller-facing operation, an audit failure here does NOT undo the work:
		// the role is already dropped, and re-creating it to preserve a clean trail would
		// put a live credential back. It is logged loudly instead.
		if aerr := s.auditor.Record(ctx, reaperActor, audit.Event{
			TenantUUID:  &tenantUUID,
			Action:      store.ActionDynamicRevoke,
			ResourceMRN: lease.ResourceMRN,
			Outcome:     store.OutcomeSuccess,
			Metadata: map[string]any{
				"lease_uuid":   lease.LeaseUUID.String(),
				"db_role_name": lease.RoleName,
				"requester":    lease.Requester,
				"reason":       store.DynamicRevokeExpired,
				"late_by":      time.Since(lease.ExpiresAt).Truncate(time.Second).String(),
			},
		}); aerr != nil {
			slog.Error("dynamic reaper: revoked a credential but could not record it",
				"mrn", lease.ResourceMRN, "error", aerr)
		}
	}
	return out, nil
}
