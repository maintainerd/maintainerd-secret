package api

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/maintainerd/secret/internal/audit"
	"github.com/maintainerd/secret/internal/platform/apperror"
	"github.com/maintainerd/secret/internal/platform/permissions"
	"github.com/maintainerd/secret/internal/store"
)

// SecretAddress is how a caller names a secret across every surface: project,
// environment, folder path, key. It is the transport-facing twin of store.SecretRef,
// which additionally carries the resolved tenant UUID.
type SecretAddress struct {
	Project     string `json:"project"`
	Environment string `json:"environment"`
	FolderPath  string `json:"folder_path,omitempty"`
	Key         string `json:"key"`
}

func (a SecretAddress) ref(c Caller) store.SecretRef {
	return store.SecretRef{
		TenantUUID:  c.TenantUUID,
		Project:     a.Project,
		Environment: a.Environment,
		FolderPath:  a.FolderPath,
		Key:         a.Key,
	}
}

// ---------------------------------------------------------------------------
// Reveal
// ---------------------------------------------------------------------------

// Revealed is a decrypted secret leaving the service. The value is a
// crypto.Plaintext inside store.RevealedSecret, which renders as "[REDACTED]"
// through every stringly and marshalling path; the caller must Zero it.
type Revealed struct {
	Secret *store.RevealedSecret
	// ReferenceHops names the MRNs a reference chain traversed to produce this
	// value, in order. Empty for an ordinary secret. It is returned so a caller can
	// see what it actually read — a reference is an indirection, and "which secret
	// did this value really come from" is not otherwise answerable.
	ReferenceHops []string
}

// Reveal decrypts and returns a value. THIS IS THE PATH THE WHOLE SERVICE EXISTS TO
// PROTECT, and it is the one with the strictest contract:
//
//   - It requires secret:GetSecret — a DISTINCT grant from secret:ReadMetadata. A
//     principal that can describe every secret in prod may hold no ability to read
//     one, and that is the normal, intended configuration.
//   - It refuses to run without an auditor. Not "skips the audit" — refuses.
//   - It refuses to SUCCEED without an audit row: if the audit write fails, the
//     decrypted value is zeroized and an error is returned. A caller that receives a
//     value has, by construction, produced a row in audit_log.
//   - A reference value is resolved here, re-checking secret:GetSecret at every hop,
//     so a reference can never be a privilege-escalation path.
//
// version 0 means the current version; any other value is the pinning path for a
// consumer that cannot hot-reload.
func (s *Service) Reveal(ctx context.Context, c Caller, addr SecretAddress, version int32) (*Revealed, error) {
	// Checked FIRST, before the address is even resolved: an unauditable service
	// must not perform a reveal, and it must not perform the reads that lead up to
	// one either.
	if s.auditor == nil {
		return nil, audit.ErrNoAuditor
	}
	if err := validate(RevealSecretInput{Address: addr, Version: version}); err != nil {
		return nil, err
	}
	// Scope imports are resolved BEFORE the permission check, and the check is made
	// against the secret that will actually be decrypted — see internal/api/imports.go
	// for why authorization has to follow the value rather than the address.
	resolved, err := s.resolveThroughImports(ctx, c, addr)
	if err != nil {
		return nil, err
	}
	ref := resolved.addr.ref(c)
	resourceMRN := resolved.mrn
	if err := s.guard(ctx, c, permissions.PermGetSecret, store.ActionReveal, resourceMRN); err != nil {
		return nil, err
	}

	var revealed *store.RevealedSecret
	if version == 0 {
		revealed, err = s.store.GetSecret(ctx, ref)
	} else {
		revealed, err = s.store.GetSecretVersion(ctx, ref, version)
	}
	if err != nil {
		s.recordFailure(ctx, c, store.ActionReveal, resourceMRN, err)
		return nil, err
	}

	out := &Revealed{Secret: revealed}

	// A reference is resolved BEFORE the audit row is written, so the row records
	// what the caller actually obtained. Each hop writes its own row too (see
	// resolveReferences), which is what makes "who saw the underlying value"
	// answerable rather than merely "who read the pointer".
	if revealed.ValueType == store.ValueTypeReference {
		resolved, hops, rerr := s.resolveReferences(ctx, c, resourceMRN, revealed.Value.Bytes())
		if rerr != nil {
			revealed.Zero()
			s.recordFailure(ctx, c, store.ActionReveal, resourceMRN, rerr)
			return nil, rerr
		}
		// The pointer text is no longer needed and is overwritten before the resolved
		// value replaces it.
		revealed.Zero()
		revealed.Value = resolved
		out.ReferenceHops = hops
	}

	if err := s.recordSuccess(ctx, c, audit.Event{
		Action:      store.ActionReveal,
		ResourceMRN: resourceMRN,
		SecretUUID:  &revealed.Meta.UUID,
		Version:     int32Ptr(revealed.Version),
		Metadata:    revealMetadata(revealed, out.ReferenceHops, resolved),
	}); err != nil {
		// The audit write failed. The value is destroyed rather than returned: a
		// reveal nobody can prove happened is the one outcome this service must not
		// produce.
		revealed.Zero()
		return nil, err
	}
	return out, nil
}

// revealMetadata records the structural facts of a reveal. Every value here is a
// number, a type name or an MRN — never a payload.
//
// imported_from is recorded when the value came from a scope import, because "the
// caller asked staging for this key and received dev's value" is a fact an incident
// review cannot reconstruct from the resource MRN alone.
func revealMetadata(revealed *store.RevealedSecret, hops []string, resolved resolvedAddress) map[string]any {
	meta := map[string]any{"value_type": revealed.ValueType}
	if len(hops) > 0 {
		meta["reference_hops"] = hops
	}
	if resolved.importedFrom != "" {
		meta["imported_from"] = resolved.importedFrom
	}
	return meta
}

// ---------------------------------------------------------------------------
// Describe / list
// ---------------------------------------------------------------------------

// DescribeSecret returns metadata for one secret. Requires secret:ReadMetadata and
// NEVER returns a value — the store path it uses does not read secret_versions at
// all, so there is no value to accidentally include.
//
// It resolves scope imports like Reveal does, so a describe against staging answers
// for the dev secret staging inherits, and the returned metadata (including the MRN)
// is that of the secret a reveal would actually decrypt. Reporting staging's address
// with dev's rotation timestamps would be worse than either answer alone.
func (s *Service) DescribeSecret(ctx context.Context, c Caller, addr SecretAddress) (*store.SecretMeta, error) {
	if err := validate(addr); err != nil {
		return nil, err
	}
	resolved, err := s.resolveThroughImports(ctx, c, addr)
	if err != nil {
		return nil, err
	}
	resourceMRN := resolved.mrn
	if err := s.guard(ctx, c, permissions.PermReadMetadata, store.ActionRead, resourceMRN); err != nil {
		return nil, err
	}
	meta, err := s.store.DescribeSecret(ctx, resolved.addr.ref(c))
	if err != nil {
		s.recordFailure(ctx, c, store.ActionRead, resourceMRN, err)
		return nil, err
	}
	auditMeta := map[string]any{}
	if resolved.importedFrom != "" {
		auditMeta["imported_from"] = resolved.importedFrom
	}
	if err := s.recordSuccess(ctx, c, audit.Event{
		Action:      store.ActionRead,
		ResourceMRN: resourceMRN,
		SecretUUID:  &meta.UUID,
		Version:     int32Ptr(meta.CurrentVersion),
		Metadata:    auditMeta,
	}); err != nil {
		return nil, err
	}
	return meta, nil
}

// ListSecretsInput scopes a listing.
type ListSecretsInput struct {
	Project     string
	Environment string
	// PathPrefix limits the listing to a folder and its descendants. Empty or "/"
	// lists the whole environment.
	PathPrefix string
	Page       int
	Limit      int
}

// ListSecrets returns METADATA ONLY for a scope.
//
// It is authorized against the FOLDER's MRN, not the environment's, so a grant
// scoped to folder/prod/db lets a principal list that subtree and nothing else. And
// it returns []store.SecretMeta — a type with no value field — so "listing cannot
// leak a value" holds structurally rather than by filtering.
func (s *Service) ListSecrets(ctx context.Context, c Caller, in ListSecretsInput) ([]store.SecretMeta, int64, error) {
	if err := validate(in); err != nil {
		return nil, 0, err
	}
	page, limit := Pagination{Page: in.Page, Limit: in.Limit}.resolved()
	names, err := s.store.ResolveScopeNames(ctx, c.TenantUUID, in.Project, in.Environment)
	if err != nil {
		return nil, 0, err
	}
	prefix, err := store.NormalizePath(in.PathPrefix)
	if err != nil {
		return nil, 0, apperror.NewValidation(err.Error())
	}
	resourceMRN := c.mrn(names.Project, store.FolderResourcePath(names.Environment, prefix))
	if err := s.guard(ctx, c, permissions.PermListSecrets, store.ActionList, resourceMRN); err != nil {
		return nil, 0, err
	}
	metas, total, err := s.store.ListSecrets(ctx, store.ListSecretsInput{
		TenantUUID:  c.TenantUUID,
		Project:     in.Project,
		Environment: in.Environment,
		PathPrefix:  prefix,
		Page:        page,
		Limit:       limit,
	})
	if err != nil {
		s.recordFailure(ctx, c, store.ActionList, resourceMRN, err)
		return nil, 0, err
	}
	if err := s.recordSuccess(ctx, c, audit.Event{
		Action:      store.ActionList,
		ResourceMRN: resourceMRN,
		Metadata:    map[string]any{"returned": len(metas), "total": total},
	}); err != nil {
		return nil, 0, err
	}
	return metas, total, nil
}

// ListVersions returns a secret's version history as metadata: version numbers,
// which root key wrapped each, and each one's checksum. No payloads — browsing
// history must never be a way to pull every value a credential has ever held, which
// is why this needs only ReadMetadata.
func (s *Service) ListVersions(ctx context.Context, c Caller, in ListVersionsInput) ([]store.VersionMeta, int64, error) {
	if err := validate(in); err != nil {
		return nil, 0, err
	}
	page, limit := in.Pagination.resolved()
	ref := in.Address.ref(c)
	resourceMRN, err := s.store.SecretMRN(ctx, ref)
	if err != nil {
		return nil, 0, err
	}
	if err := s.guard(ctx, c, permissions.PermReadMetadata, store.ActionRead, resourceMRN); err != nil {
		return nil, 0, err
	}
	versions, total, err := s.store.ListVersions(ctx, ref, page, limit)
	if err != nil {
		s.recordFailure(ctx, c, store.ActionRead, resourceMRN, err)
		return nil, 0, err
	}
	if err := s.recordSuccess(ctx, c, audit.Event{
		Action:      store.ActionRead,
		ResourceMRN: resourceMRN,
		Metadata:    map[string]any{"versions": len(versions), "total": total},
	}); err != nil {
		return nil, 0, err
	}
	return versions, total, nil
}

// ---------------------------------------------------------------------------
// Write
// ---------------------------------------------------------------------------

// PutSecretInput is a write.
type PutSecretInput struct {
	Address SecretAddress
	// Value is the plaintext. The caller owns zeroizing it after the call.
	Value     []byte
	ValueType string
	// The fields below are applied only when the secret is CREATED, matching the
	// store's contract: a routine value rotation must not be able to silently reset
	// a secret's retention or expiry by omitting a field.
	Description    string
	Tags           []string
	KeepVersions   *int32
	RotationPolicy map[string]any
	ExpiresAt      *time.Time
	CreateFolders  bool
}

// PutSecret writes a value, creating the secret on first write and appending an
// immutable version on every subsequent one.
//
// A rotation policy supplied here is VALIDATED rather than passed through. Two
// reasons: a malformed interval silently means "never rotates" (the operator
// believes otherwise), and a policy carrying a generator `value` would put a
// plaintext credential into readable metadata.
func (s *Service) PutSecret(ctx context.Context, c Caller, in PutSecretInput) (*store.PutResult, error) {
	// Validated before the MRN is resolved: resolving reads the database, and a
	// syntactically impossible address should not buy a caller a query. The rotation
	// policy is parsed by the DTO's rules (rotationPolicyMapRule), which is the same
	// refusal this method used to make inline.
	if err := validate(in); err != nil {
		return nil, err
	}
	ref := in.Address.ref(c)
	resourceMRN, err := s.store.SecretMRN(ctx, ref)
	if err != nil {
		return nil, err
	}
	if err := s.guard(ctx, c, permissions.PermPutSecret, store.ActionWrite, resourceMRN); err != nil {
		return nil, err
	}

	result, err := s.store.PutSecret(ctx, store.PutSecretInput{
		Ref:            ref,
		Value:          in.Value,
		ValueType:      in.ValueType,
		Description:    in.Description,
		Tags:           in.Tags,
		KeepVersions:   in.KeepVersions,
		RotationPolicy: in.RotationPolicy,
		ExpiresAt:      in.ExpiresAt,
		CreateFolders:  in.CreateFolders,
	})
	if err != nil {
		s.recordFailure(ctx, c, store.ActionWrite, resourceMRN, err)
		return nil, err
	}
	if err := s.recordSuccess(ctx, c, audit.Event{
		Action:      store.ActionWrite,
		ResourceMRN: resourceMRN,
		SecretUUID:  &result.SecretUUID,
		Version:     int32Ptr(result.Version),
		Metadata: map[string]any{
			"created":   result.Created,
			"unchanged": result.Unchanged,
			"pruned":    result.Pruned,
		},
	}); err != nil {
		return nil, err
	}
	// An unchanged write produced no new version, so there is nothing for a consumer
	// to re-read. Announcing it anyway would wake every subscriber on every pass of
	// every reconciler — which is exactly the storm the checksum no-op exists to
	// prevent.
	if !result.Unchanged {
		s.notify(ctx, c, in.Address.Project, store.WebhookEventSecretChanged, resourceMRN, result.Version)
	}
	return result, nil
}

// UpdateSecretMetaInput changes metadata without touching the value.
type UpdateSecretMetaInput struct {
	Address        SecretAddress
	Description    string
	Tags           []string
	KeepVersions   *int32
	RotationPolicy map[string]any
	ExpiresAt      *time.Time
}

// UpdateSecretMeta rewrites a secret's metadata. It requires PutSecret rather than
// ReadMetadata: retention and expiry decide when a value is destroyed, so editing
// them is a write to the secret in every sense that matters.
func (s *Service) UpdateSecretMeta(ctx context.Context, c Caller, in UpdateSecretMetaInput) (*store.SecretMeta, error) {
	if err := validate(in); err != nil {
		return nil, err
	}
	ref := in.Address.ref(c)
	resourceMRN, err := s.store.SecretMRN(ctx, ref)
	if err != nil {
		return nil, err
	}
	if err := s.guard(ctx, c, permissions.PermPutSecret, store.ActionMetadataUpdate, resourceMRN); err != nil {
		return nil, err
	}
	meta, err := s.store.UpdateSecretMeta(ctx, store.UpdateSecretMetaInput{
		Ref:            ref,
		Description:    in.Description,
		Tags:           in.Tags,
		KeepVersions:   in.KeepVersions,
		RotationPolicy: in.RotationPolicy,
		ExpiresAt:      in.ExpiresAt,
	})
	if err != nil {
		s.recordFailure(ctx, c, store.ActionMetadataUpdate, resourceMRN, err)
		return nil, err
	}
	if err := s.recordSuccess(ctx, c, audit.Event{
		Action:      store.ActionMetadataUpdate,
		ResourceMRN: resourceMRN,
		SecretUUID:  &meta.UUID,
	}); err != nil {
		return nil, err
	}
	return meta, nil
}

// Rollback makes an older version current again by writing a NEW version carrying
// the old plaintext — history is never mutated (see store.RollbackSecret).
//
// It requires BOTH PutSecret and GetSecret. The write permission is obvious; the
// reveal permission is the non-obvious and important half: a rollback reads a value
// the caller did not supply and republishes it as current. A principal that may
// write but not read could otherwise use a rollback as a read primitive — write a
// known value, roll back, and compare version checksums to learn what the old value
// was.
func (s *Service) Rollback(ctx context.Context, c Caller, addr SecretAddress, version int32) (*store.PutResult, error) {
	if err := validate(RollbackSecretInput{Address: addr, Version: version}); err != nil {
		return nil, err
	}
	ref := addr.ref(c)
	resourceMRN, err := s.store.SecretMRN(ctx, ref)
	if err != nil {
		return nil, err
	}
	if err := s.guard(ctx, c, permissions.PermPutSecret, store.ActionRollback, resourceMRN); err != nil {
		return nil, err
	}
	if err := s.guard(ctx, c, permissions.PermGetSecret, store.ActionRollback, resourceMRN); err != nil {
		return nil, err
	}
	result, err := s.store.RollbackSecret(ctx, ref, version)
	if err != nil {
		s.recordFailure(ctx, c, store.ActionRollback, resourceMRN, err)
		return nil, err
	}
	if err := s.recordSuccess(ctx, c, audit.Event{
		Action:      store.ActionRollback,
		ResourceMRN: resourceMRN,
		SecretUUID:  &result.SecretUUID,
		Version:     int32Ptr(result.Version),
		Metadata:    map[string]any{"restored_from_version": version, "unchanged": result.Unchanged},
	}); err != nil {
		return nil, err
	}
	if !result.Unchanged {
		s.notify(ctx, c, addr.Project, store.WebhookEventSecretChanged, resourceMRN, result.Version)
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// Delete / restore / destroy
// ---------------------------------------------------------------------------

// DeleteSecret soft-deletes a secret, opening its recovery window. Versions are
// untouched: until the window closes, Restore puts the secret back intact.
func (s *Service) DeleteSecret(ctx context.Context, c Caller, addr SecretAddress, window *time.Duration) (*store.DeletedSecret, error) {
	if err := validate(DeleteSecretInput{Address: addr, RecoveryWindow: window}); err != nil {
		return nil, err
	}
	ref := addr.ref(c)
	resourceMRN, err := s.store.SecretMRN(ctx, ref)
	if err != nil {
		return nil, err
	}
	if err := s.guard(ctx, c, permissions.PermDeleteSecret, store.ActionDelete, resourceMRN); err != nil {
		return nil, err
	}
	deleted, err := s.store.DeleteSecret(ctx, ref, window)
	if err != nil {
		s.recordFailure(ctx, c, store.ActionDelete, resourceMRN, err)
		return nil, err
	}
	if err := s.recordSuccess(ctx, c, audit.Event{
		Action:      store.ActionDelete,
		ResourceMRN: resourceMRN,
		SecretUUID:  &deleted.UUID,
		Version:     int32Ptr(deleted.CurrentVersion),
		Metadata:    map[string]any{"destroy_after": timeString(deleted.DestroyAfter)},
	}); err != nil {
		return nil, err
	}
	return deleted, nil
}

// ListDeletedSecrets returns what is still inside its recovery window, and until
// when. Metadata only.
func (s *Service) ListDeletedSecrets(ctx context.Context, c Caller, in ListDeletedSecretsInput) ([]store.DeletedSecret, error) {
	if err := validate(in); err != nil {
		return nil, err
	}
	page, limit := in.Pagination.resolved()
	names, err := s.store.ResolveScopeNames(ctx, c.TenantUUID, in.Project, in.Environment)
	if err != nil {
		return nil, err
	}
	resourceMRN := c.mrn(names.Project, store.EnvironmentResourcePath(names.Environment))
	if err := s.guard(ctx, c, permissions.PermListSecrets, store.ActionList, resourceMRN); err != nil {
		return nil, err
	}
	out, err := s.store.ListDeletedSecrets(ctx, c.TenantUUID, in.Project, in.Environment, page, limit)
	if err != nil {
		s.recordFailure(ctx, c, store.ActionList, resourceMRN, err)
		return nil, err
	}
	if err := s.recordSuccess(ctx, c, audit.Event{
		Action:      store.ActionList,
		ResourceMRN: resourceMRN,
		Metadata:    map[string]any{"deleted_secrets": len(out)},
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// RestoreSecret cancels a pending destruction.
//
// Addressed by UUID rather than by path, and that is not an inconsistency: the
// address uniqueness index covers LIVE rows only, so several deleted secrets can
// share one path and key and a restore by address would be ambiguous. The MRN is
// therefore resolved AFTER the restore, from the restored row.
func (s *Service) RestoreSecret(ctx context.Context, c Caller, in SecretUUIDInput) (*store.SecretMeta, error) {
	if err := validate(in); err != nil {
		return nil, err
	}
	// Parsed after validation, so the is.UUID rule owns the message both transports
	// return. The error is unreachable — the rule already proved the shape.
	secretUUID, err := uuid.Parse(in.SecretUUID)
	if err != nil {
		return nil, apperror.NewValidation("secret_uuid must be a valid UUID")
	}
	// A restore is authorized at TENANT scope because the target's project and
	// environment are not known until the row is read, and reading it to build a
	// narrower MRN would itself be the unauthorized act. The trade is explicit: a
	// path-scoped delete grant does not carry a restore, which must be granted at
	// tenant scope or wider.
	resourceMRN := c.mrn("", store.ResourceProject)
	if err := s.guard(ctx, c, permissions.PermDeleteSecret, store.ActionRestore, resourceMRN); err != nil {
		return nil, err
	}
	meta, err := s.store.RestoreSecret(ctx, c.TenantUUID, secretUUID)
	if err != nil {
		s.recordFailure(ctx, c, store.ActionRestore, resourceMRN, err)
		return nil, err
	}
	if err := s.recordSuccess(ctx, c, audit.Event{
		Action:      store.ActionRestore,
		ResourceMRN: meta.MRN,
		SecretUUID:  &meta.UUID,
		Version:     int32Ptr(meta.CurrentVersion),
	}); err != nil {
		return nil, err
	}
	return meta, nil
}

// DestroySecret permanently deletes a secret and every version of it. Irreversible,
// and refused until the recovery window has closed (checked in the store, twice).
func (s *Service) DestroySecret(ctx context.Context, c Caller, in SecretUUIDInput) error {
	if err := validate(in); err != nil {
		return err
	}
	secretUUID, err := uuid.Parse(in.SecretUUID)
	if err != nil {
		return apperror.NewValidation("secret_uuid must be a valid UUID")
	}
	resourceMRN := c.mrn("", store.ResourceProject)
	if err := s.guard(ctx, c, permissions.PermDeleteSecret, store.ActionDestroy, resourceMRN); err != nil {
		return err
	}
	if err := s.store.DestroySecret(ctx, c.TenantUUID, secretUUID); err != nil {
		s.recordFailure(ctx, c, store.ActionDestroy, resourceMRN, err)
		return err
	}
	return s.recordSuccess(ctx, c, audit.Event{
		Action:      store.ActionDestroy,
		ResourceMRN: resourceMRN,
		Metadata:    map[string]any{"secret_uuid": secretUUID.String()},
	})
}

func timeString(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
