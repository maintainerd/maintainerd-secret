package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/maintainerd/secret/internal/crypto"
	"github.com/maintainerd/secret/internal/platform/apperror"
	"github.com/maintainerd/secret/internal/storage"
)

// Value types a version's plaintext may be declared as.
const (
	ValueTypeOpaque = "opaque"
	ValueTypeJSON   = "json"
	// ValueTypeReference marks a plaintext that points at another secret rather
	// than being one — core's secret-typed template parameters resolve through this.
	ValueTypeReference = "reference"
)

// GUC reasons the append-only trigger on secret_versions accepts.
const (
	deleteReasonRetention = "retention"
	deleteReasonDestroy   = "secret_destroy"
)

// PutSecretInput is a write. Value is the plaintext; the caller owns zeroizing it
// after the call returns.
type PutSecretInput struct {
	Ref   SecretRef
	Value []byte
	// ValueType defaults to opaque.
	ValueType string
	// Description, Tags, KeepVersions, RotationPolicy and ExpiresAt are applied
	// when the secret is CREATED. Updating them on an existing secret is
	// UpdateSecretMeta's job, so that a routine value rotation cannot silently
	// reset a secret's retention or expiry by omitting fields.
	Description    string
	Tags           []string
	KeepVersions   *int32
	RotationPolicy map[string]any
	ExpiresAt      *time.Time
	// CreateFolders creates missing folders along Ref.FolderPath (mkdir -p).
	CreateFolders bool
}

// PutSecret writes a value, creating the secret on first write and appending an
// immutable version on every subsequent one.
//
// The whole operation is one transaction, and the order is load-bearing:
//
//  1. Lock the secret row (SELECT ... FOR UPDATE). Two concurrent writes would
//     otherwise both read the same current_version and the second would collide on
//     uq_secret_versions_secret_version.
//  2. Compare checksums. A write whose plaintext hashes to the current version's
//     checksum returns that version and writes NOTHING — see the note below.
//  3. Seal under a fresh DEK bound to (tenant, project, environment, folder, key,
//     NEW version) as AAD, and wrap the DEK under the active root key.
//  4. Insert the version, then advance current_version. Never update a version row.
//  5. Prune outside retention, through the sanctioned GUC, never the current one.
//
// WHY THE CHECKSUM NO-OP MATTERS. Rotation jobs and reconcilers are re-entrant by
// nature: they submit the value they believe is correct on every pass. Without
// change detection, a job that runs every five minutes writes 288 identical
// versions a day, retention silently discards the real history, and get-by-version
// becomes useless. Both Infisical and Vault behave this way, and it is the reason
// checksum is a stored column rather than something computed on read.
func (s *Service) PutSecret(ctx context.Context, in PutSecretInput) (*PutResult, error) {
	valueType := in.ValueType
	if valueType == "" {
		valueType = ValueTypeOpaque
	}
	switch valueType {
	case ValueTypeOpaque, ValueTypeJSON, ValueTypeReference:
	default:
		return nil, apperror.NewValidation(fmt.Sprintf("value type %q must be one of opaque, json, reference", valueType))
	}
	if in.Value == nil {
		return nil, apperror.NewValidation("secret value is required")
	}
	if err := ValidateKey(in.Ref.Key); err != nil {
		return nil, apperror.NewValidation(err.Error())
	}
	folderPath, err := NormalizePath(in.Ref.FolderPath)
	if err != nil {
		return nil, apperror.NewValidation(err.Error())
	}

	tags, err := encodeTags(in.Tags)
	if err != nil {
		return nil, apperror.NewValidation("tags are not serializable")
	}
	rotation, err := encodeObject(in.RotationPolicy)
	if err != nil {
		return nil, apperror.NewValidation("rotation policy is not serializable")
	}
	meta, err := encodeObject(nil)
	if err != nil {
		return nil, apperror.NewInternal("encode secret metadata", err)
	}
	if in.KeepVersions != nil && *in.KeepVersions < 1 {
		return nil, apperror.NewValidation("keep_versions must be at least 1")
	}

	incoming := crypto.Checksum(in.Value)
	var result PutResult

	err = s.repo.InTx(ctx, func(tx Repository) error {
		sc, err := s.resolveEnvironment(ctx, tx, in.Ref.TenantUUID, in.Ref.Project, in.Ref.Environment)
		if err != nil {
			return err
		}
		var folder storage.Folder
		if in.CreateFolders {
			folder, err = ensureFolderPath(ctx, tx, sc, folderPath)
		} else {
			folder, err = tx.GetFolderByPath(ctx, storage.GetFolderByPathParams{
				EnvironmentID: sc.environment.EnvironmentID,
				Path:          folderPath,
				TenantID:      sc.tenant.TenantID,
			})
			if err != nil {
				err = mapReadError(err, "folder")
			}
		}
		if err != nil {
			return err
		}
		addr := address{scope: sc, folder: folder, key: in.Ref.Key}

		row, err := tx.GetSecretByAddressForUpdate(ctx, storage.GetSecretByAddressForUpdateParams{
			TenantID:      sc.tenant.TenantID,
			EnvironmentID: sc.environment.EnvironmentID,
			FolderID:      folder.FolderID,
			Key:           in.Ref.Key,
		})
		switch {
		case err == nil:
			// Existing secret: check for a no-op before doing any crypto.
			latest, cerr := tx.GetLatestVersionChecksum(ctx, row.SecretID)
			if cerr != nil && !errors.Is(cerr, pgx.ErrNoRows) {
				return apperror.NewInternal("read current version checksum", cerr)
			}
			if cerr == nil && len(latest.Checksum) > 0 && bytes.Equal(latest.Checksum, incoming) {
				result = PutResult{SecretUUID: row.SecretUuid, Version: latest.Version, Unchanged: true}
				return nil
			}
		case errors.Is(err, pgx.ErrNoRows):
			created, cerr := tx.CreateSecret(ctx, storage.CreateSecretParams{
				TenantID:        sc.tenant.TenantID,
				ProjectID:       sc.project.ProjectID,
				EnvironmentID:   sc.environment.EnvironmentID,
				FolderID:        folder.FolderID,
				MrnService:      "secret",
				MrnTenant:       sc.tenant.Name,
				MrnProject:      sc.project.Slug,
				MrnResourcePath: addr.mrnResourcePath(),
				Key:             in.Ref.Key,
				Description:     in.Description,
				Tags:            tags,
				KeepVersions:    int4(in.KeepVersions),
				RotationPolicy:  rotation,
				ExpiresAt:       timestamptz(in.ExpiresAt),
				Metadata:        meta,
			})
			if cerr != nil {
				return mapWriteError(cerr, "secret", fmt.Sprintf("secret %q already exists at %s", in.Ref.Key, folderPath))
			}
			row = created
			result.Created = true
		default:
			return apperror.NewInternal("read secret", err)
		}

		nextVersion := row.CurrentVersion + 1
		// row.SecretUuid is available on both branches above — an existing secret was
		// read, a new one was just created — which is why the row must exist before
		// the payload is sealed: the secret's UUID is part of the AAD.
		envelope, err := crypto.Seal(s.ring.Active(), addr.identity(row.SecretUuid, nextVersion), in.Value)
		if err != nil {
			// crypto errors never contain the value; safe to wrap.
			return apperror.NewInternal("seal secret version", err)
		}

		if _, err := tx.CreateSecretVersion(ctx, storage.CreateSecretVersionParams{
			SecretID:   row.SecretID,
			Version:    nextVersion,
			Ciphertext: envelope.Ciphertext,
			Nonce:      envelope.Nonce,
			DekWrapped: envelope.DEKWrapped,
			DekNonce:   envelope.DEKNonce,
			KekID:      envelope.KEKID,
			ValueType:  valueType,
			Checksum:   envelope.Checksum,
		}); err != nil {
			return mapWriteError(err, "secret version", fmt.Sprintf("version %d of %q already exists", nextVersion, in.Ref.Key))
		}

		updated, err := tx.SetSecretCurrentVersion(ctx, storage.SetSecretCurrentVersionParams{
			CurrentVersion: nextVersion,
			// Version 1 is a creation, not a rotation. Everything after it is.
			MarkRotated: nextVersion > 1,
			TenantID:    sc.tenant.TenantID,
			SecretID:    row.SecretID,
		})
		if err != nil {
			return mapReadError(err, "secret")
		}

		pruned, err := pruneVersions(ctx, tx, updated, s.effectiveKeepVersions(updated))
		if err != nil {
			return err
		}

		result.SecretUUID = updated.SecretUuid
		result.Version = nextVersion
		result.Pruned = pruned
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// GetSecret decrypts and returns the current version.
//
// The caller must call Zero on the result when finished with it.
func (s *Service) GetSecret(ctx context.Context, ref SecretRef) (*RevealedSecret, error) {
	return s.getVersion(ctx, ref, 0)
}

// GetSecretVersion decrypts and returns a specific version — the pinning path for
// consumers that cannot hot-reload.
func (s *Service) GetSecretVersion(ctx context.Context, ref SecretRef, version int32) (*RevealedSecret, error) {
	if version < 1 {
		return nil, apperror.NewValidation("version must be at least 1")
	}
	return s.getVersion(ctx, ref, version)
}

// getVersion is the single decrypt path. version 0 means "the latest".
//
// There is deliberately no second, faster route to a plaintext: one function means
// one place where the root key is used, one place where the AAD identity is built,
// and one place an audit hook attaches when the API layer lands.
func (s *Service) getVersion(ctx context.Context, ref SecretRef, version int32) (*RevealedSecret, error) {
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

	var versionRow storage.SecretVersion
	if version == 0 {
		versionRow, err = s.repo.GetLatestSecretVersion(ctx, row.SecretID)
	} else {
		versionRow, err = s.repo.GetSecretVersion(ctx, storage.GetSecretVersionParams{
			SecretID: row.SecretID,
			Version:  version,
		})
	}
	if err != nil {
		return nil, mapReadError(err, "secret version")
	}

	// Resolve the key that wrapped THIS version, not the active key. During a
	// rotation these differ, and reads must keep working throughout.
	provider, err := s.ring.Provider(versionRow.KekID)
	if err != nil {
		return nil, apperror.NewUnavailable(err.Error())
	}

	plaintext, err := crypto.Open(provider, addr.identity(row.SecretUuid, versionRow.Version), crypto.Envelope{
		Ciphertext: versionRow.Ciphertext,
		Nonce:      versionRow.Nonce,
		DEKWrapped: versionRow.DekWrapped,
		DEKNonce:   versionRow.DekNonce,
		KEKID:      versionRow.KekID,
		Checksum:   versionRow.Checksum,
	})
	if err != nil {
		return nil, apperror.NewInternal("decrypt secret version", err)
	}

	return &RevealedSecret{
		Meta:      secretRowToMeta(row, addr.folder.Path, s.policy.KeepVersions),
		Version:   versionRow.Version,
		ValueType: versionRow.ValueType,
		Value:     plaintext,
	}, nil
}

// ListSecretsInput scopes a listing.
type ListSecretsInput struct {
	TenantUUID  uuid.UUID
	Project     string
	Environment string
	// PathPrefix limits the listing to a folder and its descendants. Empty or "/"
	// lists the whole environment.
	PathPrefix string
	Page       int
	Limit      int
}

// ListSecrets returns METADATA ONLY, scoped to a tenant, an environment and a path
// prefix.
//
// No value is returned and none is decrypted — not filtered out afterwards, but
// never fetched: the query selects an explicit column list from `secrets`, a table
// that has no payload column at all (payloads live in secret_versions). Listing is
// the most frequently called read in a vault and the one most likely to be exposed
// broadly, so it must not be a bulk-decryption endpoint by accident.
func (s *Service) ListSecrets(ctx context.Context, in ListSecretsInput) ([]SecretMeta, int64, error) {
	prefix, err := NormalizePath(in.PathPrefix)
	if err != nil {
		return nil, 0, apperror.NewValidation(err.Error())
	}
	sc, err := s.resolveEnvironment(ctx, s.repo, in.TenantUUID, in.Project, in.Environment)
	if err != nil {
		return nil, 0, err
	}
	page, limit := normalizePage(in.Page, in.Limit)

	rows, err := s.repo.ListSecretMetaBySubtree(ctx, storage.ListSecretMetaBySubtreeParams{
		TenantID:      sc.tenant.TenantID,
		EnvironmentID: sc.environment.EnvironmentID,
		Path:          prefix,
		PathPattern:   SubtreePattern(prefix),
		RowLimit:      int32(limit),
		RowOffset:     int32((page - 1) * limit),
	})
	if err != nil {
		return nil, 0, apperror.NewInternal("list secrets", err)
	}
	total, err := s.repo.CountSecretsInSubtree(ctx, storage.CountSecretsInSubtreeParams{
		TenantID:      sc.tenant.TenantID,
		EnvironmentID: sc.environment.EnvironmentID,
		Path:          prefix,
		PathPattern:   SubtreePattern(prefix),
	})
	if err != nil {
		return nil, 0, apperror.NewInternal("count secrets", err)
	}
	out := make([]SecretMeta, 0, len(rows))
	for _, r := range rows {
		out = append(out, toSecretMeta(r, s.policy.KeepVersions))
	}
	return out, total, nil
}

// ListVersions returns a secret's version history as metadata — version numbers,
// which root key wrapped each, and each one's checksum. No payloads: history is
// browsable without being a way to pull every value a credential has ever held.
func (s *Service) ListVersions(ctx context.Context, ref SecretRef, page, limit int) ([]VersionMeta, int64, error) {
	addr, err := s.resolveAddress(ctx, s.repo, ref)
	if err != nil {
		return nil, 0, err
	}
	row, err := s.repo.GetSecretByAddress(ctx, storage.GetSecretByAddressParams{
		TenantID:      addr.tenant.TenantID,
		EnvironmentID: addr.environment.EnvironmentID,
		FolderID:      addr.folder.FolderID,
		Key:           addr.key,
	})
	if err != nil {
		return nil, 0, mapReadError(err, "secret")
	}
	page, limit = normalizePage(page, limit)
	rows, err := s.repo.ListSecretVersionMeta(ctx, storage.ListSecretVersionMetaParams{
		SecretID: row.SecretID,
		Limit:    int32(limit),
		Offset:   int32((page - 1) * limit),
	})
	if err != nil {
		return nil, 0, apperror.NewInternal("list secret versions", err)
	}
	total, err := s.repo.CountSecretVersions(ctx, row.SecretID)
	if err != nil {
		return nil, 0, apperror.NewInternal("count secret versions", err)
	}
	out := make([]VersionMeta, 0, len(rows))
	for _, r := range rows {
		out = append(out, toVersionMeta(r))
	}
	return out, total, nil
}

// UpdateSecretMetaInput changes a secret's metadata without touching its value.
type UpdateSecretMetaInput struct {
	Ref            SecretRef
	Description    string
	Tags           []string
	KeepVersions   *int32
	RotationPolicy map[string]any
	ExpiresAt      *time.Time
}

// UpdateSecretMeta rewrites a secret's metadata. Separate from PutSecret so a value
// rotation cannot change retention or expiry, and a metadata edit cannot create a
// version.
func (s *Service) UpdateSecretMeta(ctx context.Context, in UpdateSecretMetaInput) (*SecretMeta, error) {
	if in.KeepVersions != nil && *in.KeepVersions < 1 {
		return nil, apperror.NewValidation("keep_versions must be at least 1")
	}
	tags, err := encodeTags(in.Tags)
	if err != nil {
		return nil, apperror.NewValidation("tags are not serializable")
	}
	rotation, err := encodeObject(in.RotationPolicy)
	if err != nil {
		return nil, apperror.NewValidation("rotation policy is not serializable")
	}
	meta, err := encodeObject(nil)
	if err != nil {
		return nil, apperror.NewInternal("encode secret metadata", err)
	}

	addr, err := s.resolveAddress(ctx, s.repo, in.Ref)
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
	updated, err := s.repo.UpdateSecretMeta(ctx, storage.UpdateSecretMetaParams{
		Description:    in.Description,
		Tags:           tags,
		KeepVersions:   int4(in.KeepVersions),
		RotationPolicy: rotation,
		ExpiresAt:      timestamptz(in.ExpiresAt),
		Metadata:       meta,
		TenantID:       addr.tenant.TenantID,
		SecretUuid:     row.SecretUuid,
	})
	if err != nil {
		return nil, mapReadError(err, "secret")
	}
	out := secretRowToMeta(updated, addr.folder.Path, s.policy.KeepVersions)
	return &out, nil
}

// DeleteSecret soft-deletes a secret and opens its recovery window.
//
// The versions are not touched. That is the point of the model: until
// destroy_after passes, RestoreSecret puts the secret back with its full history
// intact, because nothing was destroyed.
func (s *Service) DeleteSecret(ctx context.Context, ref SecretRef, window *time.Duration) (*DeletedSecret, error) {
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
	destroyAfter := s.destroyAfter(window)
	deleted, err := s.repo.SoftDeleteSecret(ctx, storage.SoftDeleteSecretParams{
		DestroyAfter: pgtype.Timestamptz{Time: destroyAfter, Valid: true},
		TenantID:     addr.tenant.TenantID,
		SecretID:     row.SecretID,
	})
	if err != nil {
		return nil, mapReadError(err, "secret")
	}
	out := DeletedSecret{
		UUID:           deleted.SecretUuid,
		FolderPath:     addr.folder.Path,
		Key:            deleted.Key,
		CurrentVersion: deleted.CurrentVersion,
		DestroyAfter:   timePtr(deleted.DestroyAfter),
	}
	if deleted.DeletedAt.Valid {
		out.DeletedAt = deleted.DeletedAt.Time
	}
	return &out, nil
}

// ListDeletedSecrets returns what is still inside its recovery window, and until
// when.
//
// Addressed by UUID rather than path from here on, and that is not an inconsistency:
// the address uniqueness index covers LIVE rows only, so several deleted secrets can
// share one path and key. A restore by address would be ambiguous.
func (s *Service) ListDeletedSecrets(ctx context.Context, tenantUUID uuid.UUID, project, environment string, page, limit int) ([]DeletedSecret, error) {
	sc, err := s.resolveEnvironment(ctx, s.repo, tenantUUID, project, environment)
	if err != nil {
		return nil, err
	}
	page, limit = normalizePage(page, limit)
	rows, err := s.repo.ListDeletedSecretMeta(ctx, storage.ListDeletedSecretMetaParams{
		TenantID:      sc.tenant.TenantID,
		EnvironmentID: sc.environment.EnvironmentID,
		RowLimit:      int32(limit),
		RowOffset:     int32((page - 1) * limit),
	})
	if err != nil {
		return nil, apperror.NewInternal("list deleted secrets", err)
	}
	out := make([]DeletedSecret, 0, len(rows))
	for _, r := range rows {
		out = append(out, toDeletedSecret(r))
	}
	return out, nil
}

// RestoreSecret cancels a pending destruction, bringing the secret and every
// version back untouched.
func (s *Service) RestoreSecret(ctx context.Context, tenantUUID, secretUUID uuid.UUID) (*SecretMeta, error) {
	tenant, err := s.repo.GetTenantByUUID(ctx, tenantUUID)
	if err != nil {
		return nil, mapReadError(err, "tenant")
	}
	restored, err := s.repo.RestoreSecret(ctx, storage.RestoreSecretParams{
		TenantID:   tenant.TenantID,
		SecretUuid: secretUUID,
	})
	if err != nil {
		// A unique violation here means a NEW secret was created at the same
		// address while this one sat deleted. Surfacing that as a conflict is the
		// honest answer: silently renaming either one would be worse.
		return nil, mapWriteError(err, "secret", "a live secret already exists at this path and key; move or delete it before restoring")
	}
	folder, err := s.repo.GetFolderByID(ctx, storage.GetFolderByIDParams{
		FolderID: restored.FolderID,
		TenantID: tenant.TenantID,
	})
	if err != nil {
		return nil, mapReadError(err, "folder")
	}
	out := secretRowToMeta(restored, folder.Path, s.policy.KeepVersions)
	return &out, nil
}

// DestroySecret permanently deletes a secret and every version of it. Irreversible.
//
// Two independent guards, because there is no undo:
//
//   - The recovery window is checked here (to produce a useful error) AND in the
//     DELETE statement's WHERE clause, which compares against the database's own
//     now(). A caller with a skewed clock, or a future code path that forgets to
//     look, still cannot destroy early.
//   - The cascade into secret_versions is refused by the append-only trigger unless
//     the transaction has declared its intent through the GUC below. Deletion of
//     encrypted history is never an incidental side-effect of a DELETE.
func (s *Service) DestroySecret(ctx context.Context, tenantUUID, secretUUID uuid.UUID) error {
	tenant, err := s.repo.GetTenantByUUID(ctx, tenantUUID)
	if err != nil {
		return mapReadError(err, "tenant")
	}
	row, err := s.repo.GetDeletedSecretByUUID(ctx, storage.GetDeletedSecretByUUIDParams{
		TenantID:   tenant.TenantID,
		SecretUuid: secretUUID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Either it does not exist, or it is live. Both mean "there is nothing
			// here to destroy"; a live secret must be deleted first.
			return apperror.NewNotFound("deleted secret")
		}
		return apperror.NewInternal("read deleted secret", err)
	}
	if !row.DestroyAfter.Valid {
		return apperror.NewForbidden("secret has no scheduled destruction time and cannot be destroyed")
	}
	if row.DestroyAfter.Time.After(s.now()) {
		return apperror.NewForbidden(fmt.Sprintf(
			"secret is still inside its recovery window until %s and cannot be destroyed yet",
			row.DestroyAfter.Time.UTC().Format(time.RFC3339)))
	}

	return s.repo.InTx(ctx, func(tx Repository) error {
		if err := tx.AllowSecretVersionDelete(ctx, deleteReasonDestroy); err != nil {
			return apperror.NewInternal("authorize version destruction", err)
		}
		n, err := tx.HardDeleteSecret(ctx, storage.HardDeleteSecretParams{
			TenantID:   tenant.TenantID,
			SecretUuid: secretUUID,
		})
		if err != nil {
			return apperror.NewInternal("destroy secret", err)
		}
		if n == 0 {
			// The query's own now() disagreed with ours. Trust the database.
			return apperror.NewForbidden("secret is still inside its recovery window and cannot be destroyed yet")
		}
		return nil
	})
}

// PruneVersions applies retention to one secret outside of a write — the path a
// scheduled job or an operator uses after lowering a secret's KeepVersions.
func (s *Service) PruneVersions(ctx context.Context, ref SecretRef) (int, error) {
	addr, err := s.resolveAddress(ctx, s.repo, ref)
	if err != nil {
		return 0, err
	}
	var pruned int
	err = s.repo.InTx(ctx, func(tx Repository) error {
		row, err := tx.GetSecretByAddressForUpdate(ctx, storage.GetSecretByAddressForUpdateParams{
			TenantID:      addr.tenant.TenantID,
			EnvironmentID: addr.environment.EnvironmentID,
			FolderID:      addr.folder.FolderID,
			Key:           addr.key,
		})
		if err != nil {
			return mapReadError(err, "secret")
		}
		pruned, err = pruneVersions(ctx, tx, row, s.effectiveKeepVersions(row))
		return err
	})
	return pruned, err
}

// effectiveKeepVersions resolves the retention count for a secret: its own override
// if set, otherwise the service default. Never below 1.
func (s *Service) effectiveKeepVersions(row storage.Secret) int32 {
	keep := s.policy.KeepVersions
	if row.KeepVersions.Valid {
		keep = row.KeepVersions.Int32
	}
	if keep < 1 {
		keep = 1
	}
	return keep
}

// pruneVersions deletes the versions outside retention, oldest first.
//
// Must be called inside a transaction: AllowSecretVersionDelete sets a
// transaction-LOCAL GUC, so on a pooled connection outside a transaction the
// permission would either be lost before the delete or, worse, linger for whatever
// ran next. The trigger on secret_versions rejects the delete without it, which is
// the intended failure — history is append-only unless a caller says explicitly
// which sanctioned reason it is invoking.
//
// The current version is protected twice: excluded by number in the query, and
// always inside the newest-N window because it is always the highest version.
func pruneVersions(ctx context.Context, repo Repository, row storage.Secret, keep int32) (int, error) {
	prunable, err := repo.ListPrunableVersions(ctx, storage.ListPrunableVersionsParams{
		SecretID:       row.SecretID,
		CurrentVersion: row.CurrentVersion,
		KeepVersions:   keep,
	})
	if err != nil {
		return 0, apperror.NewInternal("list prunable versions", err)
	}
	if len(prunable) == 0 {
		return 0, nil
	}
	if err := repo.AllowSecretVersionDelete(ctx, deleteReasonRetention); err != nil {
		return 0, apperror.NewInternal("authorize version retention delete", err)
	}
	pruned := 0
	for _, v := range prunable {
		if v.Version == row.CurrentVersion {
			// Unreachable given the query, and checked anyway: this is the one
			// deletion that would destroy a live credential.
			continue
		}
		n, err := repo.DeleteSecretVersion(ctx, v.VersionID)
		if err != nil {
			return pruned, apperror.NewInternal("prune secret version", err)
		}
		pruned += int(n)
	}
	return pruned, nil
}
