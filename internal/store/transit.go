package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/maintainerd/secret/internal/crypto"
	"github.com/maintainerd/secret/internal/platform/apperror"
	"github.com/maintainerd/secret/internal/storage"
	"github.com/maintainerd/secret/internal/transit"
)

// Transit keys: the durable half of encryption-as-a-service.
//
// KEY MATERIAL IS SEALED EXACTLY LIKE A SECRET VERSION — a per-version DEK under the
// active root key, with the AAD identity bound to (tenant UUID, key UUID, version).
// That is not a stylistic echo of secrets.go; it is what makes root-key rotation cover
// transit keys with no new machinery, because crypto.Rewrap moves the wrap and never
// touches the sealed material.
//
// THE MATERIAL NEVER LEAVES THIS PACKAGE. It is decrypted into a crypto.Plaintext
// inside a single method, handed to internal/transit to seal or open one payload, and
// zeroized on every path out. There is no exported method here that returns it, no
// query in internal/storage that selects it outside the two reads below, and no
// export operation anywhere — see the internal/transit package doc for why that
// absence is the design rather than an omission.

// TransitKeyStatuses is the closed set.
const (
	TransitKeyStatusActive   = "active"
	TransitKeyStatusDisabled = "disabled"
)

// TransitKeyStatuses is the closed status set, exported so the API layer's validation
// lists exactly what this package accepts.
var TransitKeyStatuses = []string{TransitKeyStatusActive, TransitKeyStatusDisabled}

// TransitKey is a key as it leaves this package. There is no material field, and there
// cannot be one: this type cannot carry key bytes.
type TransitKey struct {
	UUID              uuid.UUID `json:"key_uuid"`
	Name              string    `json:"name"`
	Description       string    `json:"description"`
	CurrentVersion    int32     `json:"current_version"`
	Status            string    `json:"status"`
	MinDecryptVersion int32     `json:"min_decrypt_version"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// TransitKeyVersionMeta describes one key version without its material.
type TransitKeyVersionMeta struct {
	Version   int32     `json:"version"`
	KEKID     string    `json:"kek_id"`
	CreatedAt time.Time `json:"created_at"`
}

// CreateTransitKeyInput registers a key and generates its first version.
type CreateTransitKeyInput struct {
	TenantUUID  uuid.UUID
	Project     string
	Name        string
	Description string
}

// CreateTransitKey registers a key AND creates version 1, in one transaction.
//
// Both happen together because a key with no versions cannot encrypt anything: a
// half-created key would accept an Encrypt call, find no version, and fail with an
// internal error rather than telling the operator their key does not exist. This is
// the same argument CreateEnvironment makes for creating its root folder in the same
// transaction.
func (s *Service) CreateTransitKey(ctx context.Context, in CreateTransitKeyInput) (*TransitKey, error) {
	if err := ValidateTransitKeyName(in.Name); err != nil {
		return nil, apperror.NewValidation(err.Error())
	}
	meta, err := encodeObject(nil)
	if err != nil {
		return nil, apperror.NewInternal("encode transit key metadata", err)
	}
	tenant, project, err := s.resolveProject(ctx, in.TenantUUID, in.Project)
	if err != nil {
		return nil, err
	}

	var out TransitKey
	err = s.repo.InTx(ctx, func(tx Repository) error {
		row, err := tx.CreateTransitKey(ctx, storage.CreateTransitKeyParams{
			TenantID:          tenant.TenantID,
			ProjectID:         project.ProjectID,
			Name:              in.Name,
			Description:       in.Description,
			Status:            TransitKeyStatusActive,
			MinDecryptVersion: 1,
			Metadata:          meta,
		})
		if err != nil {
			return mapWriteError(err, "transit key",
				fmt.Sprintf("a transit key named %q already exists in this project", in.Name))
		}
		if err := s.sealTransitKeyVersion(ctx, tx, tenant.TenantUuid, row, 1); err != nil {
			return err
		}
		published, err := tx.SetTransitKeyCurrentVersion(ctx, storage.SetTransitKeyCurrentVersionParams{
			CurrentVersion: 1,
			TenantID:       tenant.TenantID,
			KeyID:          row.KeyID,
		})
		if err != nil {
			return mapReadError(err, "transit key")
		}
		out = toTransitKey(published)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// RotateTransitKey creates a NEW version and makes it current.
//
// OLD VERSIONS ARE KEPT AND STILL DECRYPT. That is the entire reason a transit key is
// versioned: a rotation that could no longer read its own history would make every
// ciphertext the calling application has stored unreadable — which is not a rotation,
// it is data loss with a reassuring name. New Encrypt calls use the new version; a
// token issued yesterday keeps opening under the version that sealed it, because the
// token carries that version.
func (s *Service) RotateTransitKey(ctx context.Context, tenantUUID uuid.UUID, project, name string) (*TransitKey, error) {
	tenant, proj, err := s.resolveProject(ctx, tenantUUID, project)
	if err != nil {
		return nil, err
	}

	var out TransitKey
	err = s.repo.InTx(ctx, func(tx Repository) error {
		// FOR UPDATE, because two concurrent rotations would otherwise both read the
		// same current_version and the second would collide on
		// uq_transit_key_versions_key_version. Same race GetSecretByAddressForUpdate
		// exists to serialize on the secret write path.
		row, err := tx.GetTransitKeyByNameForUpdate(ctx, storage.GetTransitKeyByNameForUpdateParams{
			TenantID:  tenant.TenantID,
			ProjectID: proj.ProjectID,
			Name:      name,
		})
		if err != nil {
			return mapReadError(err, "transit key")
		}
		next := row.CurrentVersion + 1
		if err := s.sealTransitKeyVersion(ctx, tx, tenant.TenantUuid, row, next); err != nil {
			return err
		}
		published, err := tx.SetTransitKeyCurrentVersion(ctx, storage.SetTransitKeyCurrentVersionParams{
			CurrentVersion: next,
			TenantID:       tenant.TenantID,
			KeyID:          row.KeyID,
		})
		if err != nil {
			return mapReadError(err, "transit key")
		}
		out = toTransitKey(published)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// sealTransitKeyVersion generates fresh key material, seals it, and inserts the version.
//
// The material is zeroized before this function returns on EVERY path, including the
// error paths — which is why the defer is set up before the first use rather than after
// the last.
func (s *Service) sealTransitKeyVersion(ctx context.Context, tx Repository, tenantUUID uuid.UUID, key storage.TransitKey, version int32) error {
	material, err := crypto.NewRandomKey()
	if err != nil {
		return apperror.NewInternal("generate transit key material", err)
	}
	defer crypto.Zero(material)

	envelope, err := crypto.Seal(s.ring.Active(), transitCryptoIdentity(tenantUUID, key.KeyUuid, version), material)
	if err != nil {
		return apperror.NewInternal("seal transit key material", err)
	}
	if _, err := tx.CreateTransitKeyVersion(ctx, storage.CreateTransitKeyVersionParams{
		KeyID:              key.KeyID,
		Version:            version,
		MaterialCiphertext: envelope.Ciphertext,
		MaterialNonce:      envelope.Nonce,
		MaterialDekWrapped: envelope.DEKWrapped,
		MaterialDekNonce:   envelope.DEKNonce,
		KekID:              envelope.KEKID,
	}); err != nil {
		return mapWriteError(err, "transit key version",
			fmt.Sprintf("version %d of transit key %q already exists", version, key.Name))
	}
	return nil
}

// GetTransitKey reads one key's metadata.
func (s *Service) GetTransitKey(ctx context.Context, tenantUUID uuid.UUID, project, name string) (*TransitKey, error) {
	row, _, err := s.transitKeyByName(ctx, s.repo, tenantUUID, project, name)
	if err != nil {
		return nil, err
	}
	out := toTransitKey(row)
	return &out, nil
}

// ListTransitKeys pages a project's keys. Metadata only — the query it uses does not
// select a material column at all.
func (s *Service) ListTransitKeys(ctx context.Context, tenantUUID uuid.UUID, project string, page, limit int) ([]TransitKey, int64, error) {
	tenant, proj, err := s.resolveProject(ctx, tenantUUID, project)
	if err != nil {
		return nil, 0, err
	}
	page, limit = normalizePage(page, limit)
	rows, err := s.repo.ListTransitKeyMetaByProject(ctx, storage.ListTransitKeyMetaByProjectParams{
		TenantID:  tenant.TenantID,
		ProjectID: proj.ProjectID,
		RowLimit:  int32(limit),
		RowOffset: int32((page - 1) * limit),
	})
	if err != nil {
		return nil, 0, apperror.NewInternal("list transit keys", err)
	}
	total, err := s.repo.CountTransitKeysByProject(ctx, storage.CountTransitKeysByProjectParams{
		TenantID:  tenant.TenantID,
		ProjectID: proj.ProjectID,
	})
	if err != nil {
		return nil, 0, apperror.NewInternal("count transit keys", err)
	}
	out := make([]TransitKey, 0, len(rows))
	for _, r := range rows {
		out = append(out, TransitKey{
			UUID:              r.KeyUuid,
			Name:              r.Name,
			Description:       r.Description,
			CurrentVersion:    r.CurrentVersion,
			Status:            r.Status,
			MinDecryptVersion: r.MinDecryptVersion,
			CreatedAt:         r.CreatedAt,
			UpdatedAt:         r.UpdatedAt,
		})
	}
	return out, total, nil
}

// ListTransitKeyVersions returns a key's version history as metadata: version numbers
// and which root key wraps each. No material, for the reason ListVersions returns no
// payloads.
func (s *Service) ListTransitKeyVersions(ctx context.Context, tenantUUID uuid.UUID, project, name string, page, limit int) ([]TransitKeyVersionMeta, int64, error) {
	row, _, err := s.transitKeyByName(ctx, s.repo, tenantUUID, project, name)
	if err != nil {
		return nil, 0, err
	}
	page, limit = normalizePage(page, limit)
	rows, err := s.repo.ListTransitKeyVersionMeta(ctx, storage.ListTransitKeyVersionMetaParams{
		KeyID:  row.KeyID,
		Limit:  int32(limit),
		Offset: int32((page - 1) * limit),
	})
	if err != nil {
		return nil, 0, apperror.NewInternal("list transit key versions", err)
	}
	total, err := s.repo.CountTransitKeyVersions(ctx, row.KeyID)
	if err != nil {
		return nil, 0, apperror.NewInternal("count transit key versions", err)
	}
	out := make([]TransitKeyVersionMeta, 0, len(rows))
	for _, r := range rows {
		out = append(out, TransitKeyVersionMeta{Version: r.Version, KEKID: r.KekID, CreatedAt: r.CreatedAt})
	}
	return out, total, nil
}

// UpdateTransitKeyInput changes a key's description, status and decrypt floor.
//
// THE NAME IS ABSENT because it is not editable: the name travels inside every token
// ever issued under the key, so renaming it would orphan every stored ciphertext in the
// calling application. A "rename" is a new key plus a re-encrypt, which is honest work
// rather than a silent break.
type UpdateTransitKeyInput struct {
	TenantUUID uuid.UUID
	Project    string
	Name       string
	// Description is free text.
	Description string
	Status      string
	// MinDecryptVersion retires compromised material WITHOUT deleting it: a token
	// under a version below this floor is refused. Zero leaves the floor unchanged.
	MinDecryptVersion int32
}

// UpdateTransitKey rewrites a key's mutable fields.
func (s *Service) UpdateTransitKey(ctx context.Context, in UpdateTransitKeyInput) (*TransitKey, error) {
	row, tenant, err := s.transitKeyByName(ctx, s.repo, in.TenantUUID, in.Project, in.Name)
	if err != nil {
		return nil, err
	}
	status := in.Status
	switch status {
	case TransitKeyStatusActive, TransitKeyStatusDisabled:
	case "":
		status = row.Status
	default:
		return nil, apperror.NewValidation(fmt.Sprintf("status %q must be %s or %s",
			status, TransitKeyStatusActive, TransitKeyStatusDisabled))
	}
	floor := in.MinDecryptVersion
	if floor <= 0 {
		floor = row.MinDecryptVersion
	}
	if floor > row.CurrentVersion {
		// A floor above the current version refuses EVERY token, including ones sealed
		// under the newest material — an outage rather than a retirement. Refused here
		// rather than discovered as a service-wide decrypt failure.
		return nil, apperror.NewValidation(fmt.Sprintf(
			"min_decrypt_version %d is above the key's current version %d, which would refuse every token",
			floor, row.CurrentVersion))
	}
	updated, err := s.repo.UpdateTransitKey(ctx, storage.UpdateTransitKeyParams{
		Description:       in.Description,
		Status:            status,
		MinDecryptVersion: floor,
		TenantID:          tenant.TenantID,
		KeyUuid:           row.KeyUuid,
	})
	if err != nil {
		return nil, mapWriteError(err, "transit key", "that transit key could not be updated")
	}
	out := toTransitKey(updated)
	return &out, nil
}

// DeleteTransitKey soft-deletes a key.
//
// The versions are NOT touched, deliberately, and this is the AWS-recovery-model
// argument applied to key material: a soft-deleted key can be brought back with every
// version intact, and until an explicit destruction it still exists. Hard-deleting key
// material as a side-effect of removing a row from a listing would make every
// ciphertext under it unrecoverable, which is the one mistake in this file that cannot
// be undone.
func (s *Service) DeleteTransitKey(ctx context.Context, tenantUUID uuid.UUID, project, name string) error {
	row, tenant, err := s.transitKeyByName(ctx, s.repo, tenantUUID, project, name)
	if err != nil {
		return err
	}
	n, err := s.repo.SoftDeleteTransitKey(ctx, storage.SoftDeleteTransitKeyParams{
		TenantID: tenant.TenantID,
		KeyUuid:  row.KeyUuid,
	})
	if err != nil {
		return apperror.NewInternal("delete transit key", err)
	}
	if n == 0 {
		return apperror.NewNotFound("transit key")
	}
	return nil
}

// ---------------------------------------------------------------------------
// The data plane
// ---------------------------------------------------------------------------

// TransitEncrypt seals a plaintext under a named key's CURRENT version and returns the
// wire token.
//
// The caller owns zeroizing the plaintext it passed in. The key material is zeroized
// here, on every path.
func (s *Service) TransitEncrypt(ctx context.Context, tenantUUID uuid.UUID, project, keyName string, plaintext []byte) (string, int32, error) {
	if plaintext == nil {
		return "", 0, apperror.NewValidation("a plaintext is required")
	}
	key, tenant, err := s.transitKeyByName(ctx, s.repo, tenantUUID, project, keyName)
	if err != nil {
		return "", 0, err
	}
	if key.Status != TransitKeyStatusActive {
		return "", 0, apperror.NewForbidden(fmt.Sprintf("transit key %q is %s and will not encrypt", key.Name, key.Status))
	}
	if key.CurrentVersion < 1 {
		return "", 0, apperror.NewInternal("transit key has no versions", errors.New("current_version is 0"))
	}

	material, version, err := s.openTransitMaterial(ctx, tenant.TenantUuid, key, key.CurrentVersion)
	if err != nil {
		return "", 0, err
	}
	defer crypto.Zero(material)

	token, err := transit.Seal(material, key.Name, transit.Identity{
		TenantUUID: tenant.TenantUuid.String(),
		KeyUUID:    key.KeyUuid.String(),
		KeyVersion: version,
	}, plaintext)
	if err != nil {
		return "", 0, apperror.NewInternal("transit encrypt", err)
	}
	return token.String(), version, nil
}

// TransitDecrypt opens a wire token and returns its plaintext. The caller must Zero it.
//
// THE KEY THE TOKEN NAMES IS RESOLVED WITHIN THE CALLER'S OWN TENANT AND PROJECT, never
// from the token alone. A token is a reference inside a scope, not a self-authorizing
// capability: presenting one from another tenant resolves a different key (or no key)
// and fails, because the AAD is rebuilt from the ROW that was found rather than from the
// token's own fields.
func (s *Service) TransitDecrypt(ctx context.Context, tenantUUID uuid.UUID, project, rawToken string) (crypto.Plaintext, string, int32, error) {
	token, err := transit.ParseToken(rawToken)
	if err != nil {
		return nil, "", 0, apperror.NewValidation(err.Error())
	}
	key, tenant, err := s.transitKeyByName(ctx, s.repo, tenantUUID, project, token.KeyName)
	if err != nil {
		return nil, "", 0, err
	}
	// A DISABLED key still DECRYPTS. Disabling is how an operator stops new data being
	// written under a key while its existing ciphertexts stay readable — refusing
	// decrypt too would turn a precautionary flag into data loss.
	if token.KeyVersion < key.MinDecryptVersion {
		return nil, "", 0, apperror.NewForbidden(fmt.Sprintf(
			"transit key %q no longer decrypts version %d; its minimum is %d",
			key.Name, token.KeyVersion, key.MinDecryptVersion))
	}

	material, version, err := s.openTransitMaterial(ctx, tenant.TenantUuid, key, token.KeyVersion)
	if err != nil {
		return nil, "", 0, err
	}
	defer crypto.Zero(material)

	plaintext, err := transit.Open(material, transit.Identity{
		TenantUUID: tenant.TenantUuid.String(),
		KeyUUID:    key.KeyUuid.String(),
		KeyVersion: version,
	}, token)
	if err != nil {
		// Reported as a validation failure rather than an internal one: a token that
		// does not authenticate is the caller's input being wrong, not this service
		// being broken, and the message deliberately says no more than that.
		return nil, "", 0, apperror.NewValidation(err.Error())
	}
	return plaintext, key.Name, version, nil
}

// openTransitMaterial decrypts one key version's material. The caller MUST zeroize the
// returned slice.
//
// This is the ONLY function in the repo that materializes a transit key, which is what
// makes "the key never leaves the service" checkable: there is one place to audit, and
// every caller of it defers crypto.Zero on the next line.
func (s *Service) openTransitMaterial(ctx context.Context, tenantUUID uuid.UUID, key storage.TransitKey, version int32) ([]byte, int32, error) {
	row, err := s.repo.GetTransitKeyVersion(ctx, storage.GetTransitKeyVersionParams{
		KeyID:   key.KeyID,
		Version: version,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, 0, apperror.NewNotFound(fmt.Sprintf("version %d of transit key %q", version, key.Name))
		}
		return nil, 0, apperror.NewInternal("read transit key version", err)
	}
	// Resolve the key that wrapped THIS version, not the active one. During a root-key
	// rotation they differ, and encryption and decryption must both keep working
	// throughout.
	provider, err := s.ring.Provider(row.KekID)
	if err != nil {
		return nil, 0, apperror.NewUnavailable(err.Error())
	}
	material, err := crypto.Open(provider, transitCryptoIdentity(tenantUUID, key.KeyUuid, row.Version), crypto.Envelope{
		Ciphertext: row.MaterialCiphertext,
		Nonce:      row.MaterialNonce,
		DEKWrapped: row.MaterialDekWrapped,
		DEKNonce:   row.MaterialDekNonce,
		KEKID:      row.KekID,
	})
	if err != nil {
		return nil, 0, apperror.NewInternal("open transit key material", err)
	}
	return material, row.Version, nil
}

// ---------------------------------------------------------------------------
// Root-key rewrap
// ---------------------------------------------------------------------------

// TransitRewrapStore adapts this service to crypto.RewrapStore for the transit tables.
//
// It exists so a root-key rotation drains transit key versions with the SAME batched,
// resumable, idempotent loop that drains secret versions, rather than a second
// hand-written one. RetireRootKey is deliberately a NO-OP here: retirement is a
// decision about the whole store, and a key that no transit version references may
// still be wrapping secret versions. Retiring it from this adapter would be a
// data-loss bug wearing a completion message. The secret-side rewrap owns retirement,
// and it must run after this one.
type TransitRewrapStore struct {
	svc *Service
}

// TransitRewrap returns the crypto.RewrapStore for transit key versions.
func (s *Service) TransitRewrap() *TransitRewrapStore { return &TransitRewrapStore{svc: s} }

// ListVersionWraps returns up to limit transit key versions still wrapped under kekID.
func (a *TransitRewrapStore) ListVersionWraps(ctx context.Context, kekID string, limit int32) ([]crypto.VersionWrap, error) {
	rows, err := a.svc.repo.ListTransitVersionWrapsByKEK(ctx, storage.ListTransitVersionWrapsByKEKParams{
		KekID: kekID,
		Limit: limit,
	})
	if err != nil {
		return nil, apperror.NewInternal("list transit key versions by root key", err)
	}
	out := make([]crypto.VersionWrap, 0, len(rows))
	for _, r := range rows {
		out = append(out, crypto.VersionWrap{
			VersionID:  r.VersionID,
			KEKID:      r.KekID,
			DEKWrapped: r.MaterialDekWrapped,
			DEKNonce:   r.MaterialDekNonce,
		})
	}
	return out, nil
}

// RewrapVersion persists a re-wrapped DEK inside a transaction that has declared the
// sanctioned rewrap GUC. The transaction is required, not preferred: the GUC is
// transaction-local, so on a pooled connection outside one the permission would either
// be lost before the UPDATE or linger for whatever ran next.
func (a *TransitRewrapStore) RewrapVersion(ctx context.Context, versionID int64, fromKEKID string, wrapped, nonce []byte, toKEKID string) error {
	return a.svc.repo.InTx(ctx, func(tx Repository) error {
		if err := tx.AllowTransitVersionRewrap(ctx); err != nil {
			return apperror.NewInternal("authorize transit key rewrap", err)
		}
		n, err := tx.RewrapTransitKeyVersion(ctx, storage.RewrapTransitKeyVersionParams{
			MaterialDekWrapped: wrapped,
			MaterialDekNonce:   nonce,
			KekID:              toKEKID,
			VersionID:          versionID,
			FromKekID:          fromKEKID,
		})
		if err != nil {
			return apperror.NewInternal("rewrap transit key version", err)
		}
		if n == 0 {
			// Another worker moved it first. Not an error — the rewrap loop is
			// idempotent by design and a row already on the new key is a row that no
			// longer needs work.
			return nil
		}
		return nil
	})
}

// CountVersionWraps reports how many transit key versions still reference kekID.
func (a *TransitRewrapStore) CountVersionWraps(ctx context.Context, kekID string) (int64, error) {
	n, err := a.svc.repo.CountTransitVersionsByKEK(ctx, kekID)
	if err != nil {
		return 0, apperror.NewInternal("count transit key versions by root key", err)
	}
	return n, nil
}

// RetireRootKey is a NO-OP. See the type comment: retirement is a whole-store decision
// and the secret-side rewrap owns it.
func (a *TransitRewrapStore) RetireRootKey(_ context.Context, _ string) error { return nil }

// Compile-time proof the adapter satisfies the crypto seam.
var _ crypto.RewrapStore = (*TransitRewrapStore)(nil)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// ValidateTransitKeyName checks a key name.
//
// It is a DNS-style slug, and the bound is not cosmetic: the name travels inside every
// ciphertext token, delimited by ':'. A name that could contain the delimiter would be
// a way to forge a token that resolves to a different key, so the allowlist is what
// makes the token format unambiguous.
func ValidateTransitKeyName(name string) error {
	if err := ValidateSlug("transit key name", name); err != nil {
		return err
	}
	return nil
}

// transitCryptoIdentity is the AAD identity a key version's material is sealed under.
//
// The key UUID stands where a secret's UUID stands, so material copied between key
// version rows fails authentication for exactly the same reason a secret's ciphertext
// would. Both bound values are STABLE UUIDs: renaming a key or a tenant must not
// invalidate a single sealed version.
func transitCryptoIdentity(tenantUUID, keyUUID uuid.UUID, version int32) crypto.Identity {
	return crypto.Identity{
		TenantUUID: tenantUUID.String(),
		SecretUUID: keyUUID.String(),
		Version:    version,
	}
}

// transitKeyByName resolves a key and its tenant through tenant-scoped queries.
func (s *Service) transitKeyByName(ctx context.Context, repo Repository, tenantUUID uuid.UUID, project, name string) (storage.TransitKey, storage.Tenant, error) {
	tenant, err := repo.GetTenantByUUID(ctx, tenantUUID)
	if err != nil {
		return storage.TransitKey{}, storage.Tenant{}, mapReadError(err, "tenant")
	}
	proj, err := repo.GetProjectBySlug(ctx, storage.GetProjectBySlugParams{
		TenantID: tenant.TenantID,
		Slug:     project,
	})
	if err != nil {
		return storage.TransitKey{}, storage.Tenant{}, mapReadError(err, "project")
	}
	row, err := repo.GetTransitKeyByName(ctx, storage.GetTransitKeyByNameParams{
		TenantID:  tenant.TenantID,
		ProjectID: proj.ProjectID,
		Name:      name,
	})
	if err != nil {
		return storage.TransitKey{}, storage.Tenant{}, mapReadError(err, "transit key")
	}
	return row, tenant, nil
}

func toTransitKey(r storage.TransitKey) TransitKey {
	return TransitKey{
		UUID:              r.KeyUuid,
		Name:              r.Name,
		Description:       r.Description,
		CurrentVersion:    r.CurrentVersion,
		Status:            r.Status,
		MinDecryptVersion: r.MinDecryptVersion,
		CreatedAt:         r.CreatedAt,
		UpdatedAt:         r.UpdatedAt,
	}
}
