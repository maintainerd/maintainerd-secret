package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/maintainerd/secret/internal/crypto"
	"github.com/maintainerd/secret/internal/platform/apperror"
	"github.com/maintainerd/secret/internal/storage"
)

// EnsureActiveRootKey registers the ring's active key as the one new writes wrap
// under, demoting any previously active key to 'retiring'.
//
// This runs at boot, and it must, for a structural reason:
// secret_versions.kek_id is a foreign key to root_keys. A write with an
// unregistered key fails on the FK rather than silently writing a row nobody can
// later attribute to a key. Registering at boot means the registry is correct
// before the first write, not after it.
//
// Restarting with the SAME key is a no-op — kek_id is a fingerprint of the material,
// so it resolves to the same row. Restarting with a DIFFERENT key is the first half
// of a rotation: the new key becomes active, the old one becomes 'retiring' (not
// 'retired' — versions still reference it), and the operator completes the rotation
// with RewrapRootKey. Reads keep working throughout, provided the old key is still
// on the ring.
func (s *Service) EnsureActiveRootKey(ctx context.Context) (storage.RootKey, error) {
	active := s.ring.Active()
	kekID := active.KeyID()
	provider := crypto.ProviderOf(kekID)
	if provider == "" {
		return storage.RootKey{}, apperror.NewInternal("register root key",
			fmt.Errorf("root key id %q has no provider prefix", kekID))
	}

	var out storage.RootKey
	err := s.repo.InTx(ctx, func(tx Repository) error {
		// Order matters: uq_root_keys_single_active permits exactly one active row,
		// so the incumbent has to step down before the newcomer is inserted.
		if _, err := tx.MarkOtherRootKeysRetiring(ctx, kekID); err != nil {
			return apperror.NewInternal("retire superseded root keys", err)
		}
		row, err := tx.UpsertActiveRootKey(ctx, storage.UpsertActiveRootKeyParams{
			KekID:    kekID,
			Provider: provider,
		})
		if err != nil {
			return apperror.NewInternal("register active root key", err)
		}
		out = row
		return nil
	})
	return out, err
}

// PendingRewrapKeys lists the root keys that are superseded but still referenced by
// versions — the work a rotation has left to do.
func (s *Service) PendingRewrapKeys(ctx context.Context) ([]storage.RootKey, error) {
	rows, err := s.repo.ListRootKeysByState(ctx, "retiring")
	if err != nil {
		return nil, apperror.NewInternal("list retiring root keys", err)
	}
	return rows, nil
}

// RewrapRootKey completes a root-key rotation for one superseded key: every version
// still wrapped under fromKEKID is re-wrapped under the active key, and the old key
// is retired once nothing references it.
//
// Ciphertext is never read or written. See crypto.RewrapAll for the batching,
// resumability and idempotency properties.
func (s *Service) RewrapRootKey(ctx context.Context, fromKEKID string) (crypto.RewrapReport, error) {
	if fromKEKID == "" {
		return crypto.RewrapReport{}, apperror.NewValidation("source root key id is required")
	}
	if _, err := s.repo.GetRootKey(ctx, fromKEKID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return crypto.RewrapReport{}, apperror.NewNotFound("root key")
		}
		return crypto.RewrapReport{}, apperror.NewInternal("read root key", err)
	}
	return crypto.RewrapAll(ctx, &rewrapStore{repo: s.repo}, s.ring, fromKEKID, s.policy.RewrapBatch)
}

// rewrapStore adapts the repository to crypto.RewrapStore, keeping the crypto
// package free of any dependency on sqlc or this package.
type rewrapStore struct{ repo TxRepository }

func (r *rewrapStore) ListVersionWraps(ctx context.Context, kekID string, limit int32) ([]crypto.VersionWrap, error) {
	rows, err := r.repo.ListVersionWrapsByKEK(ctx, storage.ListVersionWrapsByKEKParams{
		KekID: kekID,
		Limit: limit,
	})
	if err != nil {
		return nil, err
	}
	out := make([]crypto.VersionWrap, 0, len(rows))
	for _, row := range rows {
		out = append(out, crypto.VersionWrap{
			VersionID:  row.VersionID,
			KEKID:      row.KekID,
			DEKWrapped: row.DekWrapped,
			DEKNonce:   row.DekNonce,
		})
	}
	return out, nil
}

// RewrapVersion persists one re-wrapped DEK in its own transaction.
//
// Per-row rather than per-batch, and that is the intended trade. The rewrap GUC is
// transaction-local, so the permission to UPDATE a version row is scoped to exactly
// the statement that needs it — a batch-wide transaction would hold that permission
// open across hundreds of rows, and hold their locks with it. Row granularity also
// means an interrupted rotation leaves no partially-written batch: every row is
// either fully re-wrapped or untouched.
//
// The UPDATE additionally matches on the source key id, so a row another worker (or
// an earlier pass) already moved is not moved twice. A zero row count is therefore
// not an error — it is the idempotency working.
func (r *rewrapStore) RewrapVersion(ctx context.Context, versionID int64, fromKEKID string, wrapped, nonce []byte, toKEKID string) error {
	return r.repo.InTx(ctx, func(tx Repository) error {
		if err := tx.AllowSecretVersionRewrap(ctx); err != nil {
			return fmt.Errorf("authorize version rewrap: %w", err)
		}
		if _, err := tx.RewrapSecretVersion(ctx, storage.RewrapSecretVersionParams{
			DekWrapped: wrapped,
			DekNonce:   nonce,
			KekID:      toKEKID,
			VersionID:  versionID,
			FromKekID:  fromKEKID,
		}); err != nil {
			return err
		}
		return nil
	})
}

func (r *rewrapStore) CountVersionWraps(ctx context.Context, kekID string) (int64, error) {
	return r.repo.CountVersionsByKEK(ctx, kekID)
}

func (r *rewrapStore) RetireRootKey(ctx context.Context, kekID string) error {
	n, err := r.repo.RetireRootKey(ctx, kekID)
	if err != nil {
		return err
	}
	if n == 0 {
		// The statement refuses to retire the ACTIVE key, so zero rows means the
		// caller tried to retire the key new writes depend on.
		return fmt.Errorf("root key %s was not retired; it is still the active key", kekID)
	}
	return nil
}

var _ crypto.RewrapStore = (*rewrapStore)(nil)
