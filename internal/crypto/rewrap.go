package crypto

import (
	"context"
	"fmt"
	"log/slog"
)

// VersionWrap is the slice of a secret_versions row a rewrap touches. Note what is
// absent: ciphertext, nonce, checksum, version. A rewrap never reads a payload, and
// this struct is the type-level statement of that.
type VersionWrap struct {
	VersionID  int64
	KEKID      string
	DEKWrapped []byte
	DEKNonce   []byte
}

// RewrapStore is the storage seam RewrapAll needs. Deliberately four methods wide
// so the rotation logic is testable without a database, and so the crypto package
// carries no dependency on internal/store or sqlc.
type RewrapStore interface {
	// ListVersionWraps returns up to limit versions still wrapped under kekID.
	ListVersionWraps(ctx context.Context, kekID string, limit int32) ([]VersionWrap, error)
	// RewrapVersion persists a re-wrapped DEK. Implementations must set the
	// sanctioned rewrap GUC and must not alter the payload columns.
	RewrapVersion(ctx context.Context, versionID int64, fromKEKID string, wrapped, nonce []byte, toKEKID string) error
	// CountVersionWraps reports how many versions still reference kekID.
	CountVersionWraps(ctx context.Context, kekID string) (int64, error)
	// RetireRootKey marks a drained key retired.
	RetireRootKey(ctx context.Context, kekID string) error
}

// RewrapReport is the outcome of a rotation pass.
type RewrapReport struct {
	// FromKEKID is the key being drained.
	FromKEKID string
	// ToKEKID is the new active key.
	ToKEKID string
	// Rewrapped counts versions moved in this pass.
	Rewrapped int64
	// Remaining is how many versions still reference FromKEKID afterwards. Non-zero
	// means the pass was interrupted or new rows arrived; running again continues.
	Remaining int64
	// Retired reports whether the old key was retired (only when Remaining is 0).
	Retired bool
}

// RewrapAll moves every version wrapped under fromKEKID onto the ring's active key,
// leaving ciphertext untouched.
//
// THIS IS WHY ENVELOPE ENCRYPTION EXISTS. Rotating the root of trust is a
// requirement — a key is exposed, an operator leaves, a compliance clock runs out —
// and the naive design (payload encrypted directly under the root key) makes it a
// full re-encryption of the store. Here it is an update of a few dozen bytes per
// row: unwrap the DEK with the key that wrapped it, wrap it with the new one, write
// back three columns.
//
// Three properties are load-bearing:
//
//   - BATCHED. Work is taken in limit-sized chunks, each in its own storage
//     transaction. A single transaction over a large store would hold locks for its
//     entire duration and could not be interrupted.
//   - RESUMABLE. Progress is recorded in the data itself: a re-wrapped row no longer
//     matches the "wrapped under fromKEKID" query. A crashed rotation is resumed by
//     calling this function again — there is no cursor to persist and no way for a
//     restart to skip or repeat a row.
//   - IDEMPOTENT. Re-running after completion finds nothing to do and returns a zero
//     count. RewrapVersion is additionally guarded on the source key id, so a row
//     another worker already moved is not moved twice.
//
// The old key is retired only once the store proves no version references it. A key
// retired while rows still point at it would leave those rows permanently
// unreadable, so the check is a COUNT rather than an inference from this pass having
// finished.
func RewrapAll(ctx context.Context, store RewrapStore, ring *KeyRing, fromKEKID string, batch int32) (RewrapReport, error) {
	if store == nil || ring == nil {
		return RewrapReport{}, fmt.Errorf("crypto: rewrap needs a store and a key ring")
	}
	if batch < 1 {
		batch = 100
	}
	target := ring.Active()
	report := RewrapReport{FromKEKID: fromKEKID, ToKEKID: target.KeyID()}

	if fromKEKID == target.KeyID() {
		// Nothing to do, and saying so is not an error: this is the steady state
		// after a completed rotation, and a scheduled rewrap should be able to run
		// against it harmlessly.
		return report, nil
	}

	from, err := ring.Provider(fromKEKID)
	if err != nil {
		return report, err
	}

	for {
		wraps, err := store.ListVersionWraps(ctx, fromKEKID, batch)
		if err != nil {
			return report, fmt.Errorf("crypto: list versions wrapped under %s: %w", fromKEKID, err)
		}
		if len(wraps) == 0 {
			break
		}
		for _, w := range wraps {
			wrapped, nonce, err := Rewrap(from, target, w.DEKWrapped, w.DEKNonce)
			if err != nil {
				return report, fmt.Errorf("crypto: rewrap version %d: %w", w.VersionID, err)
			}
			if err := store.RewrapVersion(ctx, w.VersionID, fromKEKID, wrapped, nonce, target.KeyID()); err != nil {
				return report, fmt.Errorf("crypto: persist rewrap of version %d: %w", w.VersionID, err)
			}
			report.Rewrapped++
		}
		// A short batch means the queue is drained. Checking this rather than
		// looping until an empty batch saves one query per rotation and, more
		// importantly, keeps the loop from spinning if a concurrent writer keeps
		// adding rows under the old key (which cannot happen once the new key is
		// active, but the loop should not depend on that).
		if int32(len(wraps)) < batch {
			break
		}
	}

	remaining, err := store.CountVersionWraps(ctx, fromKEKID)
	if err != nil {
		return report, fmt.Errorf("crypto: count versions still wrapped under %s: %w", fromKEKID, err)
	}
	report.Remaining = remaining
	if remaining > 0 {
		slog.Warn("root key rewrap incomplete; not retiring the old key",
			"from_kek_id", fromKEKID, "to_kek_id", target.KeyID(),
			"rewrapped", report.Rewrapped, "remaining", remaining)
		return report, nil
	}

	if err := store.RetireRootKey(ctx, fromKEKID); err != nil {
		return report, fmt.Errorf("crypto: retire root key %s: %w", fromKEKID, err)
	}
	report.Retired = true
	slog.Info("root key rewrap complete",
		"from_kek_id", fromKEKID, "to_kek_id", target.KeyID(), "rewrapped", report.Rewrapped)
	return report, nil
}
