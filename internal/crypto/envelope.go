package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
)

// Identity is the immutable coordinate of a secret version, bound into the
// ciphertext as additional authenticated data.
//
// WHY AAD EXISTS HERE. Without it, a ciphertext is a free-floating blob: anyone who
// can write a row — a SQL injection, a compromised service account, a buggy
// migration, an operator with a psql prompt — could copy the ciphertext, nonce and
// wrapped DEK out of one secret's version row into another's, and the store would
// decrypt it happily. Move the staging database password into the row production
// reads and you have not broken the encryption at all; you have simply re-pointed
// it. Binding the identity makes that fail: GCM authenticates the AAD, so a
// ciphertext only opens when the row it is read from claims exactly the identity it
// was written under. Version is bound too, so a row cannot be rolled back to an
// older payload while claiming to be the current one.
//
// WHY THESE THREE FIELDS AND NOT THE PATH. The obvious formulation is to bind the
// full address — tenant, project, environment, folder path, key, version — and that
// is what an earlier draft of this package did. It is wrong, and the folder-move
// test is what proves it: the moment a folder is renamed or moved, every path under
// it changes, and every ciphertext beneath it becomes permanently undecryptable. An
// administrative reorganization would silently destroy the vault's contents. The two
// requirements are in direct conflict — a folder move must recompute paths and
// cascade, and envelope encryption exists precisely so that re-encrypting payloads
// is never necessary — so binding a mutable address cannot be right.
//
// SecretUUID is the correct thing to bind because it is what actually identifies the
// row, and it never changes: not on a folder move, not on a rename, not on a delete
// and restore. It gives the SAME anti-replay property — a ciphertext copied into a
// different secret's row meets a different SecretUUID and fails authentication —
// with none of the fragility.
//
// The path is deliberately NOT a security control here. "This secret was moved into
// a folder with looser grants" is an authorization question, and the answer is who
// may move a secret, enforced by policy over the mrn_resource_path columns. Enforcing
// it through the AAD would only "protect" the value by destroying it, and would break
// legitimate moves identically to malicious ones — a control that cannot tell the two
// apart is not a control.
type Identity struct {
	// TenantUUID is the tenant's stable UUID, not its name — names are renameable,
	// and a rename must not invalidate every ciphertext beneath it.
	TenantUUID string
	// SecretUUID is the secret's stable UUID. This is the row's real identity: it
	// survives moves, renames and restores, all of which change the address.
	SecretUUID string
	// Version is the version number this payload belongs to.
	Version int32
}

// aadDomain is a version tag so the AAD construction can change later without
// silently invalidating existing rows: a future v2 encoding gets a new tag, and rows
// written under v1 keep opening under v1.
const aadDomain = "maintainerd-secret/aad/v1"

// AAD renders the identity into the exact bytes bound to a ciphertext.
//
// Fields are LENGTH-PREFIXED rather than joined with a delimiter. A delimiter is a
// correctness bug waiting for the first value that contains it: with a '|'
// separator, ("a", "b|c") and ("a|b", "c") produce identical AAD, so one secret's
// ciphertext would open in another's row — reintroducing exactly the confusion the
// AAD is here to prevent. Length prefixes make the encoding injective.
func (id Identity) AAD() []byte {
	var b bytes.Buffer
	b.WriteString(aadDomain)
	for _, field := range []string{id.TenantUUID, id.SecretUUID} {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(field)))
		b.Write(n[:])
		b.WriteString(field)
	}
	var v [4]byte
	binary.BigEndian.PutUint32(v[:], uint32(id.Version))
	b.Write(v[:])
	return b.Bytes()
}

// Envelope is one encrypted secret version: everything that goes into a
// secret_versions row except the identity and the timestamps.
type Envelope struct {
	// Ciphertext is the payload sealed under the DEK.
	Ciphertext []byte
	// Nonce is the GCM nonce for Ciphertext.
	Nonce []byte
	// DEKWrapped is the DEK sealed under the root key.
	DEKWrapped []byte
	// DEKNonce is the GCM nonce for DEKWrapped.
	DEKNonce []byte
	// KEKID names the root key that wrapped the DEK, so a later read (or a rewrap)
	// knows which provider to ask.
	KEKID string
	// Checksum is SHA-256 of the plaintext. It travels with the envelope so the
	// store can persist it and later answer "did the value change?" without a
	// decrypt.
	Checksum []byte
}

// Checksum returns SHA-256 of a plaintext.
//
// Storing this is safe and useful. Safe, because the values in a vault are
// high-entropy credentials for which a hash is not a meaningful shortcut, and the
// column is never exposed to a caller that could not already read the value.
// Useful, because it turns two otherwise expensive questions — is this row intact,
// and is this write actually a change — into a comparison that needs neither the
// root key nor a decryption.
func Checksum(plaintext []byte) []byte {
	sum := sha256.Sum256(plaintext)
	return sum[:]
}

// Seal encrypts plaintext for the given identity under a fresh per-version DEK, and
// wraps that DEK with the provider's root key.
//
// The DEK is generated per version, never reused and never stored unwrapped. It is
// zeroized before this function returns on every path, including the error paths —
// which is why the defer is set up before the first use rather than after the last.
func Seal(p RootKeyProvider, id Identity, plaintext []byte) (*Envelope, error) {
	if p == nil {
		return nil, fmt.Errorf("crypto: no root key provider")
	}
	if id.Version < 1 {
		return nil, fmt.Errorf("crypto: version must be at least 1, got %d", id.Version)
	}

	dek, err := NewRandomKey()
	if err != nil {
		return nil, err
	}
	defer Zero(dek)

	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("crypto: build dek cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: build dek gcm: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("crypto: read payload nonce: %w", err)
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, id.AAD())

	wrapped, wrapNonce, err := p.Wrap(dek)
	if err != nil {
		return nil, err
	}

	return &Envelope{
		Ciphertext: ciphertext,
		Nonce:      nonce,
		DEKWrapped: wrapped,
		DEKNonce:   wrapNonce,
		KEKID:      p.KeyID(),
		Checksum:   Checksum(plaintext),
	}, nil
}

// Open reverses Seal. The provider must be the one named by env.KEKID — resolving
// that is the KeyRing's job, not this function's.
//
// A failure here is reported as an authentication failure without elaboration. That
// is not vagueness for its own sake: the failure modes (wrong root key, tampered
// ciphertext, ciphertext moved to a different secret's row, version mismatch) are
// all "this ciphertext does not belong to this identity under this key", and
// distinguishing them for the caller would hand an attacker a probing oracle.
func Open(p RootKeyProvider, id Identity, env Envelope) (Plaintext, error) {
	if p == nil {
		return nil, fmt.Errorf("crypto: no root key provider")
	}
	if env.KEKID != "" && p.KeyID() != env.KEKID {
		return nil, fmt.Errorf("crypto: version is wrapped under root key %s but provider is %s", env.KEKID, p.KeyID())
	}

	dek, err := p.Unwrap(env.DEKWrapped, env.DEKNonce)
	if err != nil {
		return nil, err
	}
	defer Zero(dek)

	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("crypto: build dek cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: build dek gcm: %w", err)
	}
	if len(env.Nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("crypto: payload nonce must be %d bytes, got %d", aead.NonceSize(), len(env.Nonce))
	}

	plaintext, err := aead.Open(nil, env.Nonce, env.Ciphertext, id.AAD())
	if err != nil {
		return nil, fmt.Errorf("crypto: decrypt version %d of secret %s failed authentication", id.Version, id.SecretUUID)
	}

	// Integrity check against the stored checksum. GCM already authenticated the
	// ciphertext, so this cannot catch a cryptographic forgery — what it catches is
	// the mundane corruption GCM cannot see: a checksum column that drifted from
	// its payload through a bad backfill or a partial restore. Cheap, and it turns
	// a silent inconsistency into a loud one.
	if len(env.Checksum) > 0 && !bytes.Equal(Checksum(plaintext), env.Checksum) {
		Zero(plaintext)
		return nil, fmt.Errorf("crypto: version %d of secret %s decrypted but does not match its stored checksum", id.Version, id.SecretUUID)
	}
	return plaintext, nil
}

// Rewrap moves one version's DEK from the key that wrapped it to a new root key,
// WITHOUT touching the ciphertext — which is the entire economic argument for
// envelope encryption. Returns the newly wrapped DEK and its nonce.
//
// Idempotent by construction: if from and to are the same key the wrapped DEK is
// returned unchanged, so a rotation that is re-run over rows it already converted
// does no work and no harm.
func Rewrap(from, to RootKeyProvider, wrapped, nonce []byte) (newWrapped, newNonce []byte, err error) {
	if from == nil || to == nil {
		return nil, nil, fmt.Errorf("crypto: rewrap needs both a source and a target root key provider")
	}
	if from.KeyID() == to.KeyID() {
		return wrapped, nonce, nil
	}
	dek, err := from.Unwrap(wrapped, nonce)
	if err != nil {
		return nil, nil, err
	}
	defer Zero(dek)
	return to.Wrap(dek)
}
