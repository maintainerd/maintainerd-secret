// Package crypto is this service's cryptographic core: the root of trust, envelope
// encryption, and root-key rotation.
//
// The shape is standard envelope encryption, and the reason for it is operational
// rather than cryptographic. Every secret version gets its own data encryption key
// (DEK) which encrypts the payload; that DEK is then encrypted ("wrapped") by a
// root key (the KEK) which never touches a payload. Rotating the root of trust
// therefore rewrites a few dozen bytes per row instead of re-encrypting the entire
// store — see RewrapAll.
//
// Three rules hold everywhere in this package:
//
//  1. A store cannot unlock itself. The KEK always arrives from outside the
//     database, through a RootKeyProvider. There is no code path that reads key
//     material from Postgres.
//  2. No plaintext, and no DEK, ever appears in an error, a log line, a String()
//     or a marshalled struct. See the Plaintext type and TestErrorsCarryNoSecrets.
//  3. Outside development, a missing or malformed root key is a boot error. It is
//     never replaced with a generated one — the prototype did that, and the result
//     was that every secret written before a restart became undecryptable after it,
//     silently.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

// Sizes fixed by the algorithms this package uses.
const (
	// KeySize is 32 bytes: both the KEK and every DEK are AES-256 keys. Unlike the
	// prototype, which accepted any AES key length, this is not configurable —
	// there is no reason to offer an operator a weaker option for data at rest.
	KeySize = 32

	// NonceSize is the standard 12-byte GCM nonce.
	NonceSize = 12
)

// Root-key provider names. These are simultaneously the accepted values of
// SECRET_ROOT_KEY_PROVIDER, the values stored in root_keys.provider, and the
// prefix of every kek_id.
const (
	ProviderEnv       = "env"
	ProviderFile      = "file"
	ProviderAWSKMS    = "aws_kms"
	ProviderGCPKMS    = "gcp_kms"
	ProviderAzureKV   = "azure_kv"
	ProviderEphemeral = "ephemeral"
)

// RootKeyProvider is the root of trust, and the seam that keeps it swappable.
//
// The interface is deliberately this small: it wraps and unwraps a DEK and it can
// name itself. Everything a cloud KMS does differently — the network call, the IAM
// grant, the fact that the key material never leaves the HSM — lives behind Wrap
// and Unwrap, so aws_kms is a new implementation of these three methods and NOT a
// change to the schema, the store, or the rewrap logic. That is why the KMS
// providers are already registered (returning a clear not-built error) rather than
// absent: the seam is finished even though the implementations are not.
//
// KeyID must be STABLE for a given key: it is the value written into
// secret_versions.kek_id, and a restart that produced a different id would orphan
// every row the previous process wrote. Implementations derive it from the key
// material (or from the KMS key ARN/resource name), never randomly.
type RootKeyProvider interface {
	// KeyID returns the stable fingerprint of this root key, prefixed with the
	// provider name.
	KeyID() string
	// Wrap encrypts a DEK under the root key, returning the wrapped bytes and the
	// nonce needed to reverse it.
	Wrap(dek []byte) (wrapped, nonce []byte, err error)
	// Unwrap recovers a DEK. The caller is responsible for zeroizing the result.
	Unwrap(wrapped, nonce []byte) ([]byte, error)
}

// ProviderConfig is everything the factory needs to build a root of trust.
type ProviderConfig struct {
	// Provider is one of the Provider* constants.
	Provider string
	// AppEnv gates the development-only ephemeral fallback. It is compared against
	// the exact string "development", so a typo fails closed.
	AppEnv string
	// Key is the encoded key material for the env provider (hex or base64).
	Key string
	// KeyFile is the sealed key file path for the file provider.
	KeyFile string
}

// EnvDevelopment is the one AppEnv value that permits an ephemeral key.
const EnvDevelopment = "development"

// providerFactory builds one kind of root of trust.
type providerFactory func(ProviderConfig) (RootKeyProvider, error)

// registry is the single list of known providers. Config validation, the schema's
// provider CHECK constraint, and this map are three views of the same set; keeping
// the map here means adding a provider is one entry plus one implementation.
var registry = map[string]providerFactory{
	ProviderEnv:     newEnvProvider,
	ProviderFile:    newFileProvider,
	ProviderAWSKMS:  notBuilt(ProviderAWSKMS, "AWS KMS"),
	ProviderGCPKMS:  notBuilt(ProviderGCPKMS, "GCP KMS"),
	ProviderAzureKV: notBuilt(ProviderAzureKV, "Azure Key Vault"),
}

// KnownProviders returns the provider names the factory accepts, for config
// validation and error messages.
func KnownProviders() []string {
	return []string{ProviderEnv, ProviderFile, ProviderAWSKMS, ProviderGCPKMS, ProviderAzureKV}
}

// NewRootKeyProvider builds the root of trust named by cfg.Provider.
func NewRootKeyProvider(cfg ProviderConfig) (RootKeyProvider, error) {
	name := strings.ToLower(strings.TrimSpace(cfg.Provider))
	if name == "" {
		name = ProviderEnv
	}
	build, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("crypto: unknown root key provider %q, expected one of %s", name, strings.Join(KnownProviders(), ", "))
	}
	return build(cfg)
}

// ProviderOf extracts the provider name from a kek_id. Used when registering a key
// in root_keys, so the provider column and the id can never disagree.
func ProviderOf(kekID string) string {
	if i := strings.IndexByte(kekID, ':'); i > 0 {
		return kekID[:i]
	}
	return ""
}

// ParseKeyMaterial decodes an encoded 32-byte key. Hex and base64 (standard,
// URL-safe, padded or not) are accepted; anything else, or any length other than
// 32 bytes, is an error.
//
// The encoding is not guessed loosely: a value that looks like hex is decoded as
// hex, and only then is base64 tried. This matters because a truncated base64
// string can decode "successfully" to the wrong number of bytes, and a root key
// that is silently 24 bytes instead of 32 is a weakened store nobody notices. The
// length check is what actually protects against that, and it has no fallback.
func ParseKeyMaterial(encoded string) ([]byte, error) {
	s := strings.TrimSpace(encoded)
	if s == "" {
		return nil, fmt.Errorf("crypto: root key is empty")
	}

	if len(s) == hex.EncodedLen(KeySize) {
		if key, err := hex.DecodeString(s); err == nil {
			return key, nil
		}
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
	} {
		key, err := enc.DecodeString(s)
		if err != nil {
			continue
		}
		if len(key) != KeySize {
			Zero(key)
			return nil, fmt.Errorf("crypto: root key decodes to %d bytes, need exactly %d (AES-256)", len(key), KeySize)
		}
		return key, nil
	}
	return nil, fmt.Errorf("crypto: root key is neither %d-character hex nor base64 of %d bytes", hex.EncodedLen(KeySize), KeySize)
}

// NewRandomKey returns a fresh 32-byte key from the system CSPRNG.
func NewRandomKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("crypto: read random key: %w", err)
	}
	return key, nil
}

// fingerprint derives the stable kek_id from key material.
//
// Domain-separated so this hash can never collide with any other hash of the same
// bytes computed elsewhere in the system, and truncated to 12 bytes because it is
// an identifier, not a commitment — 96 bits is far beyond what is needed to keep a
// handful of root keys distinct, and a shorter id keeps kek_id inside VARCHAR(64).
func fingerprint(provider string, key []byte) string {
	h := sha256.New()
	h.Write([]byte("maintainerd-secret/kek-id/v1"))
	h.Write(key)
	sum := h.Sum(nil)
	return provider + ":" + hex.EncodeToString(sum[:12])
}

// dekWrapAAD is the additional authenticated data bound into every DEK wrap. It
// pins a wrapped DEK to the specific root key that produced it, so a wrapped DEK
// cannot be presented as though a different key had wrapped it.
func dekWrapAAD(keyID string) []byte {
	return []byte("maintainerd-secret/dek-wrap/v1|" + keyID)
}

// aesKEK is the shared AES-256-GCM implementation behind the env, file and
// ephemeral providers: all three differ only in where the 32 bytes came from.
type aesKEK struct {
	keyID string
	aead  cipher.AEAD
}

// newAESKEK takes ownership of key and zeroizes the caller's copy once the cipher
// has absorbed it. The caller must not reuse the slice afterwards.
func newAESKEK(provider string, key []byte) (*aesKEK, error) {
	if len(key) != KeySize {
		Zero(key)
		return nil, fmt.Errorf("crypto: root key must be %d bytes, got %d", KeySize, len(key))
	}
	keyID := fingerprint(provider, key)
	block, err := aes.NewCipher(key)
	if err != nil {
		Zero(key)
		return nil, fmt.Errorf("crypto: build cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		Zero(key)
		return nil, fmt.Errorf("crypto: build gcm: %w", err)
	}
	// aes.NewCipher copies the key into its own key schedule, so the caller's
	// buffer is dead weight from here on — and dead key material in memory is
	// exactly what memory hygiene is about.
	Zero(key)
	return &aesKEK{keyID: keyID, aead: aead}, nil
}

func (k *aesKEK) KeyID() string { return k.keyID }

func (k *aesKEK) Wrap(dek []byte) ([]byte, []byte, error) {
	if len(dek) != KeySize {
		return nil, nil, fmt.Errorf("crypto: dek must be %d bytes, got %d", KeySize, len(dek))
	}
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("crypto: read wrap nonce: %w", err)
	}
	// Seal into a fresh slice rather than appending to nonce: ciphertext and nonce
	// are stored in separate columns, so keeping them separate here avoids a
	// slice-aliasing mistake at the storage boundary.
	wrapped := k.aead.Seal(nil, nonce, dek, dekWrapAAD(k.keyID))
	return wrapped, nonce, nil
}

func (k *aesKEK) Unwrap(wrapped, nonce []byte) ([]byte, error) {
	if len(nonce) != k.aead.NonceSize() {
		return nil, fmt.Errorf("crypto: wrap nonce must be %d bytes, got %d", k.aead.NonceSize(), len(nonce))
	}
	dek, err := k.aead.Open(nil, nonce, wrapped, dekWrapAAD(k.keyID))
	if err != nil {
		// Deliberately opaque, and deliberately not wrapping err: GCM's own error
		// text is uninformative anyway, and the one thing that must never leak from
		// this path is anything derived from the material being unwrapped.
		return nil, fmt.Errorf("crypto: unwrap dek under key %s failed authentication", k.keyID)
	}
	if len(dek) != KeySize {
		Zero(dek)
		return nil, fmt.Errorf("crypto: unwrapped dek is %d bytes, expected %d", len(dek), KeySize)
	}
	return dek, nil
}
