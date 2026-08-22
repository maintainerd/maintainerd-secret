package crypto

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"time"
)

// The cloud KMS providers — shared scaffolding.
//
// A cloud root key differs from an env root key in exactly one respect: Wrap and
// Unwrap become network round-trips to a service that never hands over the key
// material. Nothing else in this service changes. The DEK is still 32 bytes,
// secret_versions still stores the wrapped DEK and a kek_id, and RewrapAll still
// rotates by re-wrapping DEKs — which is why a version wrapped under aws_kms can be
// rewrapped onto gcp_kms without a payload ever being decrypted.
//
// FOUR PROPERTIES ARE SHARED BY ALL THREE and live in this file because getting any
// one of them wrong is a production incident rather than a style problem:
//
//  1. A NARROW INTERFACE per provider (awsKMSAPI, gcpKMSAPI, azureKeysAPI). Each
//     names only the calls its adapter makes, so a provider's blast radius is
//     enumerable by reading one type, and the adapter logic is unit-testable without
//     a cloud credential. Each has a compile-time assertion that the real SDK client
//     satisfies it, so a fake and the SDK cannot drift apart silently.
//  2. A BOOT SELF-TEST. Construction wraps and unwraps a throwaway probe before
//     returning the provider. A misconfigured key, an unreachable endpoint or a
//     credential that holds encrypt but not decrypt therefore fails at BOOT, not on
//     the first write after the service is already serving. That asymmetric grant is
//     the failure this exists for: a vault that accepts writes it can never read back
//     is worse than one that refuses to start.
//  3. A PER-CALL DEADLINE. RootKeyProvider is deliberately ctx-free — it is called
//     from Seal and Open, which are pure functions over bytes — so each provider owns
//     its own deadline rather than inheriting a caller's. A root-key call that hung
//     would otherwise pin a request goroutine for as long as the network allowed.
//  4. RETRY ON TRANSIENT FAILURES ONLY. Throttling and a 5xx are worth another
//     attempt; AccessDenied, NotFound and a failed decryption are not, and retrying
//     them turns one clear error into three slow ones. Each provider supplies its own
//     classifier, because the three SDKs express "transient" in three different ways.
//
// NO KEY MATERIAL IS EVER LOGGED OR RETURNED IN AN ERROR. Errors name the kek_id and
// the operation; a failed unwrap is reported as an opaque authentication failure, for
// the same reason aesKEK.Unwrap is. See TestKMSErrorsCarryNoSecrets.

// kmsServiceName is bound into every cloud AAD / encryption context. It is not a
// secret and it is deliberately readable: AWS records the encryption context in
// CloudTrail, so this is the field that lets an operator see which service made a
// KMS call. Nothing derived from a key or a payload ever goes in there.
const kmsServiceName = "maintainerd-secret"

// DefaultKMSTimeout bounds a single Wrap or Unwrap round-trip. Ten seconds is long
// enough for a cold TLS handshake plus a cross-region call, and short enough that a
// black-holed endpoint fails instead of hanging a request.
const DefaultKMSTimeout = 10 * time.Second

// Retry bounds. Three attempts, not more: a root-key call sits inside a request, so
// the useful ceiling is "survive one throttle" and the per-call deadline is the real
// backstop. defaultKMSRetryDelay is the first backoff step; it doubles, with full
// jitter, and tests inject 0 to keep the suite fast and deterministic.
const (
	kmsRetryAttempts     = 3
	defaultKMSRetryDelay = 100 * time.Millisecond
)

// KMSConfig carries the cloud-KMS settings. Only the fields belonging to the
// selected provider are read; the rest are ignored rather than validated, so an
// operator may leave a previous provider's variables in place while switching.
//
// These are populated from the environment by internal/platform/config, which
// validates them AT BOOT. This struct is a plain carrier: the crypto package never
// reads the environment, and it knows variable names only well enough to name them in
// the error it returns when one is missing.
type KMSConfig struct {
	// Timeout bounds one Wrap or Unwrap call. Zero means DefaultKMSTimeout.
	Timeout time.Duration

	// AWSKeyID (SECRET_KMS_AWS_KEY_ID) is the key ARN, key id, alias name
	// ("alias/...") or alias ARN of a symmetric ENCRYPT_DECRYPT KMS key.
	AWSKeyID string
	// AWSRegion (SECRET_KMS_AWS_REGION) is the region the key lives in. It is
	// REQUIRED rather than left to the SDK's own region resolution because it is
	// part of the kek_id: an alias resolved from an ambient AWS_REGION on one host
	// and an explicit region on another would otherwise produce two ids for what
	// the operator believes is one key.
	AWSRegion string

	// GCPKeyName (SECRET_KMS_GCP_KEY_NAME) is the fully qualified CryptoKey
	// resource name: projects/{p}/locations/{l}/keyRings/{r}/cryptoKeys/{k}.
	// A cryptoKeyVersions/... suffix is refused, because Decrypt takes a CryptoKey
	// and chooses the version itself — a version-pinned name would encrypt happily
	// and then fail every decrypt.
	GCPKeyName string

	// AzureVaultURL (SECRET_KMS_AZURE_VAULT_URL) is the vault base URL, e.g.
	// https://my-vault.vault.azure.net/
	AzureVaultURL string
	// AzureKeyName (SECRET_KMS_AZURE_KEY_NAME) is the key's name in that vault.
	AzureKeyName string
	// AzureKeyVersion (SECRET_KMS_AZURE_KEY_VERSION) pins a key version. Empty
	// means the vault's current version, which is the normal choice: Key Vault
	// keeps prior versions usable, so unwrapping old blobs keeps working while new
	// wraps move to the current version.
	AzureKeyVersion string
}

// kmsTimeout applies the default to a zero or negative value.
func kmsTimeout(d time.Duration) time.Duration {
	if d <= 0 {
		return DefaultKMSTimeout
	}
	return d
}

// missingKMSSettings is the construction error for a provider selected without its
// required settings.
//
// It names EVERY missing variable at once, for the same reason standaloneMissing does
// in the config package: a message that reports them one boot at a time turns a
// two-minute setup into three restarts. Config validation catches this first on a
// normal boot; this exists so the factory is still safe to call directly.
func missingKMSSettings(provider string, missing []string) error {
	return fmt.Errorf(
		"crypto: root key provider %q requires %s; set them or choose another SECRET_ROOT_KEY_PROVIDER",
		provider, strings.Join(missing, ", "))
}

// fingerprintRef derives a stable kek_id from a cloud key REFERENCE.
//
// The reference is hashed rather than key material because there is no key material
// here to hash — that is the whole point of a KMS. What matters is the property KeyID
// promises: the same configured key must produce the same id on every host and across
// every restart, or rows written by one process become unreadable to the next. So the
// input is the operator's configured coordinates, canonicalised by the caller (region
// plus key reference, the full GCP resource name, vault plus key plus version).
//
// The domain tag differs from fingerprint's on purpose: the two hash different kinds
// of input, and sharing a tag would let a key reference and a key's material collide
// on one id.
//
// Truncated to 12 bytes for the same reason fingerprint is — kek_id is an identifier
// in a VARCHAR(64) column, not a commitment. "aws_kms:" plus 24 hex characters is 32,
// comfortably inside the column.
func fingerprintRef(provider, ref string) string {
	h := sha256.New()
	h.Write([]byte("maintainerd-secret/kek-id/ref/v1"))
	h.Write([]byte(ref))
	sum := h.Sum(nil)
	return provider + ":" + hex.EncodeToString(sum[:12])
}

// noNonce is the nonce every cloud provider returns.
//
// THE CONTRACT'S NONCE IS PROVIDER-OPTIONAL. AES-GCM needs a nonce stored beside its
// ciphertext, so the interface carries one; a KMS returns a single self-describing
// ciphertext blob that already contains whatever IV the service chose, so there is
// nothing for the second return value to hold. Returning empty is correct rather than
// a gap: Unwrap is handed back exactly what Wrap produced, and requireNoNonce refuses
// anything else.
//
// It is NON-NIL on purpose. secret_versions.dek_nonce is BYTEA NOT NULL and pgx sends
// a nil []byte as SQL NULL, so a nil here would turn every KMS write into a constraint
// violation. An empty non-nil slice becomes an empty bytea.
func noNonce() []byte { return []byte{} }

// requireNoNonce rejects a nonce on a cloud unwrap.
//
// Reaching this means a version's dek_nonce disagrees with the provider its kek_id
// resolved to — which the KeyRing should make impossible — so the message points at
// that mismatch rather than at the caller's arguments.
func requireNoNonce(provider string, nonce []byte) error {
	if len(nonce) != 0 {
		return fmt.Errorf(
			"crypto: %s wrapped deks carry no nonce but %d bytes were supplied; this version was wrapped by a different provider",
			provider, len(nonce))
	}
	return nil
}

// requireWrapInput validates a DEK before it goes on the network. Checking locally
// keeps a malformed value off the wire entirely instead of paying a round-trip to be
// told what we already knew.
func requireWrapInput(dek []byte) error {
	if len(dek) != KeySize {
		return fmt.Errorf("crypto: dek must be %d bytes, got %d", KeySize, len(dek))
	}
	return nil
}

// requireUnwrapped checks what came back from a cloud unwrap.
//
// The length check is not distrust of the service: it is the guard that a truncated
// or substituted blob cannot become a short AES key downstream. The value is zeroized
// on the failure path because it is real key material either way.
func requireUnwrapped(dek []byte) ([]byte, error) {
	if len(dek) != KeySize {
		Zero(dek)
		return nil, fmt.Errorf("crypto: unwrapped dek is %d bytes, expected %d", len(dek), KeySize)
	}
	return dek, nil
}

// authFailure is the deliberately opaque error a failed cloud unwrap produces.
//
// Same reasoning as aesKEK.Unwrap: the distinguishable causes (wrong key, tampered
// blob, mismatched encryption context, a blob from another provider) are all "this
// wrapped DEK does not belong to this key", and telling them apart for the caller
// hands an attacker a probing oracle. The underlying error is NOT wrapped, so nothing
// derived from the material being unwrapped can travel out with it.
func authFailure(keyID string) error {
	return fmt.Errorf("crypto: unwrap dek under key %s failed authentication", keyID)
}

// kmsSelfTest proves at construction that the configured key is actually usable.
//
// It wraps a random probe and unwraps it again, so it exercises BOTH halves of the
// grant — Encrypt/Decrypt on AWS, useToEncrypt/useToDecrypt on GCP,
// wrapKey/unwrapKey on Azure. A credential holding only the first half is the failure
// this catches: without the self-test the service boots, accepts writes, and
// discovers on the first read that it cannot decrypt anything it wrote. It costs two
// KMS calls per process start.
//
// The probe is zeroized on every path and compared in constant time — not because a
// throwaway probe is worth protecting, but because this comparison shape gets copied.
func kmsSelfTest(p RootKeyProvider) error {
	probe, err := NewRandomKey()
	if err != nil {
		return err
	}
	defer Zero(probe)
	// A copy to compare against: Wrap has no business mutating its input, but the
	// self-test should not be the thing that assumes it.
	want := make([]byte, len(probe))
	copy(want, probe)
	defer Zero(want)

	wrapped, nonce, err := p.Wrap(probe)
	if err != nil {
		return fmt.Errorf("crypto: root key self-test could not wrap under %s: %w", p.KeyID(), err)
	}
	got, err := p.Unwrap(wrapped, nonce)
	if err != nil {
		return fmt.Errorf(
			"crypto: root key self-test could not unwrap under %s (a credential with encrypt but not decrypt looks exactly like this): %w",
			p.KeyID(), err)
	}
	defer Zero(got)
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return fmt.Errorf("crypto: root key self-test under %s did not round-trip; refusing to boot", p.KeyID())
	}
	return nil
}

// retryTransient runs call, retrying only while isTransient says the failure was
// worth another attempt.
//
// Two rules make this safe to sit underneath a Wrap:
//
//   - A CONTEXT ERROR IS NEVER RETRIED. The deadline this loop runs under is the
//     provider's own per-call timeout, so once it has fired, retrying spends a
//     caller's remaining budget on calls that cannot succeed.
//   - THE API'S ERROR IS WHAT COMES BACK, including when the backoff wait is cut
//     short by the deadline. An operator needs "throttled by KMS", not "context
//     deadline exceeded" three layers away from the cause.
//
// Backoff is exponential with full jitter. Jitter matters because every write of a
// secret takes this path: without it, one throttle turns into a synchronised retry
// burst from every in-flight write at once.
func retryTransient(ctx context.Context, baseDelay time.Duration, isTransient func(error) bool, call func(context.Context) error) error {
	delay := baseDelay
	for attempt := 1; ; attempt++ {
		err := call(ctx)
		if err == nil {
			return nil
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return err
		}
		if attempt >= kmsRetryAttempts || !isTransient(err) {
			return err
		}
		wait := time.Duration(0)
		if delay > 0 {
			wait = time.Duration(rand.Int64N(int64(delay)) + 1)
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(wait):
		}
		delay *= 2
	}
}
