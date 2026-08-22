package crypto

import (
	"context"
	"fmt"
	"hash/crc32"
	"log/slog"
	"strings"
	"time"

	gcpkms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	gax "github.com/googleapis/gax-go/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// gcpKMSAPI is the narrow slice of the Cloud KMS client this provider calls.
//
// Close is deliberately absent. The provider is built once at boot and lives for the
// process, so there is no lifecycle to manage — and leaving Close out of the interface
// means no code path can shut down the root of trust while the service is serving.
type gcpKMSAPI interface {
	Encrypt(ctx context.Context, req *kmspb.EncryptRequest, opts ...gax.CallOption) (*kmspb.EncryptResponse, error)
	Decrypt(ctx context.Context, req *kmspb.DecryptRequest, opts ...gax.CallOption) (*kmspb.DecryptResponse, error)
}

// Compile-time check that the real client satisfies the narrow interface.
var _ gcpKMSAPI = (*gcpkms.KeyManagementClient)(nil)

// gcpKMSProvider wraps DEKs with a Cloud KMS symmetric CryptoKey.
type gcpKMSProvider struct {
	api gcpKMSAPI
	// keyName is the fully qualified CryptoKey resource name. Encrypt uses the
	// key's primary version; Decrypt lets the service pick the version that
	// actually wrapped the blob, which is what makes a Google-side key rotation
	// invisible to this service.
	keyName    string
	keyID      string
	timeout    time.Duration
	retryDelay time.Duration
}

// crc32cTable is the Castagnoli polynomial Cloud KMS uses for its integrity
// checksums. Not a cryptographic hash and not used as one — see gcpWrap.
var crc32cTable = crc32.MakeTable(crc32.Castagnoli)

func crc32cOf(b []byte) uint32 { return crc32.Checksum(b, crc32cTable) }

func crc32cValue(b []byte) *wrapperspb.Int64Value {
	return wrapperspb.Int64(int64(crc32cOf(b)))
}

// newGCPKMSProvider builds the provider from configuration, authenticating with
// Application Default Credentials — a workload-identity binding on GKE, the attached
// service account on GCE/Cloud Run, GOOGLE_APPLICATION_CREDENTIALS, or a developer's
// gcloud login. As with AWS, none of that is read here: the client library owns
// credential resolution.
func newGCPKMSProvider(cfg ProviderConfig) (RootKeyProvider, error) {
	keyName := strings.TrimSpace(cfg.KMS.GCPKeyName)
	if keyName == "" {
		return nil, missingKMSSettings(ProviderGCPKMS, []string{"SECRET_KMS_GCP_KEY_NAME"})
	}
	if err := ValidateGCPKeyName(keyName); err != nil {
		return nil, err
	}

	timeout := kmsTimeout(cfg.KMS.Timeout)
	dialCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	client, err := gcpkms.NewKeyManagementClient(dialCtx)
	if err != nil {
		return nil, fmt.Errorf("crypto: gcp_kms could not resolve application default credentials: %w", err)
	}
	return newGCPKMS(client, keyName, timeout, defaultKMSRetryDelay)
}

// newGCPKMS is the injectable constructor — see newAWSKMS for why the split exists.
func newGCPKMS(api gcpKMSAPI, keyName string, timeout, retryDelay time.Duration) (RootKeyProvider, error) {
	if api == nil {
		return nil, fmt.Errorf("crypto: gcp_kms needs a client")
	}
	p := &gcpKMSProvider{
		api: api,
		// The resource name is already globally unique and already contains the
		// project, location and key ring, so it needs no further qualification.
		keyName:    keyName,
		keyID:      fingerprintRef(ProviderGCPKMS, keyName),
		timeout:    kmsTimeout(timeout),
		retryDelay: retryDelay,
	}
	if err := kmsSelfTest(p); err != nil {
		return nil, err
	}
	slog.Info("cloud KMS root key ready",
		"provider", ProviderGCPKMS, "kek_id", p.keyID, "key", keyName)
	return p, nil
}

func (p *gcpKMSProvider) KeyID() string { return p.keyID }

// ValidateGCPKeyName checks the shape of a Cloud KMS CryptoKey resource name.
//
// Exported because internal/platform/config validates it at boot, and one
// implementation is the only way config and the factory can agree. Two mistakes are
// worth catching before the first network call:
//
//   - A name that is not a CryptoKey at all (a key ring, a truncated path, a bare
//     key id) — Encrypt would fail with an opaque InvalidArgument.
//   - A cryptoKeyVersions/... suffix. Encrypt ACCEPTS a version name, Decrypt does
//     NOT: it takes a CryptoKey and resolves the version from the ciphertext itself.
//     A version-pinned name therefore boots, wraps successfully, and fails every
//     unwrap — the exact class of deferred failure this service refuses to allow.
func ValidateGCPKeyName(name string) error {
	parts := strings.Split(name, "/")
	shapeErr := fmt.Errorf(
		"crypto: SECRET_KMS_GCP_KEY_NAME %q is not a CryptoKey resource name; expected projects/{project}/locations/{location}/keyRings/{ring}/cryptoKeys/{key}",
		name)
	if len(parts) != 8 {
		if len(parts) == 10 && parts[8] == "cryptoKeyVersions" {
			return fmt.Errorf(
				"crypto: SECRET_KMS_GCP_KEY_NAME %q pins a cryptoKeyVersion; use the CryptoKey name without the /cryptoKeyVersions/... suffix — Decrypt takes a CryptoKey and chooses the version itself, so a pinned version wraps fine and then fails every unwrap",
				name)
		}
		return shapeErr
	}
	// The literals at the even positions and a non-empty id at each odd one. Both
	// halves matter: "projects//locations/..." has the right shape and names nothing.
	for i, literal := range []string{"projects", "", "locations", "", "keyRings", "", "cryptoKeys", ""} {
		if literal != "" && parts[i] != literal {
			return shapeErr
		}
		if literal == "" && parts[i] == "" {
			return shapeErr
		}
	}
	return nil
}

// Wrap encrypts a DEK with the CryptoKey's primary version.
//
// AdditionalAuthenticatedData carries the same binding the AES providers use —
// dekWrapAAD(kek_id) — so Cloud KMS itself refuses to decrypt a blob presented under
// a different key id, rather than that check living only in this process.
//
// The CRC32C fields are Google's documented client-side integrity protocol, and they
// close a gap the AAD does not: gRPC's own checksums cover a hop, not the whole path
// through the client library. Sending a checksum makes the service verify what it
// received (VerifiedPlaintextCrc32C), and checking the response checksum makes this
// process verify what came back. A corrupted DEK that got wrapped anyway would be an
// unreadable secret version, so the cost is worth paying on every call.
func (p *gcpKMSProvider) Wrap(dek []byte) ([]byte, []byte, error) {
	if err := requireWrapInput(dek); err != nil {
		return nil, nil, err
	}
	aad := dekWrapAAD(p.keyID)
	ctx, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()

	var resp *kmspb.EncryptResponse
	err := retryTransient(ctx, p.retryDelay, gcpTransient, func(ctx context.Context) error {
		var callErr error
		resp, callErr = p.api.Encrypt(ctx, &kmspb.EncryptRequest{
			Name:                              p.keyName,
			Plaintext:                         dek,
			AdditionalAuthenticatedData:       aad,
			PlaintextCrc32C:                   crc32cValue(dek),
			AdditionalAuthenticatedDataCrc32C: crc32cValue(aad),
		})
		return callErr
	})
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: gcp_kms encrypt dek under %s: %w", p.keyID, err)
	}
	if !resp.GetVerifiedPlaintextCrc32C() || !resp.GetVerifiedAdditionalAuthenticatedDataCrc32C() {
		return nil, nil, fmt.Errorf(
			"crypto: gcp_kms did not verify the request checksums for %s; the request was corrupted in transit", p.keyID)
	}
	blob := resp.GetCiphertext()
	if len(blob) == 0 {
		return nil, nil, fmt.Errorf("crypto: gcp_kms returned an empty ciphertext for %s", p.keyID)
	}
	if resp.GetCiphertextCrc32C().GetValue() != int64(crc32cOf(blob)) {
		return nil, nil, fmt.Errorf(
			"crypto: gcp_kms response checksum mismatch for %s; the wrapped dek was corrupted in transit", p.keyID)
	}
	return blob, noNonce(), nil
}

// Unwrap recovers a DEK. The caller zeroizes the result.
func (p *gcpKMSProvider) Unwrap(wrapped, nonce []byte) ([]byte, error) {
	if err := requireNoNonce(ProviderGCPKMS, nonce); err != nil {
		return nil, err
	}
	if len(wrapped) == 0 {
		return nil, fmt.Errorf("crypto: gcp_kms cannot unwrap an empty blob under %s", p.keyID)
	}
	aad := dekWrapAAD(p.keyID)
	ctx, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()

	var resp *kmspb.DecryptResponse
	err := retryTransient(ctx, p.retryDelay, gcpTransient, func(ctx context.Context) error {
		var callErr error
		resp, callErr = p.api.Decrypt(ctx, &kmspb.DecryptRequest{
			Name:                              p.keyName,
			Ciphertext:                        wrapped,
			AdditionalAuthenticatedData:       aad,
			CiphertextCrc32C:                  crc32cValue(wrapped),
			AdditionalAuthenticatedDataCrc32C: crc32cValue(aad),
		})
		return callErr
	})
	if err != nil {
		// Cloud KMS reports a mismatched AAD, a tampered blob and a blob from
		// another key as InvalidArgument. A wrong key NAME is NotFound or
		// PermissionDenied instead, so this mapping does not swallow a config
		// mistake — it collapses only the cases that are genuinely one fact.
		if status.Code(err) == codes.InvalidArgument {
			return nil, authFailure(p.keyID)
		}
		return nil, fmt.Errorf("crypto: gcp_kms decrypt dek under %s: %w", p.keyID, err)
	}
	dek := resp.GetPlaintext()
	if resp.GetPlaintextCrc32C().GetValue() != int64(crc32cOf(dek)) {
		Zero(dek)
		return nil, fmt.Errorf(
			"crypto: gcp_kms response checksum mismatch for %s; the unwrapped dek was corrupted in transit", p.keyID)
	}
	return requireUnwrapped(dek)
}

// gcpTransient reports whether a Cloud KMS failure is worth retrying.
//
// Unavailable and Internal are the ordinary server-side blips; ResourceExhausted is
// the quota/throttle signal; Aborted is a concurrency conflict. DeadlineExceeded is
// included for a server-side deadline, and is harmless for our own: retryTransient
// returns as soon as the per-call context is done, so an expired deadline cannot
// generate extra attempts.
//
// Deliberately absent: InvalidArgument, NotFound, PermissionDenied,
// FailedPrecondition — a disabled key, a wrong name or a missing IAM grant will read
// the same way on the third attempt as on the first.
func gcpTransient(err error) bool {
	switch status.Code(err) {
	case codes.Unavailable, codes.Internal, codes.ResourceExhausted, codes.Aborted, codes.DeadlineExceeded:
		return true
	default:
		return false
	}
}
