package crypto

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	gax "github.com/googleapis/gax-go/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// ---------------------------------------------------------------------------
// What these tests prove, and what they cannot
// ---------------------------------------------------------------------------
//
// THE FAKES PROVE THE ADAPTER, NOT THE CLOUD. Every test below runs the real
// provider — the real encryption context, the real key pinning, the real retry
// classification, the real redaction — against an in-process stand-in for the cloud
// service. That is the whole reason each provider sits behind a narrow interface with
// a compile-time assertion that the SDK client satisfies it: there is no cloud
// credential in CI, and "we could not test it" is how an encrypt-only IAM policy
// reaches production.
//
// What the fakes cannot prove is that a particular key exists, that this service's
// principal can reach it, or that the IAM grant is correct. That is an OPERATOR STEP,
// and it is checked twice:
//
//  1. Before deploying, with the CLI commands in README.md's root-of-trust section
//     (aws kms encrypt | decrypt, gcloud kms encrypt | decrypt, az keyvault key show).
//  2. At every boot, by kmsSelfTest — the provider wraps and unwraps a throwaway
//     probe during construction, so a missing decrypt grant is a boot error instead
//     of a surprise on the first read. TestKMSSelfTestCatchesAnEncryptOnlyGrant is
//     the test for that behaviour.
//
// The fakes use real AES-256-GCM (fakeHSM) rather than echoing bytes, so an AAD or
// encryption-context mismatch fails the way the service fails, not the way a stub was
// told to.

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

// fakeHSM stands in for a cloud key: a real AEAD over a random key that never leaves
// the struct, which is about as close to a KMS's contract as an in-process fake gets.
type fakeHSM struct {
	aead cipher.AEAD
}

func newFakeHSM(t *testing.T) *fakeHSM {
	t.Helper()
	key := make([]byte, KeySize)
	_, err := io.ReadFull(rand.Reader, key)
	require.NoError(t, err)
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)
	return &fakeHSM{aead: aead}
}

// seal returns one self-describing blob (nonce ‖ ciphertext), mirroring the way a real
// KMS returns a single opaque value and no separate nonce.
func (h *fakeHSM) seal(plaintext, aad []byte) []byte {
	nonce := make([]byte, h.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err)
	}
	return h.aead.Seal(nonce, nonce, plaintext, aad)
}

func (h *fakeHSM) open(blob, aad []byte) ([]byte, error) {
	n := h.aead.NonceSize()
	if len(blob) < n {
		return nil, errors.New("fake hsm: blob too short")
	}
	return h.aead.Open(nil, blob[:n], blob[n:], aad)
}

// fakeFaults scripts a fake client's failure behaviour and counts the calls the
// adapter actually made, which is how "retried" and "not retried" are asserted. The
// mutex is there because TestKMSProviderIsConcurrencySafe runs under -race.
type fakeFaults struct {
	mu sync.Mutex
	// failNext fails this many upcoming calls before letting one through.
	failNext int
	// err is the failure returned while failNext is positive.
	err error
	// block makes every call wait for the context, so a timeout is observable
	// without a sleep.
	block bool
	// calls counts every call the adapter made.
	calls int
}

func (f *fakeFaults) next(ctx context.Context) error {
	f.mu.Lock()
	f.calls++
	block := f.block
	var err error
	if f.failNext > 0 {
		f.failNext--
		err = f.err
	}
	f.mu.Unlock()

	if block {
		<-ctx.Done()
		return ctx.Err()
	}
	return err
}

// script sets the failure plan. reset clears it after construction, so the boot
// self-test's two calls do not count towards a test's assertions.
func (f *fakeFaults) script(failNext int, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failNext, f.err = failNext, err
}

func (f *fakeFaults) blockForever() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.block = true
}

func (f *fakeFaults) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls, f.failNext, f.err, f.block = 0, 0, nil, false
}

func (f *fakeFaults) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// --- AWS -------------------------------------------------------------------

// canonicalContext renders a KMS encryption context into deterministic AAD bytes.
// Length-prefixed and sorted for the same reason Identity.AAD is length-prefixed: a
// delimiter-joined map is not an injective encoding.
func canonicalContext(ctx map[string]string) []byte {
	keys := make([]string, 0, len(ctx))
	for k := range ctx {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b bytes.Buffer
	for _, k := range keys {
		for _, field := range []string{k, ctx[k]} {
			var n [4]byte
			binary.BigEndian.PutUint32(n[:], uint32(len(field)))
			b.Write(n[:])
			b.WriteString(field)
		}
	}
	return b.Bytes()
}

type fakeAWSKMS struct {
	hsm    *fakeHSM
	keyRef string
	faults fakeFaults

	mu sync.Mutex
	// decryptSawKeyID records whether the adapter pinned the key on Decrypt.
	decryptSawKeyID string
	decryptCalls    int
}

var _ awsKMSAPI = (*fakeAWSKMS)(nil)

func (f *fakeAWSKMS) Encrypt(ctx context.Context, in *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	if err := f.faults.next(ctx); err != nil {
		return nil, err
	}
	if aws.ToString(in.KeyId) != f.keyRef {
		return nil, &kmstypes.NotFoundException{Message: aws.String("fake: no such key")}
	}
	return &kms.EncryptOutput{CiphertextBlob: f.hsm.seal(in.Plaintext, canonicalContext(in.EncryptionContext))}, nil
}

func (f *fakeAWSKMS) Decrypt(ctx context.Context, in *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	if err := f.faults.next(ctx); err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.decryptCalls++
	f.decryptSawKeyID = aws.ToString(in.KeyId)
	pinned := f.decryptSawKeyID
	f.mu.Unlock()

	if pinned != f.keyRef {
		// A real KMS decrypts with whatever key an unpinned blob names; the fake
		// insists on the pin, so the adapter losing it is a test failure rather
		// than a silent widening of the trust boundary.
		return nil, &kmstypes.IncorrectKeyException{Message: aws.String("fake: wrong key pinned")}
	}
	plain, err := f.hsm.open(in.CiphertextBlob, canonicalContext(in.EncryptionContext))
	if err != nil {
		return nil, &kmstypes.InvalidCiphertextException{}
	}
	return &kms.DecryptOutput{Plaintext: plain}, nil
}

func (f *fakeAWSKMS) observedDecrypt() (string, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.decryptSawKeyID, f.decryptCalls
}

// --- GCP -------------------------------------------------------------------

type fakeGCPKMS struct {
	hsm     *fakeHSM
	keyName string
	faults  fakeFaults
	// dropRequestVerification makes the fake claim it did not verify the request
	// checksums, which is how the corruption guard is exercised.
	dropRequestVerification bool
	// corruptResponseChecksum returns a checksum that does not match the payload.
	corruptResponseChecksum bool
}

var _ gcpKMSAPI = (*fakeGCPKMS)(nil)

func (f *fakeGCPKMS) Encrypt(ctx context.Context, req *kmspb.EncryptRequest, _ ...gax.CallOption) (*kmspb.EncryptResponse, error) {
	if err := f.faults.next(ctx); err != nil {
		return nil, err
	}
	if req.GetName() != f.keyName {
		return nil, status.Error(codes.NotFound, "fake: no such key")
	}
	if req.GetPlaintextCrc32C().GetValue() != int64(crc32cOf(req.GetPlaintext())) {
		return nil, status.Error(codes.InvalidArgument, "fake: plaintext checksum mismatch")
	}
	blob := f.hsm.seal(req.GetPlaintext(), req.GetAdditionalAuthenticatedData())
	checksum := crc32cValue(blob)
	if f.corruptResponseChecksum {
		checksum = wrapperspb.Int64(checksum.GetValue() ^ 1)
	}
	return &kmspb.EncryptResponse{
		Name:                    f.keyName,
		Ciphertext:              blob,
		CiphertextCrc32C:        checksum,
		VerifiedPlaintextCrc32C: !f.dropRequestVerification,
		VerifiedAdditionalAuthenticatedDataCrc32C: !f.dropRequestVerification,
	}, nil
}

func (f *fakeGCPKMS) Decrypt(ctx context.Context, req *kmspb.DecryptRequest, _ ...gax.CallOption) (*kmspb.DecryptResponse, error) {
	if err := f.faults.next(ctx); err != nil {
		return nil, err
	}
	if req.GetName() != f.keyName {
		return nil, status.Error(codes.NotFound, "fake: no such key")
	}
	plain, err := f.hsm.open(req.GetCiphertext(), req.GetAdditionalAuthenticatedData())
	if err != nil {
		// What Cloud KMS returns for a mismatched AAD or a tampered blob.
		return nil, status.Error(codes.InvalidArgument, "fake: decryption failed")
	}
	checksum := crc32cValue(plain)
	if f.corruptResponseChecksum {
		checksum = wrapperspb.Int64(checksum.GetValue() ^ 1)
	}
	return &kmspb.DecryptResponse{Plaintext: plain, PlaintextCrc32C: checksum}, nil
}

// --- Azure -----------------------------------------------------------------

type fakeAzureKeys struct {
	hsm        *fakeHSM
	keyName    string
	keyVersion string
	faults     fakeFaults

	mu sync.Mutex
	// observed call parameters, so the algorithm and coordinates are assertable.
	sawAlgorithm  azkeys.EncryptionAlgorithm
	sawName       string
	sawKeyVersion string
}

var _ azureKeysAPI = (*fakeAzureKeys)(nil)

func azureStatusError(code int) error {
	return &azcore.ResponseError{
		StatusCode:  code,
		ErrorCode:   "FakeVaultError",
		RawResponse: &http.Response{StatusCode: code, Body: http.NoBody},
	}
}

func (f *fakeAzureKeys) observe(name, version string, params azkeys.KeyOperationParameters) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sawName, f.sawKeyVersion = name, version
	if params.Algorithm != nil {
		f.sawAlgorithm = *params.Algorithm
	}
}

func (f *fakeAzureKeys) observed() (azkeys.EncryptionAlgorithm, string, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sawAlgorithm, f.sawName, f.sawKeyVersion
}

func (f *fakeAzureKeys) WrapKey(ctx context.Context, name, version string, params azkeys.KeyOperationParameters, _ *azkeys.WrapKeyOptions) (azkeys.WrapKeyResponse, error) {
	if err := f.faults.next(ctx); err != nil {
		return azkeys.WrapKeyResponse{}, err
	}
	f.observe(name, version, params)
	if name != f.keyName || version != f.keyVersion {
		return azkeys.WrapKeyResponse{}, azureStatusError(http.StatusNotFound)
	}
	// RSA-OAEP has no AAD channel, which is exactly why the provider frames the
	// binding into the wrapped plaintext instead. The fake therefore takes no AAD.
	return azkeys.WrapKeyResponse{
		KeyOperationResult: azkeys.KeyOperationResult{Result: f.hsm.seal(params.Value, nil)},
	}, nil
}

func (f *fakeAzureKeys) UnwrapKey(ctx context.Context, name, version string, params azkeys.KeyOperationParameters, _ *azkeys.UnwrapKeyOptions) (azkeys.UnwrapKeyResponse, error) {
	if err := f.faults.next(ctx); err != nil {
		return azkeys.UnwrapKeyResponse{}, err
	}
	f.observe(name, version, params)
	if name != f.keyName || version != f.keyVersion {
		return azkeys.UnwrapKeyResponse{}, azureStatusError(http.StatusNotFound)
	}
	plain, err := f.hsm.open(params.Value, nil)
	if err != nil {
		// A blob wrapped under a different key fails RSA-OAEP's padding check,
		// which Key Vault reports as a 400.
		return azkeys.UnwrapKeyResponse{}, azureStatusError(http.StatusBadRequest)
	}
	return azkeys.UnwrapKeyResponse{KeyOperationResult: azkeys.KeyOperationResult{Result: plain}}, nil
}

// ---------------------------------------------------------------------------
// Test builders
// ---------------------------------------------------------------------------

// Fixed coordinates, so a kek_id assertion is about the derivation rather than about
// a random value that happened to differ.
const (
	testAWSRegion   = "us-east-2"
	testAWSKeyARN   = "arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
	testGCPKeyName  = "projects/acme/locations/us-east1/keyRings/secret/cryptoKeys/root"
	testVaultURL    = "https://acme-vault.vault.azure.net/"
	testAzureKey    = "secret-root"
	testAzureKeyVer = ""
	// testKMSTimeout keeps the timeout test fast while staying far above the cost of
	// an in-process fake call.
	testKMSTimeout = 500 * time.Millisecond
)

// newTestAWSKMS builds the real adapter over a fake KMS. Construction runs the boot
// self-test, so the fault script is reset afterwards: a test asserting "one call"
// should not have to account for the probe.
func newTestAWSKMS(t *testing.T) (RootKeyProvider, *fakeAWSKMS) {
	t.Helper()
	api := &fakeAWSKMS{hsm: newFakeHSM(t), keyRef: testAWSKeyARN}
	p, err := newAWSKMS(api, testAWSRegion, testAWSKeyARN, testKMSTimeout, 0)
	require.NoError(t, err)
	api.faults.reset()
	api.mu.Lock()
	api.decryptCalls, api.decryptSawKeyID = 0, ""
	api.mu.Unlock()
	return p, api
}

func newTestGCPKMS(t *testing.T) (RootKeyProvider, *fakeGCPKMS) {
	t.Helper()
	api := &fakeGCPKMS{hsm: newFakeHSM(t), keyName: testGCPKeyName}
	p, err := newGCPKMS(api, testGCPKeyName, testKMSTimeout, 0)
	require.NoError(t, err)
	api.faults.reset()
	return p, api
}

func newTestAzureKV(t *testing.T) (RootKeyProvider, *fakeAzureKeys) {
	t.Helper()
	api := &fakeAzureKeys{hsm: newFakeHSM(t), keyName: testAzureKey, keyVersion: testAzureKeyVer}
	p, err := newAzureKV(api, testVaultURL, testAzureKey, testAzureKeyVer, testKMSTimeout, 0)
	require.NoError(t, err)
	api.faults.reset()
	return p, api
}

// kmsCase is one cloud provider expressed uniformly, so the properties every provider
// must have are asserted once instead of three times with three chances to diverge.
type kmsCase struct {
	name string
	// build returns the provider plus a handle on the fake's fault script.
	build func(t *testing.T) (RootKeyProvider, *fakeFaults)
	// transient is an error the provider's classifier must retry.
	transient error
	// permanent is an error it must not.
	permanent error
}

func kmsCases() []kmsCase {
	return []kmsCase{
		{
			name: ProviderAWSKMS,
			build: func(t *testing.T) (RootKeyProvider, *fakeFaults) {
				p, api := newTestAWSKMS(t)
				return p, &api.faults
			},
			transient: &kmstypes.KMSInternalException{Message: aws.String("internal")},
			permanent: &kmstypes.NotFoundException{Message: aws.String("not found")},
		},
		{
			name: ProviderGCPKMS,
			build: func(t *testing.T) (RootKeyProvider, *fakeFaults) {
				p, api := newTestGCPKMS(t)
				return p, &api.faults
			},
			transient: status.Error(codes.Unavailable, "unavailable"),
			permanent: status.Error(codes.PermissionDenied, "permission denied"),
		},
		{
			name: ProviderAzureKV,
			build: func(t *testing.T) (RootKeyProvider, *fakeFaults) {
				p, api := newTestAzureKV(t)
				return p, &api.faults
			},
			transient: azureStatusError(http.StatusTooManyRequests),
			permanent: azureStatusError(http.StatusForbidden),
		},
	}
}

func mustKey(t *testing.T) []byte {
	t.Helper()
	k, err := NewRandomKey()
	require.NoError(t, err)
	return k
}

// ---------------------------------------------------------------------------
// Registration and configuration
// ---------------------------------------------------------------------------

func TestKMSProvidersAreBuiltAndDemandTheirSettings(t *testing.T) {
	// The three cloud providers are BUILT now: selecting one without its settings is
	// a configuration error naming the variables, not a "not built yet" refusal.
	// Both are boot errors — what changed is which question the operator is left
	// holding.
	cases := map[string][]string{
		ProviderAWSKMS:  {"SECRET_KMS_AWS_KEY_ID", "SECRET_KMS_AWS_REGION"},
		ProviderGCPKMS:  {"SECRET_KMS_GCP_KEY_NAME"},
		ProviderAzureKV: {"SECRET_KMS_AZURE_VAULT_URL", "SECRET_KMS_AZURE_KEY_NAME"},
	}
	for provider, wantNamed := range cases {
		t.Run(provider, func(t *testing.T) {
			_, err := NewRootKeyProvider(ProviderConfig{Provider: provider, AppEnv: "production"})
			require.Error(t, err)
			assert.NotContains(t, err.Error(), "not built")
			for _, name := range wantNamed {
				assert.Contains(t, err.Error(), name,
					"the error must name every missing variable at once, not one per restart")
			}
			assert.Contains(t, KnownProviders(), provider)
		})
	}
}

func TestKMSKeyIDIsStableProviderPrefixedAndColumnSized(t *testing.T) {
	for _, tc := range kmsCases() {
		t.Run(tc.name, func(t *testing.T) {
			p1, _ := tc.build(t)
			p2, _ := tc.build(t)
			// Two providers over two different fake HSMs: the id comes from the
			// configured coordinates, never from key material and never from a
			// random value, so a restart cannot orphan the rows the previous
			// process wrote.
			assert.Equal(t, p1.KeyID(), p2.KeyID())
			assert.Equal(t, tc.name, ProviderOf(p1.KeyID()))
			assert.LessOrEqual(t, len(p1.KeyID()), 64, "kek_id must fit VARCHAR(64)")
		})
	}
}

func TestKMSKeyIDChangesWithTheConfiguredKey(t *testing.T) {
	awsBase, _ := newTestAWSKMS(t)

	// Same key reference, different region: an alias is region-scoped, so these are
	// two different keys and must not collide on one kek_id.
	otherRegion, err := newAWSKMS(&fakeAWSKMS{hsm: newFakeHSM(t), keyRef: testAWSKeyARN},
		"eu-west-1", testAWSKeyARN, testKMSTimeout, 0)
	require.NoError(t, err)
	assert.NotEqual(t, awsBase.KeyID(), otherRegion.KeyID())

	// Same region, different key.
	const otherKey = "alias/another-root"
	other, err := newAWSKMS(&fakeAWSKMS{hsm: newFakeHSM(t), keyRef: otherKey},
		testAWSRegion, otherKey, testKMSTimeout, 0)
	require.NoError(t, err)
	assert.NotEqual(t, awsBase.KeyID(), other.KeyID())

	// Azure: vault, key name and pinned version each participate.
	azBase, _ := newTestAzureKV(t)
	azPinned, err := newAzureKV(&fakeAzureKeys{hsm: newFakeHSM(t), keyName: testAzureKey, keyVersion: "v2"},
		testVaultURL, testAzureKey, "v2", testKMSTimeout, 0)
	require.NoError(t, err)
	assert.NotEqual(t, azBase.KeyID(), azPinned.KeyID())

	// And a reference-derived kek_id must never collide with a material-derived one.
	assert.NotEqual(t,
		fingerprint(ProviderAWSKMS, bytes.Repeat([]byte{1}, KeySize)),
		fingerprintRef(ProviderAWSKMS, testAWSRegion+"|"+testAWSKeyARN))
}

func TestGCPKeyNameValidation(t *testing.T) {
	require.NoError(t, ValidateGCPKeyName(testGCPKeyName))

	t.Run("a pinned key version is refused with the reason", func(t *testing.T) {
		// Encrypt accepts a version name and Decrypt does not, so this
		// configuration would boot, wrap, and then fail every unwrap — the exact
		// deferred failure this service refuses to allow.
		err := ValidateGCPKeyName(testGCPKeyName + "/cryptoKeyVersions/3")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cryptoKeyVersion")
		assert.Contains(t, err.Error(), "fails every unwrap")
	})

	for _, bad := range []string{
		"",
		"root",
		"projects/acme/locations/us-east1/keyRings/secret",
		"projects/acme/locations/us-east1/keyRings/secret/cryptoKeys/",
		"projects//locations/us-east1/keyRings/secret/cryptoKeys/root",
		"project/acme/locations/us-east1/keyRings/secret/cryptoKeys/root",
	} {
		t.Run("rejects "+bad, func(t *testing.T) {
			require.Error(t, ValidateGCPKeyName(bad))
		})
	}
}

func TestAzureVaultURLValidation(t *testing.T) {
	require.NoError(t, ValidateAzureVaultURL(testVaultURL))

	t.Run("plain http is refused", func(t *testing.T) {
		err := ValidateAzureVaultURL("http://acme-vault.vault.azure.net/")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "https")
	})
	for _, bad := range []string{"", "acme-vault.vault.azure.net", "https://"} {
		t.Run("rejects "+bad, func(t *testing.T) {
			require.Error(t, ValidateAzureVaultURL(bad))
		})
	}
}

// ---------------------------------------------------------------------------
// The boot self-test
// ---------------------------------------------------------------------------

// encryptOnlyAWS is a fake whose credential can encrypt but not decrypt — the
// asymmetric IAM grant that, without a self-test, produces a vault which accepts
// writes it can never read back.
type encryptOnlyAWS struct{ *fakeAWSKMS }

func (encryptOnlyAWS) Decrypt(context.Context, *kms.DecryptInput, ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	return nil, errors.New("AccessDeniedException: kms:Decrypt is not permitted")
}

func TestKMSSelfTestCatchesAnEncryptOnlyGrant(t *testing.T) {
	api := &fakeAWSKMS{hsm: newFakeHSM(t), keyRef: testAWSKeyARN}
	_, err := newAWSKMS(encryptOnlyAWS{api}, testAWSRegion, testAWSKeyARN, testKMSTimeout, 0)
	require.Error(t, err, "construction must fail at boot, not on the first read")
	assert.Contains(t, err.Error(), "self-test")
	assert.Contains(t, err.Error(), "decrypt")
}

func TestKMSSelfTestRunsAtConstructionForEveryProvider(t *testing.T) {
	// One wrap and one unwrap per provider before it is handed back: that is what
	// makes a wrong key or a one-sided grant a boot error.
	t.Run(ProviderAWSKMS, func(t *testing.T) {
		api := &fakeAWSKMS{hsm: newFakeHSM(t), keyRef: testAWSKeyARN}
		_, err := newAWSKMS(api, testAWSRegion, testAWSKeyARN, testKMSTimeout, 0)
		require.NoError(t, err)
		assert.Equal(t, 2, api.faults.count())
	})
	t.Run(ProviderGCPKMS, func(t *testing.T) {
		api := &fakeGCPKMS{hsm: newFakeHSM(t), keyName: testGCPKeyName}
		_, err := newGCPKMS(api, testGCPKeyName, testKMSTimeout, 0)
		require.NoError(t, err)
		assert.Equal(t, 2, api.faults.count())
	})
	t.Run(ProviderAzureKV, func(t *testing.T) {
		api := &fakeAzureKeys{hsm: newFakeHSM(t), keyName: testAzureKey, keyVersion: testAzureKeyVer}
		_, err := newAzureKV(api, testVaultURL, testAzureKey, testAzureKeyVer, testKMSTimeout, 0)
		require.NoError(t, err)
		assert.Equal(t, 2, api.faults.count())
	})
}

func TestKMSConstructorsRejectANilClient(t *testing.T) {
	_, err := newAWSKMS(nil, testAWSRegion, testAWSKeyARN, testKMSTimeout, 0)
	require.Error(t, err)
	_, err = newGCPKMS(nil, testGCPKeyName, testKMSTimeout, 0)
	require.Error(t, err)
	_, err = newAzureKV(nil, testVaultURL, testAzureKey, "", testKMSTimeout, 0)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// Properties every cloud provider must have
// ---------------------------------------------------------------------------

func TestKMSWrapUnwrapRoundTrip(t *testing.T) {
	for _, tc := range kmsCases() {
		t.Run(tc.name, func(t *testing.T) {
			p, _ := tc.build(t)
			dek := mustKey(t)

			wrapped, nonce, err := p.Wrap(dek)
			require.NoError(t, err)
			assert.NotEmpty(t, wrapped)
			// A KMS blob needs no separate nonce — but the empty slice must be
			// NON-NIL, because secret_versions.dek_nonce is BYTEA NOT NULL and pgx
			// sends a nil []byte as SQL NULL.
			assert.Empty(t, nonce)
			assert.NotNil(t, nonce)
			assert.NotContains(t, string(wrapped), string(dek), "the wrapped blob must not contain the dek")

			got, err := p.Unwrap(wrapped, nonce)
			require.NoError(t, err)
			assert.Equal(t, dek, got)
		})
	}
}

func TestKMSWrapRejectsAMalformedDEK(t *testing.T) {
	for _, tc := range kmsCases() {
		t.Run(tc.name, func(t *testing.T) {
			p, faults := tc.build(t)
			_, _, err := p.Wrap(make([]byte, KeySize-1))
			require.Error(t, err)
			assert.Zero(t, faults.count(), "a malformed dek must never reach the network")
		})
	}
}

func TestKMSUnwrapRefusesANonEmptyNonce(t *testing.T) {
	// A nonce here means the version's dek_nonce disagrees with the provider its
	// kek_id resolved to. Refusing is what keeps that from being read as ciphertext.
	for _, tc := range kmsCases() {
		t.Run(tc.name, func(t *testing.T) {
			p, _ := tc.build(t)
			wrapped, _, err := p.Wrap(mustKey(t))
			require.NoError(t, err)

			_, err = p.Unwrap(wrapped, bytes.Repeat([]byte{0x01}, NonceSize))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "no nonce")
		})
	}
}

func TestKMSUnwrapRefusesAnEmptyBlob(t *testing.T) {
	for _, tc := range kmsCases() {
		t.Run(tc.name, func(t *testing.T) {
			p, faults := tc.build(t)
			_, err := p.Unwrap(nil, nil)
			require.Error(t, err)
			assert.Zero(t, faults.count())
		})
	}
}

func TestKMSRetriesTransientFailuresOnly(t *testing.T) {
	for _, tc := range kmsCases() {
		t.Run(tc.name+"/transient is retried", func(t *testing.T) {
			p, faults := tc.build(t)
			faults.script(kmsRetryAttempts-1, tc.transient)

			wrapped, nonce, err := p.Wrap(mustKey(t))
			require.NoError(t, err, "a throttle or a 5xx must not fail the write")
			assert.Equal(t, kmsRetryAttempts, faults.count())
			assert.NotEmpty(t, wrapped)
			assert.NotNil(t, nonce)
		})

		t.Run(tc.name+"/transient beyond the attempt budget gives up", func(t *testing.T) {
			p, faults := tc.build(t)
			faults.script(kmsRetryAttempts+5, tc.transient)

			_, _, err := p.Wrap(mustKey(t))
			require.Error(t, err)
			assert.Equal(t, kmsRetryAttempts, faults.count(),
				"retrying forever inside a request is not a strategy")
		})

		t.Run(tc.name+"/permanent is not retried", func(t *testing.T) {
			p, faults := tc.build(t)
			faults.script(1, tc.permanent)

			_, _, err := p.Wrap(mustKey(t))
			require.Error(t, err)
			assert.Equal(t, 1, faults.count(),
				"AccessDenied and NotFound read the same on the third attempt; retrying turns one clear error into three slow ones")
		})
	}
}

func TestKMSPerCallTimeoutIsHonoured(t *testing.T) {
	// The provider owns its deadline because RootKeyProvider takes no context. A
	// black-holed endpoint must therefore fail fast rather than pin a request
	// goroutine for as long as the network allows.
	for _, tc := range kmsCases() {
		t.Run(tc.name, func(t *testing.T) {
			p, faults := tc.build(t)
			faults.blockForever()
			dek := mustKey(t)

			done := make(chan error, 1)
			start := time.Now()
			go func() {
				_, _, err := p.Wrap(dek)
				done <- err
			}()
			select {
			case err := <-done:
				require.Error(t, err)
				assert.Less(t, time.Since(start), 10*testKMSTimeout)
				assert.Equal(t, 1, faults.count(), "a deadline that has fired must not be retried")
			case <-time.After(30 * testKMSTimeout):
				t.Fatal("Wrap did not honour its per-call timeout")
			}
		})
	}
}

func TestKMSErrorsCarryNoSecrets(t *testing.T) {
	// The package rule, applied to the cloud paths: no error may carry a DEK or a
	// wrapped blob, in any encoding. The provider is what is under test — the fake's
	// errors are ordinary API errors, so anything leaking here leaked because the
	// adapter put it there.
	for _, tc := range kmsCases() {
		t.Run(tc.name, func(t *testing.T) {
			p, faults := tc.build(t)
			dek := mustKey(t)
			wrapped, nonce, err := p.Wrap(dek)
			require.NoError(t, err)

			var messages []string

			// 1. A failed wrap.
			faults.script(1, tc.permanent)
			_, _, err = p.Wrap(dek)
			require.Error(t, err)
			messages = append(messages, err.Error())

			// 2. A failed unwrap on a permanent fault.
			faults.script(1, tc.permanent)
			_, err = p.Unwrap(wrapped, nonce)
			require.Error(t, err)
			messages = append(messages, err.Error())

			// 3. A blob that does not belong to this key — the authentication
			//    failure path, which stays opaque so it is not a probing oracle.
			tampered := append([]byte(nil), wrapped...)
			tampered[len(tampered)-1] ^= 0xff
			_, err = p.Unwrap(tampered, nonce)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "failed authentication")
			messages = append(messages, err.Error())

			// 4. A nonce that should not be there.
			_, err = p.Unwrap(wrapped, bytes.Repeat([]byte{0x02}, NonceSize))
			require.Error(t, err)
			messages = append(messages, err.Error())

			for _, msg := range messages {
				assertNoSecretMaterial(t, msg, dek, wrapped, tampered)
			}
		})
	}
}

// assertNoSecretMaterial checks a message against every plausible rendering of the
// material: raw bytes, hex, and all four base64 alphabets. A leak that only shows up
// base64-encoded is still a leak.
func assertNoSecretMaterial(t *testing.T, message string, secrets ...[]byte) {
	t.Helper()
	for _, secret := range secrets {
		if len(secret) == 0 {
			continue
		}
		for _, rendering := range []string{
			string(secret),
			hex.EncodeToString(secret),
			base64.StdEncoding.EncodeToString(secret),
			base64.RawStdEncoding.EncodeToString(secret),
			base64.URLEncoding.EncodeToString(secret),
			base64.RawURLEncoding.EncodeToString(secret),
		} {
			assert.NotContains(t, message, rendering)
		}
	}
}

// ---------------------------------------------------------------------------
// Per-provider AAD binding
// ---------------------------------------------------------------------------

func TestAWSEncryptionContextIsBoundToTheServiceAndKey(t *testing.T) {
	p, api := newTestAWSKMS(t)

	// The context is what KMS authenticates, so it is what stops a blob wrapped for
	// this service under this key being decrypted as something else's.
	wrapped, nonce, err := p.Wrap(mustKey(t))
	require.NoError(t, err)

	got := awsEncryptionContext(p.KeyID())
	assert.Equal(t, kmsServiceName, got["maintainerd_service"])
	assert.Equal(t, p.KeyID(), got["kek_id"])

	// A blob sealed under a DIFFERENT context does not open under ours. The fake
	// enforces the context the way KMS does, so this is the real check.
	foreign := api.hsm.seal(mustKey(t), canonicalContext(map[string]string{"kek_id": "aws_kms:deadbeefdeadbeefdeadbeef"}))
	_, err = p.Unwrap(foreign, nonce)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed authentication")

	// And ours still opens.
	_, err = p.Unwrap(wrapped, nonce)
	require.NoError(t, err)
}

func TestAWSDecryptPinsTheConfiguredKey(t *testing.T) {
	// Without KeyId on Decrypt, KMS uses whatever key the blob names — so anything
	// able to write a dek_wrapped column could hand this service a blob encrypted
	// under a key the attacker controls. The fake refuses an unpinned call, so a
	// regression here fails instead of silently widening the trust boundary.
	p, api := newTestAWSKMS(t)
	wrapped, nonce, err := p.Wrap(mustKey(t))
	require.NoError(t, err)
	_, err = p.Unwrap(wrapped, nonce)
	require.NoError(t, err)

	sawKeyID, calls := api.observedDecrypt()
	assert.Equal(t, testAWSKeyARN, sawKeyID)
	assert.Positive(t, calls)
}

func TestGCPAADIsBoundToTheKey(t *testing.T) {
	p, api := newTestGCPKMS(t)
	wrapped, nonce, err := p.Wrap(mustKey(t))
	require.NoError(t, err)

	// Sealed under a different kek_id's AAD: Cloud KMS reports InvalidArgument and
	// the provider collapses that to an opaque authentication failure.
	foreign := api.hsm.seal(mustKey(t), dekWrapAAD("gcp_kms:deadbeefdeadbeefdeadbeef"))
	_, err = p.Unwrap(foreign, nonce)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed authentication")

	_, err = p.Unwrap(wrapped, nonce)
	require.NoError(t, err)
}

func TestGCPChecksumMismatchIsRefused(t *testing.T) {
	t.Run("an unverified request", func(t *testing.T) {
		// Cloud KMS reports whether it verified what we sent. If it did not, the
		// DEK may have been corrupted on the way in — and a wrapped-but-corrupt DEK
		// is an unreadable secret version, so this refuses rather than proceeds.
		p, api := newTestGCPKMS(t)
		api.dropRequestVerification = true
		_, _, err := p.Wrap(mustKey(t))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "corrupted in transit")
	})

	t.Run("a corrupted wrap response", func(t *testing.T) {
		p, api := newTestGCPKMS(t)
		api.corruptResponseChecksum = true
		_, _, err := p.Wrap(mustKey(t))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "checksum mismatch")
	})

	t.Run("a corrupted unwrap response", func(t *testing.T) {
		p, api := newTestGCPKMS(t)
		wrapped, nonce, err := p.Wrap(mustKey(t))
		require.NoError(t, err)
		api.corruptResponseChecksum = true
		_, err = p.Unwrap(wrapped, nonce)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "checksum mismatch")
	})
}

func TestAzureUsesRSAOAEP256AndBindsTheKeyID(t *testing.T) {
	p, api := newTestAzureKV(t)

	wrapped, nonce, err := p.Wrap(mustKey(t))
	require.NoError(t, err)
	algorithm, name, version := api.observed()
	assert.Equal(t, azkeys.EncryptionAlgorithmRSAOAEP256, algorithm)
	assert.Equal(t, testAzureKey, name)
	assert.Equal(t, testAzureKeyVer, version)

	_, err = p.Unwrap(wrapped, nonce)
	require.NoError(t, err)

	// RSA-OAEP has no AAD channel, so the binding is framed into the wrapped
	// plaintext. A frame carrying another key's binding must be refused — that is
	// the property Key Vault cannot enforce on our behalf.
	foreign := api.hsm.seal(append(dekWrapAAD("azure_kv:deadbeefdeadbeefdeadbeef"), mustKey(t)...), nil)
	_, err = p.Unwrap(foreign, nonce)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed authentication")

	// A frame of the right length carrying no binding at all is refused too.
	blank := api.hsm.seal(bytes.Repeat([]byte{0x00}, len(dekWrapAAD(p.KeyID()))+KeySize), nil)
	_, err = p.Unwrap(blank, nonce)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed authentication")
}

func TestAzureBindingFrameFitsRSAOAEP(t *testing.T) {
	// RSA-OAEP-256 over a 2048-bit key carries at most 190 bytes. The frame is the
	// binding plus a 32-byte DEK; if a future kek_id format grew, this is the test
	// that catches it before a wrap fails in production.
	p, _ := newTestAzureKV(t)
	frame := len(dekWrapAAD(p.KeyID())) + KeySize
	assert.LessOrEqual(t, frame, 190, "the wrap frame must fit RSA-OAEP-256 on a 2048-bit key")
}

// ---------------------------------------------------------------------------
// Retry classification, directly
// ---------------------------------------------------------------------------

func awsResponseError(status int) error {
	return &awshttp.ResponseError{
		ResponseError: &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{Response: &http.Response{StatusCode: status}},
			Err:      fmt.Errorf("http %d", status),
		},
	}
}

func TestTransientClassifiers(t *testing.T) {
	t.Run("aws", func(t *testing.T) {
		for _, err := range []error{
			&kmstypes.DependencyTimeoutException{},
			&kmstypes.KMSInternalException{},
			&kmstypes.KeyUnavailableException{},
			&kmstypes.LimitExceededException{},
			awsResponseError(http.StatusTooManyRequests),
			awsResponseError(http.StatusBadGateway),
		} {
			assert.True(t, awsTransient(err), "%T should be transient", err)
		}
		for _, err := range []error{
			&kmstypes.NotFoundException{},
			&kmstypes.DisabledException{},
			&kmstypes.InvalidCiphertextException{},
			&kmstypes.KMSInvalidStateException{},
			awsResponseError(http.StatusForbidden),
			errors.New("something else"),
		} {
			assert.False(t, awsTransient(err), "%T should be permanent", err)
		}
	})

	t.Run("gcp", func(t *testing.T) {
		for _, code := range []codes.Code{codes.Unavailable, codes.Internal, codes.ResourceExhausted, codes.Aborted, codes.DeadlineExceeded} {
			assert.True(t, gcpTransient(status.Error(code, "x")), "%s should be transient", code)
		}
		for _, code := range []codes.Code{codes.InvalidArgument, codes.NotFound, codes.PermissionDenied, codes.FailedPrecondition, codes.Unauthenticated} {
			assert.False(t, gcpTransient(status.Error(code, "x")), "%s should be permanent", code)
		}
	})

	t.Run("azure", func(t *testing.T) {
		for _, code := range []int{http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout} {
			assert.True(t, azureTransient(azureStatusError(code)), "%d should be transient", code)
		}
		for _, code := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusConflict} {
			assert.False(t, azureTransient(azureStatusError(code)), "%d should be permanent", code)
		}
		assert.False(t, azureTransient(errors.New("not an azure error")))
	})
}

func TestRetryTransientNeverRetriesAContextError(t *testing.T) {
	// Once the per-call deadline has fired, another attempt spends a caller's
	// remaining budget on a call that cannot succeed.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	err := retryTransient(ctx, 0, func(error) bool { return true }, func(context.Context) error {
		calls++
		return context.Canceled
	})
	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, 1, calls)
}

func TestRetryTransientReturnsTheAPIErrorNotTheContextError(t *testing.T) {
	// An operator needs "throttled by KMS", not "context deadline exceeded" three
	// layers away from the cause.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	sentinel := errors.New("throttled")
	err := retryTransient(ctx, time.Second, func(error) bool { return true }, func(context.Context) error {
		return sentinel
	})
	require.ErrorIs(t, err, sentinel)
}

// ---------------------------------------------------------------------------
// Rewrap across providers
// ---------------------------------------------------------------------------

func TestRewrapMovesVersionsBetweenAnyTwoProviders(t *testing.T) {
	// THIS IS THE CLAIM THE WHOLE SEAM EXISTS TO SUPPORT: a version wrapped under one
	// root of trust moves to any other by re-wrapping a few dozen bytes, with no
	// payload decrypted and no ciphertext rewritten. Migrating a live store from an
	// env key to a cloud KMS — or from one cloud to another — is exactly that
	// operation, so it is tested as a chain rather than as a single hop.
	awsProvider, _ := newTestAWSKMS(t)
	gcpProvider, _ := newTestGCPKMS(t)
	azureProvider, _ := newTestAzureKV(t)
	envA := newTestProvider(t, 0xa1)
	envB := newTestProvider(t, 0xa2)

	chain := []struct {
		name string
		from RootKeyProvider
		to   RootKeyProvider
	}{
		{"env → aws_kms", envA, awsProvider},
		{"aws_kms → gcp_kms", awsProvider, gcpProvider},
		{"gcp_kms → azure_kv", gcpProvider, azureProvider},
		{"azure_kv → env", azureProvider, envB},
		{"env → gcp_kms", envB, gcpProvider},
		{"azure_kv → aws_kms", azureProvider, awsProvider},
	}

	id := testIdentity()
	plaintext := []byte("postgres://vault:correct-horse@db.internal:5432/prod")

	for _, hop := range chain {
		t.Run(hop.name, func(t *testing.T) {
			// A real sealed version, so the claim about ciphertext is about a
			// ciphertext and not a placeholder.
			env, err := Seal(hop.from, id, plaintext)
			require.NoError(t, err)
			originalCiphertext := append([]byte(nil), env.Ciphertext...)
			originalNonce := append([]byte(nil), env.Nonce...)

			newWrapped, newNonce, err := Rewrap(hop.from, hop.to, env.DEKWrapped, env.DEKNonce)
			require.NoError(t, err)

			env.DEKWrapped, env.DEKNonce, env.KEKID = newWrapped, newNonce, hop.to.KeyID()
			assert.Equal(t, originalCiphertext, env.Ciphertext, "a rewrap must never touch the payload")
			assert.Equal(t, originalNonce, env.Nonce)

			got, err := Open(hop.to, id, *env)
			require.NoError(t, err)
			assert.Equal(t, plaintext, got.Bytes())
			got.Zero()

			// The source key can no longer unwrap the moved DEK, which is what makes
			// retiring it meaningful rather than cosmetic.
			_, err = hop.from.Unwrap(newWrapped, newNonce)
			require.Error(t, err)
		})
	}
}

func TestRewrapAllDrainsAcrossProviders(t *testing.T) {
	// The same claim at store level: RewrapAll resolves each version's provider from
	// its recorded kek_id, so a mid-migration store drains correctly and the old key
	// is retired only once a COUNT proves nothing references it.
	awsProvider, _ := newTestAWSKMS(t)
	gcpProvider, _ := newTestGCPKMS(t)
	azureProvider, _ := newTestAzureKV(t)

	hops := []struct {
		name string
		from RootKeyProvider
		to   RootKeyProvider
	}{
		{"env → aws_kms", newTestProvider(t, 0xb1), awsProvider},
		{"aws_kms → gcp_kms", awsProvider, gcpProvider},
		{"gcp_kms → azure_kv", gcpProvider, azureProvider},
		{"azure_kv → env", azureProvider, newTestProvider(t, 0xb2)},
	}

	for _, hop := range hops {
		t.Run(hop.name, func(t *testing.T) {
			store := seedRewrapStore(t, hop.from, 7)
			ring, err := NewKeyRing(hop.to, hop.from)
			require.NoError(t, err)

			report, err := RewrapAll(context.Background(), store, ring, hop.from.KeyID(), 3)
			require.NoError(t, err)
			assert.Equal(t, int64(7), report.Rewrapped)
			assert.Zero(t, report.Remaining)
			assert.True(t, report.Retired)
			assert.Equal(t, []string{hop.from.KeyID()}, store.retired)

			// Every moved version is genuinely readable under the new key, and the
			// nonce column round-tripped whatever shape the target provider uses.
			for _, w := range store.wraps {
				require.Equal(t, hop.to.KeyID(), w.KEKID)
				dek, err := hop.to.Unwrap(w.DEKWrapped, w.DEKNonce)
				require.NoError(t, err)
				assert.Len(t, dek, KeySize)
				Zero(dek)
			}
		})
	}
}

func TestRewrapAllIsIdempotentOnACloudKey(t *testing.T) {
	awsProvider, _ := newTestAWSKMS(t)
	envProvider := newTestProvider(t, 0xc1)
	store := seedRewrapStore(t, envProvider, 4)
	ring, err := NewKeyRing(awsProvider, envProvider)
	require.NoError(t, err)

	first, err := RewrapAll(context.Background(), store, ring, envProvider.KeyID(), 10)
	require.NoError(t, err)
	require.Equal(t, int64(4), first.Rewrapped)

	// Re-running a completed rotation must be a no-op: a scheduled rewrap should be
	// safe to fire against a store that is already converted.
	second, err := RewrapAll(context.Background(), store, ring, envProvider.KeyID(), 10)
	require.NoError(t, err)
	assert.Zero(t, second.Rewrapped)

	// And rewrapping onto the key that is already active does nothing at all.
	third, err := RewrapAll(context.Background(), store, ring, awsProvider.KeyID(), 10)
	require.NoError(t, err)
	assert.Zero(t, third.Rewrapped)
	assert.Equal(t, awsProvider.KeyID(), third.ToKEKID)
}

func TestKeyRingResolvesMixedProviderVersions(t *testing.T) {
	// Mid-migration a store legitimately holds versions under an env key and two
	// clouds at once. The ring is what makes each of them readable.
	awsProvider, _ := newTestAWSKMS(t)
	gcpProvider, _ := newTestGCPKMS(t)
	envProvider := newTestProvider(t, 0xd1)

	ring, err := NewKeyRing(gcpProvider, envProvider, awsProvider)
	require.NoError(t, err)

	id := testIdentity()
	for _, p := range []RootKeyProvider{envProvider, awsProvider, gcpProvider} {
		env, err := Seal(p, id, []byte("value-"+p.KeyID()))
		require.NoError(t, err)

		resolved, err := ring.Provider(env.KEKID)
		require.NoError(t, err)
		assert.Equal(t, p.KeyID(), resolved.KeyID())

		plain, err := Open(resolved, id, *env)
		require.NoError(t, err)
		assert.Equal(t, "value-"+p.KeyID(), string(plain.Bytes()))
		plain.Zero()
	}

	_, err = ring.Provider("aws_kms:000000000000000000000000")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be read until it is supplied")
}

// TestKMSNonceIsStorable guards the one storage detail an empty nonce touches.
// secret_versions.dek_nonce and webhook_endpoints.secret_dek_nonce are both BYTEA NOT
// NULL, and pgx encodes a nil []byte as SQL NULL — so a nil nonce would turn every
// cloud-wrapped write into a constraint violation at runtime.
func TestKMSNonceIsStorable(t *testing.T) {
	for _, tc := range kmsCases() {
		t.Run(tc.name, func(t *testing.T) {
			p, _ := tc.build(t)
			_, nonce, err := p.Wrap(mustKey(t))
			require.NoError(t, err)
			require.NotNil(t, nonce, "a nil nonce becomes SQL NULL and violates NOT NULL")
			assert.Empty(t, nonce)

			env, err := Seal(p, testIdentity(), []byte("x"))
			require.NoError(t, err)
			require.NotNil(t, env.DEKNonce, "Seal must carry the provider's non-nil empty nonce through")
		})
	}
}

// TestKMSProviderIsConcurrencySafe is a race-detector target: the providers hold no
// mutable state after construction, and the suite runs with -race.
func TestKMSProviderIsConcurrencySafe(t *testing.T) {
	p, _ := newTestGCPKMS(t)
	const n = 16
	errCh := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			dek := make([]byte, KeySize)
			if _, err := io.ReadFull(rand.Reader, dek); err != nil {
				errCh <- err
				return
			}
			wrapped, nonce, err := p.Wrap(dek)
			if err != nil {
				errCh <- err
				return
			}
			got, err := p.Unwrap(wrapped, nonce)
			if err != nil {
				errCh <- err
				return
			}
			if !bytes.Equal(dek, got) {
				errCh <- errors.New("round trip mismatch")
				return
			}
			errCh <- nil
		}()
	}
	for i := 0; i < n; i++ {
		require.NoError(t, <-errCh)
	}
}
