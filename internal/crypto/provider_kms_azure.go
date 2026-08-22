package crypto

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

// azureKeysAPI is the narrow slice of the Key Vault keys client this provider calls.
//
// WrapKey and UnwrapKey rather than Encrypt and Decrypt, because they are what this
// operation actually is — and because they map to a different, narrower Key Vault
// grant (keys/wrapKey, keys/unwrapKey) than the general-purpose encrypt permission.
// An operator granting least privilege should not have to hand this service the
// ability to encrypt arbitrary data.
type azureKeysAPI interface {
	WrapKey(ctx context.Context, name, version string, parameters azkeys.KeyOperationParameters, options *azkeys.WrapKeyOptions) (azkeys.WrapKeyResponse, error)
	UnwrapKey(ctx context.Context, name, version string, parameters azkeys.KeyOperationParameters, options *azkeys.UnwrapKeyOptions) (azkeys.UnwrapKeyResponse, error)
}

// Compile-time check that the real SDK client satisfies the narrow interface.
var _ azureKeysAPI = (*azkeys.Client)(nil)

// azureWrapAlgorithm is the documented algorithm for this provider.
//
// RSA-OAEP-256 is the only sound choice among what a standard vault offers: RSA1_5 is
// PKCS#1 v1.5 (Bleichenbacher), plain RSA-OAEP uses SHA-1, and the AES key-wrap and
// AES-GCM algorithms need a symmetric key, which only Managed HSM has. A key vault
// key is therefore an RSA key of 2048 bits or more, and RSA-OAEP-256 is what wraps
// under it.
const azureWrapAlgorithm = azkeys.EncryptionAlgorithmRSAOAEP256

// azureKVProvider wraps DEKs with an RSA key held in Azure Key Vault.
type azureKVProvider struct {
	api        azureKeysAPI
	keyName    string
	keyVersion string
	keyID      string
	timeout    time.Duration
	retryDelay time.Duration
}

// newAzureKVProvider builds the provider from configuration, authenticating with
// DefaultAzureCredential — a managed identity on Azure, a workload-identity
// federation on AKS, the AZURE_CLIENT_ID/SECRET/TENANT_ID environment triple, or a
// developer's az login. The credential chain is the SDK's, not ours.
func newAzureKVProvider(cfg ProviderConfig) (RootKeyProvider, error) {
	vaultURL := strings.TrimSpace(cfg.KMS.AzureVaultURL)
	keyName := strings.TrimSpace(cfg.KMS.AzureKeyName)

	var missing []string
	if vaultURL == "" {
		missing = append(missing, "SECRET_KMS_AZURE_VAULT_URL")
	}
	if keyName == "" {
		missing = append(missing, "SECRET_KMS_AZURE_KEY_NAME")
	}
	if len(missing) > 0 {
		return nil, missingKMSSettings(ProviderAzureKV, missing)
	}
	if err := ValidateAzureVaultURL(vaultURL); err != nil {
		return nil, err
	}

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("crypto: azure_kv could not resolve a default Azure credential: %w", err)
	}
	client, err := azkeys.NewClient(vaultURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("crypto: azure_kv could not build a Key Vault client for %s: %w", vaultURL, err)
	}
	return newAzureKV(client, vaultURL, keyName, strings.TrimSpace(cfg.KMS.AzureKeyVersion),
		kmsTimeout(cfg.KMS.Timeout), defaultKMSRetryDelay)
}

// newAzureKV is the injectable constructor — see newAWSKMS for why the split exists.
func newAzureKV(api azureKeysAPI, vaultURL, keyName, keyVersion string, timeout, retryDelay time.Duration) (RootKeyProvider, error) {
	if api == nil {
		return nil, fmt.Errorf("crypto: azure_kv needs a client")
	}
	p := &azureKVProvider{
		api:        api,
		keyName:    keyName,
		keyVersion: keyVersion,
		// The vault URL is in the id because a key name alone is only unique
		// within a vault, and the version is in it because pinning one is a
		// different key from "whatever is current".
		keyID:      fingerprintRef(ProviderAzureKV, vaultURL+"|"+keyName+"|"+keyVersion),
		timeout:    kmsTimeout(timeout),
		retryDelay: retryDelay,
	}
	if err := kmsSelfTest(p); err != nil {
		return nil, err
	}
	slog.Info("cloud KMS root key ready",
		"provider", ProviderAzureKV, "kek_id", p.keyID,
		"vault", vaultURL, "key", keyName, "key_version", keyVersion)
	return p, nil
}

func (p *azureKVProvider) KeyID() string { return p.keyID }

// ValidateAzureVaultURL checks that the configured vault URL is a usable HTTPS base
// URL. Exported so internal/platform/config validates it at boot with the same rule.
//
// The scheme check is not cosmetic: a plain-http vault URL would send a bearer token
// for a credential that can unwrap this vault's root key over the network in the
// clear.
func ValidateAzureVaultURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("crypto: SECRET_KMS_AZURE_VAULT_URL %q is not a URL: %w", raw, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf(
			"crypto: SECRET_KMS_AZURE_VAULT_URL %q must be an https URL; a plain-http vault URL would send this service's Azure token in the clear", raw)
	}
	if u.Host == "" {
		return fmt.Errorf("crypto: SECRET_KMS_AZURE_VAULT_URL %q has no host; expected https://{vault-name}.vault.azure.net/", raw)
	}
	return nil
}

// azureBinding is the kek_id binding for this provider.
//
// WHY IT IS A PREFIX AND NOT AAD. The other two providers hand their AAD to the
// service: KMS authenticates the encryption context, Cloud KMS authenticates
// AdditionalAuthenticatedData. Key Vault's KeyOperationParameters HAS an
// AdditionalAuthenticatedData field, but RSA-OAEP-256 has no AAD channel — the field
// applies to the authenticated symmetric algorithms only, so setting it under
// RSA-OAEP would be silently ignored. That is worse than not setting it: it looks
// like a binding and is not one.
//
// So the binding is carried in the wrapped plaintext instead: the exact bytes
// dekWrapAAD produces, followed by the DEK. Unwrap checks the prefix and refuses
// anything else, which gives the same property — a blob wrapped under one kek_id
// cannot be presented as another's — enforced locally rather than by the vault.
//
// The frame is ~96 bytes (a 31-byte domain tag, a 33-character kek_id, a 32-byte
// DEK), well inside RSA-OAEP-256's 190-byte limit for a 2048-bit key.
func (p *azureKVProvider) azureBinding() []byte { return dekWrapAAD(p.keyID) }

// Wrap wraps a DEK with the vault key using RSA-OAEP-256.
//
// The returned nonce is EMPTY — RSA-OAEP's randomness is inside the blob. See noNonce
// for why the empty slice is non-nil.
func (p *azureKVProvider) Wrap(dek []byte) ([]byte, []byte, error) {
	if err := requireWrapInput(dek); err != nil {
		return nil, nil, err
	}
	binding := p.azureBinding()
	frame := make([]byte, 0, len(binding)+len(dek))
	frame = append(frame, binding...)
	frame = append(frame, dek...)
	// The frame holds a copy of the DEK, so it is key material and gets the same
	// treatment as the DEK itself.
	defer Zero(frame)

	ctx, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()

	algorithm := azureWrapAlgorithm
	var resp azkeys.WrapKeyResponse
	err := retryTransient(ctx, p.retryDelay, azureTransient, func(ctx context.Context) error {
		var callErr error
		resp, callErr = p.api.WrapKey(ctx, p.keyName, p.keyVersion, azkeys.KeyOperationParameters{
			Algorithm: &algorithm,
			Value:     frame,
		}, nil)
		return callErr
	})
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: azure_kv wrap dek under %s: %w", p.keyID, err)
	}
	if len(resp.Result) == 0 {
		return nil, nil, fmt.Errorf("crypto: azure_kv returned an empty wrapped key for %s", p.keyID)
	}
	return resp.Result, noNonce(), nil
}

// Unwrap recovers a DEK. The caller zeroizes the result.
func (p *azureKVProvider) Unwrap(wrapped, nonce []byte) ([]byte, error) {
	if err := requireNoNonce(ProviderAzureKV, nonce); err != nil {
		return nil, err
	}
	if len(wrapped) == 0 {
		return nil, fmt.Errorf("crypto: azure_kv cannot unwrap an empty blob under %s", p.keyID)
	}
	ctx, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()

	algorithm := azureWrapAlgorithm
	var resp azkeys.UnwrapKeyResponse
	err := retryTransient(ctx, p.retryDelay, azureTransient, func(ctx context.Context) error {
		var callErr error
		resp, callErr = p.api.UnwrapKey(ctx, p.keyName, p.keyVersion, azkeys.KeyOperationParameters{
			Algorithm: &algorithm,
			Value:     wrapped,
		}, nil)
		return callErr
	})
	if err != nil {
		// A blob wrapped under a different vault key fails the RSA-OAEP padding
		// check, which Key Vault reports as a 400. That is the same single fact the
		// other providers collapse: this blob does not belong to this key.
		var respErr *azcore.ResponseError
		if errors.As(err, &respErr) && respErr.StatusCode == http.StatusBadRequest {
			return nil, authFailure(p.keyID)
		}
		return nil, fmt.Errorf("crypto: azure_kv unwrap dek under %s: %w", p.keyID, err)
	}

	frame := resp.Result
	defer Zero(frame)
	binding := p.azureBinding()
	// Length first — a length is not secret, and the constant-time compare below
	// needs equal-length inputs anyway.
	if len(frame) != len(binding)+KeySize ||
		subtle.ConstantTimeCompare(frame[:len(binding)], binding) != 1 {
		return nil, authFailure(p.keyID)
	}
	dek := make([]byte, KeySize)
	copy(dek, frame[len(binding):])
	return requireUnwrapped(dek)
}

// azureTransient reports whether a Key Vault failure is worth retrying.
//
// Key Vault throttles hard and documents 429 as the signal to back off; the 5xx
// family is the ordinary server-side blip. Everything else — 400 (a blob that does
// not belong to this key), 401/403 (a missing wrapKey/unwrapKey grant), 404 (a wrong
// vault or key name) — is a decision that will not change on a retry.
func azureTransient(err error) bool {
	var respErr *azcore.ResponseError
	if !errors.As(err, &respErr) {
		return false
	}
	switch respErr.StatusCode {
	case http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}
