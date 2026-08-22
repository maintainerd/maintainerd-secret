package crypto

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// awsKMSAPI is the narrow slice of the AWS KMS SDK this provider calls.
//
// Two calls, and that is the whole surface: everything this service can ever do to an
// operator's KMS key is enumerable by reading these two lines. Keeping it private and
// minimal also means the adapter is unit-testable against a fake, which matters here
// more than usual — there is no credential in CI, and "we could not test it" is how
// an encrypt-only IAM policy reaches production.
type awsKMSAPI interface {
	Encrypt(ctx context.Context, params *kms.EncryptInput, optFns ...func(*kms.Options)) (*kms.EncryptOutput, error)
	Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

// Compile-time check that the real SDK client satisfies the narrow interface, so the
// fake in the tests cannot drift away from the API it stands in for.
var _ awsKMSAPI = (*kms.Client)(nil)

// awsKMSProvider wraps DEKs with a symmetric AWS KMS key.
//
// The key material never leaves KMS, so this type holds only coordinates and a
// deadline. It is safe for concurrent use: the SDK client is, and nothing here is
// mutated after construction.
type awsKMSProvider struct {
	api awsKMSAPI
	// keyRef is what the operator configured — a key ARN, key id, alias name or
	// alias ARN. Sent on every call, including Decrypt (see Unwrap).
	keyRef string
	// keyID is the stable kek_id written to secret_versions.
	keyID      string
	timeout    time.Duration
	retryDelay time.Duration
}

// newAWSKMSProvider builds the provider from configuration, resolving credentials
// through the standard AWS chain: environment variables, an EC2/ECS instance role,
// web identity (IRSA on EKS), or a shared profile. None of those are read by this
// package — LoadDefaultConfig owns that, which is exactly why it is used instead of
// a hand-rolled credential lookup.
func newAWSKMSProvider(cfg ProviderConfig) (RootKeyProvider, error) {
	keyRef := strings.TrimSpace(cfg.KMS.AWSKeyID)
	region := strings.TrimSpace(cfg.KMS.AWSRegion)

	var missing []string
	if keyRef == "" {
		missing = append(missing, "SECRET_KMS_AWS_KEY_ID")
	}
	if region == "" {
		missing = append(missing, "SECRET_KMS_AWS_REGION")
	}
	if len(missing) > 0 {
		return nil, missingKMSSettings(ProviderAWSKMS, missing)
	}

	timeout := kmsTimeout(cfg.KMS.Timeout)
	// Credential resolution can itself go to the network (IMDS, STS), so it gets the
	// same deadline as a key operation rather than an unbounded one.
	loadCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	awsCfg, err := awsconfig.LoadDefaultConfig(loadCtx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("crypto: aws_kms could not resolve credentials for region %s: %w", region, err)
	}
	return newAWSKMS(kms.NewFromConfig(awsCfg), region, keyRef, timeout, defaultKMSRetryDelay)
}

// newAWSKMS is the injectable constructor. Everything past the SDK client lives here
// so the tests exercise the real adapter — encryption context, key pinning, retry
// classification, redaction — against a fake KMS.
func newAWSKMS(api awsKMSAPI, region, keyRef string, timeout, retryDelay time.Duration) (RootKeyProvider, error) {
	if api == nil {
		return nil, fmt.Errorf("crypto: aws_kms needs a client")
	}
	p := &awsKMSProvider{
		api:    api,
		keyRef: keyRef,
		// Region is part of the id because an alias is region-scoped: the same
		// "alias/secret-root" in two regions is two different keys.
		keyID:      fingerprintRef(ProviderAWSKMS, region+"|"+keyRef),
		timeout:    kmsTimeout(timeout),
		retryDelay: retryDelay,
	}
	if err := kmsSelfTest(p); err != nil {
		return nil, err
	}
	// The key reference and region are not secrets, and printing them next to the
	// kek_id is the one thing that lets an operator connect a fingerprint in
	// root_keys back to a key in their console.
	slog.Info("cloud KMS root key ready",
		"provider", ProviderAWSKMS, "kek_id", p.keyID, "region", region, "key", keyRef)
	return p, nil
}

func (p *awsKMSProvider) KeyID() string { return p.keyID }

// awsEncryptionContext is KMS's AAD channel.
//
// KMS has no separate AAD parameter — the encryption context IS the AAD, and it is
// authenticated: a Decrypt with a different context fails with
// InvalidCiphertextException. Binding the service name and the kek_id gives the same
// property dekWrapAAD gives the AES providers, so a blob wrapped for this service
// under this key cannot be decrypted as though it belonged somewhere else, even by
// something else that holds Decrypt on the key.
//
// It also shows up in CloudTrail, which is a second, unrelated benefit: KMS calls
// become attributable to this service without any extra plumbing. Nothing derived
// from a key or a payload goes in here.
func awsEncryptionContext(keyID string) map[string]string {
	return map[string]string{
		"maintainerd_service": kmsServiceName,
		"kek_id":              keyID,
	}
}

// Wrap encrypts a DEK with the KMS key.
//
// The returned nonce is EMPTY. KMS hands back one self-describing ciphertext blob
// containing whatever IV it used, so there is no second value to store — see noNonce
// for why the empty slice is non-nil.
func (p *awsKMSProvider) Wrap(dek []byte) ([]byte, []byte, error) {
	if err := requireWrapInput(dek); err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()

	var out *kms.EncryptOutput
	err := retryTransient(ctx, p.retryDelay, awsTransient, func(ctx context.Context) error {
		var callErr error
		out, callErr = p.api.Encrypt(ctx, &kms.EncryptInput{
			KeyId:             aws.String(p.keyRef),
			Plaintext:         dek,
			EncryptionContext: awsEncryptionContext(p.keyID),
		})
		return callErr
	})
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: aws_kms encrypt dek under %s: %w", p.keyID, err)
	}
	if out == nil || len(out.CiphertextBlob) == 0 {
		return nil, nil, fmt.Errorf("crypto: aws_kms returned an empty ciphertext blob for %s", p.keyID)
	}
	return out.CiphertextBlob, noNonce(), nil
}

// Unwrap recovers a DEK. The caller zeroizes the result.
//
// KeyId IS SET ON DECRYPT, which is not the default and is the important line here.
// Without it, KMS decrypts with whatever key the blob names, so anything that can
// write a dek_wrapped column can hand this service a blob encrypted under a key the
// attacker controls and have it decrypted into a DEK of their choosing. Pinning the
// key turns that into an IncorrectKeyException. (The encryption context closes the
// same door from the other side; both are cheap, so both are used.)
func (p *awsKMSProvider) Unwrap(wrapped, nonce []byte) ([]byte, error) {
	if err := requireNoNonce(ProviderAWSKMS, nonce); err != nil {
		return nil, err
	}
	if len(wrapped) == 0 {
		return nil, fmt.Errorf("crypto: aws_kms cannot unwrap an empty blob under %s", p.keyID)
	}
	ctx, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()

	var out *kms.DecryptOutput
	err := retryTransient(ctx, p.retryDelay, awsTransient, func(ctx context.Context) error {
		var callErr error
		out, callErr = p.api.Decrypt(ctx, &kms.DecryptInput{
			KeyId:             aws.String(p.keyRef),
			CiphertextBlob:    wrapped,
			EncryptionContext: awsEncryptionContext(p.keyID),
		})
		return callErr
	})
	if err != nil {
		// A wrong encryption context, a tampered blob and a blob from another key
		// all arrive here; they are one fact — this wrapped DEK does not belong to
		// this key — and the opaque form is what keeps this from being an oracle.
		var invalidCiphertext *kmstypes.InvalidCiphertextException
		var incorrectKey *kmstypes.IncorrectKeyException
		if errors.As(err, &invalidCiphertext) || errors.As(err, &incorrectKey) {
			return nil, authFailure(p.keyID)
		}
		// Everything else — AccessDenied, NotFound, a disabled key, a throttle that
		// outlived its retries — is an operational fault the operator must see, and
		// the SDK's message carries none of our material.
		return nil, fmt.Errorf("crypto: aws_kms decrypt dek under %s: %w", p.keyID, err)
	}
	if out == nil {
		return nil, fmt.Errorf("crypto: aws_kms returned no plaintext for %s", p.keyID)
	}
	return requireUnwrapped(out.Plaintext)
}

// awsTransient reports whether a KMS failure is worth retrying.
//
// The four typed exceptions are the ones AWS documents as retryable: a dependency
// timeout, an internal error, a key that is momentarily unavailable, and a request
// limit. Everything else — AccessDenied, NotFound, DisabledException,
// InvalidCiphertextException, KMSInvalidStateException — is a decision that will not
// change on a second attempt.
//
// The HTTP fallback catches throttles and 5xx responses the SDK did not model as a
// typed exception. Note that the SDK's own retryer is also active underneath this, so
// a transient fault gets both; that is deliberate belt-and-braces on the one call
// path that can make a write fail.
func awsTransient(err error) bool {
	var (
		dependencyTimeout *kmstypes.DependencyTimeoutException
		internal          *kmstypes.KMSInternalException
		unavailable       *kmstypes.KeyUnavailableException
		limit             *kmstypes.LimitExceededException
	)
	if errors.As(err, &dependencyTimeout) ||
		errors.As(err, &internal) ||
		errors.As(err, &unavailable) ||
		errors.As(err, &limit) {
		return true
	}
	var respErr *awshttp.ResponseError
	if errors.As(err, &respErr) {
		code := respErr.HTTPStatusCode()
		return code == http.StatusTooManyRequests || code >= http.StatusInternalServerError
	}
	return false
}
