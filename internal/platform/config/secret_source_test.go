package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeSecretDir materializes a file-provider directory holding the given settings,
// one file per key under the store-side name (DB_PASSWORD → db-password).
func writeSecretDir(t *testing.T, values map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for key, value := range values {
		name := strings.ToLower(strings.ReplaceAll(key, "_", "-"))
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(value), 0o600))
	}
	return dir
}

// ---------------------------------------------------------------------------
// The default: nothing configured behaves exactly as it did before
// ---------------------------------------------------------------------------

func TestSecretProviderDefaultsToEnv(t *testing.T) {
	// A deployment that sets nothing must be unaffected by the source being
	// pluggable, or adopting this would be a behaviour change nobody asked for.
	setRequiredEnv(t)
	require.NoError(t, Init())
	assert.Equal(t, "env", SecretProvider)
	assert.False(t, SecretStrict)
	assert.Equal(t, "postgres", DBPassword)
	assert.Equal(t, "bootstrap-token", SetupBootstrapToken)
	assert.Equal(t, "secret-backend-secret", ClientSecret)
}

// ---------------------------------------------------------------------------
// Fail closed on an unknown name, and stay distinct from the ROOT KEY axis
// ---------------------------------------------------------------------------

// TestUnknownSecretProviderIsABootError. The shared implementation this replaced
// logged a warning and fell back to the environment, so a typo started the service
// reading environment variables while the operator believed it was reading Vault.
func TestUnknownSecretProviderIsABootError(t *testing.T) {
	for _, bad := range []string{"hashicorp", "aws", "aws_kms", "secretsmanager"} {
		t.Run(bad, func(t *testing.T) {
			setRequiredEnv(t)
			t.Setenv("SECRET_PROVIDER", bad)
			err := Init()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "SECRET_PROVIDER")
			// The message has to point at the OTHER axis, because "aws_kms" is a valid
			// value for SECRET_ROOT_KEY_PROVIDER and an operator who set it here has
			// almost certainly confused the two.
			assert.Contains(t, err.Error(), "SECRET_ROOT_KEY_PROVIDER")
		})
	}
}

// TestTheTwoProviderAxesAreIndependENT is the interaction that must not collide:
// SECRET_PROVIDER says where CONFIGURATION comes from, SECRET_ROOT_KEY_PROVIDER says
// what wraps this vault's DATA KEYS. Every combination is legitimate.
func TestTheTwoProviderAxesAreIndependent(t *testing.T) {
	rootKey := strings.Repeat("ab", 32)

	t.Run("a file config source with a cloud root key", func(t *testing.T) {
		dir := writeSecretDir(t, map[string]string{
			"DB_PASSWORD":           "file-db-password",
			"SETUP_BOOTSTRAP_TOKEN": "file-bootstrap-token",
			"SECRET_CLIENT_SECRET":  "file-client-secret",
		})
		setRequiredEnv(t)
		setKMSEnv(t)
		t.Setenv("SECRET_PROVIDER", "file")
		t.Setenv("SECRET_FILE_PATH", dir)
		t.Setenv("SECRET_ROOT_KEY_PROVIDER", "aws_kms")

		require.NoError(t, Init())
		assert.Equal(t, "file", SecretProvider, "the config source")
		assert.Equal(t, "aws_kms", RootKeyProvider, "the root of trust")
		assert.Equal(t, "file-db-password", DBPassword)
	})

	t.Run("an env config source with a cloud root key", func(t *testing.T) {
		setRequiredEnv(t)
		setKMSEnv(t)
		t.Setenv("SECRET_ROOT_KEY_PROVIDER", "gcp_kms")
		require.NoError(t, Init())
		assert.Equal(t, "env", SecretProvider)
		assert.Equal(t, "gcp_kms", RootKeyProvider)
	})

	// azure_kv is a valid name on BOTH axes and means different things — Key Vault
	// SECRETS for the config source, Key Vault KEYS for the root key. Setting it on
	// one must not require or imply anything on the other.
	t.Run("azure_kv on the root key axis alone", func(t *testing.T) {
		setRequiredEnv(t)
		setKMSEnv(t)
		t.Setenv("SECRET_ROOT_KEY_PROVIDER", "azure_kv")
		require.NoError(t, Init())
		assert.Equal(t, "env", SecretProvider)
		assert.Equal(t, "azure_kv", RootKeyProvider)
		// Each axis reads its OWN vault URL variable; the config source's is unset
		// here and that is not an error.
		assert.Empty(t, SecretAzureVaultURL)
		assert.Equal(t, "https://acme-vault.vault.azure.net/", KMSAzureVaultURL)
	})

	// And the config source's own settings must not be validated against the root
	// key's, in either direction.
	t.Run("config-source settings are not validated for an unselected provider", func(t *testing.T) {
		setRequiredEnv(t)
		t.Setenv("VAULT_ADDR", "http://insecure.example:8200")
		t.Setenv("GCP_PROJECT_ID", "")
		t.Setenv("AZURE_KEYVAULT_URL", "http://insecure.example/")
		// An operator mid-migration keeps two sets in place; only the selected one is
		// checked. SECRET_PROVIDER is still env here.
		require.NoError(t, Init())
		assert.Equal(t, "env", SecretProvider)
		assert.Equal(t, rootKey, RootKey)
	})
}

// ---------------------------------------------------------------------------
// Per-provider settings, validated at boot, all named at once
// ---------------------------------------------------------------------------

// TestSecretSourceSettingsAreRequiredAtBootForTheSelectedProvider mirrors
// TestKMSSettingsAreRequiredAtBootForTheSelectedProvider: a store selected without its
// coordinates must refuse to start rather than fail on the first configuration read
// after the process is already serving.
func TestSecretSourceSettingsAreRequiredAtBootForTheSelectedProvider(t *testing.T) {
	cases := []struct {
		provider string
		set      map[string]string
		wantName string
	}{
		{"aws_secrets", nil, "AWS_REGION"},
		{"aws_ssm", nil, "AWS_REGION"},
		{"vault", map[string]string{"VAULT_TOKEN": "root"}, "VAULT_ADDR"},
		{"vault", map[string]string{"VAULT_ADDR": "https://vault.internal:8200"}, "VAULT_TOKEN or VAULT_ROLE_ID+VAULT_SECRET_ID"},
		{"gcp", nil, "GCP_PROJECT_ID"},
		{"azure_kv", nil, "AZURE_KEYVAULT_URL"},
	}
	for _, tc := range cases {
		t.Run(tc.provider+" without "+tc.wantName, func(t *testing.T) {
			setRequiredEnv(t)
			t.Setenv("SECRET_PROVIDER", tc.provider)
			for k, v := range tc.set {
				t.Setenv(k, v)
			}
			err := Init()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantName)
			assert.Contains(t, err.Error(), "SECRET_PROVIDER="+tc.provider)
		})
	}
}

func TestSecretSourceMissingSettingsAreAllNamedAtOnce(t *testing.T) {
	// One restart per missing variable turns a two-minute setup into three restarts.
	setRequiredEnv(t)
	t.Setenv("SECRET_PROVIDER", "vault")
	err := Init()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "VAULT_ADDR")
	assert.Contains(t, err.Error(), "VAULT_TOKEN or VAULT_ROLE_ID+VAULT_SECRET_ID")
}

func TestAWSRegionForTheConfigSourceFallsBackToTheSDKVariable(t *testing.T) {
	// A workload that already sets AWS_DEFAULT_REGION for its other calls should not
	// have to set a second name for the same fact. This is a SEPARATE variable from
	// SECRET_KMS_AWS_REGION on purpose: the account's configuration secrets and the
	// vault's KMS key can live in different regions.
	// readSecretSourceSettings rather than Init: this is about the REQUIREMENT being
	// satisfied, and Init would go on to build a client and reach for a store no test
	// can talk to. A unit test that touches the network is a unit test that takes a
	// timeout to fail.
	for _, fallback := range []string{"AWS_REGION", "AWS_DEFAULT_REGION"} {
		t.Run(fallback, func(t *testing.T) {
			setRequiredEnv(t)
			t.Setenv("SECRET_PROVIDER", "aws_secrets")
			t.Setenv(fallback, "eu-west-1")
			require.NoError(t, readSecretSourceSettings())
			assert.Equal(t, "eu-west-1", SecretAWSRegion)
		})
	}

	t.Run("neither is set", func(t *testing.T) {
		setRequiredEnv(t)
		t.Setenv("SECRET_PROVIDER", "aws_secrets")
		err := readSecretSourceSettings()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "AWS_REGION")
	})

	// And it is a DIFFERENT variable from the root key's region, which has its own
	// SECRET_KMS_AWS_REGION with its own fallback. Setting one must not satisfy the
	// other.
	t.Run("the root key's region is not this one", func(t *testing.T) {
		setRequiredEnv(t)
		t.Setenv("SECRET_PROVIDER", "aws_secrets")
		t.Setenv("SECRET_KMS_AWS_REGION", "us-east-2")
		err := readSecretSourceSettings()
		require.Error(t, err, "SECRET_KMS_AWS_REGION must not satisfy the config source")
		assert.Contains(t, err.Error(), "AWS_REGION")
	})
}

// A plaintext remote store would send every one of this service's credentials across
// the network in the clear.
func TestAPlaintextRemoteVaultIsRefusedOutsideDevelopment(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("SECRET_PROVIDER", "vault")
	t.Setenv("VAULT_ADDR", "http://vault.internal:8200")
	t.Setenv("VAULT_TOKEN", "root")
	err := Init()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "https")
	assert.NotContains(t, err.Error(), "root", "the refusal must not carry the token")
}

func TestSecretStrictIsValidatedAsABoolean(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("SECRET_STRICT", "maybe")
	err := Init()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SECRET_STRICT")

	t.Setenv("SECRET_STRICT", "true")
	require.NoError(t, Init())
	assert.True(t, SecretStrict)
}

// ---------------------------------------------------------------------------
// The four settings actually route through the provider
// ---------------------------------------------------------------------------

func TestAllFourSecretValuedSettingsComeFromTheProvider(t *testing.T) {
	rootKey := strings.Repeat("cd", 32)
	dir := writeSecretDir(t, map[string]string{
		"DB_PASSWORD":           "store-db-password",
		"SECRET_ROOT_KEY":       rootKey,
		"SETUP_BOOTSTRAP_TOKEN": "store-bootstrap-token",
		"SECRET_CLIENT_SECRET":  "store-client-secret",
	})

	setRequiredEnv(t)
	// Every one is ALSO left in the environment with a different value, which is the
	// state of a deployment mid-migration. The store must win for all four.
	t.Setenv("DB_PASSWORD", "env-db-password")
	t.Setenv("SECRET_ROOT_KEY", strings.Repeat("ef", 32))
	t.Setenv("SETUP_BOOTSTRAP_TOKEN", "env-bootstrap-token")
	t.Setenv("SECRET_CLIENT_SECRET", "env-client-secret")
	t.Setenv("SECRET_PROVIDER", "file")
	t.Setenv("SECRET_FILE_PATH", dir)

	require.NoError(t, Init())
	assert.Equal(t, "store-db-password", DBPassword)
	assert.Equal(t, rootKey, RootKey)
	assert.Equal(t, "store-bootstrap-token", SetupBootstrapToken)
	assert.Equal(t, "store-client-secret", ClientSecret)
}

// TestNonSecretSettingsStayInTheEnvironment. The mixed model only works if the split
// is where it says it is: a hostname or a port that started routing through a secret
// manager would make every deployment's boot depend on the store being reachable for
// values that are not secrets.
func TestNonSecretSettingsStayInTheEnvironment(t *testing.T) {
	dir := writeSecretDir(t, map[string]string{
		"DB_HOST":               "store-should-not-be-read",
		"DB_PORT":               "9999",
		"AUTH_ISSUER":           "https://store.example/",
		"DB_PASSWORD":           "store-db-password",
		"SETUP_BOOTSTRAP_TOKEN": "store-bootstrap-token",
		"SECRET_CLIENT_SECRET":  "store-client-secret",
	})
	setRequiredEnv(t)
	t.Setenv("SECRET_PROVIDER", "file")
	t.Setenv("SECRET_FILE_PATH", dir)

	require.NoError(t, Init())
	assert.Equal(t, "localhost", DBHost, "DB_HOST is not a secret and must come from the environment")
	assert.Equal(t, "5432", DBPort)
	assert.Equal(t, "https://auth.example/", AuthIssuer)
	assert.Equal(t, "store-db-password", DBPassword, "...while the password does come from the store")
}

// TestSomeSecretsInTheStoreAndOthersInTheEnvironment is the incremental-migration
// model the default (SECRET_STRICT=false) exists for.
func TestSomeSecretsInTheStoreAndOthersInTheEnvironment(t *testing.T) {
	dir := writeSecretDir(t, map[string]string{"DB_PASSWORD": "store-db-password"})

	setRequiredEnv(t)
	t.Setenv("SECRET_PROVIDER", "file")
	t.Setenv("SECRET_FILE_PATH", dir)

	require.NoError(t, Init())
	assert.Equal(t, "store-db-password", DBPassword, "migrated")
	assert.Equal(t, "bootstrap-token", SetupBootstrapToken, "not migrated; still the environment")
	assert.Equal(t, "secret-backend-secret", ClientSecret, "not migrated; still the environment")
	assert.Equal(t, strings.Repeat("ab", 32), RootKey, "not migrated; still the environment")
}

// TestStrictModeDisablesTheFallbackEntirely. Once a migration is finished, a
// forgotten variable must fail the boot instead of silently resolving to whatever the
// environment still holds.
func TestStrictModeDisablesTheFallbackEntirely(t *testing.T) {
	// Everything migrated EXCEPT the bootstrap token, which is still only in the
	// environment. Off, that boots; on, it must not.
	migrated := map[string]string{
		"DB_PASSWORD":          "store-db-password",
		"SECRET_ROOT_KEY":      strings.Repeat("ab", 32),
		"SECRET_CLIENT_SECRET": "store-client-secret",
	}

	t.Run("off, the environment fills the gap", func(t *testing.T) {
		setRequiredEnv(t)
		t.Setenv("SECRET_PROVIDER", "file")
		t.Setenv("SECRET_FILE_PATH", writeSecretDir(t, migrated))
		require.NoError(t, Init())
		assert.Equal(t, "bootstrap-token", SetupBootstrapToken)
	})

	t.Run("on, the gap is a boot error", func(t *testing.T) {
		setRequiredEnv(t)
		t.Setenv("SECRET_PROVIDER", "file")
		t.Setenv("SECRET_FILE_PATH", writeSecretDir(t, migrated))
		t.Setenv("SECRET_STRICT", "true")
		err := Init()
		require.Error(t, err, "the token is only in the environment, which strict mode does not consult")
		assert.Contains(t, err.Error(), "SETUP_BOOTSTRAP_TOKEN")
	})
}

// The shared value handling applies to these settings too, and it is the same for
// every provider: `echo value > secret` leaves a newline, and a base64 payload must
// arrive decoded.
func TestStoredSecretsAreNormalizedTheSameWayForEveryProvider(t *testing.T) {
	t.Run("a trailing newline is stripped", func(t *testing.T) {
		dir := writeSecretDir(t, map[string]string{"DB_PASSWORD": "store-db-password\n"})
		setRequiredEnv(t)
		t.Setenv("SECRET_PROVIDER", "file")
		t.Setenv("SECRET_FILE_PATH", dir)
		require.NoError(t, Init())
		assert.Equal(t, "store-db-password", DBPassword)
	})

	t.Run("a base64 payload is decoded", func(t *testing.T) {
		encoded := "base64:" + base64.StdEncoding.EncodeToString([]byte("hunter2"))
		dir := writeSecretDir(t, map[string]string{"DB_PASSWORD": encoded})
		setRequiredEnv(t)
		t.Setenv("SECRET_PROVIDER", "file")
		t.Setenv("SECRET_FILE_PATH", dir)
		require.NoError(t, Init())
		assert.Equal(t, "hunter2", DBPassword)
	})

	t.Run("a malformed base64 payload is a boot error", func(t *testing.T) {
		dir := writeSecretDir(t, map[string]string{"DB_PASSWORD": "base64:!!!not-base64!!!"})
		setRequiredEnv(t)
		t.Setenv("SECRET_PROVIDER", "file")
		t.Setenv("SECRET_FILE_PATH", dir)
		err := Init()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "DB_PASSWORD")
	})
}

// ---------------------------------------------------------------------------
// The boot line
// ---------------------------------------------------------------------------

func TestDescribeSecretSourceNamesTheStoreWithoutACredential(t *testing.T) {
	t.Run("env", func(t *testing.T) {
		setRequiredEnv(t)
		require.NoError(t, Init())
		assert.Equal(t, "env", DescribeSecretSource())
	})

	t.Run("file", func(t *testing.T) {
		dir := writeSecretDir(t, map[string]string{"DB_PASSWORD": "p"})
		setRequiredEnv(t)
		t.Setenv("SECRET_PROVIDER", "file")
		t.Setenv("SECRET_FILE_PATH", dir)
		require.NoError(t, Init())
		got := DescribeSecretSource()
		assert.Contains(t, got, "file")
		assert.Contains(t, got, dir)
		assert.Contains(t, got, "environment fallback permitted",
			"an auditor has to be able to tell whether the store is authoritative")
	})

	t.Run("strict is stated", func(t *testing.T) {
		dir := writeSecretDir(t, map[string]string{
			"DB_PASSWORD":           "p",
			"SECRET_ROOT_KEY":       strings.Repeat("ab", 32),
			"SETUP_BOOTSTRAP_TOKEN": "t",
			"SECRET_CLIENT_SECRET":  "s",
		})
		setRequiredEnv(t)
		t.Setenv("SECRET_PROVIDER", "file")
		t.Setenv("SECRET_FILE_PATH", dir)
		t.Setenv("SECRET_STRICT", "true")
		require.NoError(t, Init())
		assert.Contains(t, DescribeSecretSource(), "SECRET_STRICT")
	})

	// The Vault token and the AppRole secret id are credentials; the address, mount
	// and prefix are not. Asserted on the values directly because the boot line is
	// where a leak would be permanent.
	t.Run("a vault token never appears", func(t *testing.T) {
		SecretProvider = "vault"
		SecretVaultAddress = "https://vault.internal:8200"
		SecretVaultMount = "secret"
		SecretVaultToken = "hvs.super-secret-token"
		SecretVaultSecretID = "approle-secret-id"
		SecretPrefix = "maintainerd/secret"
		SecretStrict = false
		t.Cleanup(func() { require.NoError(t, os.Unsetenv("SECRET_PROVIDER")) })

		got := DescribeSecretSource()
		assert.Contains(t, got, "https://vault.internal:8200")
		assert.NotContains(t, got, "hvs.super-secret-token")
		assert.NotContains(t, got, "approle-secret-id")
	})
}
