package config

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setRequiredEnv sets the minimum a successful Init needs.
//
// It runs at APP_ENV=production in the DEFAULT run mode (standalone), which is
// what makes it the honest baseline: standalone is what an operator gets when
// they set no mode at all, and it requires a complete identity configuration.
// Every variable below is genuinely required in that combination — see
// TestStandaloneRequiresItsIdentityConfiguration, which removes them one at a
// time and asserts the boot error names the one it removed.
func setRequiredEnv(t *testing.T) {
	t.Helper()
	t.Setenv("DB_HOST", "localhost")
	t.Setenv("DB_PORT", "5432")
	t.Setenv("DB_USER", "postgres")
	t.Setenv("DB_PASSWORD", "postgres")
	t.Setenv("DB_NAME", "maintainerd_secret")
	t.Setenv("SECRET_ROOT_KEY", strings.Repeat("ab", 32))
	t.Setenv("SETUP_BOOTSTRAP_TOKEN", "bootstrap-token")
	t.Setenv("APP_ENV", "production")
	setStandaloneEnv(t)
}

// setStandaloneEnv sets the identity configuration standalone mode requires: the
// three inbound-token checks, this service's own backend client, and the
// console's public SPA client.
func setStandaloneEnv(t *testing.T) {
	t.Helper()
	t.Setenv("MAINTAINERD_MODE", "")
	t.Setenv("AUTH_JWKS_URL", "https://auth.example/.well-known/jwks.json")
	t.Setenv("AUTH_ISSUER", "https://auth.example/")
	t.Setenv("AUTH_AUDIENCE", "maintainerd-secret")
	t.Setenv("SECRET_CLIENT_ID", "secret-backend")
	t.Setenv("SECRET_CLIENT_SECRET", "secret-backend-secret")
	t.Setenv("SECRET_CLIENT_PRIVATE_KEY_FILE", "")
	t.Setenv("SECRET_CONSOLE_CLIENT_ID", "secret-console")
}

// clearAuthEnv blanks the three inbound-token variables, for the tests that are
// about their absence.
func clearAuthEnv(t *testing.T) {
	t.Helper()
	t.Setenv("AUTH_JWKS_URL", "")
	t.Setenv("AUTH_ISSUER", "")
	t.Setenv("AUTH_AUDIENCE", "")
}

func TestInitDefaults(t *testing.T) {
	setRequiredEnv(t)
	require.NoError(t, Init())

	assert.Equal(t, ":9092", GRPCAddr)
	assert.Equal(t, ":8092", HTTPAddr)
	assert.Equal(t, "env", RootKeyProvider)
	assert.Equal(t, 10, KeepVersions)
	assert.Equal(t, 30*24*time.Hour, RecoveryWindow)
	assert.Equal(t, 500, RewrapBatchSize)
	assert.True(t, DefaultScopeAutocreate)
	assert.Equal(t, "default", DefaultTenant)
	assert.False(t, IsDevelopment())
}

func TestInitRequiresDatabaseSettings(t *testing.T) {
	for _, missing := range []string{"DB_HOST", "DB_PORT", "DB_USER", "DB_PASSWORD", "DB_NAME"} {
		t.Run("missing "+missing, func(t *testing.T) {
			setRequiredEnv(t)
			t.Setenv(missing, "")
			err := Init()
			require.Error(t, err)
			assert.Contains(t, err.Error(), missing)
		})
	}
}

func TestInitRefusesMalformedNumbersRatherThanDefaulting(t *testing.T) {
	// A typo in a retention or pool setting that silently becomes the default is a
	// configuration change nobody made — and for retention it destroys history.
	for _, key := range []string{
		"SECRET_KEEP_VERSIONS", "SECRET_REWRAP_BATCH_SIZE",
		"DB_MAX_OPEN_CONNS", "DB_MAX_IDLE_CONNS", "DB_STATEMENT_TIMEOUT_MS",
	} {
		for _, bad := range []string{"ten", "0", "-1", "3.5"} {
			t.Run(key+"="+bad, func(t *testing.T) {
				setRequiredEnv(t)
				t.Setenv(key, bad)
				err := Init()
				require.Error(t, err)
				assert.Contains(t, err.Error(), key)
			})
		}
	}
}

func TestInitRejectsAnIdlePoolLargerThanTheMax(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("DB_MAX_OPEN_CONNS", "5")
	t.Setenv("DB_MAX_IDLE_CONNS", "10")
	err := Init()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DB_MAX_IDLE_CONNS")
}

func TestInitValidatesTheRootKeyProvider(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("SECRET_ROOT_KEY_PROVIDER", "hashicorp-vault")
	err := Init()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SECRET_ROOT_KEY_PROVIDER")

	// Every provider the factory builds is accepted here, each with the settings it
	// actually needs. Config validation and crypto.KnownProviders are two views of
	// one set, and this is the test that keeps them from drifting.
	for _, provider := range []string{"env", "file", "aws_kms", "gcp_kms", "azure_kv"} {
		t.Run(provider, func(t *testing.T) {
			setRequiredEnv(t)
			t.Setenv("SECRET_ROOT_KEY_PROVIDER", provider)
			if provider == "file" {
				t.Setenv("SECRET_ROOT_KEY_FILE", "/run/secrets/root.key")
			}
			setKMSEnv(t)
			require.NoError(t, Init())
			assert.Equal(t, provider, RootKeyProvider)
		})
	}
}

func TestInitRequiresAKeyFileForTheFileProvider(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("SECRET_ROOT_KEY_PROVIDER", "file")
	err := Init()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SECRET_ROOT_KEY_FILE")
}

func TestInitRequiresABootstrapTokenOutsideDevelopment(t *testing.T) {
	// An empty token left the prototype's setup window open to anyone after a
	// restart. Outside development that is a boot error.
	setRequiredEnv(t)
	t.Setenv("SETUP_BOOTSTRAP_TOKEN", "")
	err := Init()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SETUP_BOOTSTRAP_TOKEN")

	// Development may leave it open.
	t.Setenv("APP_ENV", "development")
	require.NoError(t, Init())
	assert.True(t, IsDevelopment())
}

func TestInitRefusesAZeroRecoveryWindowOutsideDevelopment(t *testing.T) {
	// A zero window turns every mistaken delete into permanent data loss.
	setRequiredEnv(t)
	t.Setenv("SECRET_RECOVERY_WINDOW", "0s")
	err := Init()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SECRET_RECOVERY_WINDOW")

	t.Setenv("APP_ENV", "development")
	require.NoError(t, Init())
	assert.Equal(t, time.Duration(0), RecoveryWindow)
}

func TestRecoveryWindowAcceptsDurationsAndBareSeconds(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("SECRET_RECOVERY_WINDOW", "48h")
	require.NoError(t, Init())
	assert.Equal(t, 48*time.Hour, RecoveryWindow)

	t.Setenv("SECRET_RECOVERY_WINDOW", "3600")
	require.NoError(t, Init())
	assert.Equal(t, time.Hour, RecoveryWindow)
}

func TestIsDevelopmentFailsClosedOnATypo(t *testing.T) {
	// Anything other than the exact sanctioned value reads as production, so a typo
	// cannot accidentally enable the ephemeral key or an open setup window.
	for _, env := range []string{"dev", "Development", "DEVELOPMENT", "develop", " development"} {
		setRequiredEnv(t)
		t.Setenv("APP_ENV", env)
		require.NoError(t, Init())
		assert.False(t, IsDevelopment(), "APP_ENV=%q must not count as development", env)
	}
}

func TestInitValidatesBooleans(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("SECRET_DEFAULT_SCOPE_AUTOCREATE", "maybe")
	err := Init()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SECRET_DEFAULT_SCOPE_AUTOCREATE")

	t.Setenv("SECRET_DEFAULT_SCOPE_AUTOCREATE", "false")
	require.NoError(t, Init())
	assert.False(t, DefaultScopeAutocreate)
}

func TestConnectionStringQuotesTheOptionsValue(t *testing.T) {
	// The options value contains a space; unquoted, the driver splits it and Postgres
	// receives a bare -c.
	setRequiredEnv(t)
	require.NoError(t, Init())
	dsn := GetDBConnectionString()
	assert.Contains(t, dsn, "options='-c statement_timeout=30000'")
	assert.Contains(t, dsn, "host=localhost")
	assert.Contains(t, dsn, "dbname=maintainerd_secret")
}

func TestConnectionStringCarriesThePasswordButConfigDoesNotLogIt(t *testing.T) {
	// The DSN necessarily holds the password; what matters is that it is only ever
	// handed to the driver. This test documents the boundary.
	setRequiredEnv(t)
	t.Setenv("DB_PASSWORD", "s3cr3t-db-pass")
	require.NoError(t, Init())
	assert.Contains(t, GetDBConnectionString(), "s3cr3t-db-pass")
}

func TestRootKeyIsNotValidatedByConfig(t *testing.T) {
	// Config records the value; crypto validates and refuses it. Keeping the
	// validation in one place means the "no ephemeral key outside development" rule
	// has exactly one implementation.
	setRequiredEnv(t)
	t.Setenv("SECRET_ROOT_KEY", "obviously-not-a-key")
	require.NoError(t, Init())
	assert.Equal(t, "obviously-not-a-key", RootKey)

	// And a well-formed key round-trips untouched.
	key := hex.EncodeToString(make([]byte, 32))
	t.Setenv("SECRET_ROOT_KEY", key)
	require.NoError(t, Init())
	assert.Equal(t, key, RootKey)
}

// ---------------------------------------------------------------------------
// Authorization, rotation and webhook settings (wave 2)
// ---------------------------------------------------------------------------

// TestAuthVariablesAreAllOrNothing is the one that matters. Setting only
// AUTH_JWKS_URL LOOKS configured and accepts any token Auth ever signed, including
// tokens minted for a completely different service — so a partial configuration is a
// boot error rather than a silent degradation an operator discovers after an incident.
func TestAuthVariablesAreAllOrNothing(t *testing.T) {
	partials := []map[string]string{
		{"AUTH_JWKS_URL": "https://auth.example/.well-known/jwks.json"},
		{"AUTH_ISSUER": "https://auth.example/"},
		{"AUTH_AUDIENCE": "maintainerd-secret"},
		{"AUTH_JWKS_URL": "https://auth.example/.well-known/jwks.json", "AUTH_ISSUER": "https://auth.example/"},
	}
	// Each case runs as a SUBTEST because t.Setenv only restores at the end of the
	// test that called it: in a flat loop the second iteration would inherit the
	// first's variable and quietly become a complete configuration.
	for i, partial := range partials {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			setRequiredEnv(t)
			clearAuthEnv(t)
			for k, v := range partial {
				t.Setenv(k, v)
			}
			err := Init()
			require.Error(t, err, "partial auth configuration %v must be refused", partial)
			assert.Contains(t, err.Error(), "must be set together")
		})
	}
}

func TestCompleteAuthConfigurationIsAccepted(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("AUTH_JWKS_URL", "https://auth.example/.well-known/jwks.json")
	t.Setenv("AUTH_ISSUER", "https://auth.example/")
	t.Setenv("AUTH_AUDIENCE", "maintainerd-secret")
	require.NoError(t, Init())
	assert.Equal(t, "https://auth.example/.well-known/jwks.json", AuthJWKSURL)
	assert.Equal(t, "https://auth.example/", AuthIssuer)
	assert.Equal(t, "maintainerd-secret", AuthAudience)
}

// TestNoAuthConfigurationIsPermittedInCoreMode. In core mode booting without auth
// is the NORMAL pre-provisioning state: core has not driven the setup RPC yet, so
// the instance must come up and be reachable on its setup surface. The guard, not
// config, is what refuses the API in the meantime.
func TestNoAuthConfigurationIsPermittedInCoreMode(t *testing.T) {
	setRequiredEnv(t)
	clearAuthEnv(t)
	t.Setenv("MAINTAINERD_MODE", "core")
	// The gRPC TLS material is supplied because setRequiredEnv runs in production, and
	// core mode refuses to serve the control plane in the clear (initTransportSecurity;
	// asserted by TestCoreModeRefusesToServeTheControlPlaneInTheClear). That rule is not
	// this test's subject — which is that MISSING AUTH is the normal pre-provisioning
	// state — so the transport is configured here to keep the two from being tested
	// through each other.
	setGRPCMaterial(t)
	require.NoError(t, Init())
	assert.Equal(t, ModeCore, Mode)
	assert.False(t, IsStandalone())
	assert.Empty(t, AuthJWKSURL)
	assert.Empty(t, AuthIssuer)
	assert.Empty(t, AuthAudience)
}

// ---------------------------------------------------------------------------
// Run modes
// ---------------------------------------------------------------------------

// TestModeDefaultsToStandalone is the requirement, not a convenience: a developer
// who never adopts core must get a working auth+secret deployment by doing
// nothing, which means standalone has to be what an unset variable produces.
func TestModeDefaultsToStandalone(t *testing.T) {
	setRequiredEnv(t)
	require.NoError(t, Init())
	assert.Equal(t, ModeStandalone, Mode)
	assert.True(t, IsStandalone())
	assert.Contains(t, DescribeMode(), "standalone")
}

func TestModeIsValidated(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("MAINTAINERD_MODE", "attached")
	err := Init()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "MAINTAINERD_MODE")
	assert.Contains(t, err.Error(), "standalone, core")

	t.Run("case and whitespace are tolerated", func(t *testing.T) {
		setRequiredEnv(t)
		t.Setenv("MAINTAINERD_MODE", "  CORE ")
		// Resolving to core mode brings the control-plane TLS requirement with it; the
		// subject here is only that the value is normalised.
		setGRPCMaterial(t)
		require.NoError(t, Init())
		assert.Equal(t, ModeCore, Mode)
	})
}

// TestStandaloneRequiresItsIdentityConfiguration is the "not a silent degrade"
// requirement. Each variable is removed on its own and the boot error must name
// exactly the one that went missing — an operator who forgot the console client
// id should not have to guess which of six things is wrong.
func TestStandaloneRequiresItsIdentityConfiguration(t *testing.T) {
	cases := map[string]string{
		"SECRET_CLIENT_ID":         "SECRET_CLIENT_ID",
		"SECRET_CLIENT_SECRET":     "SECRET_CLIENT_SECRET or SECRET_CLIENT_PRIVATE_KEY_FILE",
		"SECRET_CONSOLE_CLIENT_ID": "SECRET_CONSOLE_CLIENT_ID",
	}
	for missing, named := range cases {
		t.Run("missing "+missing, func(t *testing.T) {
			setRequiredEnv(t)
			t.Setenv(missing, "")
			err := Init()
			require.Error(t, err)
			assert.Contains(t, err.Error(), named)
			assert.Contains(t, err.Error(), "maintainerd-auth's console",
				"the error has to say where to create the thing that is missing")
			assert.Contains(t, err.Error(), "MAINTAINERD_MODE=core",
				"and it has to say what the other mode is, for an operator who set the wrong one")
		})
	}

	// The three inbound-token variables are refused one rung EARLIER, by the
	// all-or-nothing check, which is the more specific message: a JWKS URL with no
	// issuer or audience check is dangerous in a way a merely absent one is not.
	// Their absence as a SET is what the standalone rule catches.
	t.Run("all three auth variables absent", func(t *testing.T) {
		setRequiredEnv(t)
		clearAuthEnv(t)
		err := Init()
		require.Error(t, err)
		for _, name := range []string{"AUTH_ISSUER", "AUTH_JWKS_URL", "AUTH_AUDIENCE"} {
			assert.Contains(t, err.Error(), name)
		}
		assert.Contains(t, err.Error(), "maintainerd-auth's console")
	})
}

// TestStandaloneAcceptsAPrivateKeyInsteadOfASecret: private_key_jwt is the
// stronger client authentication and must not be a second-class configuration.
func TestStandaloneAcceptsAPrivateKeyInsteadOfASecret(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("SECRET_CLIENT_SECRET", "")
	t.Setenv("SECRET_CLIENT_PRIVATE_KEY_FILE", "/run/secrets/secret-client.pem")
	require.NoError(t, Init())
	assert.Equal(t, "/run/secrets/secret-client.pem", ClientPrivateKeyFile)
	assert.Empty(t, ClientSecret)
}

// TestBothClientCredentialsAreRefused. Holding two is not extra safety, it is an
// ambiguity: the process uses one while the operator maintains the other.
func TestBothClientCredentialsAreRefused(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("SECRET_CLIENT_SECRET", "shared-secret")
	t.Setenv("SECRET_CLIENT_PRIVATE_KEY_FILE", "/run/secrets/secret-client.pem")
	err := Init()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not both")
}

// TestStandaloneDegradesInDevelopment. On a laptop with no Auth running, the
// dev-open guard and its loud banner are the point of the ladder; refusing to
// boot there would make the reduced-safety development path unusable.
func TestStandaloneDegradesInDevelopment(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("APP_ENV", "development")
	t.Setenv("SETUP_BOOTSTRAP_TOKEN", "")
	clearAuthEnv(t)
	t.Setenv("SECRET_CLIENT_ID", "")
	t.Setenv("SECRET_CLIENT_SECRET", "")
	t.Setenv("SECRET_CONSOLE_CLIENT_ID", "")

	require.NoError(t, Init())
	assert.True(t, IsDevelopment())
	assert.Equal(t, ModeStandalone, Mode)
}

// TestCoreModeIgnoresTheStandaloneCredentials: they are core's to provision, so
// their absence is not this process's error to raise.
func TestCoreModeIgnoresTheStandaloneCredentials(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("MAINTAINERD_MODE", "core")
	t.Setenv("SECRET_CLIENT_ID", "")
	t.Setenv("SECRET_CLIENT_SECRET", "")
	t.Setenv("SECRET_CONSOLE_CLIENT_ID", "")
	// Core mode's control-plane TLS requirement is a separate rule; supplied so this
	// test stays about the standalone credentials being core's to provision.
	setGRPCMaterial(t)
	require.NoError(t, Init())
	assert.Equal(t, ModeCore, Mode)
	assert.Contains(t, DescribeMode(), "core")
}

func TestRotationAndWebhookDefaults(t *testing.T) {
	setRequiredEnv(t)
	require.NoError(t, Init())
	assert.True(t, RotationEnabled)
	assert.Equal(t, 5*time.Minute, RotationInterval)
	assert.Equal(t, 50, RotationBatch)
	assert.True(t, WebhooksEnabled)
	assert.Equal(t, 4, WebhookConcurrency)
	assert.Equal(t, 8, ReferenceMaxDepth)
}

func TestRotationCanBeDisabledWithoutRemovingPolicies(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("SECRET_ROTATION_ENABLED", "false")
	require.NoError(t, Init())
	assert.False(t, RotationEnabled)
}

// TestMalformedNumericSettingsAreRefused rather than silently defaulted: a typo in a
// batch or depth setting that becomes the default is a configuration change nobody
// made.
func TestMalformedNumericSettingsAreRefused(t *testing.T) {
	for _, key := range []string{"SECRET_ROTATION_BATCH", "SECRET_REFERENCE_MAX_DEPTH", "SECRET_WEBHOOK_CONCURRENCY"} {
		setRequiredEnv(t)
		t.Setenv(key, "lots")
		require.Error(t, Init(), "%s must refuse a non-integer", key)
	}
}

// ---------------------------------------------------------------------------
// Cloud KMS root keys
// ---------------------------------------------------------------------------

// setKMSEnv sets a complete, valid set of coordinates for all three cloud providers
// at once, and clears the ambient AWS variables the region falls back to so a
// developer's own shell cannot change what a test proves.
//
// Setting all three is deliberate: only the SELECTED provider's variables are
// validated, and an operator mid-migration legitimately has two sets in place.
func setKMSEnv(t *testing.T) {
	t.Helper()
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_DEFAULT_REGION", "")
	t.Setenv("SECRET_KMS_AWS_KEY_ID", "arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab")
	t.Setenv("SECRET_KMS_AWS_REGION", "us-east-2")
	t.Setenv("SECRET_KMS_GCP_KEY_NAME", "projects/acme/locations/us-east1/keyRings/secret/cryptoKeys/root")
	t.Setenv("SECRET_KMS_AZURE_VAULT_URL", "https://acme-vault.vault.azure.net/")
	t.Setenv("SECRET_KMS_AZURE_KEY_NAME", "secret-root")
	t.Setenv("SECRET_KMS_AZURE_KEY_VERSION", "")
}

func TestKMSSettingsAreRequiredAtBootForTheSelectedProvider(t *testing.T) {
	// THE WHOLE POINT: a cloud provider selected without its coordinates must refuse
	// to boot. The alternative is a process that starts, passes its health check,
	// joins the load balancer, and fails on the first Wrap — the same class of
	// deferred failure as a silently generated root key.
	cases := []struct {
		provider string
		clear    []string
		wantName string
	}{
		{"aws_kms", []string{"SECRET_KMS_AWS_KEY_ID"}, "SECRET_KMS_AWS_KEY_ID"},
		{"aws_kms", []string{"SECRET_KMS_AWS_REGION"}, "SECRET_KMS_AWS_REGION"},
		{"gcp_kms", []string{"SECRET_KMS_GCP_KEY_NAME"}, "SECRET_KMS_GCP_KEY_NAME"},
		{"azure_kv", []string{"SECRET_KMS_AZURE_VAULT_URL"}, "SECRET_KMS_AZURE_VAULT_URL"},
		{"azure_kv", []string{"SECRET_KMS_AZURE_KEY_NAME"}, "SECRET_KMS_AZURE_KEY_NAME"},
	}
	for _, tc := range cases {
		t.Run(tc.provider+" without "+tc.wantName, func(t *testing.T) {
			setRequiredEnv(t)
			setKMSEnv(t)
			t.Setenv("SECRET_ROOT_KEY_PROVIDER", tc.provider)
			for _, key := range tc.clear {
				t.Setenv(key, "")
			}
			err := Init()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantName)
			assert.Contains(t, err.Error(), "SECRET_ROOT_KEY_PROVIDER="+tc.provider)
		})
	}
}

func TestKMSMissingSettingsAreAllNamedAtOnce(t *testing.T) {
	// One restart per missing variable turns a two-minute setup into three restarts,
	// which is why kmsMissing reports the whole list.
	setRequiredEnv(t)
	setKMSEnv(t)
	t.Setenv("SECRET_ROOT_KEY_PROVIDER", "azure_kv")
	t.Setenv("SECRET_KMS_AZURE_VAULT_URL", "")
	t.Setenv("SECRET_KMS_AZURE_KEY_NAME", "")

	err := Init()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SECRET_KMS_AZURE_VAULT_URL")
	assert.Contains(t, err.Error(), "SECRET_KMS_AZURE_KEY_NAME")
}

func TestAWSRegionFallsBackToTheSDKVariables(t *testing.T) {
	// A workload that already sets AWS_REGION for its other AWS calls should not
	// have to set a second name for the same fact.
	for _, fallback := range []string{"AWS_REGION", "AWS_DEFAULT_REGION"} {
		t.Run(fallback, func(t *testing.T) {
			setRequiredEnv(t)
			setKMSEnv(t)
			t.Setenv("SECRET_ROOT_KEY_PROVIDER", "aws_kms")
			t.Setenv("SECRET_KMS_AWS_REGION", "")
			t.Setenv(fallback, "eu-west-1")
			require.NoError(t, Init())
			assert.Equal(t, "eu-west-1", KMSAWSRegion)
		})
	}
}

func TestKMSSettingsForAnUnselectedProviderAreNotValidated(t *testing.T) {
	// An operator migrating aws_kms → gcp_kms keeps both sets in place through the
	// rewrap. Validating the inactive one would make that migration impossible.
	setRequiredEnv(t)
	setKMSEnv(t)
	t.Setenv("SECRET_ROOT_KEY_PROVIDER", "env")
	t.Setenv("SECRET_KMS_GCP_KEY_NAME", "this-is-not-a-resource-name")
	t.Setenv("SECRET_KMS_AZURE_VAULT_URL", "http://insecure.example/")
	require.NoError(t, Init())
}

func TestGCPKeyNameShapeIsValidatedAtBoot(t *testing.T) {
	t.Run("a pinned key version is refused", func(t *testing.T) {
		// Encrypt accepts a cryptoKeyVersion name and Decrypt does not, so this
		// would boot, wrap, and then fail every unwrap.
		setRequiredEnv(t)
		setKMSEnv(t)
		t.Setenv("SECRET_ROOT_KEY_PROVIDER", "gcp_kms")
		t.Setenv("SECRET_KMS_GCP_KEY_NAME",
			"projects/acme/locations/us-east1/keyRings/secret/cryptoKeys/root/cryptoKeyVersions/3")
		err := Init()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cryptoKeyVersion")
	})

	t.Run("a key-ring name is refused", func(t *testing.T) {
		setRequiredEnv(t)
		setKMSEnv(t)
		t.Setenv("SECRET_ROOT_KEY_PROVIDER", "gcp_kms")
		t.Setenv("SECRET_KMS_GCP_KEY_NAME", "projects/acme/locations/us-east1/keyRings/secret")
		err := Init()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "SECRET_KMS_GCP_KEY_NAME")
	})
}

func TestAzureVaultURLMustBeHTTPS(t *testing.T) {
	// A plain-http vault URL would send this service's Azure token — a credential
	// that can unwrap the vault's root key — in the clear.
	setRequiredEnv(t)
	setKMSEnv(t)
	t.Setenv("SECRET_ROOT_KEY_PROVIDER", "azure_kv")
	t.Setenv("SECRET_KMS_AZURE_VAULT_URL", "http://acme-vault.vault.azure.net/")
	err := Init()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "https")
}

func TestKMSTimeoutDefaultsAndRefusesGarbage(t *testing.T) {
	setRequiredEnv(t)
	setKMSEnv(t)
	require.NoError(t, Init())
	assert.Equal(t, 10*time.Second, KMSTimeout)

	t.Setenv("SECRET_KMS_TIMEOUT", "2s")
	require.NoError(t, Init())
	assert.Equal(t, 2*time.Second, KMSTimeout)

	for _, bad := range []string{"soon", "0s", "-5s"} {
		t.Setenv("SECRET_KMS_TIMEOUT", bad)
		err := Init()
		require.Error(t, err, "SECRET_KMS_TIMEOUT=%s must be refused", bad)
		assert.Contains(t, err.Error(), "SECRET_KMS_TIMEOUT")
	}
}

func TestRootKeyProviderConfigCarriesEverythingTheFactoryNeeds(t *testing.T) {
	// The root of trust is assembled from ONE place, so no call site has to know
	// which fields a given provider reads.
	setRequiredEnv(t)
	setKMSEnv(t)
	t.Setenv("SECRET_ROOT_KEY_PROVIDER", "aws_kms")
	t.Setenv("SECRET_KMS_TIMEOUT", "3s")
	require.NoError(t, Init())

	cfg := RootKeyProviderConfig()
	assert.Equal(t, "aws_kms", cfg.Provider)
	assert.Equal(t, AppEnv, cfg.AppEnv)
	assert.Equal(t, RootKey, cfg.Key)
	assert.Equal(t, RootKeyFile, cfg.KeyFile)
	assert.Equal(t, 3*time.Second, cfg.KMS.Timeout)
	assert.Equal(t, KMSAWSKeyID, cfg.KMS.AWSKeyID)
	assert.Equal(t, "us-east-2", cfg.KMS.AWSRegion)
	assert.Equal(t, KMSGCPKeyName, cfg.KMS.GCPKeyName)
	assert.Equal(t, KMSAzureVaultURL, cfg.KMS.AzureVaultURL)
	assert.Equal(t, KMSAzureKeyName, cfg.KMS.AzureKeyName)
	assert.Equal(t, KMSAzureKeyVersion, cfg.KMS.AzureKeyVersion)
}

func TestDescribeRootKeyNamesTheKeyWithoutMaterial(t *testing.T) {
	setRequiredEnv(t)
	setKMSEnv(t)

	t.Setenv("SECRET_ROOT_KEY_PROVIDER", "aws_kms")
	require.NoError(t, Init())
	assert.Contains(t, DescribeRootKey(), "us-east-2")
	assert.NotContains(t, DescribeRootKey(), RootKey)

	t.Setenv("SECRET_ROOT_KEY_PROVIDER", "azure_kv")
	require.NoError(t, Init())
	assert.Contains(t, DescribeRootKey(), "current", "an unpinned Azure version reads as current, not empty")

	t.Setenv("SECRET_ROOT_KEY_PROVIDER", "env")
	require.NoError(t, Init())
	assert.Equal(t, "env", DescribeRootKey())
	assert.NotContains(t, DescribeRootKey(), RootKey)
}
