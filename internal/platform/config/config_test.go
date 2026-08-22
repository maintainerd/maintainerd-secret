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

	// The KMS providers are accepted by config even though the clients are not built
	// — that is the point of the seam: an operator's aws_kms config validates today.
	for _, provider := range []string{"env", "file", "aws_kms", "gcp_kms", "azure_kv"} {
		t.Run(provider, func(t *testing.T) {
			setRequiredEnv(t)
			t.Setenv("SECRET_ROOT_KEY_PROVIDER", provider)
			if provider == "file" {
				t.Setenv("SECRET_ROOT_KEY_FILE", "/run/secrets/root.key")
			}
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
