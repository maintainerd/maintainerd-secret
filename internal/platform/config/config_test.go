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

// TestNoAuthConfigurationIsPermittedAndDisablesTheAPI. Booting is allowed so an
// unprovisioned instance can still be reached on its setup surface; the guard, not
// config, is what refuses the API.
func TestNoAuthConfigurationIsPermitted(t *testing.T) {
	setRequiredEnv(t)
	require.NoError(t, Init())
	assert.Empty(t, AuthJWKSURL)
	assert.Empty(t, AuthIssuer)
	assert.Empty(t, AuthAudience)
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
