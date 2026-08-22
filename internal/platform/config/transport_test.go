package config

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Tests for transport security and the two multi-replica switches.
//
// The behaviour under test is a set of BOOT DECISIONS: which combinations of TLS
// material this service refuses to start with, and which it starts with while saying
// so. Every one of them exists to remove a silent plaintext downgrade.

// clearTransportEnv blanks the transport variables so a test starts from a known
// state regardless of what the operator's shell or a sibling test left behind.
func clearTransportEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"SECRET_GRPC_CERT_FILE", "SECRET_GRPC_KEY_FILE", "SECRET_GRPC_CA_FILE",
		"SECRET_TLS_CERT_FILE", "SECRET_TLS_KEY_FILE",
		"SECRET_LEADER_ELECTION_ENABLED", "SECRET_RATE_LIMIT_SHARED",
	} {
		t.Setenv(k, "")
	}
}

// transportPaths returns three distinct paths. The values are never opened by
// config — it validates the SHAPE of the configuration, and the files themselves are
// loaded later by grpcserver.ServerTLSConfig, which has its own tests over real
// certificates. Keeping that split is why a bad path is not a config error.
func transportPaths(t *testing.T) (cert, key, ca string) {
	t.Helper()
	dir := t.TempDir()
	return filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key"), filepath.Join(dir, "ca.crt")
}

func setGRPCMaterial(t *testing.T) {
	t.Helper()
	cert, key, ca := transportPaths(t)
	t.Setenv("SECRET_GRPC_CERT_FILE", cert)
	t.Setenv("SECRET_GRPC_KEY_FILE", key)
	t.Setenv("SECRET_GRPC_CA_FILE", ca)
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

func TestTransportAndCoordinationDefaults(t *testing.T) {
	setRequiredEnv(t)
	clearTransportEnv(t)
	require.NoError(t, Init())

	assert.Empty(t, GRPCTLSCertFile)
	assert.Empty(t, GRPCTLSKeyFile)
	assert.Empty(t, GRPCClientCAFile)
	assert.False(t, GRPCMutualTLSEnabled())

	assert.Empty(t, HTTPTLSCertFile)
	assert.Empty(t, HTTPTLSKeyFile)
	assert.False(t, HTTPTLSEnabled(), "direct HTTP TLS is optional; the dev stack terminates at nginx")

	// BOTH DEFAULT ON. The failures they prevent are invisible in a healthy-looking
	// service — a secret rotated twice, a reveal budget quietly multiplied by the
	// replica count — so an operator must have to opt OUT of correctness, not in.
	assert.True(t, LeaderElectionEnabled, "leader election is on unless an operator turns it off")
	assert.True(t, RateLimitShared, "the rate limit budget is shared unless an operator turns it off")
}

// ---------------------------------------------------------------------------
// gRPC: partial material
// ---------------------------------------------------------------------------

// TestPartialGRPCMaterialIsABootErrorInEveryEnvironment.
//
// This is the branch that matters most, because a partial configuration is the one
// that LOOKS configured. A cert and key with no CA is server-only TLS that accepts
// any client while the operator believes peers are verified; a CA with no cert and
// key configures nothing at all while looking complete.
func TestPartialGRPCMaterialIsABootErrorInEveryEnvironment(t *testing.T) {
	for _, env := range []string{"production", EnvDevelopment} {
		for _, mode := range []string{ModeStandalone, ModeCore} {
			cases := map[string][]string{
				"cert and key without a CA": {"SECRET_GRPC_CERT_FILE", "SECRET_GRPC_KEY_FILE"},
				"cert and CA without a key": {"SECRET_GRPC_CERT_FILE", "SECRET_GRPC_CA_FILE"},
				"key and CA without a cert": {"SECRET_GRPC_KEY_FILE", "SECRET_GRPC_CA_FILE"},
				"a cert alone":              {"SECRET_GRPC_CERT_FILE"},
				"a key alone":               {"SECRET_GRPC_KEY_FILE"},
				"a CA alone":                {"SECRET_GRPC_CA_FILE"},
			}
			for name, keys := range cases {
				t.Run(env+"/"+mode+"/"+name, func(t *testing.T) {
					setRequiredEnv(t)
					clearTransportEnv(t)
					t.Setenv("APP_ENV", env)
					t.Setenv("MAINTAINERD_MODE", mode)
					dir := t.TempDir()
					for _, k := range keys {
						t.Setenv(k, filepath.Join(dir, k))
					}

					err := Init()
					require.Error(t, err, "a partial TLS configuration must never boot")
					assert.Contains(t, err.Error(), "together or not at all")
				})
			}
		}
	}
}

// ---------------------------------------------------------------------------
// gRPC: the control-plane rule
// ---------------------------------------------------------------------------

// TestCoreModeRefusesToServeTheControlPlaneInTheClear.
//
// In core mode the gRPC listener IS the control plane: SetupService is how
// maintainerd-core provisions this vault's identity and records itself as
// controller. The caller's claim to be core is the only thing between an arbitrary
// peer and ownership of every secret in the store, and that claim must be PROVEN by
// a certificate rather than asserted by a token. So there is no plaintext option.
func TestCoreModeRefusesToServeTheControlPlaneInTheClear(t *testing.T) {
	setRequiredEnv(t)
	clearTransportEnv(t)
	t.Setenv("APP_ENV", "production")
	t.Setenv("MAINTAINERD_MODE", ModeCore)

	err := Init()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SECRET_GRPC_CERT_FILE")
	assert.Contains(t, err.Error(), "SECRET_GRPC_KEY_FILE")
	assert.Contains(t, err.Error(), "SECRET_GRPC_CA_FILE")
	assert.Contains(t, err.Error(), "never served in the clear")
}

// TestCoreModeWithFullMaterialBoots, and reports mutual TLS.
func TestCoreModeWithFullMaterialBoots(t *testing.T) {
	setRequiredEnv(t)
	clearTransportEnv(t)
	t.Setenv("APP_ENV", "production")
	t.Setenv("MAINTAINERD_MODE", ModeCore)
	setGRPCMaterial(t)

	require.NoError(t, Init())
	assert.True(t, GRPCMutualTLSEnabled(), "the control plane must require a client certificate")
}

// TestCoreModeInDevelopmentStillBootsWithoutMaterial. A laptop instance with no
// certificates is exactly the case the development degrade exists for, and it is the
// only environment in which the control plane may be plaintext.
func TestCoreModeInDevelopmentStillBootsWithoutMaterial(t *testing.T) {
	setRequiredEnv(t)
	clearTransportEnv(t)
	t.Setenv("APP_ENV", EnvDevelopment)
	t.Setenv("MAINTAINERD_MODE", ModeCore)

	require.NoError(t, Init())
	assert.False(t, GRPCMutualTLSEnabled())
}

// TestStandaloneInProductionWarnsRatherThanRefuses.
//
// The asymmetry with core mode is deliberate. In standalone the gRPC listener is
// service-to-service traffic between workloads the operator already runs on a
// network they control, commonly a mesh that provides mTLS BELOW this process.
// Refusing would break those deployments to protect them from a risk they have
// already handled, and the likely response would be to disable TLS somewhere else
// rather than to configure it here. So it is stated at boot, every boot, and left
// as the operator's call.
func TestStandaloneInProductionWarnsRatherThanRefuses(t *testing.T) {
	setRequiredEnv(t)
	clearTransportEnv(t)
	t.Setenv("APP_ENV", "production")
	t.Setenv("MAINTAINERD_MODE", ModeStandalone)

	require.NoError(t, Init(), "standalone service-to-service traffic may be plaintext behind a mesh")
	assert.False(t, GRPCMutualTLSEnabled())
}

// TestStandaloneWithFullMaterialEnablesMutualTLS.
func TestStandaloneWithFullMaterialEnablesMutualTLS(t *testing.T) {
	setRequiredEnv(t)
	clearTransportEnv(t)
	t.Setenv("APP_ENV", "production")
	setGRPCMaterial(t)

	require.NoError(t, Init())
	assert.True(t, GRPCMutualTLSEnabled())
	assert.NotEmpty(t, GRPCClientCAFile)
}

// ---------------------------------------------------------------------------
// HTTP TLS
// ---------------------------------------------------------------------------

// TestPartialHTTPTLSMaterialIsABootError, same reasoning as the gRPC partial case.
func TestPartialHTTPTLSMaterialIsABootError(t *testing.T) {
	for _, key := range []string{"SECRET_TLS_CERT_FILE", "SECRET_TLS_KEY_FILE"} {
		t.Run(key+" alone", func(t *testing.T) {
			setRequiredEnv(t)
			clearTransportEnv(t)
			t.Setenv(key, filepath.Join(t.TempDir(), "http.pem"))

			err := Init()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "SECRET_TLS_CERT_FILE")
			assert.Contains(t, err.Error(), "SECRET_TLS_KEY_FILE")
		})
	}
}

// TestBothHTTPTLSFilesEnableDirectTLS.
func TestBothHTTPTLSFilesEnableDirectTLS(t *testing.T) {
	setRequiredEnv(t)
	clearTransportEnv(t)
	dir := t.TempDir()
	t.Setenv("SECRET_TLS_CERT_FILE", filepath.Join(dir, "http.crt"))
	t.Setenv("SECRET_TLS_KEY_FILE", filepath.Join(dir, "http.key"))

	require.NoError(t, Init())
	assert.True(t, HTTPTLSEnabled())
}

// TestAbsentHTTPTLSIsFineInProduction: the REST surface sits behind a terminating
// proxy in every sanctioned deployment, so mandating a certificate here would mean
// every operator generating one for a socket nothing external reaches.
func TestAbsentHTTPTLSIsFineInProduction(t *testing.T) {
	setRequiredEnv(t)
	clearTransportEnv(t)
	t.Setenv("APP_ENV", "production")

	require.NoError(t, Init())
	assert.False(t, HTTPTLSEnabled())
}

// ---------------------------------------------------------------------------
// The coordination switches
// ---------------------------------------------------------------------------

func TestCoordinationSwitchesCanBeTurnedOff(t *testing.T) {
	setRequiredEnv(t)
	clearTransportEnv(t)
	t.Setenv("SECRET_LEADER_ELECTION_ENABLED", "false")
	t.Setenv("SECRET_RATE_LIMIT_SHARED", "false")

	require.NoError(t, Init(), "both are legitimate choices for a single-replica deployment")
	assert.False(t, LeaderElectionEnabled)
	assert.False(t, RateLimitShared)
}

// TestCoordinationSwitchesRefuseAMalformedValue rather than falling back to the
// default. A switch that silently becomes its default is a configuration change
// nobody made — and for these two, the change is invisible in a healthy service.
func TestCoordinationSwitchesRefuseAMalformedValue(t *testing.T) {
	for _, key := range []string{"SECRET_LEADER_ELECTION_ENABLED", "SECRET_RATE_LIMIT_SHARED"} {
		t.Run(key, func(t *testing.T) {
			setRequiredEnv(t)
			clearTransportEnv(t)
			t.Setenv(key, "yes-please")

			err := Init()
			require.Error(t, err)
			assert.Contains(t, err.Error(), key)
		})
	}
}
