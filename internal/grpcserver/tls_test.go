package grpcserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Certificate fixtures
// ---------------------------------------------------------------------------

// writeCertFixtures produces a self-signed CA plus a leaf certificate signed by it,
// and returns their paths. Real certificates rather than dummy files, because half
// the behaviour under test is what tls.LoadX509KeyPair and AppendCertsFromPEM do
// with the bytes.
func writeCertFixtures(t *testing.T) (certFile, keyFile, caFile string) {
	t.Helper()
	dir := t.TempDir()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "maintainerd-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "maintainerd-secret"},
		DNSNames:     []string{"secret.maintainerd.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)

	leafKeyDER, err := x509.MarshalECPrivateKey(leafKey)
	require.NoError(t, err)

	certFile = filepath.Join(dir, "server.crt")
	keyFile = filepath.Join(dir, "server.key")
	caFile = filepath.Join(dir, "ca.crt")

	writePEM(t, certFile, "CERTIFICATE", leafDER)
	writePEM(t, keyFile, "EC PRIVATE KEY", leafKeyDER)
	writePEM(t, caFile, "CERTIFICATE", caDER)
	return certFile, keyFile, caFile
}

func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600))
}

// ---------------------------------------------------------------------------
// No material configured
// ---------------------------------------------------------------------------

// TestNoMaterialServesInTheClear. config decides whether plaintext is permissible
// for a given run (it is a boot error in core mode outside development); this
// function's job is only to report "nothing configured", not to re-litigate it.
func TestNoMaterialServesInTheClear(t *testing.T) {
	cfg, err := ServerTLSConfig(TLSOptions{})
	require.NoError(t, err)
	assert.Nil(t, cfg, "no material must mean no TLS config, not an error")

	creds, err := ServerCredentials(TLSOptions{})
	require.NoError(t, err)
	assert.Nil(t, creds, "the caller passes over nil credentials")

	assert.False(t, TLSOptions{}.Configured())
}

// ---------------------------------------------------------------------------
// Partial material — the branch that matters most
// ---------------------------------------------------------------------------

// TestPartialMaterialIsRefusedRatherThanDowngraded.
//
// THIS IS THE "NO SILENT PLAINTEXT DOWNGRADE" RULE at the transport layer. A
// partial configuration is the dangerous one because it LOOKS configured: an
// operator with a cert and key but no CA has built server-only TLS and believes
// they have mutual TLS, so they believe peers are verified when in fact any client
// is accepted.
func TestPartialMaterialIsRefusedRatherThanDowngraded(t *testing.T) {
	certFile, keyFile, caFile := writeCertFixtures(t)

	cases := map[string]TLSOptions{
		"cert and key without a client CA": {CertFile: certFile, KeyFile: keyFile},
		"cert without a key":               {CertFile: certFile, ClientCAFile: caFile},
		"key without a cert":               {KeyFile: keyFile, ClientCAFile: caFile},
		"a client CA alone":                {ClientCAFile: caFile},
		"a cert alone":                     {CertFile: certFile},
		"a key alone":                      {KeyFile: keyFile},
	}
	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			require.True(t, opts.Configured(), "the fixture must count as configured")
			cfg, err := ServerTLSConfig(opts)
			require.Error(t, err, "a partial configuration must never produce a listener")
			assert.Nil(t, cfg)

			creds, err := ServerCredentials(opts)
			require.Error(t, err)
			assert.Nil(t, creds, "there must be no path from a partial config to a serving listener")
		})
	}
}

// ---------------------------------------------------------------------------
// Full material
// ---------------------------------------------------------------------------

// TestFullMaterialRequiresAndVerifiesTheClientCertificate.
//
// RequireAndVerifyClientCert, not VerifyClientCertIfGiven. The weaker setting
// verifies a certificate when one is offered and admits the peer that offers none —
// which means the ATTACKER chooses whether to be authenticated.
func TestFullMaterialRequiresAndVerifiesTheClientCertificate(t *testing.T) {
	certFile, keyFile, caFile := writeCertFixtures(t)

	cfg, err := ServerTLSConfig(TLSOptions{CertFile: certFile, KeyFile: keyFile, ClientCAFile: caFile})
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.Equal(t, tls.RequireAndVerifyClientCert, cfg.ClientAuth,
		"an unverified peer must never reach an interceptor")
	assert.NotNil(t, cfg.ClientCAs, "verification needs the CA pool")
	assert.Len(t, cfg.Certificates, 1)

	creds, err := ServerCredentials(TLSOptions{CertFile: certFile, KeyFile: keyFile, ClientCAFile: caFile})
	require.NoError(t, err)
	assert.NotNil(t, creds)
}

// TestMinimumVersionIsTLS12. 1.0 and 1.1 have no AEAD suites and no modern curve
// support; they are not negotiable at all.
func TestMinimumVersionIsTLS12(t *testing.T) {
	certFile, keyFile, caFile := writeCertFixtures(t)
	cfg, err := ServerTLSConfig(TLSOptions{CertFile: certFile, KeyFile: keyFile, ClientCAFile: caFile})
	require.NoError(t, err)

	assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
	assert.Equal(t, uint16(tls.VersionTLS12), BaseTLSConfig().MinVersion,
		"both listeners must share one floor")
}

// TestTheCipherPolicyIsForwardSecretAndAEADOnly.
//
// Every suite offered must be BOTH:
//
//	ECDHE  forward secret. A static-RSA suite means recording the traffic today and
//	       decrypting it after the server key leaks — and this transport carries
//	       wrapped DEKs and setup credentials.
//	AEAD   GCM or ChaCha20-Poly1305. This excludes every CBC suite and with them the
//	       whole Lucky13 / padding-oracle family, which are the attacks that have
//	       actually broken TLS 1.2 deployments in practice.
func TestTheCipherPolicyIsForwardSecretAndAEADOnly(t *testing.T) {
	cfg := BaseTLSConfig()
	require.NotEmpty(t, cfg.CipherSuites, "an empty list would silently fall back to Go's defaults")

	// Build the set of suites Go considers acceptable, so this test describes the
	// policy rather than restating the literal.
	insecure := map[uint16]string{}
	for _, s := range tls.InsecureCipherSuites() {
		insecure[s.ID] = s.Name
	}
	byID := map[uint16]*tls.CipherSuite{}
	for _, s := range tls.CipherSuites() {
		byID[s.ID] = s
	}

	for _, id := range cfg.CipherSuites {
		name, isInsecure := insecure[id]
		assert.False(t, isInsecure, "suite %s is on Go's insecure list", name)

		suite, ok := byID[id]
		require.True(t, ok, "suite %#x is not a recognised secure suite", id)

		// TLS 1.2 only: setting CipherSuites has no effect on 1.3, whose three
		// suites are already AEAD and forward secret and are not configurable.
		assert.Contains(t, suite.SupportedVersions, uint16(tls.VersionTLS12),
			"suite %s is not a TLS 1.2 suite, so listing it is misleading", suite.Name)

		assert.Contains(t, suite.Name, "ECDHE", "suite %s is not forward secret", suite.Name)
		assert.True(t,
			containsAny(suite.Name, "GCM", "CHACHA20_POLY1305"),
			"suite %s is not AEAD; CBC suites carry the padding-oracle family", suite.Name)
		assert.NotContains(t, suite.Name, "_CBC_", "suite %s is a CBC suite", suite.Name)
		assert.NotContains(t, suite.Name, "RC4", "suite %s uses RC4", suite.Name)
		assert.NotContains(t, suite.Name, "3DES", "suite %s uses 3DES", suite.Name)
	}
}

// TestBothListenersShareOneCipherPolicy: two listeners in one process with different
// policies is a configuration nobody chose and nobody could explain.
func TestBothListenersShareOneCipherPolicy(t *testing.T) {
	certFile, keyFile, caFile := writeCertFixtures(t)
	grpcCfg, err := ServerTLSConfig(TLSOptions{CertFile: certFile, KeyFile: keyFile, ClientCAFile: caFile})
	require.NoError(t, err)

	assert.Equal(t, BaseTLSConfig().CipherSuites, grpcCfg.CipherSuites)
	assert.Equal(t, BaseTLSConfig().MinVersion, grpcCfg.MinVersion)
}

// ---------------------------------------------------------------------------
// Bad material is an error, never a degrade
// ---------------------------------------------------------------------------

// TestUnreadableOrInvalidMaterialIsAnErrorNeverAPlaintextFallback.
//
// There must be no branch that logs a warning and returns a plaintext listener. An
// unreadable certificate or a CA file with no PEM in it is an operator mistake, and
// the "helpful" fallback would silently reopen the control plane to anyone who can
// route to it.
func TestUnreadableOrInvalidMaterialIsAnErrorNeverAPlaintextFallback(t *testing.T) {
	certFile, keyFile, caFile := writeCertFixtures(t)
	dir := t.TempDir()

	emptyCA := filepath.Join(dir, "empty-ca.crt")
	require.NoError(t, os.WriteFile(emptyCA, []byte("not a certificate at all\n"), 0o600))

	cases := map[string]TLSOptions{
		"missing certificate file": {
			CertFile: filepath.Join(dir, "absent.crt"), KeyFile: keyFile, ClientCAFile: caFile,
		},
		"missing key file": {
			CertFile: certFile, KeyFile: filepath.Join(dir, "absent.key"), ClientCAFile: caFile,
		},
		"missing client CA file": {
			CertFile: certFile, KeyFile: keyFile, ClientCAFile: filepath.Join(dir, "absent-ca.crt"),
		},
		"client CA with no PEM block": {
			CertFile: certFile, KeyFile: keyFile, ClientCAFile: emptyCA,
		},
		"key that does not match the certificate": {
			CertFile: certFile, KeyFile: caFile, ClientCAFile: caFile,
		},
	}
	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			cfg, err := ServerTLSConfig(opts)
			require.Error(t, err, "bad material must fail the boot, not downgrade the listener")
			assert.Nil(t, cfg)
		})
	}
}

// TestTheErrorNamesTheFileSoAnOperatorCanActOnIt.
func TestTheErrorNamesTheFileSoAnOperatorCanActOnIt(t *testing.T) {
	certFile, keyFile, _ := writeCertFixtures(t)
	absentCA := filepath.Join(t.TempDir(), "absent-ca.crt")

	_, err := ServerTLSConfig(TLSOptions{CertFile: certFile, KeyFile: keyFile, ClientCAFile: absentCA})
	require.Error(t, err)
	assert.Contains(t, err.Error(), absentCA)
}

// TestPartialErrorsNameTheEnvironmentVariables, so the fix does not require reading
// the source.
func TestPartialErrorsNameTheEnvironmentVariables(t *testing.T) {
	certFile, _, _ := writeCertFixtures(t)
	_, err := ServerTLSConfig(TLSOptions{CertFile: certFile})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SECRET_GRPC_KEY_FILE")
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
	}
	return false
}
