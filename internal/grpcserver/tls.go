package grpcserver

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"google.golang.org/grpc/credentials"
)

// Transport security for the gRPC listener.
//
// ============================================================================
// WHY MUTUAL TLS HERE AND NOT A BEARER TOKEN
// ============================================================================
//
// This listener is not a second REST API. It is the SERVICE-TO-SERVICE surface,
// and it carries SetupService — the RPC through which maintainerd-core provisions
// this vault's identity and records itself as controller. A caller on that socket
// is claiming to be another maintainerd process.
//
// A bearer token ASSERTS that claim: it is a string, it travels in metadata, it is
// as trustworthy as every place it has ever been logged, cached, or copied into an
// environment variable. A verified client certificate DEMONSTRATES the claim: the
// peer had to possess a private key that a CA the operator controls has vouched
// for, and it had to prove that possession in the handshake. For a surface whose
// compromise means ownership of every secret in the store, the difference is not
// stylistic.
//
// This mirrors how maintainerd-auth guards its own control plane (auth
// internal/server/grpc.go), deliberately: the two services protect the same kind of
// surface and should be reasoned about the same way by the same operator.
//
// The interceptors are NOT a substitute. AuthUnaryInterceptor runs after the
// handshake — mutual TLS decides who is allowed to reach an interceptor at all.
//
// ============================================================================
// THE CIPHER POLICY, AND WHY IT IS WRITTEN OUT
// ============================================================================
//
// Go's default TLS 1.2 cipher list is chosen for the compatibility needs of the
// public web, which is not what this listener is. Its peers are other maintainerd
// services — modern Go and gRPC clients the operator deploys themselves — so there
// is no legacy client to accommodate and no reason to offer a suite that only a
// legacy client would pick. The list below is therefore narrowed to suites that
// are, without exception:
//
//   - FORWARD SECRET (ECDHE). A suite with static RSA key exchange means recording
//     the traffic today and decrypting it after the server key leaks. For a
//     transport carrying wrapped DEKs and setup credentials, that is the whole
//     threat.
//   - AEAD (GCM or ChaCha20-Poly1305). This excludes every CBC suite, and with
//     them the entire Lucky13 / padding-oracle family, which are the attacks that
//     have actually broken TLS 1.2 deployments in practice.
//
// TLS 1.3 suites are deliberately absent from the list: Go does not permit
// configuring them, because all three are already AEAD and forward-secret. Setting
// CipherSuites affects TLS 1.2 only, and TLS 1.3 is negotiated in preference to it
// whenever the peer supports it.
//
// MinVersion is TLS 1.2 rather than 1.3. 1.3 would be stricter and is what both
// ends will actually negotiate; 1.2 is the floor because an operator's sidecar,
// mesh proxy or load balancer may still terminate at 1.2, and refusing that would
// push them to disable TLS rather than upgrade it. 1.0 and 1.1 are not negotiable
// at all — they are the versions with no AEAD and no modern curve support.

// TLSOptions is the material for the gRPC listener. All three fields are present
// or all are empty; config.initTransportSecurity refuses anything in between, so
// this package does not re-litigate it.
type TLSOptions struct {
	// CertFile and KeyFile are this service's server certificate and private key.
	CertFile string
	KeyFile  string
	// ClientCAFile is the CA whose client certificates this listener accepts. Its
	// presence is what makes the listener mutual: it is the difference between
	// "encrypted" and "encrypted, and I know who you are".
	ClientCAFile string
}

// Configured reports whether any TLS material was supplied.
func (o TLSOptions) Configured() bool {
	return o.CertFile != "" || o.KeyFile != "" || o.ClientCAFile != ""
}

// tlsCipherSuites is the TLS 1.2 policy described above: ECDHE key exchange and
// AEAD bulk encryption, nothing else.
func tlsCipherSuites() []uint16 {
	return []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	}
}

// BaseTLSConfig is the version and cipher policy both listeners share.
//
// Exported so the HTTP listener applies the SAME policy rather than a second,
// drifting copy of it. Two listeners on one process with different minimum
// versions is a configuration nobody chose and nobody would be able to explain.
func BaseTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		CipherSuites: tlsCipherSuites(),
	}
}

// ServerTLSConfig builds the listener's TLS configuration.
//
// It returns (nil, nil) when no material is configured — the caller then serves in
// the clear, which config has already decided is permissible for this run (it is a
// boot error in core mode outside development, and a loud warning otherwise).
//
// EVERY FAILURE HERE IS AN ERROR, NEVER A DEGRADE. There is no branch that logs a
// warning and returns a plaintext listener: an unreadable certificate, a CA file
// with no PEM block in it, a mismatched key — each is an operator mistake, and the
// "helpful" fallback would silently reopen the control plane to anyone who can
// route to it. That is the exact downgrade this function exists to remove.
func ServerTLSConfig(opts TLSOptions) (*tls.Config, error) {
	if !opts.Configured() {
		return nil, nil
	}
	if opts.CertFile == "" || opts.KeyFile == "" {
		return nil, fmt.Errorf(
			"grpcserver: a server certificate and key are both required to serve TLS " +
				"(SECRET_GRPC_CERT_FILE, SECRET_GRPC_KEY_FILE)")
	}

	cert, err := tls.LoadX509KeyPair(opts.CertFile, opts.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("grpcserver: load the gRPC server certificate: %w", err)
	}

	cfg := BaseTLSConfig()
	cfg.Certificates = []tls.Certificate{cert}

	if opts.ClientCAFile == "" {
		// Reachable only if config's all-or-nothing check is ever relaxed. Refusing
		// beats serving server-only TLS on a surface documented as mutual: the
		// operator would believe peers are verified when any client is accepted.
		return nil, fmt.Errorf(
			"grpcserver: SECRET_GRPC_CA_FILE is required — without a client CA this listener " +
				"would accept any client, which is server TLS and not the mutual TLS this surface documents")
	}

	caPEM, err := os.ReadFile(opts.ClientCAFile)
	if err != nil {
		return nil, fmt.Errorf("grpcserver: read the gRPC client CA file %q: %w", opts.ClientCAFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf(
			"grpcserver: the gRPC client CA file %q contains no PEM certificate", opts.ClientCAFile)
	}
	cfg.ClientCAs = pool
	// RequireAndVerifyClientCert, not VerifyClientCertIfGiven. The weaker setting
	// verifies a certificate when one is offered and admits the peer that offers
	// none, which means an attacker chooses whether to be authenticated.
	cfg.ClientAuth = tls.RequireAndVerifyClientCert

	return cfg, nil
}

// ServerCredentials wraps ServerTLSConfig for grpc.Creds. It returns nil
// credentials when no material is configured, which the caller passes over.
func ServerCredentials(opts TLSOptions) (credentials.TransportCredentials, error) {
	cfg, err := ServerTLSConfig(opts)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}
	return credentials.NewTLS(cfg), nil
}
