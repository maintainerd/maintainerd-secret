// Package config loads and validates this service's configuration from the
// environment exactly once, at boot, into read-only package variables — the same
// shape core uses (core internal/platform/config).
//
// Everything that can fail is validated HERE rather than defaulted at the point of
// use. For a secret store that is not style: a mis-parsed retention count silently
// destroys version history, and a mis-read root key silently makes every stored
// value undecryptable. A service that will not work correctly must refuse to boot
// instead of discovering the problem on its first write.
package config

import (
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"

	kitconfig "github.com/maintainerd/kit/config"

	"github.com/maintainerd/secret/internal/crypto"
)

// EnvDevelopment is the one APP_ENV value in which reduced-safety behaviour (an
// ephemeral root key, an open setup window) is permitted.
const EnvDevelopment = crypto.EnvDevelopment

// The two worlds this service can run in — MAINTAINERD_MODE.
//
// THEY ARE NOT DEGREES OF THE SAME THING. They differ in WHO CREATES THIS
// SERVICE'S IDENTITY IN AUTH, and therefore in what has to be in the environment
// before the process can enforce anything.
//
//	ModeStandalone (the DEFAULT)
//	  There is no maintainerd-core anywhere. An operator already runs
//	  maintainerd-auth and, in Auth's own console, creates by hand: the secret
//	  SERVICE PRINCIPAL, its RESOURCE API and permissions, a BACKEND M2M CLIENT
//	  for this service, and a FRONTEND SPA CLIENT for its console. They then hand
//	  those credentials to this process as environment variables — issuer, JWKS
//	  URL, audience, SECRET_CLIENT_ID plus a secret or a private key, and
//	  SECRET_CONSOLE_CLIENT_ID. Nothing about core is involved or required, and
//	  this is a first-class supported way to run the service rather than a
//	  fallback. The REST setup wizard is the bootstrap path.
//
//	ModeCore
//	  maintainerd-core provisions all of the above through its setup gRPC surface
//	  and its templates, and records itself as this instance's controller. The
//	  REST setup wizard refuses, because two open first-run paths is a race whose
//	  winner owns the vault.
//
// IN NEITHER MODE DOES THIS SERVICE MANAGE AUTHENTICATION. Auth mints tokens and
// owns principals, roles and grants; this service only ENFORCES the permissions a
// token carries. The mode decides how it learns which Auth to trust, not whether
// it trusts one.
const (
	ModeStandalone = "standalone"
	ModeCore       = "core"
)

// KnownModes is the accepted MAINTAINERD_MODE set, in the order they are listed
// in an error message.
func KnownModes() []string { return []string{ModeStandalone, ModeCore} }

// Populated once by Init and read-only thereafter. Tests use t.Setenv and call
// Init again.
var (
	// --- app ---------------------------------------------------------------
	AppEnv   string // APP_ENV; "development" or "production". Default "development".
	LogLevel string // LOG_LEVEL; debug|info|warn|error. Default "info".
	GRPCAddr string // GRPC_PORT; default ":9092".
	HTTPAddr string // HTTP_PORT; default ":8092".

	// --- run mode ----------------------------------------------------------

	// Mode (MAINTAINERD_MODE) is standalone or core. DEFAULT: standalone —
	// see the ModeStandalone/ModeCore doc comment above for the full contrast.
	// The default is deliberate: a developer who has never adopted core must be
	// able to run auth + secret and nothing else, and the way to make that a
	// first-class path rather than a documented workaround is to make it what
	// happens when nobody sets the variable.
	Mode string

	// --- standalone credentials --------------------------------------------
	//
	// These are the backend M2M client an operator creates BY HAND in Auth's
	// console for this service, plus the SPA client they create for its console.
	// They are required in standalone mode outside development; in core mode they
	// are unused, because core provisions the equivalent through its templates.
	//
	// They are validated as a SET (see initRunMode), and the failure message names
	// exactly what to set. A secret store that boots with half its identity
	// configured is a secret store that fails on its first outbound call, at a
	// moment nobody is watching the log.

	// ClientID (SECRET_CLIENT_ID) is this service's own client id in Auth — the
	// backend, confidential, machine-to-machine client. It is what this service
	// presents when it needs a token OF ITS OWN (for example to call another
	// maintainerd service); it is NOT what verifies inbound tokens, which is
	// AuthJWKSURL/AuthIssuer/AuthAudience.
	ClientID string

	// ClientSecret (SECRET_CLIENT_SECRET) is that client's secret. NEVER LOG THIS
	// VALUE. Exactly one of it or ClientPrivateKeyFile is required.
	ClientSecret string

	// ClientPrivateKeyFile (SECRET_CLIENT_PRIVATE_KEY_FILE) is the path to a
	// private key for private_key_jwt client authentication — the stronger
	// alternative to a shared secret, because the credential never leaves the
	// host. Exactly one of it or ClientSecret is required.
	ClientPrivateKeyFile string

	// ConsoleClientID (SECRET_CONSOLE_CLIENT_ID) is the PUBLIC SPA client id the
	// console signs in with (authorization code + PKCE, no client secret). It is
	// not a credential — it is published in the browser by design — but it is
	// required, because a console pointed at a client id that does not exist sends
	// the operator to an authorize endpoint that answers with an error they cannot
	// act on.
	//
	// The service itself never USES this value: the console reads it from its own
	// runtime config (web/console/public/config.js). It is required and logged
	// here so that "the console cannot log in" is caught at boot, by the process
	// that already knows the rest of the identity wiring, rather than by an
	// operator reading a browser console.
	ConsoleClientID string

	// --- http server timeouts ----------------------------------------------
	//
	// Every one of these exists to bound a resource an anonymous peer can hold.
	// A server with no timeouts is a server whose connection table is a
	// denial-of-service target: a slowloris client opens sockets, sends one byte
	// a minute, and never has to authenticate to do it.

	// HTTPReadHeaderTimeout (HTTP_READ_HEADER_TIMEOUT, default 10s) bounds how
	// long a peer may take to send request headers. This is the slowloris bound
	// specifically, and it is separate from the body bound because a slow BODY
	// from an authenticated client is ordinary and a slow HEADER never is.
	HTTPReadHeaderTimeout time.Duration
	// HTTPReadTimeout (HTTP_READ_TIMEOUT, default 15s) bounds headers plus body.
	HTTPReadTimeout time.Duration
	// HTTPWriteTimeout (HTTP_WRITE_TIMEOUT, default 60s) bounds the response.
	HTTPWriteTimeout time.Duration
	// HTTPIdleTimeout (HTTP_IDLE_TIMEOUT, default 120s) bounds a keep-alive
	// connection between requests.
	HTTPIdleTimeout time.Duration
	// HTTPRequestTimeout (HTTP_REQUEST_TIMEOUT, default 30s) is the per-request
	// context deadline handlers inherit, so a query that will never finish stops
	// occupying a pool connection. It must be shorter than HTTPWriteTimeout, or
	// the write deadline fires first and the client sees a truncated response
	// instead of a 503.
	HTTPRequestTimeout time.Duration
	// HTTPMaxBodyBytes (HTTP_MAX_BODY_BYTES, default 4 MiB) caps a request body.
	// Enforced by http.MaxBytesReader on EVERY route, including the ones that
	// take no body, because the guard runs after the body has started arriving.
	HTTPMaxBodyBytes int64
	// ShutdownTimeout (SHUTDOWN_TIMEOUT, default 20s) bounds the drain on
	// SIGTERM: in-flight HTTP requests, in-flight RPCs, and the rotator's
	// current pass. A container runtime will send SIGKILL after its own grace
	// period, so this must be shorter than that (Kubernetes defaults to 30s).
	ShutdownTimeout time.Duration

	// --- database ----------------------------------------------------------
	DBHost               string // DB_HOST (required)
	DBPort               string // DB_PORT (required)
	DBUser               string // DB_USER (required)
	DBPassword           string // DB_PASSWORD (required; never logged)
	DBName               string // DB_NAME (required)
	DBSSLMode            string // DB_SSLMODE; default "disable". "disable" is refused in production.
	DBMaxOpenConns       int    // DB_MAX_OPEN_CONNS; default 25
	DBMaxIdleConns       int    // DB_MAX_IDLE_CONNS; default 5
	DBConnMaxLifetimeSec int    // DB_CONN_MAX_LIFETIME_SEC; default 300
	DBConnMaxIdleSec     int    // DB_CONN_MAX_IDLE_SEC; default 90
	DBStatementTimeoutMs int    // DB_STATEMENT_TIMEOUT_MS; default 30000

	// --- root of trust -----------------------------------------------------

	// RootKeyProvider (SECRET_ROOT_KEY_PROVIDER) selects where the KEK comes
	// from: env | file | aws_kms | gcp_kms | azure_kv. Default "env".
	RootKeyProvider string

	// RootKey (SECRET_ROOT_KEY) is the 32-byte AES-256 KEK for the "env"
	// provider, encoded as hex or base64. NEVER LOG THIS VALUE. Outside
	// development an empty or malformed value is a boot error — the prototype
	// generated a random key instead, which quietly made every secret written
	// before the restart undecryptable after it.
	RootKey string

	// RootKeyFile (SECRET_ROOT_KEY_FILE) is the sealed key file for the "file"
	// provider. The file must not be group- or world-readable.
	RootKeyFile string

	// --- store policy ------------------------------------------------------

	// KeepVersions (SECRET_KEEP_VERSIONS, default 10) is the service-wide default
	// number of versions retained per secret; a secret may override it. Pruning
	// never touches the current version. Must be >= 1: a value of 0 would mean
	// "keep nothing", and the only version there is to delete is the live one.
	KeepVersions int

	// RecoveryWindow (SECRET_RECOVERY_WINDOW, default 720h = 30d) is how long a
	// soft-deleted secret stays restorable before it may be destroyed. Matches the
	// AWS Secrets Manager model. Zero is permitted only in development: immediate
	// destruction in production turns a mistaken delete into permanent data loss.
	RecoveryWindow time.Duration

	// RewrapBatchSize (SECRET_REWRAP_BATCH_SIZE, default 500) is how many version
	// rows one root-key rewrap transaction re-wraps. Batching is what makes a
	// rotation resumable rather than one enormous transaction that cannot be
	// interrupted.
	RewrapBatchSize int

	// --- authorization -----------------------------------------------------

	// AuthJWKSURL (AUTH_JWKS_URL) is maintainerd-auth's public JWKS endpoint —
	// where the keys that verify a caller's bearer token are fetched from.
	//
	// This variable and the two below are a SET: all three or none. A JWKS URL
	// without an issuer and audience check accepts any token Auth ever signed,
	// including tokens minted for a completely different service, so a partial
	// configuration is treated as no configuration. With none of them set, the
	// API is DISABLED outside development (REST answers 503, gRPC serves health
	// only); in development it opens with a loud boot banner naming every guard
	// that is off.
	AuthJWKSURL string

	// AuthIssuer (AUTH_ISSUER) is the `iss` a token must carry.
	AuthIssuer string

	// AuthAudience (AUTH_AUDIENCE) is the `aud` a token must carry — this
	// service's resource-API identifier in Auth.
	AuthAudience string

	// --- setup -------------------------------------------------------------

	// SetupBootstrapToken (SETUP_BOOTSTRAP_TOKEN) gates BOTH setup surfaces: the
	// standalone REST wizard (X-Setup-Token header) and the controlled gRPC
	// SetupService (x-setup-token metadata). Empty leaves setup open, which is
	// refused outside development. Never log it.
	SetupBootstrapToken string

	// --- default scope (flat-key compatibility) ----------------------------

	// DefaultScopeAutocreate (SECRET_DEFAULT_SCOPE_AUTOCREATE, default true)
	// creates the default tenant/project/environment/root folder on boot if they
	// are absent. A standalone install needs somewhere to put a secret before
	// anyone has provisioned a hierarchy, and the flat-key RPCs address that
	// scope. Idempotent.
	DefaultScopeAutocreate bool

	DefaultTenant      string // SECRET_DEFAULT_TENANT; default "default"
	DefaultProject     string // SECRET_DEFAULT_PROJECT; default "default"
	DefaultEnvironment string // SECRET_DEFAULT_ENVIRONMENT; default "default"

	// --- references --------------------------------------------------------

	// ReferenceMaxDepth (SECRET_REFERENCE_MAX_DEPTH, default 8) bounds how many
	// hops a reference chain may be followed. It is a correctness bound, not a
	// tuning knob: the resolver detects cycles precisely, and this is the backstop
	// for a chain that is legitimately shaped but unreasonably long.
	ReferenceMaxDepth int

	// --- rotation ----------------------------------------------------------

	// RotationEnabled (SECRET_ROTATION_ENABLED, default true) runs the background
	// rotator. Turning it off preserves every policy — an operator disabling
	// rotation during an incident wants the schedules kept, not deleted.
	RotationEnabled bool

	// RotationInterval (SECRET_ROTATION_INTERVAL, default 5m) is how often the
	// rotator scans for due secrets. Rotation intervals are measured in days, so
	// this is two orders of magnitude finer than what it schedules.
	RotationInterval time.Duration

	// RotationBatch (SECRET_ROTATION_BATCH, default 50) bounds one pass, so a
	// thousand secrets coming due at once (a policy applied in bulk) does not
	// become a thousand writes in one tick.
	RotationBatch int

	// --- webhooks ----------------------------------------------------------

	// WebhooksEnabled (SECRET_WEBHOOKS_ENABLED, default true) delivers change and
	// rotation notifications. Deliveries never carry a value — only the MRN and
	// the new version — so a consumer knows to re-read.
	WebhooksEnabled bool

	// WebhookConcurrency (SECRET_WEBHOOK_CONCURRENCY, default 4) bounds parallel
	// deliveries for one event, so a slow endpoint cannot serialize the fan-out.
	WebhookConcurrency int

	// WebhookMaxTimeoutSeconds (SECRET_WEBHOOK_MAX_TIMEOUT_SEC, default 30) caps
	// the per-endpoint delivery timeout a caller may register. Deliveries run
	// inline on the write path, so this is also a bound on how long a secret
	// write can be held open by a tenant-supplied URL.
	WebhookMaxTimeoutSeconds int
	// WebhookMaxAttempts (SECRET_WEBHOOK_MAX_ATTEMPTS, default 10) caps the
	// per-endpoint retry budget, for the same reason.
	WebhookMaxAttempts int

	// --- request limits ----------------------------------------------------
	//
	// These are the server-side bounds on what one request may CONTAIN, as
	// opposed to how long it may take. They are surfaced to the API layer as an
	// api.Limits (see internal/api/limits.go), which the request DTOs read, so
	// REST and gRPC are bounded identically. Every one is clamped to a positive
	// value: setting a limit to 0 yields the default, never "no limit".

	// MaxSecretValueBytes (SECRET_MAX_VALUE_BYTES, default 65536) bounds one
	// secret's plaintext, measured on the DECODED bytes.
	MaxSecretValueBytes int
	// MaxBatchItems (SECRET_MAX_BATCH_ITEMS, default 100) bounds items in one
	// bulk get/put. It may be LOWERED but never raised past 100: an unbounded
	// batch get is a bulk-decryption endpoint.
	MaxBatchItems int
	// MaxTags (SECRET_MAX_TAGS, default 32) and MaxTagLength
	// (SECRET_MAX_TAG_LENGTH, default 64) bound a secret's tag list, which is
	// returned in every listing.
	MaxTags      int
	MaxTagLength int
	// MaxPageLimit (SECRET_MAX_PAGE_LIMIT, default 200) is the largest page a
	// client may request. A larger `limit` is REFUSED, not clamped.
	MaxPageLimit int
	// MaxDescriptionLength (SECRET_MAX_DESCRIPTION_LENGTH, default 500) bounds
	// free-text description fields.
	MaxDescriptionLength int

	// --- rate limiting -----------------------------------------------------
	//
	// The limiter is IN-PROCESS (see internal/platform/middleware/rate_limit.go).
	// This service has no Redis, so the counters are per-replica: with N
	// replicas behind a load balancer the effective ceiling is N times the
	// configured one. That is stated plainly rather than papered over — it is a
	// brute-force and burst dampener, not a distributed quota.

	// RateLimitEnabled (SECRET_RATE_LIMIT_ENABLED, default true) turns the
	// limiter off. Off is a supported configuration for a deployment that meters
	// at its ingress; it is not the default.
	RateLimitEnabled bool
	// RateLimitWindow (SECRET_RATE_LIMIT_WINDOW, default 1m) is the counting
	// window every budget below is measured over.
	RateLimitWindow time.Duration
	// RateLimitReveal (SECRET_RATE_LIMIT_REVEAL, default 300) budgets the reveal
	// surfaces per principal per window — the single reveal and the batch get.
	// It is the exfiltration bound: a compromised token with broad grants is
	// metered on how fast it can walk a store.
	RateLimitReveal int
	// RateLimitWrite (SECRET_RATE_LIMIT_WRITE, default 120) budgets every
	// mutating surface per principal per window.
	RateLimitWrite int
	// RateLimitSetup (SECRET_RATE_LIMIT_SETUP, default 10) budgets the
	// self-guarded setup surface per client IP per window. That surface compares
	// a bootstrap token, so it is the one brute-forceable path reachable without
	// an Auth-minted credential, and it is keyed by IP because there is no
	// principal yet.
	RateLimitSetup int

	// --- readiness ---------------------------------------------------------

	// ReadinessTimeout (SECRET_READINESS_TIMEOUT, default 2s) bounds the
	// dependency probes /readyz performs. A probe that hangs must report NOT
	// ready rather than hang with it: a readiness endpoint that never answers is
	// read as a failing pod by some orchestrators and a healthy one by others.
	ReadinessTimeout time.Duration
)

// Init reads, validates and freezes the configuration. It returns an error rather
// than exiting so the caller owns the process lifecycle.
func Init() error {
	base := kitconfig.LoadBase()
	AppEnv = base.AppEnv
	LogLevel = base.LogLevel
	GRPCAddr = kitconfig.NormalizePort(kitconfig.GetEnv("GRPC_PORT", "9092"))
	HTTPAddr = kitconfig.NormalizePort(kitconfig.GetEnv("HTTP_PORT", "8092"))

	var err error
	if err = initServerTimeouts(); err != nil {
		return err
	}
	if DBHost, err = required("DB_HOST"); err != nil {
		return err
	}
	if DBPort, err = required("DB_PORT"); err != nil {
		return err
	}
	if DBUser, err = required("DB_USER"); err != nil {
		return err
	}
	if DBPassword, err = required("DB_PASSWORD"); err != nil {
		return err
	}
	if DBName, err = required("DB_NAME"); err != nil {
		return err
	}
	DBSSLMode = kitconfig.GetEnv("DB_SSLMODE", "disable")
	if DBMaxOpenConns, err = positiveInt("DB_MAX_OPEN_CONNS", 25); err != nil {
		return err
	}
	if DBMaxIdleConns, err = positiveInt("DB_MAX_IDLE_CONNS", 5); err != nil {
		return err
	}
	if DBConnMaxLifetimeSec, err = positiveInt("DB_CONN_MAX_LIFETIME_SEC", 300); err != nil {
		return err
	}
	if DBConnMaxIdleSec, err = positiveInt("DB_CONN_MAX_IDLE_SEC", 90); err != nil {
		return err
	}
	if DBStatementTimeoutMs, err = positiveInt("DB_STATEMENT_TIMEOUT_MS", 30000); err != nil {
		return err
	}
	if DBMaxIdleConns > DBMaxOpenConns {
		return fmt.Errorf("config: DB_MAX_IDLE_CONNS (%d) exceeds DB_MAX_OPEN_CONNS (%d)", DBMaxIdleConns, DBMaxOpenConns)
	}

	// The accepted provider names come from crypto.KnownProviders rather than a
	// second list here: config validation and the factory registry must not be able
	// to disagree about what "aws_kms" means.
	RootKeyProvider = strings.ToLower(strings.TrimSpace(kitconfig.GetEnv("SECRET_ROOT_KEY_PROVIDER", crypto.ProviderEnv)))
	if !slices.Contains(crypto.KnownProviders(), RootKeyProvider) {
		return fmt.Errorf("config: SECRET_ROOT_KEY_PROVIDER %q is not one of %s",
			RootKeyProvider, strings.Join(crypto.KnownProviders(), ", "))
	}
	RootKey = kitconfig.GetEnv("SECRET_ROOT_KEY", "")
	RootKeyFile = kitconfig.GetEnv("SECRET_ROOT_KEY_FILE", "")
	if RootKeyProvider == crypto.ProviderFile && RootKeyFile == "" {
		return fmt.Errorf("config: SECRET_ROOT_KEY_FILE is required when SECRET_ROOT_KEY_PROVIDER=file")
	}

	if KeepVersions, err = positiveInt("SECRET_KEEP_VERSIONS", 10); err != nil {
		return err
	}
	if RewrapBatchSize, err = positiveInt("SECRET_REWRAP_BATCH_SIZE", 500); err != nil {
		return err
	}
	RecoveryWindow = kitconfig.GetDuration("SECRET_RECOVERY_WINDOW", 30*24*time.Hour)
	if RecoveryWindow < 0 {
		return fmt.Errorf("config: SECRET_RECOVERY_WINDOW must not be negative")
	}
	if RecoveryWindow == 0 && !IsDevelopment() {
		return fmt.Errorf("config: SECRET_RECOVERY_WINDOW of 0 makes every delete immediately unrecoverable; not allowed outside %s", EnvDevelopment)
	}

	AuthJWKSURL = strings.TrimSpace(kitconfig.GetEnv("AUTH_JWKS_URL", ""))
	AuthIssuer = strings.TrimSpace(kitconfig.GetEnv("AUTH_ISSUER", ""))
	AuthAudience = strings.TrimSpace(kitconfig.GetEnv("AUTH_AUDIENCE", ""))
	// A PARTIAL auth configuration is a boot error rather than a silent
	// degradation. Setting only AUTH_JWKS_URL is the mistake that matters: it looks
	// configured, and it accepts any token Auth ever signed. Refusing here means an
	// operator who set two of three learns it now instead of after an incident.
	if authSet := boolCount(AuthJWKSURL != "", AuthIssuer != "", AuthAudience != ""); authSet != 0 && authSet != 3 {
		return fmt.Errorf(
			"config: AUTH_JWKS_URL, AUTH_ISSUER and AUTH_AUDIENCE must be set together or not at all; " +
				"a JWKS URL without an issuer and audience check accepts tokens minted for other services")
	}
	// The run mode is resolved AFTER the auth variables, because what it requires is
	// expressed in terms of them.
	if err = initRunMode(); err != nil {
		return err
	}

	if ReferenceMaxDepth, err = positiveInt("SECRET_REFERENCE_MAX_DEPTH", 8); err != nil {
		return err
	}
	if RotationEnabled, err = boolEnv("SECRET_ROTATION_ENABLED", true); err != nil {
		return err
	}
	RotationInterval = kitconfig.GetDuration("SECRET_ROTATION_INTERVAL", 5*time.Minute)
	if RotationInterval <= 0 {
		return fmt.Errorf("config: SECRET_ROTATION_INTERVAL must be positive")
	}
	if RotationBatch, err = positiveInt("SECRET_ROTATION_BATCH", 50); err != nil {
		return err
	}
	if WebhooksEnabled, err = boolEnv("SECRET_WEBHOOKS_ENABLED", true); err != nil {
		return err
	}
	if WebhookConcurrency, err = positiveInt("SECRET_WEBHOOK_CONCURRENCY", 4); err != nil {
		return err
	}
	if WebhookMaxTimeoutSeconds, err = positiveInt("SECRET_WEBHOOK_MAX_TIMEOUT_SEC", 30); err != nil {
		return err
	}
	if WebhookMaxAttempts, err = positiveInt("SECRET_WEBHOOK_MAX_ATTEMPTS", 10); err != nil {
		return err
	}
	if err = initRequestLimits(); err != nil {
		return err
	}
	if err = initRateLimits(); err != nil {
		return err
	}

	SetupBootstrapToken = kitconfig.GetEnv("SETUP_BOOTSTRAP_TOKEN", "")
	if SetupBootstrapToken == "" && !IsDevelopment() {
		return fmt.Errorf("config: SETUP_BOOTSTRAP_TOKEN is required outside %s — an empty token leaves the one-time setup window open to anyone", EnvDevelopment)
	}

	if DefaultScopeAutocreate, err = boolEnv("SECRET_DEFAULT_SCOPE_AUTOCREATE", true); err != nil {
		return err
	}
	DefaultTenant = kitconfig.GetEnv("SECRET_DEFAULT_TENANT", "default")
	DefaultProject = kitconfig.GetEnv("SECRET_DEFAULT_PROJECT", "default")
	DefaultEnvironment = kitconfig.GetEnv("SECRET_DEFAULT_ENVIRONMENT", "default")

	return nil
}

// initRunMode reads MAINTAINERD_MODE and validates what that mode requires.
//
// THE WHOLE POINT IS THAT STANDALONE IS NOT A DEGRADED MODE. An operator running
// auth + secret with no core at all has done real work by hand in Auth's console
// — created the service principal, its resource API and permissions, a backend
// M2M client and a frontend SPA client — and every one of those produces a value
// this process needs. Missing one is a MISTAKE, not a configuration choice, so
// outside development it is a boot error that names exactly what to set rather
// than a service that starts and answers 503 to everything until somebody reads
// the guard banner.
//
// In DEVELOPMENT the same absence degrades to the dev-open guard with its loud
// banner, unchanged: a laptop instance with no Auth running is the case the
// dev-open ladder exists for.
//
// In CORE MODE none of it is required here, because core provisions all of it
// through its setup gRPC surface and then supplies the values; the pre-core
// window is exactly the state ModeUnavailable was designed to hold, and it is
// warned about rather than refused.
func initRunMode() error {
	Mode = strings.ToLower(strings.TrimSpace(kitconfig.GetEnv("MAINTAINERD_MODE", ModeStandalone)))
	if !slices.Contains(KnownModes(), Mode) {
		return fmt.Errorf("config: MAINTAINERD_MODE %q is not one of %s",
			Mode, strings.Join(KnownModes(), ", "))
	}

	ClientID = strings.TrimSpace(kitconfig.GetEnv("SECRET_CLIENT_ID", ""))
	ClientSecret = kitconfig.GetEnv("SECRET_CLIENT_SECRET", "")
	ClientPrivateKeyFile = strings.TrimSpace(kitconfig.GetEnv("SECRET_CLIENT_PRIVATE_KEY_FILE", ""))
	ConsoleClientID = strings.TrimSpace(kitconfig.GetEnv("SECRET_CONSOLE_CLIENT_ID", ""))

	// Two client credentials is not "extra safety", it is an ambiguity: the two
	// authenticate this service to Auth in different ways, and a process that holds
	// both will use one of them while the operator maintains the other.
	if ClientSecret != "" && ClientPrivateKeyFile != "" {
		return fmt.Errorf("config: set SECRET_CLIENT_SECRET or SECRET_CLIENT_PRIVATE_KEY_FILE, not both — " +
			"they are two ways to authenticate the same client and only one is used")
	}

	if Mode == ModeCore {
		if AuthJWKSURL == "" {
			slog.Warn("config: MAINTAINERD_MODE=core and no auth configuration yet — "+
				"the API answers 503 and gRPC serves health only until core provisions this instance",
				"missing", "AUTH_JWKS_URL, AUTH_ISSUER, AUTH_AUDIENCE")
		}
		return nil
	}

	// --- standalone ---------------------------------------------------------
	missing := standaloneMissing()
	if len(missing) == 0 {
		return nil
	}
	if IsDevelopment() {
		slog.Warn("config: MAINTAINERD_MODE=standalone with an incomplete identity configuration — "+
			"permitted in "+EnvDevelopment+" only; the guard will open in development mode",
			"missing", strings.Join(missing, ", "))
		return nil
	}
	return fmt.Errorf(
		"config: MAINTAINERD_MODE=%s requires %s. Create them in maintainerd-auth's console "+
			"(the secret service principal, its resource API and permissions, a backend m2m client "+
			"and a frontend SPA client for the console), then set them here. "+
			"Set MAINTAINERD_MODE=%s if maintainerd-core provisions this instance instead",
		ModeStandalone, strings.Join(missing, ", "), ModeCore)
}

// standaloneMissing lists the variables standalone mode needs and does not have,
// in the order an operator would set them. Naming every one at once matters: a
// message that reports them one boot at a time turns a five-minute setup into
// five restarts.
func standaloneMissing() []string {
	var missing []string
	if AuthIssuer == "" {
		missing = append(missing, "AUTH_ISSUER")
	}
	if AuthJWKSURL == "" {
		missing = append(missing, "AUTH_JWKS_URL")
	}
	if AuthAudience == "" {
		missing = append(missing, "AUTH_AUDIENCE")
	}
	if ClientID == "" {
		missing = append(missing, "SECRET_CLIENT_ID")
	}
	if ClientSecret == "" && ClientPrivateKeyFile == "" {
		missing = append(missing, "SECRET_CLIENT_SECRET or SECRET_CLIENT_PRIVATE_KEY_FILE")
	}
	if ConsoleClientID == "" {
		missing = append(missing, "SECRET_CONSOLE_CLIENT_ID")
	}
	return missing
}

// IsStandalone reports whether this instance owns its own identity wiring.
func IsStandalone() bool { return Mode == ModeStandalone }

// DescribeMode renders the run mode for a boot log line.
func DescribeMode() string {
	switch Mode {
	case ModeCore:
		return ModeCore + " (maintainerd-core provisions this instance through the gRPC SetupService)"
	default:
		return ModeStandalone + " (an operator provisions this instance; auth is configured by environment)"
	}
}

// initServerTimeouts reads the HTTP server and shutdown bounds.
//
// The one CROSS-CHECK is deliberate: a per-request deadline longer than the write
// timeout is a configuration that cannot work, because the write deadline fires first
// and the client sees a truncated response rather than the 503 the deadline was meant
// to produce. Refusing at boot means the operator learns it now.
func initServerTimeouts() error {
	var err error
	if HTTPReadHeaderTimeout, err = positiveDuration("HTTP_READ_HEADER_TIMEOUT", 10*time.Second); err != nil {
		return err
	}
	if HTTPReadTimeout, err = positiveDuration("HTTP_READ_TIMEOUT", 15*time.Second); err != nil {
		return err
	}
	if HTTPWriteTimeout, err = positiveDuration("HTTP_WRITE_TIMEOUT", 60*time.Second); err != nil {
		return err
	}
	if HTTPIdleTimeout, err = positiveDuration("HTTP_IDLE_TIMEOUT", 120*time.Second); err != nil {
		return err
	}
	if HTTPRequestTimeout, err = positiveDuration("HTTP_REQUEST_TIMEOUT", 30*time.Second); err != nil {
		return err
	}
	if ShutdownTimeout, err = positiveDuration("SHUTDOWN_TIMEOUT", 20*time.Second); err != nil {
		return err
	}
	if ReadinessTimeout, err = positiveDuration("SECRET_READINESS_TIMEOUT", 2*time.Second); err != nil {
		return err
	}
	if HTTPRequestTimeout >= HTTPWriteTimeout {
		return fmt.Errorf(
			"config: HTTP_REQUEST_TIMEOUT (%s) must be shorter than HTTP_WRITE_TIMEOUT (%s), "+
				"or the write deadline fires first and a timed-out request returns a truncated response instead of an error",
			HTTPRequestTimeout, HTTPWriteTimeout)
	}
	if HTTPMaxBodyBytes, err = positiveInt64("HTTP_MAX_BODY_BYTES", 4<<20); err != nil {
		return err
	}
	return nil
}

// initRequestLimits reads the bounds on request CONTENT.
func initRequestLimits() error {
	var err error
	if MaxSecretValueBytes, err = positiveInt("SECRET_MAX_VALUE_BYTES", 64<<10); err != nil {
		return err
	}
	if MaxBatchItems, err = positiveInt("SECRET_MAX_BATCH_ITEMS", 100); err != nil {
		return err
	}
	if MaxTags, err = positiveInt("SECRET_MAX_TAGS", 32); err != nil {
		return err
	}
	if MaxTagLength, err = positiveInt("SECRET_MAX_TAG_LENGTH", 64); err != nil {
		return err
	}
	if MaxPageLimit, err = positiveInt("SECRET_MAX_PAGE_LIMIT", 200); err != nil {
		return err
	}
	if MaxDescriptionLength, err = positiveInt("SECRET_MAX_DESCRIPTION_LENGTH", 500); err != nil {
		return err
	}
	// A value bound larger than the body bound is not wrong, but it is a lie: the
	// body reader refuses first, and the operator who raised one and not the other
	// would be debugging a 413 while reading a 64 KiB limit.
	if int64(MaxSecretValueBytes) >= HTTPMaxBodyBytes {
		return fmt.Errorf(
			"config: SECRET_MAX_VALUE_BYTES (%d) must be smaller than HTTP_MAX_BODY_BYTES (%d); "+
				"base64 on the REST surface makes a value roughly a third larger on the wire",
			MaxSecretValueBytes, HTTPMaxBodyBytes)
	}
	return nil
}

// initRateLimits reads the in-process limiter's budgets.
func initRateLimits() error {
	var err error
	if RateLimitEnabled, err = boolEnv("SECRET_RATE_LIMIT_ENABLED", true); err != nil {
		return err
	}
	if RateLimitWindow, err = positiveDuration("SECRET_RATE_LIMIT_WINDOW", time.Minute); err != nil {
		return err
	}
	if RateLimitReveal, err = positiveInt("SECRET_RATE_LIMIT_REVEAL", 300); err != nil {
		return err
	}
	if RateLimitWrite, err = positiveInt("SECRET_RATE_LIMIT_WRITE", 120); err != nil {
		return err
	}
	if RateLimitSetup, err = positiveInt("SECRET_RATE_LIMIT_SETUP", 10); err != nil {
		return err
	}
	return nil
}

// IsDevelopment reports whether reduced-safety behaviour is permitted. Written as
// an exact match against the one sanctioned value, so that a typo like "dev" or
// "Development" reads as production and fails closed.
func IsDevelopment() bool { return AppEnv == EnvDevelopment }

// GetDBConnectionString builds the pgx keyword/value DSN.
//
// The `options` value contains a space, so it must be single-quoted or the driver
// splits it and Postgres receives a bare `-c` (this bug is documented in core's
// identical helper).
func GetDBConnectionString() string {
	return fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s options='-c statement_timeout=%d'",
		DBHost, DBPort, DBUser, DBPassword, DBName, DBSSLMode, DBStatementTimeoutMs,
	)
}

func required(key string) (string, error) {
	v := kitconfig.GetEnv(key, "")
	if v == "" {
		return "", fmt.Errorf("config: %s is required", key)
	}
	return v, nil
}

// positiveInt parses an int env var and REFUSES a malformed value rather than
// falling back to the default. A typo in a retention or pool setting that silently
// becomes the default is a configuration change nobody made.
func positiveInt(key string, def int) (int, error) {
	raw := kitconfig.GetEnv(key, "")
	if raw == "" {
		return def, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("config: %s must be an integer, got %q", key, raw)
	}
	if n < 1 {
		return 0, fmt.Errorf("config: %s must be at least 1, got %d", key, n)
	}
	return n, nil
}

// positiveInt64 is positiveInt for a byte count, which can legitimately exceed an
// int32 on a 32-bit build.
func positiveInt64(key string, def int64) (int64, error) {
	raw := kitconfig.GetEnv(key, "")
	if raw == "" {
		return def, nil
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("config: %s must be an integer, got %q", key, raw)
	}
	if n < 1 {
		return 0, fmt.Errorf("config: %s must be at least 1, got %d", key, n)
	}
	return n, nil
}

// positiveDuration parses a duration env var and REFUSES a malformed or non-positive
// value rather than falling back to the default. A timeout that silently becomes the
// default is a bound nobody chose; a timeout of zero is no bound at all, which for
// every variable that uses this helper means an unbounded resource an anonymous peer
// can hold.
func positiveDuration(key string, def time.Duration) (time.Duration, error) {
	raw := strings.TrimSpace(kitconfig.GetEnv(key, ""))
	if raw == "" {
		return def, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("config: %s must be a duration such as \"30s\", got %q", key, raw)
	}
	if d <= 0 {
		return 0, fmt.Errorf("config: %s must be positive, got %s", key, d)
	}
	return d, nil
}

// boolCount counts how many of the flags are set, used for the all-or-nothing
// variable groups.
func boolCount(flags ...bool) int {
	n := 0
	for _, f := range flags {
		if f {
			n++
		}
	}
	return n
}

func boolEnv(key string, def bool) (bool, error) {
	raw := kitconfig.GetEnv(key, "")
	if raw == "" {
		return def, nil
	}
	b, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("config: %s must be a boolean, got %q", key, raw)
	}
	return b, nil
}
