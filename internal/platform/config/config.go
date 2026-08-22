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
	"os"
	"path/filepath"
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

// AppVersion is this build's version, stamped at LINK TIME:
//
//	go build -ldflags "-X github.com/maintainerd/secret/internal/platform/config.AppVersion=1.4.0"
//
// IT IS NOT READ FROM THE ENVIRONMENT, deliberately. A version an operator can set
// is a version that can disagree with the binary, and the one job of this string is
// to answer "what is actually running" — on the boot line, in the capability
// endpoint, and in the console's footer. The release image passes its own tag (see
// the Dockerfile), so the value the OCI label advertises and the value the service
// reports are the same one.
//
// "dev" is the honest answer for a `go build` with no ldflags, which is every local
// build and every test.
var AppVersion = "dev"

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

	// --- transport security ------------------------------------------------
	//
	// TWO LISTENERS, TWO DIFFERENT POSTURES, and the asymmetry is deliberate
	// rather than an oversight:
	//
	//	gRPC  is the SERVICE-TO-SERVICE and CONTROL-PLANE surface. It carries
	//	      SetupService, through which maintainerd-core provisions this vault.
	//	      A peer on that socket is claiming to be another maintainerd service,
	//	      and a bearer token only ASSERTS that — a verified client certificate
	//	      DEMONSTRATES it. So this listener supports mutual TLS, and in
	//	      core-attached mode outside development it REQUIRES it.
	//	HTTP  is the REST API and the console's origin, and in every sanctioned
	//	      deployment it sits behind a terminating proxy (nginx in the dev
	//	      stack, an ingress in production). Direct TLS is therefore OPTIONAL —
	//	      offered for the operator who serves it directly, not mandated for
	//	      the majority who do not.
	//
	// Each group is ALL-OR-NOTHING. A partial set is a boot error, for the same
	// reason a partial AUTH_* set is: half a TLS configuration looks configured
	// and serves plaintext.

	// GRPCTLSCertFile (SECRET_GRPC_CERT_FILE) and GRPCTLSKeyFile
	// (SECRET_GRPC_KEY_FILE) are this service's server certificate and private
	// key for the gRPC listener.
	GRPCTLSCertFile string
	GRPCTLSKeyFile  string

	// GRPCClientCAFile (SECRET_GRPC_CA_FILE) is the CA that issues the client
	// certificates this listener will accept. Its presence is what turns server
	// TLS into MUTUAL TLS: with it, the listener is configured
	// tls.RequireAndVerifyClientCert, so an unverified peer never reaches an
	// interceptor.
	GRPCClientCAFile string

	// HTTPTLSCertFile (SECRET_TLS_CERT_FILE) and HTTPTLSKeyFile
	// (SECRET_TLS_KEY_FILE) serve the REST surface over TLS directly, for a
	// deployment with no terminating proxy in front of it. Optional; both or
	// neither.
	HTTPTLSCertFile string
	HTTPTLSKeyFile  string

	// --- multi-replica coordination ----------------------------------------

	// LeaderElectionEnabled (SECRET_LEADER_ELECTION_ENABLED, default true) gates
	// the background workers on a PostgreSQL advisory lock so exactly one replica
	// runs them (see internal/leader).
	//
	// DEFAULT TRUE, because the failure it prevents is invisible. Two replicas
	// both running the rotator rotate the same secret twice — two versions, two
	// webhook fan-outs, and a consumer holding a value that is already
	// superseded — and the service looks perfectly healthy while doing it. An
	// operator should have to opt OUT of correctness, not in.
	LeaderElectionEnabled bool

	// RateLimitShared (SECRET_RATE_LIMIT_SHARED, default true) meters the rate
	// limiter's budgets through PostgreSQL so they span the replica set instead
	// of being per-process. Same reasoning as above: a per-process budget on N
	// replicas is N times the configured ceiling, and the reveal ceiling is the
	// exfiltration bound on a compromised token.
	RateLimitShared bool

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

	// --- root of trust: cloud KMS ------------------------------------------
	//
	// Only the variables belonging to the SELECTED provider are required, and the
	// requirement is checked AT BOOT (initRootKeyKMS). That is the whole point of
	// having them here: selecting aws_kms without a key id must be a refusal to
	// start, not a failure on the first Wrap after the service is already serving.
	// None of these values is a secret — a key ARN, a resource name and a vault URL
	// are all safe to log, and the boot line prints them next to the kek_id so a
	// fingerprint in root_keys can be traced back to a key in a cloud console.

	// KMSTimeout (SECRET_KMS_TIMEOUT, default 10s) bounds ONE Wrap or Unwrap
	// round-trip, for whichever cloud provider is selected. It exists because the
	// root key sits on the read and write path of every secret: an unbounded KMS
	// call would hold a request goroutine for as long as the network allowed.
	KMSTimeout time.Duration

	// KMSAWSKeyID (SECRET_KMS_AWS_KEY_ID) is the key ARN, key id, alias name
	// ("alias/...") or alias ARN of a symmetric ENCRYPT_DECRYPT KMS key.
	KMSAWSKeyID string
	// KMSAWSRegion (SECRET_KMS_AWS_REGION) is the region the key lives in. It
	// falls back to AWS_REGION and then AWS_DEFAULT_REGION, but it is REQUIRED one
	// way or another rather than left to the SDK's resolution, because the region
	// participates in the kek_id: an alias resolved ambiently on one host and
	// explicitly on another would produce two ids for one key.
	KMSAWSRegion string

	// KMSGCPKeyName (SECRET_KMS_GCP_KEY_NAME) is the fully qualified CryptoKey
	// resource name, projects/{p}/locations/{l}/keyRings/{r}/cryptoKeys/{k}.
	// Validated for shape at boot, including a refusal of a
	// /cryptoKeyVersions/... suffix — Encrypt accepts one and Decrypt does not, so
	// a pinned version would wrap happily and fail every unwrap.
	KMSGCPKeyName string

	// KMSAzureVaultURL (SECRET_KMS_AZURE_VAULT_URL) is the vault base URL,
	// https://{vault}.vault.azure.net/. Must be https.
	KMSAzureVaultURL string
	// KMSAzureKeyName (SECRET_KMS_AZURE_KEY_NAME) is the RSA key's name in that
	// vault.
	KMSAzureKeyName string
	// KMSAzureKeyVersion (SECRET_KMS_AZURE_KEY_VERSION) optionally pins a key
	// version. Empty — the normal choice — means the vault's current version.
	KMSAzureKeyVersion string

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

	// --- dynamic-credential reaper -----------------------------------------

	// DynamicReaperEnabled (SECRET_DYNAMIC_REAPER_ENABLED, default true) revokes
	// dynamic credentials whose leases have expired.
	//
	// WITHOUT IT A DYNAMIC CREDENTIAL'S TTL IS A COMMENT. Issuing one creates a real
	// PostgreSQL role; the lease row records when it must stop existing, but a row
	// expiring does not drop a role — this sweep is the only thing that does. An
	// operator who turns it off is accepting that issued credentials outlive their
	// leases, and the boot log says so in those words. It is a real switch because a
	// reaper hammering an unreachable target database during an incident is a
	// legitimate thing to stop; it is not one to leave off.
	DynamicReaperEnabled bool

	// DynamicReaperInterval (SECRET_DYNAMIC_REAPER_INTERVAL, default 1m) is how often
	// the sweep runs. Finer than the rotator's because the overdue window here is the
	// window in which a credential nobody is entitled to still works.
	DynamicReaperInterval time.Duration

	// DynamicReaperBatch (SECRET_DYNAMIC_REAPER_BATCH, default 100) bounds one pass,
	// so a mass expiry does not become an unbounded run of DDL against a target
	// database in a single tick.
	DynamicReaperBatch int

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

	// --- webhook re-drive --------------------------------------------------
	//
	// The bounds above govern the INLINE attempt sequence, which runs on the write
	// path and is therefore measured in milliseconds. These govern the DURABLE loop
	// that owns anything the inline attempt could not deliver (internal/webhook,
	// redrive.go) — the reason a receiver that was redeploying still gets told.
	//
	// The two are separate budgets on purpose: an operator raising the inline retry
	// count is buying write latency, and an operator raising the durable one is
	// buying patience with a broken receiver. Neither number should move because of
	// the other.

	// WebhookRedriveEnabled (SECRET_WEBHOOK_REDRIVE_ENABLED, default true) runs the
	// durable retry loop. Turning it off preserves the backlog — the rows keep their
	// 'retrying' status — so delivery resumes when it is turned back on. With it off,
	// a delivery that exhausts its inline attempts is recorded 'failed' and nothing
	// retries it, which is the behaviour before re-drive existed.
	WebhookRedriveEnabled bool
	// WebhookRedriveInterval (SECRET_WEBHOOK_REDRIVE_INTERVAL, default 30s) is how
	// often the worker looks for due deliveries. Much finer than the backoff schedule,
	// so a delivery is picked up within a tick of becoming due.
	WebhookRedriveInterval time.Duration
	// WebhookRedriveBatch (SECRET_WEBHOOK_REDRIVE_BATCH, default 50) bounds one pass,
	// so draining an hour's backlog does not become a self-inflicted flood.
	WebhookRedriveBatch int
	// WebhookRedriveMaxAttempts (SECRET_WEBHOOK_REDRIVE_MAX_ATTEMPTS, default 10) is
	// the durable budget in WORKER attempts. Past it the delivery is marked
	// permanently failed — the row an operator greps for — because retrying forever
	// against an endpoint nobody owns is a queue that never drains.
	WebhookRedriveMaxAttempts int
	// WebhookRedriveBaseBackoff (SECRET_WEBHOOK_REDRIVE_BASE_BACKOFF, default 30s) is
	// the first delay; it doubles each attempt up to WebhookRedriveMaxBackoff
	// (SECRET_WEBHOOK_REDRIVE_MAX_BACKOFF, default 1h). On the defaults the schedule
	// spans roughly four hours, which covers a long deploy or an expired certificate
	// somebody has to be paged about.
	WebhookRedriveBaseBackoff time.Duration
	WebhookRedriveMaxBackoff  time.Duration

	// --- console ------------------------------------------------------------

	// ConsoleDir (CONSOLE_DIR) is the directory holding the console's built SPA.
	// EMPTY DISABLES IT, which is the default and is what a development instance
	// wants: the console runs under vite there, and this process serves only the API.
	//
	// The release image bakes the built SPA at /srv/console and sets this variable, so
	// the image serves its own UI on the REST port with no nginx and no second
	// container. Runtime directory rather than go:embed — see internal/httpapi
	// (console.go) for why that choice, and for the traversal-safe resolver.
	//
	// A path that is set but does not contain a readable index.html is a BOOT ERROR.
	// The alternative is a service that starts and answers 404 for every console
	// route, which an operator diagnoses in a browser instead of in a log line.
	ConsoleDir string

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
	// The budgets below are SHARED ACROSS REPLICAS by default, metered through
	// PostgreSQL (see internal/platform/middleware/rate_limit.go for the
	// reservation protocol and its trade-off). So each number is a fleet-wide
	// ceiling, not a per-process one.
	//
	// Two configurations make them per-process again, and both say so at boot:
	// SECRET_RATE_LIMIT_SHARED=false, and a database the shared store cannot
	// reach — which degrades to per-replica metering rather than failing open or
	// taking the service down with it.

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
	if err = initRootKeyKMS(); err != nil {
		return err
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
	// Transport security is resolved AFTER the run mode, because whether the gRPC
	// listener may serve in the clear depends on whether it is a control plane.
	if err = initTransportSecurity(); err != nil {
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
	if DynamicReaperEnabled, err = boolEnv("SECRET_DYNAMIC_REAPER_ENABLED", true); err != nil {
		return err
	}
	DynamicReaperInterval = kitconfig.GetDuration("SECRET_DYNAMIC_REAPER_INTERVAL", time.Minute)
	if DynamicReaperInterval <= 0 {
		return fmt.Errorf("config: SECRET_DYNAMIC_REAPER_INTERVAL must be positive")
	}
	if DynamicReaperBatch, err = positiveInt("SECRET_DYNAMIC_REAPER_BATCH", 100); err != nil {
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
	if err = initWebhookRedrive(); err != nil {
		return err
	}
	if err = initConsole(); err != nil {
		return err
	}
	if err = initRequestLimits(); err != nil {
		return err
	}
	if err = initRateLimits(); err != nil {
		return err
	}
	// Coordination is resolved LAST of the groups it talks about: it warns on
	// combinations of the rate-limit switches, so those must already be read.
	if err = initCoordination(); err != nil {
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

// initRootKeyKMS reads the cloud-KMS settings and validates the ones the SELECTED
// provider needs.
//
// THE VALIDATION IS THE POINT, not the reading. A cloud provider selected without its
// key coordinates would otherwise fail on the first Wrap — which is to say, after the
// process has started, passed its health check, joined the load balancer, and accepted
// a write. That is the same class of deferred failure as the prototype's generated
// root key: invisible until it is expensive. So a missing setting is a boot error, and
// it names every missing variable at once rather than one per restart.
//
// Settings belonging to the OTHER providers are read and left alone. An operator
// migrating from aws_kms to gcp_kms keeps both sets in place through the rewrap, and
// validating the inactive one would make that impossible.
func initRootKeyKMS() error {
	var err error
	if KMSTimeout, err = positiveDuration("SECRET_KMS_TIMEOUT", crypto.DefaultKMSTimeout); err != nil {
		return err
	}

	KMSAWSKeyID = strings.TrimSpace(kitconfig.GetEnv("SECRET_KMS_AWS_KEY_ID", ""))
	KMSAWSRegion = strings.TrimSpace(kitconfig.GetEnv("SECRET_KMS_AWS_REGION", ""))
	// The AWS SDK's own variables are accepted as a fallback because a workload that
	// already sets them for other AWS calls should not have to set a second name for
	// the same fact.
	for _, fallback := range []string{"AWS_REGION", "AWS_DEFAULT_REGION"} {
		if KMSAWSRegion != "" {
			break
		}
		KMSAWSRegion = strings.TrimSpace(kitconfig.GetEnv(fallback, ""))
	}

	KMSGCPKeyName = strings.TrimSpace(kitconfig.GetEnv("SECRET_KMS_GCP_KEY_NAME", ""))

	KMSAzureVaultURL = strings.TrimSpace(kitconfig.GetEnv("SECRET_KMS_AZURE_VAULT_URL", ""))
	KMSAzureKeyName = strings.TrimSpace(kitconfig.GetEnv("SECRET_KMS_AZURE_KEY_NAME", ""))
	KMSAzureKeyVersion = strings.TrimSpace(kitconfig.GetEnv("SECRET_KMS_AZURE_KEY_VERSION", ""))

	if missing := kmsMissing(); len(missing) > 0 {
		return fmt.Errorf(
			"config: SECRET_ROOT_KEY_PROVIDER=%s requires %s. "+
				"Selecting a cloud root key without its coordinates would fail on the first write rather than at boot, so this is refused here",
			RootKeyProvider, strings.Join(missing, ", "))
	}

	// Shape checks, only for the selected provider. Both catch a configuration that
	// would authenticate, boot, and then misbehave — which is worse than one that
	// does not start. The rules live in the crypto package so the validator and the
	// factory cannot disagree about them.
	switch RootKeyProvider {
	case crypto.ProviderGCPKMS:
		if err := crypto.ValidateGCPKeyName(KMSGCPKeyName); err != nil {
			return fmt.Errorf("config: %w", err)
		}
	case crypto.ProviderAzureKV:
		if err := crypto.ValidateAzureVaultURL(KMSAzureVaultURL); err != nil {
			return fmt.Errorf("config: %w", err)
		}
	}
	return nil
}

// kmsMissing lists the variables the selected cloud provider needs and does not have,
// in the order an operator would set them. Empty for env and file, which have their
// own checks above.
func kmsMissing() []string {
	var missing []string
	switch RootKeyProvider {
	case crypto.ProviderAWSKMS:
		if KMSAWSKeyID == "" {
			missing = append(missing, "SECRET_KMS_AWS_KEY_ID")
		}
		if KMSAWSRegion == "" {
			missing = append(missing, "SECRET_KMS_AWS_REGION (or AWS_REGION)")
		}
	case crypto.ProviderGCPKMS:
		if KMSGCPKeyName == "" {
			missing = append(missing, "SECRET_KMS_GCP_KEY_NAME")
		}
	case crypto.ProviderAzureKV:
		if KMSAzureVaultURL == "" {
			missing = append(missing, "SECRET_KMS_AZURE_VAULT_URL")
		}
		if KMSAzureKeyName == "" {
			missing = append(missing, "SECRET_KMS_AZURE_KEY_NAME")
		}
	}
	return missing
}

// RootKeyProviderConfig assembles the validated configuration the crypto factory
// needs, so the root of trust is built from ONE place and no call site has to know
// which fields a given provider reads.
//
// It is a pure read of the package variables Init already validated — it does not
// touch the environment, and it never returns an error, because everything that can
// be wrong about this configuration was refused at boot.
func RootKeyProviderConfig() crypto.ProviderConfig {
	return crypto.ProviderConfig{
		Provider: RootKeyProvider,
		AppEnv:   AppEnv,
		Key:      RootKey,
		KeyFile:  RootKeyFile,
		KMS: crypto.KMSConfig{
			Timeout:         KMSTimeout,
			AWSKeyID:        KMSAWSKeyID,
			AWSRegion:       KMSAWSRegion,
			GCPKeyName:      KMSGCPKeyName,
			AzureVaultURL:   KMSAzureVaultURL,
			AzureKeyName:    KMSAzureKeyName,
			AzureKeyVersion: KMSAzureKeyVersion,
		},
	}
}

// DescribeRootKey renders the root of trust for a boot log line. Never includes key
// material — for the cloud providers there is none to include, and for env and file
// the value and the path are deliberately omitted.
func DescribeRootKey() string {
	switch RootKeyProvider {
	case crypto.ProviderAWSKMS:
		return fmt.Sprintf("%s (%s in %s)", crypto.ProviderAWSKMS, KMSAWSKeyID, KMSAWSRegion)
	case crypto.ProviderGCPKMS:
		return fmt.Sprintf("%s (%s)", crypto.ProviderGCPKMS, KMSGCPKeyName)
	case crypto.ProviderAzureKV:
		version := KMSAzureKeyVersion
		if version == "" {
			version = "current"
		}
		return fmt.Sprintf("%s (%s key %s, version %s)", crypto.ProviderAzureKV, KMSAzureVaultURL, KMSAzureKeyName, version)
	case crypto.ProviderFile:
		return crypto.ProviderFile
	default:
		return RootKeyProvider
	}
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

// initTransportSecurity reads the TLS material for both listeners and refuses the
// combinations that cannot be served safely.
//
// THE RULE, AND WHY EACH BRANCH IS WHERE IT IS. This mirrors how maintainerd-auth
// guards its own control plane (auth internal/server/grpc.go loadGRPCTLSConfig),
// because the thing being protected is the same: a surface through which another
// process provisions this one.
//
//	PARTIAL gRPC material (one or two of the three)
//	  ALWAYS a boot error, in every environment including development. This is the
//	  branch that matters most, because it is the one that looks configured. An
//	  operator who set a cert and a key but no CA has built server TLS and believes
//	  they have mutual TLS; an operator who set a CA but no cert has configured
//	  nothing at all and believes they have configured everything. Neither should
//	  discover it from a peer that got in.
//
//	NO gRPC material, MAINTAINERD_MODE=core, outside development
//	  A boot error. In core mode this listener IS the control plane: SetupService is
//	  how core provisions the vault's identity, and the caller's claim to be core is
//	  the only thing standing between an arbitrary peer and ownership of the vault.
//	  That claim must be proven by a certificate, not asserted by a token, and it is
//	  never served in the clear. This is the "no silent plaintext downgrade" rule.
//
//	NO gRPC material, standalone, outside development
//	  A loud WARNING, not an error. In standalone mode the gRPC listener is
//	  service-to-service traffic between workloads the operator already runs on a
//	  network they already control, commonly a mesh that provides mTLS below this
//	  process. Refusing would break those deployments to protect them from a risk
//	  they have already handled elsewhere — so it is stated at boot, every boot,
//	  and left as the operator's call.
//
//	PARTIAL HTTP material
//	  A boot error, same reasoning as the gRPC partial case. Absent material is
//	  fine in any mode: the REST surface is behind a terminating proxy in every
//	  sanctioned deployment.
func initTransportSecurity() error {
	GRPCTLSCertFile = strings.TrimSpace(kitconfig.GetEnv("SECRET_GRPC_CERT_FILE", ""))
	GRPCTLSKeyFile = strings.TrimSpace(kitconfig.GetEnv("SECRET_GRPC_KEY_FILE", ""))
	GRPCClientCAFile = strings.TrimSpace(kitconfig.GetEnv("SECRET_GRPC_CA_FILE", ""))

	switch boolCount(GRPCTLSCertFile != "", GRPCTLSKeyFile != "", GRPCClientCAFile != "") {
	case 3:
		// Fully configured: mutual TLS, client certificate required and verified.
	case 0:
		if Mode == ModeCore && !IsDevelopment() {
			return fmt.Errorf(
				"config: MAINTAINERD_MODE=%s requires SECRET_GRPC_CERT_FILE, SECRET_GRPC_KEY_FILE and "+
					"SECRET_GRPC_CA_FILE outside %s — in core mode the gRPC listener is the control plane "+
					"through which this vault is provisioned, and it is never served in the clear. A bearer "+
					"token asserts that the peer is core; a verified client certificate proves it",
				ModeCore, EnvDevelopment)
		}
		if !IsDevelopment() {
			slog.Warn("config: the gRPC listener has no TLS material — service-to-service traffic is PLAINTEXT",
				"acceptable_only_if", "a service mesh or sidecar terminates mTLS in front of this process",
				"to_enable", "SECRET_GRPC_CERT_FILE, SECRET_GRPC_KEY_FILE, SECRET_GRPC_CA_FILE")
		}
	default:
		return fmt.Errorf(
			"config: SECRET_GRPC_CERT_FILE, SECRET_GRPC_KEY_FILE and SECRET_GRPC_CA_FILE must be set " +
				"together or not at all — a cert and key without a CA is server TLS that accepts any " +
				"client, and a CA without a cert and key configures nothing while looking configured")
	}

	HTTPTLSCertFile = strings.TrimSpace(kitconfig.GetEnv("SECRET_TLS_CERT_FILE", ""))
	HTTPTLSKeyFile = strings.TrimSpace(kitconfig.GetEnv("SECRET_TLS_KEY_FILE", ""))
	if boolCount(HTTPTLSCertFile != "", HTTPTLSKeyFile != "") == 1 {
		return fmt.Errorf(
			"config: SECRET_TLS_CERT_FILE and SECRET_TLS_KEY_FILE must be set together or not at all; " +
				"leave both unset to serve plain HTTP behind a terminating proxy")
	}
	return nil
}

// GRPCMutualTLSEnabled reports whether the gRPC listener will require and verify a
// client certificate. All three files are present or none are (initTransportSecurity
// refuses anything else), so one check answers it.
func GRPCMutualTLSEnabled() bool {
	return GRPCTLSCertFile != "" && GRPCTLSKeyFile != "" && GRPCClientCAFile != ""
}

// HTTPTLSEnabled reports whether the REST listener serves TLS directly.
func HTTPTLSEnabled() bool { return HTTPTLSCertFile != "" && HTTPTLSKeyFile != "" }

// initCoordination reads the two multi-replica switches.
//
// BOTH DEFAULT ON, and both warn rather than refuse when turned off. The reasoning is
// the same for each: the correct behaviour must be what happens when nobody sets the
// variable, because the failures these prevent are invisible in a healthy-looking
// service — a secret rotated twice, or a reveal budget quietly multiplied by the
// replica count. But turning either off is a legitimate choice for a single-replica
// deployment or one that meters at its ingress, so it is a warning and not a wall.
func initCoordination() error {
	var err error
	if LeaderElectionEnabled, err = boolEnv("SECRET_LEADER_ELECTION_ENABLED", true); err != nil {
		return err
	}
	if RateLimitShared, err = boolEnv("SECRET_RATE_LIMIT_SHARED", true); err != nil {
		return err
	}
	if !LeaderElectionEnabled {
		slog.Warn("config: leader election is DISABLED — every replica runs the background workers",
			"effect", "with more than one replica the same secret is rotated once per replica, "+
				"each producing a version and a webhook fan-out",
			"variable", "SECRET_LEADER_ELECTION_ENABLED")
	}
	if RateLimitShared && !RateLimitEnabled {
		slog.Warn("config: SECRET_RATE_LIMIT_SHARED is set but rate limiting is off; it has no effect",
			"variable", "SECRET_RATE_LIMIT_ENABLED")
	}
	if !RateLimitShared && RateLimitEnabled {
		slog.Warn("config: the rate limit budget is PER-REPLICA — the shared counter is disabled",
			"effect", "with N replicas a client that spreads its requests gets N times each configured budget",
			"variable", "SECRET_RATE_LIMIT_SHARED")
	}
	return nil
}

// initWebhookRedrive reads the durable retry loop's bounds.
//
// The one CROSS-CHECK refuses a maximum backoff BELOW the base. That combination is
// not merely odd, it silently flattens the schedule: every attempt would wait the cap,
// so an exponential backoff an operator configured would behave as a fixed one. It is
// the sort of mistake that only shows up as "why is this still retrying every thirty
// seconds four hours later", so it is refused at boot with both numbers named.
func initWebhookRedrive() error {
	var err error
	if WebhookRedriveEnabled, err = boolEnv("SECRET_WEBHOOK_REDRIVE_ENABLED", true); err != nil {
		return err
	}
	if WebhookRedriveInterval, err = positiveDuration("SECRET_WEBHOOK_REDRIVE_INTERVAL", 30*time.Second); err != nil {
		return err
	}
	if WebhookRedriveBatch, err = positiveInt("SECRET_WEBHOOK_REDRIVE_BATCH", 50); err != nil {
		return err
	}
	if WebhookRedriveMaxAttempts, err = positiveInt("SECRET_WEBHOOK_REDRIVE_MAX_ATTEMPTS", 10); err != nil {
		return err
	}
	if WebhookRedriveBaseBackoff, err = positiveDuration("SECRET_WEBHOOK_REDRIVE_BASE_BACKOFF", 30*time.Second); err != nil {
		return err
	}
	if WebhookRedriveMaxBackoff, err = positiveDuration("SECRET_WEBHOOK_REDRIVE_MAX_BACKOFF", time.Hour); err != nil {
		return err
	}
	if WebhookRedriveMaxBackoff < WebhookRedriveBaseBackoff {
		return fmt.Errorf(
			"config: SECRET_WEBHOOK_REDRIVE_MAX_BACKOFF (%s) must not be shorter than "+
				"SECRET_WEBHOOK_REDRIVE_BASE_BACKOFF (%s); a cap below the first delay makes every "+
				"retry wait the cap, which is a fixed backoff wearing an exponential one's name",
			WebhookRedriveMaxBackoff, WebhookRedriveBaseBackoff)
	}
	if !WebhooksEnabled && WebhookRedriveEnabled {
		slog.Warn("config: SECRET_WEBHOOK_REDRIVE_ENABLED is set but webhooks are off; the loop will not run",
			"variable", "SECRET_WEBHOOKS_ENABLED")
	}
	return nil
}

// initConsole resolves CONSOLE_DIR and PROVES it is servable before the process
// starts answering.
//
// The check is index.html specifically rather than "the directory exists", because
// index.html is what every SPA deep link falls back to: a directory that exists but
// has no shell produces a console whose every route is a 404, which is exactly the
// failure this endpoint exists to prevent and the hardest one to read in a browser.
// Failing at boot names the path.
func initConsole() error {
	ConsoleDir = strings.TrimSpace(kitconfig.GetEnv("CONSOLE_DIR", ""))
	if ConsoleDir == "" {
		return nil
	}
	index := filepath.Join(ConsoleDir, "index.html")
	if _, err := os.Stat(index); err != nil {
		return fmt.Errorf(
			"config: CONSOLE_DIR is %q but %q is not readable (%v). Unset CONSOLE_DIR to disable "+
				"serving the console from this process, or point it at the SPA's built output "+
				"(the release image bakes it at /srv/console)",
			ConsoleDir, index, err)
	}
	return nil
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
