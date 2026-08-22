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

// Populated once by Init and read-only thereafter. Tests use t.Setenv and call
// Init again.
var (
	// --- app ---------------------------------------------------------------
	AppEnv   string // APP_ENV; "development" or "production". Default "development".
	LogLevel string // LOG_LEVEL; debug|info|warn|error. Default "info".
	GRPCAddr string // GRPC_PORT; default ":9092".
	HTTPAddr string // HTTP_PORT; default ":8092".

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
	if authSet := boolCount(AuthJWKSURL != "", AuthIssuer != "", AuthAudience != ""); authSet == 0 && !IsDevelopment() {
		slog.Warn("config: no auth configuration — the API will answer 503 and gRPC will serve health only",
			"missing", "AUTH_JWKS_URL, AUTH_ISSUER, AUTH_AUDIENCE")
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
