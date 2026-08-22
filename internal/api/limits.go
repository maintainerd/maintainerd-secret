package api

import "sync/atomic"

// Request limits: the server-side bounds every request is measured against.
//
// WHY THEY LIVE HERE RATHER THAN IN EACH TRANSPORT. A limit enforced in a handler is
// a limit one transport has and the other does not, and the transport that forgets is
// the one an attacker uses. These are read by the DTO Validate() methods in
// validation_*.go, which both the REST handlers and the gRPC service funnel through,
// so a bound cannot apply to only half the API.
//
// THEY ARE CONFIGURABLE BUT NEVER UNBOUNDED. Every field is clamped to a positive
// value by Apply: an operator who sets a limit to 0 gets the default, not "no limit".
// A secret store whose batch size can be configured to infinity is a bulk-decryption
// endpoint one environment variable away.
type Limits struct {
	// MaxSecretValueBytes bounds one secret's plaintext. Generous enough for a PEM
	// bundle or a service-account JSON, small enough that a batch put cannot be a
	// memory-exhaustion primitive.
	MaxSecretValueBytes int
	// MaxBatchItems bounds items in one bulk get/put. See internal/api/bulk.go: the
	// bound is what keeps a reveal an event rather than a stream.
	MaxBatchItems int
	// MaxTags and MaxTagLength bound a secret's tag list. Tags are indexed metadata
	// returned in every listing, so an unbounded list is an unbounded response.
	MaxTags      int
	MaxTagLength int
	// MaxPageLimit is the largest page a client may ask for. A client cannot exceed
	// it: the value is clamped, and a request that names a bigger one is refused
	// rather than silently narrowed, so a caller paging by 10000 learns it is not
	// getting 10000 rows.
	MaxPageLimit int
	// MaxDescriptionLength bounds free-text description fields.
	MaxDescriptionLength int
	// MaxWebhookTimeoutSeconds caps a per-endpoint delivery timeout. Deliveries run
	// inline on a write path, so an endpoint configured with a 10-minute timeout
	// would hold a write open for 10 minutes.
	MaxWebhookTimeoutSeconds int
	// MaxWebhookAttempts caps per-endpoint retries, for the same reason.
	MaxWebhookAttempts int
	// MaxTransitPlaintextBytes bounds one transit Encrypt.
	//
	// It is SMALLER than MaxSecretValueBytes on purpose. A secret write is an
	// occasional administrative act; transit is a DATA PLANE that an application calls
	// on every row it stores, so the same generous bound would turn one request into a
	// megabyte-scale allocation plus an AES pass, repeatedly, from a caller that only
	// needs to encrypt a column. A caller with genuinely large payloads should encrypt
	// a data key here and use it locally, which is what transit is for.
	MaxTransitPlaintextBytes int
	// MaxDynamicLeaseTTLSeconds caps the lease TTL a caller may REQUEST, on top of the
	// per-role ceiling. Two bounds rather than one because the role's ceiling is an
	// operator's choice per database and this is the service's refusal to issue a
	// long-lived credential at all.
	MaxDynamicLeaseTTLSeconds int
}

// Defaults. Every one of these is a safe value on its own — the service is correct
// with no limit configuration at all.
const (
	DefaultMaxSecretValueBytes      = 64 << 10 // 64 KiB
	DefaultMaxBatchItems            = 100
	DefaultMaxTags                  = 32
	DefaultMaxTagLength             = 64
	DefaultMaxPageLimit             = 200
	DefaultMaxDescriptionLength     = 500
	DefaultMaxWebhookTimeoutSeconds = 30
	DefaultMaxWebhookAttempts       = 10
	// DefaultMaxTransitPlaintextBytes is 32 KiB — comfortably more than any column a
	// caller encrypts, and less than the secret-value bound for the reason above.
	DefaultMaxTransitPlaintextBytes = 32 << 10
	// DefaultMaxDynamicLeaseTTLSeconds is 24 hours. A dynamic credential that outlives
	// a working day has stopped being short-lived.
	DefaultMaxDynamicLeaseTTLSeconds = 24 * 60 * 60
)

// MaxBatchSize is the compile-time ceiling on a configured MaxBatchItems.
//
// It is deliberately a constant and deliberately not configurable upward: the batch
// bound is a security property (see internal/api/bulk.go), so an operator may lower
// it, never raise it past what this service is willing to decrypt in one request.
const MaxBatchSize = 100

// DefaultLimits returns the built-in bounds.
func DefaultLimits() Limits {
	return Limits{
		MaxSecretValueBytes:      DefaultMaxSecretValueBytes,
		MaxBatchItems:            DefaultMaxBatchItems,
		MaxTags:                  DefaultMaxTags,
		MaxTagLength:             DefaultMaxTagLength,
		MaxPageLimit:             DefaultMaxPageLimit,
		MaxDescriptionLength:     DefaultMaxDescriptionLength,
		MaxWebhookTimeoutSeconds: DefaultMaxWebhookTimeoutSeconds,
		MaxWebhookAttempts:       DefaultMaxWebhookAttempts,

		MaxTransitPlaintextBytes:  DefaultMaxTransitPlaintextBytes,
		MaxDynamicLeaseTTLSeconds: DefaultMaxDynamicLeaseTTLSeconds,
	}
}

// normalized returns l with every non-positive field replaced by its default and
// MaxBatchItems clamped to MaxBatchSize.
func (l Limits) normalized() Limits {
	d := DefaultLimits()
	if l.MaxSecretValueBytes < 1 {
		l.MaxSecretValueBytes = d.MaxSecretValueBytes
	}
	if l.MaxBatchItems < 1 {
		l.MaxBatchItems = d.MaxBatchItems
	}
	if l.MaxBatchItems > MaxBatchSize {
		l.MaxBatchItems = MaxBatchSize
	}
	if l.MaxTags < 1 {
		l.MaxTags = d.MaxTags
	}
	if l.MaxTagLength < 1 {
		l.MaxTagLength = d.MaxTagLength
	}
	if l.MaxPageLimit < 1 {
		l.MaxPageLimit = d.MaxPageLimit
	}
	if l.MaxDescriptionLength < 1 {
		l.MaxDescriptionLength = d.MaxDescriptionLength
	}
	if l.MaxWebhookTimeoutSeconds < 1 {
		l.MaxWebhookTimeoutSeconds = d.MaxWebhookTimeoutSeconds
	}
	if l.MaxWebhookAttempts < 1 {
		l.MaxWebhookAttempts = d.MaxWebhookAttempts
	}
	if l.MaxTransitPlaintextBytes < 1 {
		l.MaxTransitPlaintextBytes = d.MaxTransitPlaintextBytes
	}
	if l.MaxDynamicLeaseTTLSeconds < 1 {
		l.MaxDynamicLeaseTTLSeconds = d.MaxDynamicLeaseTTLSeconds
	}
	return l
}

// active holds the process-wide limits. An atomic pointer rather than a plain
// variable because the bootstrap writes it once while every request goroutine reads
// it, and a data race on a security bound is still a data race.
var active atomic.Pointer[Limits]

// ApplyLimits installs l (normalized) as the process-wide bounds. The bootstrap calls
// it once, before any surface is served; tests call it and restore with
// ApplyLimits(DefaultLimits()).
func ApplyLimits(l Limits) {
	normalized := l.normalized()
	active.Store(&normalized)
}

// CurrentLimits returns the bounds in force. Safe before ApplyLimits has run — the
// defaults apply — so a unit test that constructs a Service directly is bounded too.
func CurrentLimits() Limits {
	if l := active.Load(); l != nil {
		return *l
	}
	return DefaultLimits()
}
