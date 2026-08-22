package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/maintainerd/secret/internal/platform/apperror"
	"github.com/maintainerd/secret/internal/store"
)

// The DURABLE half of webhook delivery.
//
// WHY THIS EXISTS. Notify (webhook.go) attempts a delivery INLINE on the secret write
// that caused it, with a retry budget measured in hundreds of milliseconds, because
// the whole sequence sits inside a request an operator is waiting on. That is the
// right bound for a receiver with a hiccup and completely the wrong one for a receiver
// that is redeploying: two minutes of downtime and the notification is lost, while the
// value it announced has already changed. The delivery ROW was always written before
// the attempt, so the miss was visible — but visible is not delivered, and a consumer
// that never learned its credential rotated is running on a credential that no longer
// works.
//
// So a delivery that exhausts its inline budget is PARKED rather than dropped:
// status 'retrying', with next_attempt_at saying when it may be tried again. This
// worker picks those up, retries with exponential backoff, and after a bounded budget
// marks the row permanently 'failed' — the row an operator greps for. It mirrors the
// retry/backoff shape of core's deployment loop: a bounded exponential schedule, a
// terminal state, and no path that ends the process.
//
// IT NEVER SENDS A VALUE. It replays the stored payload verbatim, and that payload has
// nowhere to put a credential (see Payload) — so the guarantee the inline path asserts
// by structure is the same one here, for free. What it DOES recompute is the
// signature, over a fresh timestamp: the timestamp is inside the MAC, so a receiver's
// replay window stays enforceable and a retry arriving an hour later is not rejected
// as stale.
//
// CONCURRENCY. The claim is FOR UPDATE SKIP LOCKED and moves next_attempt_at forward
// by a visibility lease before any attempt is made, so the worker is correct in every
// replica even with no coordination: two replicas take disjoint batches, and a replica
// that dies holding a claim releases it when the lease expires. It is ADDITIONALLY
// gated by the shared leader election (internal/leader) when the bootstrap supplies
// one, which is what keeps the backlog drained by one replica at a steady rate rather
// than by all of them at once. Either mechanism alone is sufficient; both together
// mean a misconfigured election cannot cause a double-post.

// Re-drive defaults.
const (
	// DefaultRedriveInterval is how often the worker looks for due deliveries. It is
	// far finer than the backoff schedule below, so a delivery becomes due and is
	// picked up within one tick rather than waiting out a coarse scan.
	DefaultRedriveInterval = 30 * time.Second
	// DefaultRedriveBatch bounds one pass. A receiver that was down for an hour comes
	// back to a backlog, and draining it must not become a self-inflicted flood: the
	// remainder is picked up on the next tick moments later.
	DefaultRedriveBatch = 50
	// DefaultRedriveMaxAttempts is the DURABLE budget — worker attempts only, counted
	// separately from the inline ones (see webhook_deliveries.redrive_attempts). Ten
	// attempts on the default schedule spans roughly four hours, which covers a long
	// deploy or an expired certificate somebody has to be paged about, and stops well
	// short of retrying forever against an endpoint nobody owns any more.
	DefaultRedriveMaxAttempts = 10
	// DefaultRedriveBaseBackoff is the first delay, doubling from there.
	DefaultRedriveBaseBackoff = 30 * time.Second
	// DefaultRedriveMaxBackoff caps the doubling. Past an hour the schedule stops
	// being a retry and becomes a slow poll, and the budget is the thing that should
	// end it.
	DefaultRedriveMaxBackoff = time.Hour
	// DefaultRedriveLease is how long a claimed delivery is invisible to other
	// workers. It must exceed one attempt's timeout (capped at
	// Options.MaxTimeout, 30s by default) with room to spare, or a slow receiver
	// produces a concurrent second attempt against itself.
	DefaultRedriveLease = 2 * time.Minute
)

// RedriveStore is the persistence the worker needs. *store.Service satisfies it.
//
// It is an interface for the usual reason — the worker is testable without a database
// — and it is deliberately narrow: a worker that could reach the secret store could
// reach a value, and this one must never need to.
type RedriveStore interface {
	ClaimDeliveriesForRedrive(ctx context.Context, limit int, lease time.Duration) ([]store.RedriveDelivery, error)
	SignedEndpointByID(ctx context.Context, endpointID int64) (*store.SignedWebhookEndpoint, error)
	RecordRedriveOutcome(ctx context.Context, deliveryID int64, status string, responseStatus *int32, failure string, nextAttempt *time.Time) error
	AbandonDelivery(ctx context.Context, deliveryID int64, reason string) error
	CountDeliveriesAwaitingRedrive(ctx context.Context) (int64, error)
	TouchWebhookEndpoint(ctx context.Context, endpointID int64) error
}

// RedriveOptions tunes the worker. A zero value is a working configuration.
type RedriveOptions struct {
	// Enabled turns the loop off without touching the backlog. An operator stopping
	// re-drive during an incident on a receiver wants the rows preserved, so delivery
	// resumes when they turn it back on.
	Enabled bool
	// Interval is how often a pass runs.
	Interval time.Duration
	// Batch bounds one pass.
	Batch int
	// MaxAttempts is the durable budget, in worker attempts.
	MaxAttempts int32
	// BaseBackoff is the first delay; MaxBackoff caps the doubling.
	BaseBackoff time.Duration
	MaxBackoff  time.Duration
	// Lease is the claim's visibility timeout.
	Lease time.Duration
	// MaxTimeout caps ONE attempt, clamping whatever the endpoint row asks for — the
	// same bound and the same argument as Options.MaxTimeout on the inline path.
	MaxTimeout time.Duration
}

func (o RedriveOptions) withDefaults() RedriveOptions {
	if o.Interval <= 0 {
		o.Interval = DefaultRedriveInterval
	}
	if o.Batch < 1 {
		o.Batch = DefaultRedriveBatch
	}
	if o.MaxAttempts < 1 {
		o.MaxAttempts = DefaultRedriveMaxAttempts
	}
	if o.BaseBackoff <= 0 {
		o.BaseBackoff = DefaultRedriveBaseBackoff
	}
	if o.MaxBackoff <= 0 {
		o.MaxBackoff = DefaultRedriveMaxBackoff
	}
	if o.MaxBackoff < o.BaseBackoff {
		// A cap below the first delay would make the schedule flat at the cap, which
		// is a configuration nobody means. The base wins, because it is the one an
		// operator set deliberately.
		o.MaxBackoff = o.BaseBackoff
	}
	if o.Lease <= 0 {
		o.Lease = DefaultRedriveLease
	}
	if o.MaxTimeout <= 0 {
		o.MaxTimeout = DefaultMaxTimeout
	}
	if o.Lease <= o.MaxTimeout {
		// The lease has to outlast an attempt or the row becomes claimable again while
		// this process is still posting it. Widened rather than refused: this is a
		// derived bound, and a boot error for it would be a boot error an operator
		// cannot act on from the message alone.
		o.Lease = 2 * o.MaxTimeout
	}
	return o
}

// Redriver is the durable retry loop.
type Redriver struct {
	store  RedriveStore
	client *http.Client
	opts   RedriveOptions
}

// NewRedriver builds the worker over the store.
func NewRedriver(st RedriveStore, opts RedriveOptions) *Redriver {
	return &Redriver{store: st, client: SafeDeliveryClient, opts: opts.withDefaults()}
}

// Interval is the tick the caller should schedule this worker on.
func (r *Redriver) Interval() time.Duration {
	if r == nil {
		return DefaultRedriveInterval
	}
	return r.opts.Interval
}

// Enabled reports whether the loop should run at all.
func (r *Redriver) Enabled() bool { return r != nil && r.store != nil && r.opts.Enabled }

// Tick runs one pass: claim a batch of due deliveries and attempt each one.
//
// It returns an error only for a failure that made the whole pass impossible (the
// claim query itself). A single delivery that could not be attempted is recorded on
// its own row and does not fail the pass — the point of a re-drive loop is that one
// broken endpoint cannot stop the others.
func (r *Redriver) Tick(ctx context.Context) error {
	if !r.Enabled() || ctx.Err() != nil {
		return nil
	}
	claimed, err := r.store.ClaimDeliveriesForRedrive(ctx, r.opts.Batch, r.opts.Lease)
	if err != nil {
		return err
	}
	if len(claimed) == 0 {
		return nil
	}

	var delivered, requeued, abandoned int
	for i := range claimed {
		if ctx.Err() != nil {
			// The remaining claims simply expire and are picked up by the next pass or
			// the next replica. Nothing is lost by stopping here, and continuing into a
			// cancelled context would post with a dead deadline.
			break
		}
		switch r.attemptOne(ctx, claimed[i]) {
		case outcomeDelivered:
			delivered++
		case outcomeRequeued:
			requeued++
		case outcomeAbandoned:
			abandoned++
		}
	}

	backlog, berr := r.store.CountDeliveriesAwaitingRedrive(ctx)
	if berr != nil {
		backlog = -1
	}
	slog.Info("webhook re-drive: pass complete",
		"claimed", len(claimed), "delivered", delivered, "requeued", requeued,
		"permanently_failed", abandoned, "backlog", backlog)
	return nil
}

type redriveOutcome int

const (
	outcomeDelivered redriveOutcome = iota
	outcomeRequeued
	outcomeAbandoned
)

// attemptOne performs one retry of one delivery and records what happened.
func (r *Redriver) attemptOne(ctx context.Context, delivery store.RedriveDelivery) redriveOutcome {
	endpoint, err := r.store.SignedEndpointByID(ctx, delivery.EndpointID)
	if err != nil {
		// A DELETED endpoint is terminal: the operator withdrew it, backlog included.
		// Anything else (a root key this process does not hold, a database blip) is
		// transient, so the row keeps its lease and comes back on a later pass.
		if apperror.IsNotFound(err) {
			r.abandon(ctx, delivery, "the endpoint was deleted before this delivery could be retried")
			return outcomeAbandoned
		}
		slog.Warn("webhook re-drive: could not load the endpoint; the delivery stays scheduled",
			"delivery", delivery.UUID, "error", err)
		return outcomeRequeued
	}
	defer endpoint.Zero()

	status, attemptErr := r.post(ctx, endpoint, delivery)
	var responseStatus *int32
	if status != 0 {
		s := status
		responseStatus = &s
	}

	if attemptErr == nil {
		if err := r.store.RecordRedriveOutcome(ctx, delivery.ID, store.WebhookDeliverySuccess, responseStatus, "", nil); err != nil {
			slog.Warn("webhook re-drive: delivery succeeded but recording it failed",
				"delivery", delivery.UUID, "error", err)
		}
		if err := r.store.TouchWebhookEndpoint(ctx, endpoint.ID); err != nil {
			slog.Debug("webhook re-drive: updating last_triggered_at failed", "endpoint", endpoint.UUID, "error", err)
		}
		slog.Info("webhook re-drive: delivered after retrying",
			"delivery", delivery.UUID, "endpoint", endpoint.UUID,
			"resource", delivery.ResourceMRN, "attempts", delivery.AttemptCount+1)
		return outcomeDelivered
	}

	spent := delivery.RedriveAttempts + 1
	if spent >= r.opts.MaxAttempts {
		// Budget exhausted. The row becomes permanently failed, which is the honest
		// record: the consumer was never told, and somebody has to know that.
		if err := r.store.RecordRedriveOutcome(ctx, delivery.ID, store.WebhookDeliveryFailed, responseStatus,
			fmt.Sprintf("permanently failed after %d re-drive attempts: %s", spent, attemptErr.Error()), nil); err != nil {
			slog.Warn("webhook re-drive: recording permanent failure failed", "delivery", delivery.UUID, "error", err)
		}
		slog.Warn("webhook re-drive: giving up on a delivery — the consumer was never notified",
			"delivery", delivery.UUID, "endpoint", endpoint.UUID, "resource", delivery.ResourceMRN,
			"redrive_attempts", spent, "error", attemptErr)
		return outcomeAbandoned
	}

	next := time.Now().Add(Backoff(r.opts.BaseBackoff, r.opts.MaxBackoff, spent))
	if err := r.store.RecordRedriveOutcome(ctx, delivery.ID, store.WebhookDeliveryRetrying, responseStatus,
		attemptErr.Error(), &next); err != nil {
		slog.Warn("webhook re-drive: rescheduling failed; the claim lease will re-expose the row",
			"delivery", delivery.UUID, "error", err)
	}
	return outcomeRequeued
}

// abandon marks a delivery permanently failed without spending an attempt.
func (r *Redriver) abandon(ctx context.Context, delivery store.RedriveDelivery, reason string) {
	if err := r.store.AbandonDelivery(ctx, delivery.ID, reason); err != nil {
		slog.Warn("webhook re-drive: abandoning a delivery failed", "delivery", delivery.UUID, "error", err)
		return
	}
	slog.Info("webhook re-drive: delivery abandoned", "delivery", delivery.UUID, "reason", reason)
}

// post replays one delivery's stored body to its endpoint, freshly signed.
func (r *Redriver) post(ctx context.Context, endpoint *store.SignedWebhookEndpoint, delivery store.RedriveDelivery) (int32, error) {
	// The stored payload is replayed byte for byte and SIGNED AS SENT, so the MAC
	// covers exactly the bytes on the wire regardless of how Postgres normalised the
	// JSONB. The event id inside it is unchanged, which is what lets a receiver
	// de-duplicate a retry against the attempt it already processed.
	body := delivery.Payload
	if len(body) == 0 {
		return 0, errors.New("the recorded delivery payload is empty; there is nothing to replay")
	}

	timeout := time.Duration(endpoint.TimeoutSeconds) * time.Second
	if timeout <= 0 || timeout > r.opts.MaxTimeout {
		timeout = r.opts.MaxTimeout
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint.URL, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	timestamp := time.Now().Unix()
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Maintainerd-Event", delivery.EventType)
	req.Header.Set("X-Maintainerd-Event-Id", eventIDFrom(body))
	req.Header.Set("X-Maintainerd-Delivery", delivery.UUID.String())
	// The attempt number continues the row's own count rather than restarting at 1, so
	// a receiver logging the header sees one sequence per delivery.
	req.Header.Set("X-Maintainerd-Attempt", strconv.Itoa(int(delivery.AttemptCount+1)))
	req.Header.Set("X-Maintainerd-Timestamp", strconv.FormatInt(timestamp, 10))
	req.Header.Set("X-Maintainerd-Signature-256", Signature(endpoint.SigningKey, timestamp, body))

	resp, err := r.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return int32(resp.StatusCode), fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return int32(resp.StatusCode), nil
}

// eventIDFrom reads the notification id back out of the stored body, so a retry
// carries the same X-Maintainerd-Event-Id the first attempt did — which is the value a
// receiver de-duplicates on. An unreadable payload yields an empty header rather than
// a failed delivery: the body is still what matters, and the id is also inside it.
func eventIDFrom(body []byte) string {
	var payload Payload
	if err := json.Unmarshal(body, &payload); err != nil {
		return ""
	}
	return payload.ID
}

// Backoff is the delay before attempt n (1-based): base doubled n-1 times, capped.
//
// It is exported and pure so the schedule is unit-testable without a clock, a store or
// a server — the property that actually matters here is "monotonically increasing,
// never past the cap, never negative", and that is checkable in three lines.
//
// There is deliberately NO JITTER. Jitter exists to de-synchronise many clients
// hammering one server; here the sender is one leader-gated worker draining a bounded
// batch on a fixed tick, so the thing jitter would spread is already spread by the
// claim's LIMIT.
func Backoff(base, max time.Duration, attempt int32) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if base <= 0 {
		base = DefaultRedriveBaseBackoff
	}
	if max <= 0 || max < base {
		max = base
	}
	// Shifting past 62 overflows int64; the cap makes anything above it identical
	// anyway, so clamp the exponent rather than computing a negative duration.
	shift := attempt - 1
	if shift > 62 {
		return max
	}
	scaled := float64(base) * math.Pow(2, float64(shift))
	if scaled >= float64(max) {
		return max
	}
	return time.Duration(scaled)
}
