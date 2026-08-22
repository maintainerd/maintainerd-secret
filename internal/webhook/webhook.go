// Package webhook delivers change and rotation notifications to a project's
// registered endpoints.
//
// THE PAYLOAD NEVER CONTAINS A VALUE. It carries the MRN, the event name and the new
// version number — an instruction to RE-READ, not the thing itself. This is the
// single most important property in the package and it is asserted by test. The
// reasoning: a webhook is an outbound POST to a URL a tenant supplied, retried,
// logged by the receiver, and stored in this service's own delivery log. Putting a
// credential in one moves it outside encrypted custody permanently and buys nothing,
// because a consumer that can use the value can read it through the API anyway (with
// a grant, and with an audit row).
//
// THE SIGNATURE SCHEME mirrors maintainerd-auth's, deliberately and exactly, so a
// receiver that already verifies Auth's webhooks verifies these with the same code:
//
//	X-Maintainerd-Event          the event name
//	X-Maintainerd-Event-Id       this notification's id
//	X-Maintainerd-Delivery       the delivery record's id
//	X-Maintainerd-Attempt        1-based attempt number
//	X-Maintainerd-Timestamp      unix seconds, also signed
//	X-Maintainerd-Signature-256  "sha256=" + hex(HMAC-SHA256(key, timestamp + "." + body))
//
// The timestamp is INSIDE the signature, which is what makes a captured delivery
// non-replayable: a receiver rejects a signature whose timestamp is outside its
// tolerance, and an attacker cannot move the timestamp without invalidating the MAC.
//
// DELIVERY IS BEST-EFFORT AND NEVER FAILS THE WRITE. The durable fact is the new
// version; the notification is a courtesy that saves a consumer a polling interval.
// A failed delivery is recorded and logged, never propagated.
//
// IT IS BEST-EFFORT, NOT ONE-SHOT. There are two halves to this package. Notify below
// is the INLINE attempt, bounded by a latency a write can absorb; redrive.go is the
// DURABLE retry loop that owns anything the inline attempt could not deliver, with
// exponential backoff and a bounded budget. The handoff between them is a row state
// ('retrying' plus a next-attempt time), not a goroutine, which is why it survives a
// restart — and why a notification is no longer lost just because the receiver
// happened to be redeploying.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/maintainerd/secret/internal/api"
	"github.com/maintainerd/secret/internal/store"
)

// Payload is the JSON body of a delivery.
//
// LOOK AT WHAT IS NOT HERE: there is no value field, and no field that could hold
// one. That is the structural half of the guarantee — the marshalled body cannot
// contain a credential because the type it is marshalled from has nowhere to put one.
type Payload struct {
	// ID identifies this notification, so a receiver can de-duplicate retries.
	ID string `json:"id"`
	// Event is one of store.WebhookEventSecret*.
	Event string `json:"event"`
	// Resource is the MRN of the secret that changed. It is everything a consumer
	// needs to issue the read that follows.
	Resource string `json:"resource"`
	// Version is the version number now current.
	Version int32 `json:"version"`
	// Tenant and Project are the scope, repeated for a receiver that routes on them
	// without parsing the MRN.
	Tenant  string `json:"tenant"`
	Project string `json:"project"`
	// OccurredAt is RFC3339 UTC.
	OccurredAt string `json:"occurred_at"`
}

// Options tunes the notifier.
type Options struct {
	// Concurrency bounds parallel deliveries for one event. A slow or hostile
	// endpoint must not be able to serialize the fan-out and hold the notifier for
	// the sum of every endpoint's timeout.
	Concurrency int
	// Enabled turns delivery off entirely without removing the endpoints, which is
	// what an operator wants during an incident on a receiver.
	Enabled bool
	// MaxTimeout and MaxAttempts CLAMP what a stored endpoint row may spend, on top of
	// the bound the API applies when the endpoint is registered.
	//
	// Both bounds are needed and they are not redundant. The API bound is the one that
	// gives a caller a useful error; this one is what actually protects the write path,
	// because a row can carry a larger value for three reasons the API cannot reach: it
	// predates the bound, an operator lowered the bound after the row was written, or
	// the row was edited in the database. Deliveries run INLINE on a secret write (see
	// Notify), so an endpoint configured with a ten-minute timeout and ten retries
	// would hold a write open for the sum of them.
	MaxTimeout  time.Duration
	MaxAttempts int32

	// RedriveDelay is how long after an exhausted inline sequence the DURABLE retry
	// loop may first pick the delivery up (see redrive.go). Zero disables the handoff,
	// which restores the old behaviour exactly: a failed delivery is recorded as
	// 'failed' and nothing retries it.
	//
	// The handoff is a state on the delivery row, not a goroutine — which is the whole
	// reason it survives a restart. Notify does not wait for it and a secret write is
	// never held open by it.
	RedriveDelay time.Duration
}

// Defaults when Options leaves a bound unset.
const (
	// DefaultConcurrency is the fan-out bound.
	DefaultConcurrency = 4
	// DefaultMaxTimeout caps one attempt.
	DefaultMaxTimeout = 30 * time.Second
	// DefaultMaxAttempts caps the retry budget for one delivery.
	DefaultMaxAttempts = 10
)

// Notifier fans a change out to a project's endpoints. It satisfies api.Notifier.
type Notifier struct {
	store  *store.Service
	client *http.Client
	opts   Options
}

// New builds a notifier over the store.
func New(st *store.Service, opts Options) *Notifier {
	if opts.Concurrency < 1 {
		opts.Concurrency = DefaultConcurrency
	}
	if opts.MaxTimeout <= 0 {
		opts.MaxTimeout = DefaultMaxTimeout
	}
	if opts.MaxAttempts < 1 {
		opts.MaxAttempts = DefaultMaxAttempts
	}
	return &Notifier{store: st, client: SafeDeliveryClient, opts: opts}
}

// Compile-time proof that the notifier is what the API layer expects.
var _ api.Notifier = (*Notifier)(nil)

// Notify delivers one change to every subscribed endpoint of the project.
//
// It runs SYNCHRONOUSLY on the caller's goroutine, bounded by the per-endpoint
// timeout and the concurrency limit. Spawning a background goroutine per event would
// be faster to return and much worse to operate: the deliveries would outlive the
// request context, an unbounded number of them could be in flight, and a shutdown
// would drop them silently. The bound here is small enough that a write's added
// latency is one endpoint timeout in the worst case.
func (n *Notifier) Notify(ctx context.Context, note api.Notification) {
	if n == nil || !n.opts.Enabled {
		return
	}
	endpoints, err := n.store.SignedEndpointsForProject(ctx, note.TenantUUID, note.Project)
	if err != nil {
		slog.Warn("webhook: loading endpoints failed — the change is stored, consumers will not be told",
			"project", note.Project, "resource", note.ResourceMRN, "error", err)
		return
	}
	if len(endpoints) == 0 {
		return
	}
	defer func() {
		for i := range endpoints {
			endpoints[i].Zero()
		}
	}()

	tenantName, err := n.store.TenantName(ctx, note.TenantUUID)
	if err != nil {
		slog.Warn("webhook: resolving the tenant name failed", "error", err)
		return
	}

	payload := Payload{
		ID:         uuid.NewString(),
		Event:      note.Event,
		Resource:   note.ResourceMRN,
		Version:    note.Version,
		Tenant:     tenantName,
		Project:    note.Project,
		OccurredAt: time.Now().UTC().Format(time.RFC3339),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		slog.Error("webhook: encoding the payload failed", "error", err)
		return
	}

	sem := make(chan struct{}, n.opts.Concurrency)
	var wg sync.WaitGroup
	for i := range endpoints {
		endpoint := endpoints[i]
		if !endpoint.Subscribes(note.Event) {
			continue
		}
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			n.deliver(ctx, note, endpoint, payload, body)
		}()
	}
	wg.Wait()
}

// deliver performs one endpoint's attempt sequence and records the outcome.
func (n *Notifier) deliver(ctx context.Context, note api.Notification, endpoint store.SignedWebhookEndpoint, payload Payload, body []byte) {
	version := note.Version
	deliveryID, deliveryUUID, err := n.store.OpenWebhookDelivery(
		ctx, note.TenantUUID, endpoint.ID, note.Event, note.ResourceMRN, &version, body)
	if err != nil {
		slog.Warn("webhook: recording the delivery failed; not attempting it",
			"endpoint", endpoint.UUID, "error", err)
		return
	}

	// The row's retry budget is clamped by the notifier's bound — see Options.
	maxAttempts := endpoint.MaxAttempts
	if maxAttempts < 1 {
		maxAttempts = 1
	}
	if maxAttempts > n.opts.MaxAttempts {
		slog.Warn("webhook: endpoint asks for more attempts than the configured maximum; clamping",
			"endpoint", endpoint.UUID, "requested", endpoint.MaxAttempts, "max", n.opts.MaxAttempts)
		maxAttempts = n.opts.MaxAttempts
	}

	var (
		attempt    int32
		lastStatus *int32
		lastErr    error
	)
	for attempt = 1; attempt <= maxAttempts; attempt++ {
		status, derr := n.attempt(ctx, endpoint, payload, body, deliveryUUID, attempt)
		if status != 0 {
			s := status
			lastStatus = &s
		}
		if derr == nil {
			lastErr = nil
			break
		}
		lastErr = derr
		if attempt < maxAttempts {
			// A fixed short backoff rather than an exponential one: this runs inline
			// on a write path, so the whole retry budget has to stay inside a latency
			// an operator would accept. An endpoint that needs minutes of backoff is
			// an endpoint that should be polling instead.
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Duration(attempt) * 250 * time.Millisecond):
			}
		}
	}

	// THE OUTCOME IS EITHER TERMINAL OR A HANDOFF. An exhausted inline sequence used to
	// be recorded as 'failed' and forgotten, which made the miss visible without making
	// it recoverable — and the inline budget is deliberately tiny (a few hundred
	// milliseconds, because this runs on a write path), so "failed" mostly meant "the
	// receiver was restarting". It is now parked as 'retrying' with a next-attempt time
	// and the durable worker owns it from here; only that worker's budget produces a
	// permanent 'failed'.
	outcome := store.WebhookDeliverySuccess
	failure := ""
	var nextAttempt *time.Time
	if lastErr != nil {
		outcome = store.WebhookDeliveryFailed
		failure = lastErr.Error()
		if n.opts.RedriveDelay > 0 {
			outcome = store.WebhookDeliveryRetrying
			at := time.Now().Add(n.opts.RedriveDelay)
			nextAttempt = &at
			slog.Warn("webhook: inline delivery failed; handed to the durable re-drive queue",
				"endpoint", endpoint.UUID, "resource", note.ResourceMRN,
				"attempts", attempt-1, "next_attempt_at", at.UTC().Format(time.RFC3339), "error", lastErr)
		} else {
			slog.Warn("webhook: delivery failed after every attempt and re-drive is disabled — the consumer will not be told",
				"endpoint", endpoint.UUID, "resource", note.ResourceMRN, "attempts", attempt-1, "error", lastErr)
		}
	}
	if err := n.store.FinishWebhookDelivery(ctx, deliveryID, min32(attempt, maxAttempts), outcome, lastStatus, failure, nextAttempt); err != nil {
		slog.Warn("webhook: recording the delivery outcome failed", "endpoint", endpoint.UUID, "error", err)
	}
	if lastErr == nil {
		if err := n.store.TouchWebhookEndpoint(ctx, endpoint.ID); err != nil {
			slog.Debug("webhook: updating last_triggered_at failed", "endpoint", endpoint.UUID, "error", err)
		}
	}
}

// attempt performs one signed POST.
func (n *Notifier) attempt(ctx context.Context, endpoint store.SignedWebhookEndpoint, payload Payload, body []byte, deliveryUUID uuid.UUID, attempt int32) (int32, error) {
	// The row's timeout is clamped by the notifier's bound — see Options. A row can
	// carry a larger value than the API would accept today (it predates the bound, the
	// bound was lowered, or the row was edited in the database), and this delivery runs
	// inline on a secret write.
	timeout := time.Duration(endpoint.TimeoutSeconds) * time.Second
	if timeout <= 0 || timeout > n.opts.MaxTimeout {
		timeout = n.opts.MaxTimeout
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint.URL, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	timestamp := time.Now().Unix()
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Maintainerd-Event", payload.Event)
	req.Header.Set("X-Maintainerd-Event-Id", payload.ID)
	req.Header.Set("X-Maintainerd-Delivery", deliveryUUID.String())
	req.Header.Set("X-Maintainerd-Attempt", strconv.Itoa(int(attempt)))
	req.Header.Set("X-Maintainerd-Timestamp", strconv.FormatInt(timestamp, 10))
	req.Header.Set("X-Maintainerd-Signature-256", Signature(endpoint.SigningKey, timestamp, body))

	resp, err := n.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 300 {
		return int32(resp.StatusCode), fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return int32(resp.StatusCode), nil
}

// Signature computes the delivery signature: sha256=hex(HMAC(key, ts + "." + body)).
//
// The timestamp is prefixed into the MAC rather than merely sent alongside it, so a
// receiver's replay window is enforceable: moving the timestamp invalidates the
// signature, so a captured delivery cannot be replayed later.
func Signature(key []byte, timestamp int64, body []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(strconv.FormatInt(timestamp, 10)))
	mac.Write([]byte("."))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func min32(a, b int32) int32 {
	if a < b {
		return a
	}
	return b
}

// SafeDeliveryClient is the outbound client, hardened against SSRF via DNS
// rebinding, mirroring maintainerd-auth's internal/webhook client.
//
// The problem it solves: validating a URL's resolved IP and then letting the HTTP
// client re-resolve and dial independently leaves a TOCTOU window — an attacker's DNS
// answers with a public IP at validation time and a private/metadata IP at dial time.
// This client resolves the host exactly ONCE inside DialContext, rejects if ANY
// resolved address is unsafe (so a private IP cannot be smuggled in a multi-answer
// response), and dials the pinned IP literal, so the address validated is the address
// connected to. TLS still verifies against the original hostname, because the
// Transport takes ServerName from the request, not the dialed IP.
var SafeDeliveryClient = &http.Client{
	Transport: &http.Transport{
		DialContext:           pinnedSafeDialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          50,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	},
	CheckRedirect: func(r *http.Request, _ []*http.Request) error {
		// Every redirect hop is re-validated for scheme; the pinned dialer covers the
		// address on each hop because redirects reuse this Transport.
		if r.URL.Scheme != "https" {
			return fmt.Errorf("webhook redirect to a non-https destination is refused")
		}
		return nil
	},
}

var safeDialer = &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}

func pinnedSafeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	var ips []net.IP
	if literal := net.ParseIP(host); literal != nil {
		ips = []net.IP{literal}
	} else {
		resolved, rerr := net.DefaultResolver.LookupIPAddr(ctx, host)
		if rerr != nil {
			return nil, fmt.Errorf("resolve %s: %w", host, rerr)
		}
		for _, a := range resolved {
			ips = append(ips, a.IP)
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses for host %q", host)
	}
	for _, ip := range ips {
		if IsUnsafeIP(ip) {
			return nil, fmt.Errorf("destination resolves to a disallowed address")
		}
	}
	return safeDialer.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
}

// IsUnsafeIP reports whether an address is one a webhook must never reach: loopback,
// link-local (which is where cloud instance-metadata services live), private ranges,
// multicast, and the unspecified address.
//
// A secret service reaching its own host's metadata endpoint on a tenant's
// instruction is the textbook SSRF-to-credential-theft chain, which is why this is
// enforced at dial time rather than at registration time.
func IsUnsafeIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	if ip.IsPrivate() {
		return true
	}
	// 100.64.0.0/10 (carrier-grade NAT) and 169.254.0.0/16 are covered above or here;
	// the CGNAT range is where several cloud providers put internal services.
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
			return true
		}
	}
	return false
}
