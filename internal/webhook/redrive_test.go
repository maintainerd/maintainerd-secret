package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/maintainerd/secret/internal/crypto"
	"github.com/maintainerd/secret/internal/platform/apperror"
	"github.com/maintainerd/secret/internal/store"
)

// ---------------------------------------------------------------------------
// Backoff — the schedule
// ---------------------------------------------------------------------------

// TestBackoffDoublesFromTheBaseAndStopsAtTheCap pins the whole schedule as a table
// rather than asserting a shape, because the schedule IS the operational contract:
// it is what decides whether a receiver that was down for a deploy is reached before
// the budget runs out.
func TestBackoffDoublesFromTheBaseAndStopsAtTheCap(t *testing.T) {
	base, max := DefaultRedriveBaseBackoff, DefaultRedriveMaxBackoff

	want := map[int32]time.Duration{
		1: 30 * time.Second,
		2: time.Minute,
		3: 2 * time.Minute,
		4: 4 * time.Minute,
		5: 8 * time.Minute,
		6: 16 * time.Minute,
		7: 32 * time.Minute,
		// 64 minutes would exceed the hour cap, so the cap takes over here and stays.
		8:  time.Hour,
		9:  time.Hour,
		10: time.Hour,
		11: time.Hour,
	}
	for attempt, expected := range want {
		assert.Equal(t, expected, Backoff(base, max, attempt), "attempt %d", attempt)
	}

	// The default budget spans long enough to cover a slow deploy or an expired
	// certificate somebody has to be paged about, and stops well short of retrying
	// forever against an endpoint nobody owns any more.
	var total time.Duration
	for attempt := int32(1); attempt < DefaultRedriveMaxAttempts; attempt++ {
		total += Backoff(base, max, attempt)
	}
	assert.Greater(t, total, 2*time.Hour, "the durable budget must outlast an ordinary deploy")
	assert.Less(t, total, 6*time.Hour, "and must not become a slow poll against a dead endpoint")
}

// TestBackoffIsMonotonicBoundedAndNeverNegative sweeps the whole attempt range rather
// than sampling it. A negative delay would schedule a retry in the PAST, which the
// claim query would then hand back on every tick — a hot loop hammering a receiver
// that is already struggling.
func TestBackoffIsMonotonicBoundedAndNeverNegative(t *testing.T) {
	base, max := DefaultRedriveBaseBackoff, DefaultRedriveMaxBackoff

	var previous time.Duration
	for attempt := int32(1); attempt <= 200; attempt++ {
		got := Backoff(base, max, attempt)
		assert.Positive(t, got, "attempt %d produced a non-positive delay", attempt)
		assert.LessOrEqual(t, got, max, "attempt %d exceeded the cap", attempt)
		assert.GreaterOrEqual(t, got, previous, "attempt %d went backwards", attempt)
		previous = got
	}
}

// TestBackoffSurvivesAnOverflowingExponent. Shifting past 62 overflows int64, and a
// float multiplication that overflowed would land as a negative Duration — a retry
// scheduled in 1970. The cap makes every large attempt identical anyway, so clamping
// costs nothing.
func TestBackoffSurvivesAnOverflowingExponent(t *testing.T) {
	base, max := DefaultRedriveBaseBackoff, DefaultRedriveMaxBackoff

	for _, attempt := range []int32{62, 63, 64, 1000, 1 << 20, 2147483647} {
		got := Backoff(base, max, attempt)
		assert.Equal(t, max, got, "attempt %d must clamp to the cap", attempt)
		assert.Positive(t, got)
	}
}

func TestBackoffHandlesDegenerateConfiguration(t *testing.T) {
	cases := []struct {
		name    string
		base    time.Duration
		max     time.Duration
		attempt int32
		want    time.Duration
	}{
		// An attempt below 1 is treated as the first: the schedule is 1-based, and a
		// zero would otherwise compute a negative exponent.
		{"a zero attempt is the first", time.Second, time.Hour, 0, time.Second},
		{"a negative attempt is the first", time.Second, time.Hour, -5, time.Second},

		// A non-positive base is a misconfiguration, not a request for no delay: a zero
		// delay would spin.
		{"a zero base takes the default", 0, time.Hour, 1, DefaultRedriveBaseBackoff},
		{"a negative base takes the default", -time.Second, time.Hour, 1, DefaultRedriveBaseBackoff},

		// A cap below the base would make the schedule flat at the cap, which is a
		// configuration nobody means. The base wins, because it is the one an operator
		// set deliberately.
		{"a zero cap becomes the base", time.Minute, 0, 5, time.Minute},
		{"a negative cap becomes the base", time.Minute, -time.Hour, 5, time.Minute},
		{"a cap below the base becomes the base", time.Minute, time.Second, 5, time.Minute},
		{"a cap equal to the base is flat", time.Minute, time.Minute, 9, time.Minute},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Backoff(tc.base, tc.max, tc.attempt)
			assert.Equal(t, tc.want, got)
			assert.Positive(t, got, "no configuration may produce a non-positive delay")
		})
	}
}

// ---------------------------------------------------------------------------
// RedriveOptions defaults
// ---------------------------------------------------------------------------

func TestRedriveDefaultsMakeAZeroOptionsWorkable(t *testing.T) {
	opts := RedriveOptions{}.withDefaults()
	assert.Equal(t, DefaultRedriveInterval, opts.Interval)
	assert.Equal(t, DefaultRedriveBatch, opts.Batch)
	assert.EqualValues(t, DefaultRedriveMaxAttempts, opts.MaxAttempts)
	assert.Equal(t, DefaultRedriveBaseBackoff, opts.BaseBackoff)
	assert.Equal(t, DefaultRedriveMaxBackoff, opts.MaxBackoff)
	assert.Equal(t, DefaultRedriveLease, opts.Lease)
	assert.Equal(t, DefaultMaxTimeout, opts.MaxTimeout)
	assert.False(t, opts.Enabled, "Enabled is the one field a zero value must not turn on")

	// The tick is far finer than the backoff schedule, so a delivery becomes due and is
	// picked up within one tick rather than waiting out a coarse scan.
	assert.Less(t, opts.Interval, opts.BaseBackoff+time.Second)
}

// TestTheClaimLeaseAlwaysOutlastsOneAttempt. The lease has to outlast an attempt or
// the row becomes claimable again while THIS process is still posting it — which is a
// concurrent second POST to a customer's endpoint, from the same replica.
func TestTheClaimLeaseAlwaysOutlastsOneAttempt(t *testing.T) {
	cases := []RedriveOptions{
		{},
		{MaxTimeout: 30 * time.Second},
		{MaxTimeout: 5 * time.Minute},
		{Lease: time.Second, MaxTimeout: 30 * time.Second},
		{Lease: 30 * time.Second, MaxTimeout: 30 * time.Second},
		{Lease: time.Hour, MaxTimeout: time.Minute},
		{Lease: -time.Second, MaxTimeout: -time.Second},
	}
	for i, in := range cases {
		opts := in.withDefaults()
		assert.Greater(t, opts.Lease, opts.MaxTimeout,
			"case %d: a lease of %s cannot cover an attempt of %s", i, opts.Lease, opts.MaxTimeout)
	}

	// Widened rather than refused: this is a DERIVED bound, and a boot error for it
	// would be a boot error an operator cannot act on from the message alone.
	opts := RedriveOptions{Lease: time.Second, MaxTimeout: time.Minute}.withDefaults()
	assert.Equal(t, 2*time.Minute, opts.Lease)
}

func TestTheBackoffCapIsNeverBelowTheBase(t *testing.T) {
	opts := RedriveOptions{BaseBackoff: time.Minute, MaxBackoff: time.Second}.withDefaults()
	assert.Equal(t, time.Minute, opts.BaseBackoff)
	assert.Equal(t, time.Minute, opts.MaxBackoff, "the base an operator set deliberately wins")
}

// ---------------------------------------------------------------------------
// A fake store
// ---------------------------------------------------------------------------

// fakeRedriveStore is an in-memory RedriveStore. The interface is deliberately narrow
// — a worker that could reach the secret store could reach a value, and this one must
// never need to — so the fake is small.
type fakeRedriveStore struct {
	mu sync.Mutex

	claim    []store.RedriveDelivery
	claimErr error
	// claimCalls counts passes, so a tick can be observed without a sleep.
	claimCalls int
	// sawLimit and sawLease record what the worker asked for.
	sawLimit int
	sawLease time.Duration

	endpoint    *store.SignedWebhookEndpoint
	endpointErr error

	// outcomes records every RecordRedriveOutcome, which is the durable record the
	// whole worker exists to produce.
	outcomes  []recordedOutcome
	abandoned []string
	touched   []int64

	backlog    int64
	backlogErr error
}

type recordedOutcome struct {
	deliveryID     int64
	status         string
	responseStatus *int32
	failure        string
	nextAttempt    *time.Time
}

var _ RedriveStore = (*fakeRedriveStore)(nil)

func (f *fakeRedriveStore) ClaimDeliveriesForRedrive(_ context.Context, limit int, lease time.Duration) ([]store.RedriveDelivery, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.claimCalls++
	f.sawLimit, f.sawLease = limit, lease
	if f.claimErr != nil {
		return nil, f.claimErr
	}
	out := f.claim
	f.claim = nil
	return out, nil
}

func (f *fakeRedriveStore) SignedEndpointByID(_ context.Context, _ int64) (*store.SignedWebhookEndpoint, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.endpointErr != nil {
		return nil, f.endpointErr
	}
	// A FRESH COPY per call, because attemptOne zeroizes the signing key when it is
	// done — handing back the same struct twice would post the second attempt with a
	// key of zero bytes.
	copied := *f.endpoint
	copied.SigningKey = crypto.Plaintext(bytes.Clone(f.endpoint.SigningKey))
	return &copied, nil
}

func (f *fakeRedriveStore) RecordRedriveOutcome(_ context.Context, deliveryID int64, status string, responseStatus *int32, failure string, nextAttempt *time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.outcomes = append(f.outcomes, recordedOutcome{deliveryID, status, responseStatus, failure, nextAttempt})
	return nil
}

func (f *fakeRedriveStore) AbandonDelivery(_ context.Context, _ int64, reason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.abandoned = append(f.abandoned, reason)
	return nil
}

func (f *fakeRedriveStore) CountDeliveriesAwaitingRedrive(context.Context) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.backlog, f.backlogErr
}

func (f *fakeRedriveStore) TouchWebhookEndpoint(_ context.Context, endpointID int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.touched = append(f.touched, endpointID)
	return nil
}

func (f *fakeRedriveStore) recorded() []recordedOutcome {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recordedOutcome(nil), f.outcomes...)
}

func (f *fakeRedriveStore) passes() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.claimCalls
}

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

// testSigningKey is the endpoint's HMAC key.
var testSigningKey = []byte("a-32-byte-webhook-signing-key!!!")

// storedPayload is a payload as the FIRST attempt marshalled and stored it. Note it is
// built through Payload, so it has nowhere to put a credential.
func storedPayload(t *testing.T) []byte {
	t.Helper()
	body, err := json.Marshal(Payload{
		ID:         "5f9c1a2b-0000-4000-8000-00000000beef",
		Event:      store.WebhookEventSecretRotated,
		Resource:   "mrn:secret:acme:billing-app:secret/prod/db/PASSWORD",
		Version:    7,
		Tenant:     "acme",
		Project:    "billing-app",
		OccurredAt: "2026-08-22T12:00:00Z",
	})
	require.NoError(t, err)
	return body
}

// newTestRedriver builds a worker over the fake store, pointed at srv.
//
// THE CLIENT IS REPLACED DELIBERATELY. SafeDeliveryClient refuses loopback and every
// private range — that is the SSRF guard, and it is tested in webhook_test.go — so an
// httptest server on 127.0.0.1 is by design unreachable through it. Swapping in a
// plain client is what lets the DELIVERY logic be tested; it does not weaken the guard
// the production constructor applies.
func newTestRedriver(st RedriveStore, srv *httptest.Server, opts RedriveOptions) *Redriver {
	opts.Enabled = true
	r := NewRedriver(st, opts)
	r.client = srv.Client()
	return r
}

// capturingServer records exactly what each request carried.
type capturedRequest struct {
	body    []byte
	headers http.Header
}

func capturingServer(t *testing.T, status func(n int) int) (*httptest.Server, func() []capturedRequest) {
	t.Helper()
	var (
		mu       sync.Mutex
		captured []capturedRequest
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		mu.Lock()
		captured = append(captured, capturedRequest{body: body, headers: r.Header.Clone()})
		n := len(captured)
		mu.Unlock()
		w.WriteHeader(status(n))
	}))
	t.Cleanup(srv.Close)
	return srv, func() []capturedRequest {
		mu.Lock()
		defer mu.Unlock()
		return append([]capturedRequest(nil), captured...)
	}
}

func testDelivery(t *testing.T, redriveAttempts int32) store.RedriveDelivery {
	t.Helper()
	return store.RedriveDelivery{
		ID:              42,
		UUID:            uuid.MustParse("11111111-2222-4333-8444-555555555555"),
		EndpointID:      7,
		TenantUUID:      uuid.MustParse("6f1a0a1e-0000-4000-8000-000000000001"),
		EventType:       store.WebhookEventSecretRotated,
		Payload:         storedPayload(t),
		RedriveAttempts: redriveAttempts,
		AttemptCount:    3,
		ResourceMRN:     "mrn:secret:acme:billing-app:secret/prod/db/PASSWORD",
	}
}

func testStore(t *testing.T, srv *httptest.Server, delivery store.RedriveDelivery) *fakeRedriveStore {
	t.Helper()
	return &fakeRedriveStore{
		claim: []store.RedriveDelivery{delivery},
		endpoint: &store.SignedWebhookEndpoint{
			ID:             7,
			UUID:           uuid.MustParse("99999999-0000-4000-8000-000000000007"),
			URL:            srv.URL,
			TimeoutSeconds: 5,
			MaxAttempts:    3,
			SigningKey:     crypto.Plaintext(bytes.Clone(testSigningKey)),
		},
	}
}

// ---------------------------------------------------------------------------
// The replay itself
// ---------------------------------------------------------------------------

// TestTheReplayedPayloadIsByteIdenticalToTheStoredOne is the property the re-drive
// contract turns on.
//
// Re-marshalling the payload would risk delivering something subtly different from
// what was announced — Postgres normalises JSONB, so a round trip can reorder keys or
// change number formatting — and then two things break at once: the delivery log stops
// being a record of what was actually sent, and the MAC covers bytes the receiver
// never saw. Replaying verbatim and signing AS SENT makes both exact.
func TestTheReplayedPayloadIsByteIdenticalToTheStoredOne(t *testing.T) {
	srv, requests := capturingServer(t, func(int) int { return http.StatusOK })
	delivery := testDelivery(t, 0)
	st := testStore(t, srv, delivery)

	require.NoError(t, newTestRedriver(st, srv, RedriveOptions{}).Tick(context.Background()))

	got := requests()
	require.Len(t, got, 1)
	assert.True(t, bytes.Equal(delivery.Payload, got[0].body),
		"the replay must be the stored bytes, not a re-marshalling of them")
	// Byte-for-byte, including whatever key order the first marshalling produced.
	assert.Equal(t, string(delivery.Payload), string(got[0].body))
}

// TestTheReplayIsSignedOverExactlyTheBytesOnTheWire. The signature is recomputed
// (over a FRESH timestamp, so a receiver's replay window stays enforceable and a retry
// arriving an hour later is not rejected as stale) but it must cover the bytes actually
// sent — otherwise every retry fails verification at the receiver and the re-drive
// loop is worse than useless.
func TestTheReplayIsSignedOverExactlyTheBytesOnTheWire(t *testing.T) {
	srv, requests := capturingServer(t, func(int) int { return http.StatusOK })
	st := testStore(t, srv, testDelivery(t, 0))

	require.NoError(t, newTestRedriver(st, srv, RedriveOptions{}).Tick(context.Background()))

	got := requests()
	require.Len(t, got, 1)

	timestamp, err := strconv.ParseInt(got[0].headers.Get("X-Maintainerd-Timestamp"), 10, 64)
	require.NoError(t, err, "the timestamp header must be parseable, or no receiver can verify")
	assert.Equal(t,
		Signature(testSigningKey, timestamp, got[0].body),
		got[0].headers.Get("X-Maintainerd-Signature-256"),
		"the MAC must cover the timestamp that was sent and the body that was sent")

	// A fresh timestamp, not the stored one: the retry must not look stale.
	assert.InDelta(t, time.Now().Unix(), timestamp, 60,
		"the signed timestamp must be the retry's, so the receiver's replay window admits it")
}

// TestTheReplayedPayloadStillCarriesNoSecretValue. The inline path asserts this
// structurally (Payload has nowhere to put a credential); the worker inherits it for
// free by replaying the stored bytes rather than rebuilding them. Asserting it here is
// what keeps a future change that enriches the retry body from quietly breaking it.
func TestTheReplayedPayloadStillCarriesNoSecretValue(t *testing.T) {
	const value = "sup3r-s3cret-value"

	srv, requests := capturingServer(t, func(int) int { return http.StatusOK })
	st := testStore(t, srv, testDelivery(t, 0))
	require.NoError(t, newTestRedriver(st, srv, RedriveOptions{}).Tick(context.Background()))

	got := requests()
	require.Len(t, got, 1)
	assert.NotContains(t, string(got[0].body), value)

	// No field that could hold one, either — the same structural check the inline path
	// makes, applied to what actually went out on the retry.
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(got[0].body, &decoded))
	for key := range decoded {
		assert.NotContains(t, key, "value")
		assert.NotContains(t, key, "plaintext")
		assert.NotContains(t, key, "password")
		assert.NotContains(t, key, "secret_")
	}
	// And the signing key must not be echoed into the body or a header either.
	assert.NotContains(t, string(got[0].body), string(testSigningKey))
	for _, values := range got[0].headers {
		for _, v := range values {
			assert.NotContains(t, v, string(testSigningKey))
		}
	}
}

// TestARetryCarriesTheOriginalEventIDSoAReceiverCanDeduplicate. The event id is what a
// receiver de-duplicates on, so a retry that invented a new one would be processed as
// a second, distinct notification — the exact duplicate-processing the id exists to
// prevent.
func TestARetryCarriesTheOriginalEventIDSoAReceiverCanDeduplicate(t *testing.T) {
	srv, requests := capturingServer(t, func(int) int { return http.StatusOK })
	delivery := testDelivery(t, 0)
	st := testStore(t, srv, delivery)

	require.NoError(t, newTestRedriver(st, srv, RedriveOptions{}).Tick(context.Background()))

	var stored Payload
	require.NoError(t, json.Unmarshal(delivery.Payload, &stored))

	got := requests()
	require.Len(t, got, 1)
	assert.Equal(t, stored.ID, got[0].headers.Get("X-Maintainerd-Event-Id"),
		"the id must be read back out of the stored body, not regenerated")
	assert.Equal(t, delivery.UUID.String(), got[0].headers.Get("X-Maintainerd-Delivery"))
	assert.Equal(t, delivery.EventType, got[0].headers.Get("X-Maintainerd-Event"))
	// The attempt number continues the row's own count rather than restarting at 1, so
	// a receiver logging the header sees one sequence per delivery.
	assert.Equal(t, strconv.Itoa(int(delivery.AttemptCount+1)), got[0].headers.Get("X-Maintainerd-Attempt"))
	assert.Equal(t, "application/json", got[0].headers.Get("Content-Type"))
}

// TestAnUnreadablePayloadStillDelivers. An unreadable body yields an EMPTY event-id
// header rather than a failed delivery: the body is still what matters, and the id is
// also inside it.
func TestAnUnreadablePayloadStillDelivers(t *testing.T) {
	srv, requests := capturingServer(t, func(int) int { return http.StatusOK })
	delivery := testDelivery(t, 0)
	delivery.Payload = []byte("this is not json")
	st := testStore(t, srv, delivery)

	require.NoError(t, newTestRedriver(st, srv, RedriveOptions{}).Tick(context.Background()))

	got := requests()
	require.Len(t, got, 1)
	assert.Equal(t, "this is not json", string(got[0].body), "the stored bytes go out regardless")
	assert.Empty(t, got[0].headers.Get("X-Maintainerd-Event-Id"))
}

// TestAnEmptyStoredPayloadIsNotPosted. There is nothing to replay, and posting an
// empty body would be a signed delivery announcing nothing.
func TestAnEmptyStoredPayloadIsNotPosted(t *testing.T) {
	srv, requests := capturingServer(t, func(int) int { return http.StatusOK })
	delivery := testDelivery(t, 0)
	delivery.Payload = nil
	st := testStore(t, srv, delivery)

	require.NoError(t, newTestRedriver(st, srv, RedriveOptions{}).Tick(context.Background()))

	assert.Empty(t, requests(), "an empty payload must not reach the endpoint")
	outcomes := st.recorded()
	require.Len(t, outcomes, 1)
	assert.Equal(t, store.WebhookDeliveryRetrying, outcomes[0].status)
	assert.Contains(t, outcomes[0].failure, "nothing to replay")
}

// ---------------------------------------------------------------------------
// Outcomes
// ---------------------------------------------------------------------------

// TestASuccessfulRetryIsRecordedAsSuccessAndClearsTheSchedule. nextAttempt must be nil
// on a terminal row — the table's CHECK constraint refuses a schedule on one, so
// getting this wrong is a loud error rather than a duplicate delivery to a customer.
func TestASuccessfulRetryIsRecordedAsSuccessAndClearsTheSchedule(t *testing.T) {
	srv, _ := capturingServer(t, func(int) int { return http.StatusNoContent })
	st := testStore(t, srv, testDelivery(t, 0))

	require.NoError(t, newTestRedriver(st, srv, RedriveOptions{}).Tick(context.Background()))

	outcomes := st.recorded()
	require.Len(t, outcomes, 1)
	assert.Equal(t, store.WebhookDeliverySuccess, outcomes[0].status)
	assert.Nil(t, outcomes[0].nextAttempt, "a terminal row must carry no schedule")
	assert.Empty(t, outcomes[0].failure)
	require.NotNil(t, outcomes[0].responseStatus)
	assert.EqualValues(t, http.StatusNoContent, *outcomes[0].responseStatus)

	// last_triggered_at is advanced only on a real delivery.
	assert.Equal(t, []int64{7}, st.touched)
}

// TestAFailedRetryWithinBudgetIsRescheduledOnTheBackoff.
func TestAFailedRetryWithinBudgetIsRescheduledOnTheBackoff(t *testing.T) {
	srv, _ := capturingServer(t, func(int) int { return http.StatusInternalServerError })
	// Two worker attempts already spent, so this is the third of ten.
	st := testStore(t, srv, testDelivery(t, 2))

	before := time.Now()
	require.NoError(t, newTestRedriver(st, srv, RedriveOptions{}).Tick(context.Background()))

	outcomes := st.recorded()
	require.Len(t, outcomes, 1)
	assert.Equal(t, store.WebhookDeliveryRetrying, outcomes[0].status)
	require.NotNil(t, outcomes[0].nextAttempt, "a retrying row must carry the schedule the worker will honour")
	assert.Contains(t, outcomes[0].failure, "500")
	require.NotNil(t, outcomes[0].responseStatus)
	assert.EqualValues(t, http.StatusInternalServerError, *outcomes[0].responseStatus)

	// Scheduled on the third attempt's delay, which is base doubled twice.
	want := Backoff(DefaultRedriveBaseBackoff, DefaultRedriveMaxBackoff, 3)
	assert.WithinDuration(t, before.Add(want), *outcomes[0].nextAttempt, 5*time.Second)

	// last_triggered_at must NOT move on a failure.
	assert.Empty(t, st.touched)
}

// TestBudgetExhaustionMarksTheDeliveryPermanentlyFailed. The row becoming permanently
// failed is the honest record: the consumer was never told, and somebody has to know
// that — it is the row an operator greps for.
func TestBudgetExhaustionMarksTheDeliveryPermanentlyFailed(t *testing.T) {
	srv, requests := capturingServer(t, func(int) int { return http.StatusBadGateway })
	// The last attempt in the default budget.
	st := testStore(t, srv, testDelivery(t, DefaultRedriveMaxAttempts-1))

	require.NoError(t, newTestRedriver(st, srv, RedriveOptions{}).Tick(context.Background()))

	// The final attempt IS made before the budget is declared spent, so the budget is
	// ten real attempts rather than nine.
	assert.Len(t, requests(), 1)

	outcomes := st.recorded()
	require.Len(t, outcomes, 1)
	assert.Equal(t, store.WebhookDeliveryFailed, outcomes[0].status)
	assert.Nil(t, outcomes[0].nextAttempt, "a permanently failed row must not be rescheduled forever")
	assert.Contains(t, outcomes[0].failure, "permanently failed after")
	assert.Contains(t, outcomes[0].failure, strconv.Itoa(int(DefaultRedriveMaxAttempts)))
}

// TestTheBudgetIsExactlyMaxAttemptsWorkerTries walks the whole budget one attempt at a
// time, because an off-by-one here either gives up a retry early or retries forever.
func TestTheBudgetIsExactlyMaxAttemptsWorkerTries(t *testing.T) {
	const budget = 4

	for spent := int32(0); spent < budget; spent++ {
		srv, requests := capturingServer(t, func(int) int { return http.StatusInternalServerError })
		st := testStore(t, srv, testDelivery(t, spent))
		require.NoError(t, newTestRedriver(st, srv, RedriveOptions{MaxAttempts: budget}).Tick(context.Background()))

		outcomes := st.recorded()
		require.Len(t, outcomes, 1)
		assert.Len(t, requests(), 1, "every attempt within the budget must really be posted")

		if spent == budget-1 {
			assert.Equal(t, store.WebhookDeliveryFailed, outcomes[0].status,
				"attempt %d of %d must be the last", spent+1, budget)
		} else {
			assert.Equal(t, store.WebhookDeliveryRetrying, outcomes[0].status,
				"attempt %d of %d must still be within budget", spent+1, budget)
		}
	}
}

// TestADeletedEndpointAbandonsTheDeliveryWithoutSpendingAnAttempt. An operator who
// removed an endpoint has said they no longer want its notifications, INCLUDING the
// backlog — so this is terminal rather than a retry, and it does not consume budget.
func TestADeletedEndpointAbandonsTheDeliveryWithoutSpendingAnAttempt(t *testing.T) {
	srv, requests := capturingServer(t, func(int) int { return http.StatusOK })
	st := testStore(t, srv, testDelivery(t, 0))
	st.endpointErr = apperror.NewNotFound("webhook endpoint")

	require.NoError(t, newTestRedriver(st, srv, RedriveOptions{}).Tick(context.Background()))

	assert.Empty(t, requests(), "a withdrawn endpoint must not be posted to")
	require.Len(t, st.abandoned, 1)
	assert.Contains(t, st.abandoned[0], "deleted")
	assert.Empty(t, st.recorded(), "abandoning must not spend a re-drive attempt")
}

// TestATransientEndpointFailureKeepsTheDeliveryScheduled. A root key this process was
// not given, or a database blip, is a CONFIGURATION GAP rather than a dead delivery:
// the row keeps its lease and succeeds once the operator supplies the key. Treating it
// as terminal would silently discard a backlog an operator could still have delivered.
func TestATransientEndpointFailureKeepsTheDeliveryScheduled(t *testing.T) {
	srv, requests := capturingServer(t, func(int) int { return http.StatusOK })
	st := testStore(t, srv, testDelivery(t, 0))
	st.endpointErr = apperror.NewUnavailable("the webhook signing key is wrapped under a root key this process does not hold")

	require.NoError(t, newTestRedriver(st, srv, RedriveOptions{}).Tick(context.Background()))

	assert.Empty(t, requests())
	assert.Empty(t, st.abandoned, "a transient failure must not be terminal")
	assert.Empty(t, st.recorded(), "and must not spend an attempt either — the claim lease re-exposes the row")
}

// ---------------------------------------------------------------------------
// Tick
// ---------------------------------------------------------------------------

// TestTickIsANoOpWhenTheWorkerIsOff. An operator stopping re-drive during an incident
// on a receiver wants the ROWS PRESERVED, so delivery resumes when they turn it back
// on — the switch must not drain or discard the backlog.
func TestTickIsANoOpWhenTheWorkerIsOff(t *testing.T) {
	srv, requests := capturingServer(t, func(int) int { return http.StatusOK })
	st := testStore(t, srv, testDelivery(t, 0))

	disabled := NewRedriver(st, RedriveOptions{Enabled: false})
	disabled.client = srv.Client()

	assert.False(t, disabled.Enabled())
	require.NoError(t, disabled.Tick(context.Background()))
	assert.Zero(t, st.passes(), "a disabled worker must not even claim")
	assert.Empty(t, requests())
	assert.Empty(t, st.recorded(), "the backlog must be preserved untouched")
}

func TestEnabledRequiresAStore(t *testing.T) {
	assert.False(t, NewRedriver(nil, RedriveOptions{Enabled: true}).Enabled(),
		"a worker with no store cannot run, whatever the flag says")
	var nilRedriver *Redriver
	assert.False(t, nilRedriver.Enabled())
	assert.Equal(t, DefaultRedriveInterval, nilRedriver.Interval(),
		"a nil worker must still answer the interval question the scheduler asks")
}

// TestTickReturnsOnlyAWholePassFailure. A single delivery that could not be attempted
// is recorded on its own row and does not fail the pass — the point of a re-drive loop
// is that one broken endpoint cannot stop the others.
func TestTickReturnsOnlyAWholePassFailure(t *testing.T) {
	srv, _ := capturingServer(t, func(int) int { return http.StatusOK })

	t.Run("the claim query failing fails the pass", func(t *testing.T) {
		st := &fakeRedriveStore{claimErr: errors.New("connection refused")}
		err := newTestRedriver(st, srv, RedriveOptions{}).Tick(context.Background())
		require.Error(t, err, "the pass could not happen at all, so the caller must know")
	})

	t.Run("one failing delivery does not fail the pass", func(t *testing.T) {
		bad, _ := capturingServer(t, func(int) int { return http.StatusTeapot })
		st := testStore(t, bad, testDelivery(t, 0))
		assert.NoError(t, newTestRedriver(st, bad, RedriveOptions{}).Tick(context.Background()))
		assert.Len(t, st.recorded(), 1)
	})

	t.Run("an empty claim is not an error", func(t *testing.T) {
		st := &fakeRedriveStore{}
		assert.NoError(t, newTestRedriver(st, srv, RedriveOptions{}).Tick(context.Background()))
	})

	t.Run("a failing backlog count does not fail the pass", func(t *testing.T) {
		// The backlog is a log field, not a decision input — losing it must not lose the
		// pass that already delivered.
		st := testStore(t, srv, testDelivery(t, 0))
		st.backlogErr = errors.New("count failed")
		assert.NoError(t, newTestRedriver(st, srv, RedriveOptions{}).Tick(context.Background()))
		assert.Len(t, st.recorded(), 1)
	})
}

// TestTickPassesItsBatchAndLeaseToTheClaim. The claim IS the concurrency control: it
// runs FOR UPDATE SKIP LOCKED and pushes next_attempt_at forward by the lease before
// any attempt is made, so two replicas ticking at the same instant take disjoint
// batches. A worker that failed to pass the lease through would break that.
func TestTickPassesItsBatchAndLeaseToTheClaim(t *testing.T) {
	srv, _ := capturingServer(t, func(int) int { return http.StatusOK })
	st := &fakeRedriveStore{}

	r := newTestRedriver(st, srv, RedriveOptions{Batch: 11, Lease: 3 * time.Minute})
	require.NoError(t, r.Tick(context.Background()))

	st.mu.Lock()
	defer st.mu.Unlock()
	assert.Equal(t, 11, st.sawLimit)
	assert.Equal(t, 3*time.Minute, st.sawLease)
}

// TestTickStopsMidBatchOnCancellation. Continuing into a cancelled context would post
// with a dead deadline; the remaining claims simply expire and are picked up by the
// next pass or the next replica, so nothing is lost by stopping.
func TestTickStopsMidBatchOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	var posts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		posts++
		// Cancel after the first delivery, mid-batch.
		cancel()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	st := testStore(t, srv, testDelivery(t, 0))
	st.claim = []store.RedriveDelivery{
		testDelivery(t, 0), testDelivery(t, 0), testDelivery(t, 0), testDelivery(t, 0),
	}

	require.NoError(t, newTestRedriver(st, srv, RedriveOptions{}).Tick(ctx))
	assert.Equal(t, 1, posts, "the pass must stop rather than post the rest on a dead context")
}

// TestTickHonoursAnAlreadyCancelledContext.
func TestTickHonoursAnAlreadyCancelledContext(t *testing.T) {
	srv, requests := capturingServer(t, func(int) int { return http.StatusOK })
	st := testStore(t, srv, testDelivery(t, 0))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	require.NoError(t, newTestRedriver(st, srv, RedriveOptions{}).Tick(ctx))
	assert.Zero(t, st.passes(), "a dead context must not even claim a batch")
	assert.Empty(t, requests())
}

// ---------------------------------------------------------------------------
// Attempt timeouts
// ---------------------------------------------------------------------------

// TestOneAttemptIsCappedByMaxTimeout. A row can carry a larger timeout than the API
// would accept today — it predates the bound, an operator lowered the bound, or the
// row was edited in the database — so the worker clamps whatever the endpoint asks
// for. Without it, one slow receiver holds a worker slot for as long as it likes.
func TestOneAttemptIsCappedByMaxTimeout(t *testing.T) {
	// The handler blocks on a channel THIS TEST closes rather than on the request
	// context: a client-side deadline does not reliably cancel the server's request
	// context here, so waiting on it would hang Close and the whole package with it.
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		select {
		case <-release:
		case <-time.After(10 * time.Second): // belt, so a handler can never wedge the suite
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer func() { close(release); srv.Close() }()

	st := testStore(t, srv, testDelivery(t, 0))
	// The row asks for an hour; the worker's bound is what actually applies.
	st.endpoint.TimeoutSeconds = 3600

	start := time.Now()
	require.NoError(t, newTestRedriver(st, srv, RedriveOptions{MaxTimeout: 150 * time.Millisecond}).
		Tick(context.Background()))
	elapsed := time.Since(start)

	assert.Less(t, elapsed, 5*time.Second, "the endpoint's hour must not be honoured")
	assert.GreaterOrEqual(t, elapsed, 150*time.Millisecond, "and the bound must actually have been waited out")

	outcomes := st.recorded()
	require.Len(t, outcomes, 1)
	assert.Equal(t, store.WebhookDeliveryRetrying, outcomes[0].status,
		"a timed-out attempt is a failure within budget, so the delivery stays scheduled")
	assert.Nil(t, outcomes[0].responseStatus, "a timeout produced no status to record")
}

// TestAnEndpointAskingForNoTimeoutTakesTheBound. A zero or negative value on the row
// is a misconfiguration, not a request for an unbounded attempt.
func TestAnEndpointAskingForNoTimeoutTakesTheBound(t *testing.T) {
	for _, seconds := range []int32{0, -1} {
		srv, requests := capturingServer(t, func(int) int { return http.StatusOK })
		st := testStore(t, srv, testDelivery(t, 0))
		st.endpoint.TimeoutSeconds = seconds

		require.NoError(t, newTestRedriver(st, srv, RedriveOptions{}).Tick(context.Background()))
		assert.Len(t, requests(), 1, "TimeoutSeconds=%d must still deliver", seconds)
	}
}

// ---------------------------------------------------------------------------
// Response classification
// ---------------------------------------------------------------------------

// TestOnlyA2xxCountsAsDelivered. A 3xx is not a delivery: the receiver did not accept
// the notification, it pointed somewhere else — and treating it as success would close
// a row whose consumer was never told.
func TestOnlyA2xxCountsAsDelivered(t *testing.T) {
	cases := map[int]string{
		http.StatusOK:                  store.WebhookDeliverySuccess,
		http.StatusCreated:             store.WebhookDeliverySuccess,
		http.StatusAccepted:            store.WebhookDeliverySuccess,
		http.StatusNoContent:           store.WebhookDeliverySuccess,
		http.StatusMultipleChoices:     store.WebhookDeliveryRetrying,
		http.StatusMovedPermanently:    store.WebhookDeliveryRetrying,
		http.StatusBadRequest:          store.WebhookDeliveryRetrying,
		http.StatusUnauthorized:        store.WebhookDeliveryRetrying,
		http.StatusNotFound:            store.WebhookDeliveryRetrying,
		http.StatusTooManyRequests:     store.WebhookDeliveryRetrying,
		http.StatusInternalServerError: store.WebhookDeliveryRetrying,
		http.StatusServiceUnavailable:  store.WebhookDeliveryRetrying,
	}
	for status, want := range cases {
		t.Run(fmt.Sprintf("status %d", status), func(t *testing.T) {
			srv, _ := capturingServer(t, func(int) int { return status })
			st := testStore(t, srv, testDelivery(t, 0))
			require.NoError(t, newTestRedriver(st, srv, RedriveOptions{}).Tick(context.Background()))

			outcomes := st.recorded()
			require.Len(t, outcomes, 1)
			assert.Equal(t, want, outcomes[0].status)
			require.NotNil(t, outcomes[0].responseStatus,
				"the receiver's status must be recorded either way, so an operator can see what it said")
			assert.EqualValues(t, status, *outcomes[0].responseStatus)
		})
	}
}
