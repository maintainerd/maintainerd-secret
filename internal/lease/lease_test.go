package lease

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// The clock
// ---------------------------------------------------------------------------
//
// EVERY TIME IN THIS FILE IS DERIVED FROM `now`. This package takes Now as an input
// precisely so a test needs no stopwatch and a production path cannot disagree with
// the database about what time it is; a test that reached for time.Now() would
// reintroduce the flake the design removed, and would make a boundary assertion
// ("expiry exactly at this instant") impossible to write at all.

// now is the fixed instant every case is expressed relative to.
func now() time.Time { return time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC) }

// at returns an instant offset from now, as a pointer for the optional fields.
func at(d time.Duration) *time.Time {
	t := now().Add(d)
	return &t
}

// ---------------------------------------------------------------------------
// Policy.Enabled — the opt-in
// ---------------------------------------------------------------------------

// TestAZeroPolicyMeansNoLease is the single most important property here. A feature
// that silently started gating every read in the store would be an outage, not a
// feature: a secret nobody configured must behave exactly as it did before this
// package existed.
func TestAZeroPolicyMeansNoLease(t *testing.T) {
	assert.False(t, Policy{}.Enabled(), "an unconfigured secret is not lease-governed")

	// A cap or a ceiling WITHOUT a TTL is still no policy: the TTL is the switch, so a
	// half-filled row cannot accidentally start gating reads.
	assert.False(t, Policy{MaxReads: 5}.Enabled())
	assert.False(t, Policy{MaxTTL: time.Hour}.Enabled())
	assert.False(t, Policy{MaxReads: 5, MaxTTL: time.Hour}.Enabled())
	assert.False(t, Policy{TTL: -time.Hour}.Enabled(), "a negative TTL is not an enabled policy")

	assert.True(t, Policy{TTL: time.Nanosecond}.Enabled(), "any positive TTL opts the secret in")
	assert.True(t, Policy{TTL: time.Hour}.Enabled())
}

// TestAnUnconfiguredSecretIsServedWithoutALease. The honest answer for a caller that
// should not have asked is "consume nothing", not a refusal — a refusal here would
// break every existing consumer of an unleased secret.
func TestAnUnconfiguredSecretIsServedWithoutALease(t *testing.T) {
	decision, reason := Evaluate(Request{Policy: Policy{}, Now: now()})
	assert.Equal(t, Consume, decision)
	assert.Empty(t, reason)

	// Even an already-expired secret and an exhausted lease do not change the answer:
	// with no policy, none of this machinery applies.
	decision, reason = Evaluate(Request{
		Policy:          Policy{},
		Existing:        &State{ExpiresAt: now().Add(-time.Hour), MaxReads: 1, ReadsUsed: 99},
		SecretExpiresAt: at(-time.Hour),
		Now:             now(),
	})
	assert.Equal(t, Consume, decision, "no policy must mean unchanged behaviour, whatever else is true")
	assert.Empty(t, reason)
}

// ---------------------------------------------------------------------------
// ResolveTTL
// ---------------------------------------------------------------------------

// TestResolveTTLRefusesAnOverLongRequestRatherThanClamping. Clamping is the tempting
// choice and the wrong one: a caller that asked for 24 hours and silently got one
// believes it has 24 hours, and finds out mid-shift when its credential stops
// working — then looks everywhere except at the request it made.
func TestResolveTTLRefusesAnOverLongRequestRatherThanClamping(t *testing.T) {
	policy := Policy{TTL: time.Hour, MaxTTL: 6 * time.Hour}

	_, err := policy.ResolveTTL(24 * time.Hour)
	require.Error(t, err)
	// The message must name both numbers, or the caller cannot fix its request.
	assert.Contains(t, err.Error(), "24h")
	assert.Contains(t, err.Error(), "6h")
}

func TestResolveTTLBoundaries(t *testing.T) {
	cases := []struct {
		name      string
		policy    Policy
		requested time.Duration
		want      time.Duration
		wantErr   bool
	}{
		// A zero or absent request takes the policy's TTL. This is the common path —
		// most callers never name a TTL at all.
		{"an absent request takes the policy TTL", Policy{TTL: 30 * time.Minute}, 0, 30 * time.Minute, false},
		{"a negative request takes the policy TTL", Policy{TTL: 30 * time.Minute}, -time.Hour, 30 * time.Minute, false},
		// A policy with no TTL can never produce an already-expired lease: the default
		// stands in. (Enabled() is false for such a policy, so this is the defensive
		// half of that guarantee rather than a reachable path today.)
		{"a policy with no TTL falls back to the default", Policy{}, 0, DefaultTTL, false},

		// THE CEILING. An absent MaxTTL must never be read as an unbounded one — that
		// is the difference between "the operator set no ceiling" and "the operator
		// permitted anything", and only one of them is safe.
		{"an absent ceiling is the TTL, not infinity", Policy{TTL: time.Hour}, 2 * time.Hour, 0, true},
		{"a zero ceiling is the TTL", Policy{TTL: time.Hour, MaxTTL: 0}, 90 * time.Minute, 0, true},
		{"a negative ceiling is the TTL", Policy{TTL: time.Hour, MaxTTL: -time.Hour}, 90 * time.Minute, 0, true},

		// Exactly at the ceiling is permitted; one nanosecond past it is not. An
		// off-by-one here is the difference between an operator's documented maximum
		// working and silently failing.
		{"exactly at the ceiling", Policy{TTL: time.Hour, MaxTTL: 6 * time.Hour}, 6 * time.Hour, 6 * time.Hour, false},
		{"one nanosecond past the ceiling", Policy{TTL: time.Hour, MaxTTL: 6 * time.Hour}, 6*time.Hour + time.Nanosecond, 0, true},
		{"one nanosecond under the ceiling", Policy{TTL: time.Hour, MaxTTL: 6 * time.Hour}, 6*time.Hour - time.Nanosecond, 6*time.Hour - time.Nanosecond, false},
		{"exactly at the TTL when it is the ceiling", Policy{TTL: time.Hour}, time.Hour, time.Hour, false},

		// A request BELOW the policy TTL is honoured: a caller asking for less is
		// asking for a tighter bound on itself, which is never something to refuse.
		{"a shorter request is honoured", Policy{TTL: time.Hour, MaxTTL: 6 * time.Hour}, time.Minute, time.Minute, false},
		{"a one-nanosecond request is honoured", Policy{TTL: time.Hour, MaxTTL: 6 * time.Hour}, time.Nanosecond, time.Nanosecond, false},

		// A ceiling BELOW the TTL is a misconfigured row. The ceiling wins for a
		// caller-named TTL, which is the conservative reading.
		{"a ceiling below the TTL still bounds the request", Policy{TTL: 6 * time.Hour, MaxTTL: time.Hour}, 2 * time.Hour, 0, true},
		{"a ceiling below the TTL does not bound the default", Policy{TTL: 6 * time.Hour, MaxTTL: time.Hour}, 0, 6 * time.Hour, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.policy.ResolveTTL(tc.requested)
			if tc.wantErr {
				require.Error(t, err)
				assert.Zero(t, got, "a refused TTL must not also return a usable duration")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestResolveTTLNeverReturnsANonPositiveLifetime. A lease issued with a zero or
// negative TTL is expired the instant it is written, so the next read supersedes it —
// an infinite issue/supersede loop that serves reads while recording nothing useful.
func TestResolveTTLNeverReturnsANonPositiveLifetime(t *testing.T) {
	policies := []Policy{
		{},
		{TTL: -time.Hour},
		{TTL: 0, MaxTTL: -time.Hour},
		{TTL: time.Hour},
		{TTL: time.Hour, MaxTTL: 24 * time.Hour},
	}
	for _, policy := range policies {
		for _, requested := range []time.Duration{-time.Hour, 0, time.Nanosecond, time.Minute} {
			ttl, err := policy.ResolveTTL(requested)
			if err != nil {
				continue
			}
			assert.Positive(t, ttl, "ResolveTTL(%s) on %+v produced a lease that is born expired", requested, policy)
		}
	}
}

// ---------------------------------------------------------------------------
// State.Remaining
// ---------------------------------------------------------------------------

func TestRemainingReportsTheAllowanceAndWhetherThereIsOne(t *testing.T) {
	cases := []struct {
		name          string
		state         State
		wantRemaining int32
		wantCapped    bool
	}{
		// Zero means UNLIMITED within the TTL, which is the useful default for a
		// workload that re-reads on boot. Reporting it as "0 remaining, capped" would
		// refuse every read on every secret whose operator left the field alone.
		{"an absent cap is uncapped", State{MaxReads: 0, ReadsUsed: 0}, 0, false},
		{"an absent cap stays uncapped however much was read", State{MaxReads: 0, ReadsUsed: 1_000_000}, 0, false},
		{"a negative cap is uncapped", State{MaxReads: -1, ReadsUsed: 5}, 0, false},

		{"a fresh capped lease", State{MaxReads: 3, ReadsUsed: 0}, 3, true},
		{"one below the cap", State{MaxReads: 3, ReadsUsed: 2}, 1, true},
		{"exactly at the cap", State{MaxReads: 3, ReadsUsed: 3}, 0, true},
		// Overshoot is clamped at zero rather than reported as negative: a negative
		// allowance would compare oddly at every call site that checks `<= 0`, and a
		// row can overshoot after an operator tightens the cap mid-window.
		{"one past the cap", State{MaxReads: 3, ReadsUsed: 4}, 0, true},
		{"far past the cap", State{MaxReads: 3, ReadsUsed: 999}, 0, true},
		{"a cap of one, unused", State{MaxReads: 1, ReadsUsed: 0}, 1, true},
		{"a cap of one, used", State{MaxReads: 1, ReadsUsed: 1}, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			remaining, capped := tc.state.Remaining()
			assert.Equal(t, tc.wantRemaining, remaining)
			assert.Equal(t, tc.wantCapped, capped)
			assert.GreaterOrEqual(t, remaining, int32(0), "an allowance must never be negative")
		})
	}
}

// ---------------------------------------------------------------------------
// Evaluate — the decision
// ---------------------------------------------------------------------------

func TestEvaluateCoversEveryDecisionBoundary(t *testing.T) {
	enabled := Policy{TTL: time.Hour, MaxReads: 3}
	uncapped := Policy{TTL: time.Hour}

	cases := []struct {
		name string
		req  Request
		want Decision
		// wantReason asserts a caller-safe explanation is present (Refuse) or absent.
		wantReason bool
	}{
		// --- the secret's own expiry, which outranks everything -------------------
		//
		// A credential its owner has declared dead is not served regardless of what
		// any lease says. It is checked FIRST, so it cannot be bypassed by arriving
		// without a lease.
		{
			"an expired secret is refused even with no lease yet",
			Request{Policy: enabled, SecretExpiresAt: at(-time.Second), Now: now()},
			Refuse, true,
		},
		{
			"an expired secret is refused even with a live lease that has allowance",
			Request{Policy: enabled, Existing: &State{ExpiresAt: now().Add(time.Hour), MaxReads: 3}, SecretExpiresAt: at(-time.Second), Now: now()},
			Refuse, true,
		},
		{
			// THE BOUNDARY INSTANT. expires_at == now is EXPIRED, because the check is
			// !After(now). Treating the exact instant as still-live would serve a value
			// for one more tick after the moment its owner named.
			"a secret expiring exactly now is expired",
			Request{Policy: enabled, SecretExpiresAt: at(0), Now: now()},
			Refuse, true,
		},
		{
			"a secret expiring one nanosecond from now is still live",
			Request{Policy: enabled, SecretExpiresAt: at(time.Nanosecond), Now: now()},
			Issue, false,
		},
		{
			"a secret with no expiry is unaffected",
			Request{Policy: enabled, SecretExpiresAt: nil, Now: now()},
			Issue, false,
		},

		// --- issue and supersede -------------------------------------------------
		{
			"no lease yet issues one",
			Request{Policy: enabled, Existing: nil, Now: now()},
			Issue, false,
		},
		{
			// The old row has to be CLOSED, which is why this is not Issue; and an
			// expired lease is a routine renewal, which is why it is not Refuse.
			"a lease whose TTL has run out is superseded",
			Request{Policy: enabled, Existing: &State{ExpiresAt: now().Add(-time.Second), MaxReads: 3}, Now: now()},
			Supersede, false,
		},
		{
			"a lease expiring exactly now is superseded",
			Request{Policy: enabled, Existing: &State{ExpiresAt: now(), MaxReads: 3}, Now: now()},
			Supersede, false,
		},
		{
			"a lease expiring one nanosecond from now is still live",
			Request{Policy: enabled, Existing: &State{ExpiresAt: now().Add(time.Nanosecond), MaxReads: 3}, Now: now()},
			Consume, false,
		},

		// --- the use-count cap on a LIVE lease -----------------------------------
		{
			"a live lease under its cap is consumed",
			Request{Policy: enabled, Existing: &State{ExpiresAt: now().Add(time.Hour), MaxReads: 3, ReadsUsed: 1}, Now: now()},
			Consume, false,
		},
		{
			"a live lease one read below its cap is consumed",
			Request{Policy: enabled, Existing: &State{ExpiresAt: now().Add(time.Hour), MaxReads: 3, ReadsUsed: 2}, Now: now()},
			Consume, false,
		},
		{
			// THE SECURITY-RELEVANT REFUSAL: this is what turns an exfiltration loop —
			// one valid token pulling a value ten thousand times — from an invisible
			// read pattern into a refusal an operator sees.
			"a live lease exactly at its cap is refused",
			Request{Policy: enabled, Existing: &State{ExpiresAt: now().Add(time.Hour), MaxReads: 3, ReadsUsed: 3}, Now: now()},
			Refuse, true,
		},
		{
			"a live lease past its cap is refused",
			Request{Policy: enabled, Existing: &State{ExpiresAt: now().Add(time.Hour), MaxReads: 3, ReadsUsed: 4}, Now: now()},
			Refuse, true,
		},
		{
			"an uncapped live lease is never refused for reads",
			Request{Policy: uncapped, Existing: &State{ExpiresAt: now().Add(time.Hour), MaxReads: 0, ReadsUsed: 1_000_000}, Now: now()},
			Consume, false,
		},
		{
			"a cap of one is spent by its first read",
			Request{Policy: Policy{TTL: time.Hour, MaxReads: 1}, Existing: &State{ExpiresAt: now().Add(time.Hour), MaxReads: 1, ReadsUsed: 1}, Now: now()},
			Refuse, true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			decision, reason := Evaluate(tc.req)
			assert.Equal(t, tc.want, decision, "wanted %s, got %s", tc.want, decision)
			if tc.wantReason {
				assert.NotEmpty(t, reason, "a refusal must carry a precise, auditable reason")
			} else {
				assert.Empty(t, reason, "only a refusal carries a reason")
			}
		})
	}
}

// TestAnExhaustedLeaseRecoversWhenItsWindowCloses is the window semantics stated as a
// test, and it is the behaviour a reader is most likely to expect to be otherwise.
//
// max_reads is "this many reads per TTL window", NOT a lifetime budget. So an
// exhausted lease refuses reads until its TTL runs out, and then the SAME row —
// still exhausted, now expired — is SUPERSEDED rather than refused, starting a new
// window with a full allowance.
//
// A lifetime cap sounds stricter and is worse: it eventually refuses a correctly
// behaving consumer forever, at an unpredictable moment, with no operator action
// having caused it — an outage wearing a security control's clothes. A per-window cap
// bounds a stolen token to max_reads per window while leaving a legitimate consumer
// working indefinitely.
func TestAnExhaustedLeaseRecoversWhenItsWindowCloses(t *testing.T) {
	policy := Policy{TTL: time.Hour, MaxReads: 2}
	exhausted := State{ExpiresAt: now().Add(time.Minute), MaxReads: 2, ReadsUsed: 2}

	// Inside the window: refused, with a reason naming both the cap and when it lifts.
	decision, reason := Evaluate(Request{Policy: policy, Existing: &exhausted, Now: now()})
	require.Equal(t, Refuse, decision)
	assert.Contains(t, reason, "2 permitted reads")
	assert.Contains(t, reason, exhausted.ExpiresAt.UTC().Format(time.RFC3339),
		"the refusal must tell the caller when its allowance comes back")

	// One nanosecond before the window closes: still refused.
	decision, _ = Evaluate(Request{Policy: policy, Existing: &exhausted, Now: exhausted.ExpiresAt.Add(-time.Nanosecond)})
	assert.Equal(t, Refuse, decision)

	// At the window's edge and beyond: superseded, not refused. The TTL check runs
	// BEFORE the cap check, which is what makes this recovery possible at all.
	for _, offset := range []time.Duration{0, time.Nanosecond, time.Hour, 30 * 24 * time.Hour} {
		decision, reason = Evaluate(Request{Policy: policy, Existing: &exhausted, Now: exhausted.ExpiresAt.Add(offset)})
		assert.Equal(t, Supersede, decision, "at +%s the window has closed and a successor is due", offset)
		assert.Empty(t, reason)
	}
}

// TestTheCheckOrderIsThePolicy pins the precedence, because the order IS the
// behaviour: reshuffling these four checks changes which refusal a caller sees and
// which one an auditor records, without changing a single condition.
func TestTheCheckOrderIsThePolicy(t *testing.T) {
	policy := Policy{TTL: time.Hour, MaxReads: 1}

	// 1. The secret's own expiry beats an expired lease (which would otherwise be a
	//    routine Supersede) — a dead credential is not renewed.
	decision, reason := Evaluate(Request{
		Policy:          policy,
		Existing:        &State{ExpiresAt: now().Add(-time.Hour), MaxReads: 1, ReadsUsed: 0},
		SecretExpiresAt: at(-time.Hour),
		Now:             now(),
	})
	assert.Equal(t, Refuse, decision, "an expired secret is not renewed by an expired lease")
	assert.Contains(t, reason, "expired", "the reason must be the secret's expiry, not the lease's cap")

	// 2. The secret's own expiry beats an exhausted lease, and the reason distinguishes
	//    them: "this credential is dead" and "you have read enough" are different
	//    facts, and an operator at three in the morning needs the right one.
	decision, secretReason := Evaluate(Request{
		Policy:          policy,
		Existing:        &State{ExpiresAt: now().Add(time.Hour), MaxReads: 1, ReadsUsed: 1},
		SecretExpiresAt: at(-time.Hour),
		Now:             now(),
	})
	require.Equal(t, Refuse, decision)
	_, capReason := Evaluate(Request{
		Policy:   policy,
		Existing: &State{ExpiresAt: now().Add(time.Hour), MaxReads: 1, ReadsUsed: 1},
		Now:      now(),
	})
	assert.NotEqual(t, secretReason, capReason, "two different refusals must not read the same in an audit row")

	// 3. The policy gate beats all of it: with no policy, none of the above applies.
	decision, _ = Evaluate(Request{
		Policy:          Policy{},
		Existing:        &State{ExpiresAt: now().Add(-time.Hour), MaxReads: 1, ReadsUsed: 9},
		SecretExpiresAt: at(-time.Hour),
		Now:             now(),
	})
	assert.Equal(t, Consume, decision)
}

// TestARefusalReasonDescribesTheCallersOwnLeaseAndNothingElse. The reason travels to
// the caller and into an append-only audit row, so it must be caller-safe: it may
// describe the lease, and it may never describe the value.
func TestARefusalReasonDescribesTheCallersOwnLeaseAndNothingElse(t *testing.T) {
	const value = "sup3r-s3cret-database-password"

	reasons := []string{}
	_, r := Evaluate(Request{
		Policy:          Policy{TTL: time.Hour},
		SecretExpiresAt: at(-time.Hour),
		Now:             now(),
	})
	reasons = append(reasons, r)
	_, r = Evaluate(Request{
		Policy:   Policy{TTL: time.Hour, MaxReads: 2},
		Existing: &State{ExpiresAt: now().Add(time.Hour), MaxReads: 2, ReadsUsed: 2},
		Now:      now(),
	})
	reasons = append(reasons, r)

	for _, reason := range reasons {
		require.NotEmpty(t, reason)
		assert.NotContains(t, reason, value)
		// A UTC RFC3339 instant, so two operators in two timezones read the same thing.
		assert.Contains(t, reason, "Z", "an instant in a refusal must be rendered in UTC")
	}
}

// ---------------------------------------------------------------------------
// Decision.String
// ---------------------------------------------------------------------------

func TestDecisionRendersForALogOrAFailure(t *testing.T) {
	assert.Equal(t, "issue", Issue.String())
	assert.Equal(t, "consume", Consume.String())
	assert.Equal(t, "supersede", Supersede.String())
	assert.Equal(t, "refuse", Refuse.String())
	assert.Equal(t, "unknown", Decision(99).String(), "an unmapped decision must be legible, not blank")

	// Every name is distinct, or a log line could not tell two outcomes apart.
	seen := map[string]struct{}{}
	for _, d := range []Decision{Issue, Consume, Supersede, Refuse} {
		_, dup := seen[d.String()]
		assert.False(t, dup, "two decisions render identically")
		seen[d.String()] = struct{}{}
	}
}

// ---------------------------------------------------------------------------
// Refusal
// ---------------------------------------------------------------------------

// TestARefusalIsTypedNotStringMatched. The api layer maps "the lease said no" to a
// precise status and an audit reason; doing that by matching an error message would
// break the first time the wording changed, and would make "you may not read this"
// indistinguishable from "we could not read this" — the difference that matters to an
// operator at three in the morning.
func TestARefusalIsTypedNotStringMatched(t *testing.T) {
	err := NewRefusal("this lease has served its 2 permitted reads")
	require.Error(t, err)

	var refusal *Refusal
	require.True(t, errors.As(err, &refusal), "a refusal must be recoverable by type")
	assert.Equal(t, "this lease has served its 2 permitted reads", refusal.Reason)
	assert.Equal(t, refusal.Reason, err.Error(), "Error() must be the caller-safe reason verbatim")

	// An internal failure must NOT be mistaken for a refusal.
	assert.False(t, errors.As(errors.New("connection refused"), &refusal),
		"an ordinary error must never satisfy a refusal check")
}

// TestEvaluateAndRefusalComposeIntoTheCallersError checks the two halves fit: the
// decision produces a reason, and the reason becomes the typed error the api layer
// tests for.
func TestEvaluateAndRefusalComposeIntoTheCallersError(t *testing.T) {
	decision, reason := Evaluate(Request{
		Policy:   Policy{TTL: time.Hour, MaxReads: 1},
		Existing: &State{ExpiresAt: now().Add(time.Hour), MaxReads: 1, ReadsUsed: 1},
		Now:      now(),
	})
	require.Equal(t, Refuse, decision)

	err := NewRefusal(reason)
	var refusal *Refusal
	require.True(t, errors.As(err, &refusal))
	assert.Equal(t, reason, refusal.Reason)
}
