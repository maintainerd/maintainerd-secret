package audit

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/maintainerd/secret/internal/store"
)

// recorder captures events instead of writing them.
type recorder struct {
	events []store.AuditEvent
	err    error
}

func (r *recorder) RecordAudit(_ context.Context, ev store.AuditEvent) error {
	if r.err != nil {
		return r.err
	}
	r.events = append(r.events, ev)
	return nil
}

// TestNewRefusesANilRecorder is the structural half of "no unaudited path": an
// auditor that cannot write must not be constructible.
func TestNewRefusesANilRecorder(t *testing.T) {
	_, err := New(nil)
	require.ErrorIs(t, err, ErrNoAuditor)
}

// TestNilAuditorFailsClosed is the runtime half. A nil *Auditor is not "skip
// auditing"; it is an error, so an audited operation that reaches one refuses to run.
func TestNilAuditorFailsClosed(t *testing.T) {
	var a *Auditor
	err := a.Record(context.Background(), Actor{}, Event{Action: store.ActionReveal})
	require.ErrorIs(t, err, ErrNoAuditor)

	// The zero value is unusable for the same reason.
	empty := &Auditor{}
	err = empty.Record(context.Background(), Actor{}, Event{Action: store.ActionReveal})
	require.ErrorIs(t, err, ErrNoAuditor)
}

func TestRecordRequiresAnAction(t *testing.T) {
	a, err := New(&recorder{})
	require.NoError(t, err)
	require.Error(t, a.Record(context.Background(), Actor{}, Event{}))
}

// TestRecordCarriesTheRequestProvenance: the boundary knows who asked and how, which
// is exactly what the store cannot know and what an incident review needs.
func TestRecordCarriesTheRequestProvenance(t *testing.T) {
	rec := &recorder{}
	a, err := New(rec)
	require.NoError(t, err)

	tenant := uuid.New()
	version := int32(4)
	require.NoError(t, a.Record(context.Background(), Actor{
		Subject: "user-7", Kind: store.ActorKindUser,
		IP: "198.51.100.9", UserAgent: "curl/8", RequestID: "req-42",
	}, Event{
		TenantUUID:  &tenant,
		Action:      store.ActionReveal,
		ResourceMRN: "mrn:secret:acme:billing:secret/prod/db/PASSWORD",
		Version:     &version,
	}))

	require.Len(t, rec.events, 1)
	ev := rec.events[0]
	assert.Equal(t, "user-7", ev.ActorSubject)
	assert.Equal(t, store.ActorKindUser, ev.ActorKind)
	assert.Equal(t, "198.51.100.9", ev.IPAddress)
	assert.Equal(t, "curl/8", ev.UserAgent)
	assert.Equal(t, "req-42", ev.RequestID)
	assert.Equal(t, store.OutcomeSuccess, ev.Outcome, "an unset outcome defaults to success")
	require.NotNil(t, ev.Version)
	assert.EqualValues(t, 4, *ev.Version)
}

func TestActorKindDefaultsToService(t *testing.T) {
	rec := &recorder{}
	a, _ := New(rec)
	require.NoError(t, a.Record(context.Background(), Actor{Subject: "svc"}, Event{Action: store.ActionRead}))
	assert.Equal(t, store.ActorKindService, rec.events[0].ActorKind)
}

// TestRecordPropagatesAWriteFailure is what makes the reveal path able to fail closed:
// the caller has to be able to see that the row did not land.
func TestRecordPropagatesAWriteFailure(t *testing.T) {
	rec := &recorder{err: errors.New("sink is down")}
	a, _ := New(rec)
	err := a.Record(context.Background(), Actor{}, Event{Action: store.ActionReveal})
	require.Error(t, err)
}

// TestRecordDeniedAndRecordErrorAreErrorless: the caller is already returning a
// failure, and there is no version of "the denial could not be recorded" that should
// turn into an allow.
func TestRecordDeniedAndRecordErrorAreErrorless(t *testing.T) {
	rec := &recorder{}
	a, _ := New(rec)

	a.RecordDenied(context.Background(), Actor{Subject: "u"}, Event{
		Action: store.ActionReveal, ResourceMRN: "mrn:secret:acme:billing:secret/prod/X",
	})
	a.RecordError(context.Background(), Actor{Subject: "u"}, Event{Action: store.ActionWrite})

	require.Len(t, rec.events, 2)
	assert.Equal(t, store.OutcomeDenied, rec.events[0].Outcome)
	assert.Equal(t, store.OutcomeError, rec.events[1].Outcome)

	// A failing sink must not panic or block the denial.
	failing, _ := New(&recorder{err: errors.New("down")})
	assert.NotPanics(t, func() {
		failing.RecordDenied(context.Background(), Actor{}, Event{Action: store.ActionReveal})
	})
}

// TestEventHasNoFieldThatCouldHoldAValue is a structural assertion: the guarantee is
// stronger than "remember not to fill one in".
func TestEventHasNoFieldThatCouldHoldAValue(t *testing.T) {
	ev := Event{}
	// Metadata is the only free-form field, and it is a map of structural facts. The
	// point of this test is that adding a `Value []byte` here would break it.
	ev.Metadata = map[string]any{"version": 3}
	assert.Len(t, ev.Metadata, 1)

	rec := &recorder{}
	a, _ := New(rec)
	require.NoError(t, a.Record(context.Background(), Actor{}, Event{
		Action: store.ActionReveal, Metadata: ev.Metadata,
	}))
	assert.Equal(t, map[string]any{"version": 3}, rec.events[0].Metadata)
}
