package api

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLimitsNeverBecomeUnlimited is the property that matters about this file: an
// operator cannot turn a bound off by setting it to zero or a negative number. A
// misconfigured limit falls back to the default; it never becomes "no limit".
func TestLimitsNeverBecomeUnlimited(t *testing.T) {
	t.Cleanup(func() { ApplyLimits(DefaultLimits()) })

	ApplyLimits(Limits{}) // every field zero
	got := CurrentLimits()
	assert.Equal(t, DefaultLimits(), got, "a zero Limits must resolve to the defaults")

	ApplyLimits(Limits{
		MaxSecretValueBytes:      -1,
		MaxBatchItems:            -1,
		MaxTags:                  -1,
		MaxTagLength:             -1,
		MaxPageLimit:             -1,
		MaxDescriptionLength:     -1,
		MaxWebhookTimeoutSeconds: -1,
		MaxWebhookAttempts:       -1,
	})
	assert.Equal(t, DefaultLimits(), CurrentLimits(), "negative limits must resolve to the defaults")
}

// TestBatchBoundCannotBeRaised: MaxBatchItems may be LOWERED by an operator and never
// raised past the compile-time ceiling. An unbounded batch get is a bulk-decryption
// endpoint, so the ceiling is not a tuning knob.
func TestBatchBoundCannotBeRaised(t *testing.T) {
	t.Cleanup(func() { ApplyLimits(DefaultLimits()) })

	ApplyLimits(Limits{MaxBatchItems: 10_000})
	assert.Equal(t, MaxBatchSize, CurrentLimits().MaxBatchItems)

	ApplyLimits(Limits{MaxBatchItems: 10})
	assert.Equal(t, 10, CurrentLimits().MaxBatchItems, "lowering it must work")
}

// TestConfiguredLimitsReachTheDTOs proves the wiring: a limit installed by the
// bootstrap is what a request DTO is measured against, on both transports, because both
// funnel through these DTOs.
func TestConfiguredLimitsReachTheDTOs(t *testing.T) {
	t.Cleanup(func() { ApplyLimits(DefaultLimits()) })

	ApplyLimits(Limits{
		MaxSecretValueBytes:  16,
		MaxTags:              2,
		MaxTagLength:         4,
		MaxPageLimit:         5,
		MaxDescriptionLength: 8,
	})

	t.Run("value size", func(t *testing.T) {
		in := validPut()
		in.Tags = nil
		in.Description = ""
		in.Value = bytes.Repeat([]byte("a"), 17)
		err := in.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at most 16 bytes")
	})

	t.Run("tag count", func(t *testing.T) {
		in := validPut()
		in.Description = ""
		in.Value = []byte("short")
		in.Tags = []string{"a", "b", "c"}
		err := in.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at most 2 tags")
	})

	t.Run("tag length", func(t *testing.T) {
		in := validPut()
		in.Description = ""
		in.Value = []byte("short")
		in.Tags = []string{"toolong"}
		err := in.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at most 4 characters")
	})

	t.Run("description length", func(t *testing.T) {
		in := validPut()
		in.Tags = nil
		in.Value = []byte("short")
		in.Description = "nine char"
		err := in.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at most 8 characters")
	})

	t.Run("page limit", func(t *testing.T) {
		err := Pagination{Limit: 6}.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at most 5")
		assert.NoError(t, Pagination{Limit: 5}.Validate())
	})
}
