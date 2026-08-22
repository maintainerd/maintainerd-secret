package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Tests for the hardening configuration: server timeouts, request limits, rate limits
// and the two cross-checks that refuse a combination which cannot work.

func TestHardeningDefaults(t *testing.T) {
	setRequiredEnv(t)
	require.NoError(t, Init())

	assert.Equal(t, 10*time.Second, HTTPReadHeaderTimeout)
	assert.Equal(t, 15*time.Second, HTTPReadTimeout)
	assert.Equal(t, 60*time.Second, HTTPWriteTimeout)
	assert.Equal(t, 120*time.Second, HTTPIdleTimeout)
	assert.Equal(t, 30*time.Second, HTTPRequestTimeout)
	assert.Equal(t, int64(4<<20), HTTPMaxBodyBytes)
	assert.Equal(t, 20*time.Second, ShutdownTimeout)
	assert.Equal(t, 2*time.Second, ReadinessTimeout)

	assert.Equal(t, 64<<10, MaxSecretValueBytes)
	assert.Equal(t, 100, MaxBatchItems)
	assert.Equal(t, 32, MaxTags)
	assert.Equal(t, 64, MaxTagLength)
	assert.Equal(t, 200, MaxPageLimit)
	assert.Equal(t, 500, MaxDescriptionLength)
	assert.Equal(t, 30, WebhookMaxTimeoutSeconds)
	assert.Equal(t, 10, WebhookMaxAttempts)
	assert.Equal(t, 90, DBConnMaxIdleSec)

	assert.True(t, RateLimitEnabled, "rate limiting is on unless an operator turns it off")
	assert.Equal(t, time.Minute, RateLimitWindow)
	assert.Equal(t, 300, RateLimitReveal)
	assert.Equal(t, 120, RateLimitWrite)
	assert.Equal(t, 10, RateLimitSetup)
}

// TestDurationsAreRefusedRatherThanDefaulted: a timeout that silently becomes the
// default is a bound nobody chose, and a timeout of zero is no bound at all — which for
// every one of these means an unbounded resource an anonymous peer can hold.
func TestDurationsAreRefusedRatherThanDefaulted(t *testing.T) {
	keys := []string{
		"HTTP_READ_HEADER_TIMEOUT", "HTTP_READ_TIMEOUT", "HTTP_WRITE_TIMEOUT",
		"HTTP_IDLE_TIMEOUT", "HTTP_REQUEST_TIMEOUT", "SHUTDOWN_TIMEOUT",
		"SECRET_READINESS_TIMEOUT", "SECRET_RATE_LIMIT_WINDOW",
	}
	for _, key := range keys {
		t.Run(key+" malformed", func(t *testing.T) {
			setRequiredEnv(t)
			t.Setenv(key, "thirty-seconds")
			err := Init()
			require.Error(t, err)
			assert.Contains(t, err.Error(), key)
		})
		t.Run(key+" zero", func(t *testing.T) {
			setRequiredEnv(t)
			t.Setenv(key, "0s")
			err := Init()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "must be positive")
		})
	}
}

func TestLimitsAreRefusedRatherThanDefaulted(t *testing.T) {
	keys := []string{
		"SECRET_MAX_VALUE_BYTES", "SECRET_MAX_BATCH_ITEMS", "SECRET_MAX_TAGS",
		"SECRET_MAX_TAG_LENGTH", "SECRET_MAX_PAGE_LIMIT", "SECRET_MAX_DESCRIPTION_LENGTH",
		"SECRET_RATE_LIMIT_REVEAL", "SECRET_RATE_LIMIT_WRITE", "SECRET_RATE_LIMIT_SETUP",
		"SECRET_WEBHOOK_MAX_TIMEOUT_SEC", "SECRET_WEBHOOK_MAX_ATTEMPTS",
		"HTTP_MAX_BODY_BYTES", "DB_CONN_MAX_IDLE_SEC",
	}
	for _, key := range keys {
		t.Run(key+" malformed", func(t *testing.T) {
			setRequiredEnv(t)
			t.Setenv(key, "lots")
			err := Init()
			require.Error(t, err)
			assert.Contains(t, err.Error(), key)
		})
		t.Run(key+" zero means no limit and is refused", func(t *testing.T) {
			setRequiredEnv(t)
			t.Setenv(key, "0")
			err := Init()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "at least 1")
		})
	}
}

// TestRequestTimeoutMustBeShorterThanTheWriteTimeout. A per-request deadline longer
// than the write timeout cannot work: the write deadline fires first and the client
// sees a truncated response rather than the error the deadline was meant to produce.
func TestRequestTimeoutMustBeShorterThanTheWriteTimeout(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("HTTP_REQUEST_TIMEOUT", "90s")
	t.Setenv("HTTP_WRITE_TIMEOUT", "60s")

	err := Init()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP_REQUEST_TIMEOUT")
	assert.Contains(t, err.Error(), "HTTP_WRITE_TIMEOUT")

	t.Run("equal is also refused", func(t *testing.T) {
		setRequiredEnv(t)
		t.Setenv("HTTP_REQUEST_TIMEOUT", "60s")
		t.Setenv("HTTP_WRITE_TIMEOUT", "60s")
		require.Error(t, Init())
	})

	t.Run("shorter is accepted", func(t *testing.T) {
		setRequiredEnv(t)
		t.Setenv("HTTP_REQUEST_TIMEOUT", "20s")
		t.Setenv("HTTP_WRITE_TIMEOUT", "60s")
		require.NoError(t, Init())
	})
}

// TestValueLimitMustFitInsideTheBodyLimit. A value bound larger than the body bound is
// not wrong, it is a lie: the body reader refuses first, and an operator who raised one
// and not the other would be debugging a 413 while reading a 64 KiB limit.
func TestValueLimitMustFitInsideTheBodyLimit(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("SECRET_MAX_VALUE_BYTES", "8388608") // 8 MiB
	t.Setenv("HTTP_MAX_BODY_BYTES", "4194304")    // 4 MiB

	err := Init()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SECRET_MAX_VALUE_BYTES")
	assert.Contains(t, err.Error(), "HTTP_MAX_BODY_BYTES")

	t.Run("raising both together is accepted", func(t *testing.T) {
		setRequiredEnv(t)
		t.Setenv("SECRET_MAX_VALUE_BYTES", "8388608")
		t.Setenv("HTTP_MAX_BODY_BYTES", "16777216")
		require.NoError(t, Init())
	})
}

func TestRateLimitingCanBeTurnedOffExplicitly(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("SECRET_RATE_LIMIT_ENABLED", "false")
	require.NoError(t, Init())
	assert.False(t, RateLimitEnabled)

	t.Run("a malformed boolean is refused rather than read as off", func(t *testing.T) {
		setRequiredEnv(t)
		t.Setenv("SECRET_RATE_LIMIT_ENABLED", "no thanks")
		err := Init()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "SECRET_RATE_LIMIT_ENABLED")
	})
}
