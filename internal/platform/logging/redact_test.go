package logging

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/maintainerd/secret/internal/crypto"
	"github.com/maintainerd/secret/internal/rotation"
)

// capture returns a logger writing through the redactor into buf.
func capture() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	inner := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	return slog.New(NewRedactHandler(inner)), &buf
}

// TestASecretValueCannotReachTheLog is the assertion this package exists for.
//
// It walks every shape a credential arrives in on this service and requires that none
// of them survives a log call: the structural one (crypto.Plaintext), the four ordinary
// strings that cannot be Plaintext without changing contracts outside this service, and
// the case where somebody logs a whole request body under one attribute.
func TestASecretValueCannotReachTheLog(t *testing.T) {
	const value = "hunter2-the-production-database-password"

	cases := []struct {
		name string
		log  func(*slog.Logger)
	}{
		{
			"a crypto.Plaintext logged as an attribute",
			func(l *slog.Logger) { l.Info("revealed", "secret_value", crypto.Plaintext(value)) },
		},
		{
			"a crypto.Plaintext under an innocuous key",
			func(l *slog.Logger) { l.Info("revealed", "detail", crypto.Plaintext(value)) },
		},
		{
			"a raw string under a sensitive key",
			func(l *slog.Logger) { l.Info("wrote", "value", value) },
		},
		{
			"a bootstrap token",
			func(l *slog.Logger) { l.Info("setup", "bootstrap_token", value) },
		},
		{
			"an authorization header",
			func(l *slog.Logger) { l.Info("request", "authorization", "Bearer "+value) },
		},
		{
			"a webhook signing key",
			func(l *slog.Logger) { l.Info("endpoint created", "signing_key", value) },
		},
		{
			"a supplied generator value, by dotted key",
			func(l *slog.Logger) { l.Info("rotating", "generator.value", value) },
		},
		{
			"a rotation.Spec carrying a supplied value",
			func(l *slog.Logger) {
				l.Info("rotating", "spec",
					rotation.Spec{Type: rotation.GeneratorSupplied, Value: value})
			},
		},
		{
			"a request body",
			func(l *slog.Logger) { l.Info("decoded", "body", `{"value":"`+value+`"}`) },
		},
		{
			"a panic value",
			func(l *slog.Logger) { l.Error("panicked", "panic", "wrote "+value) },
		},
		{
			"pre-bound with slog.With",
			func(l *slog.Logger) { l.With("token", value).Info("using a bound logger") },
		},
		{
			"nested inside a group",
			func(l *slog.Logger) {
				l.Info("nested", slog.Group("request", slog.String("value", value)))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logger, buf := capture()
			tc.log(logger)
			assert.NotContains(t, buf.String(), value,
				"a credential reached the log: %s", buf.String())
			assert.Contains(t, buf.String(), crypto.Redacted)
		})
	}
}

// TestOperationalAttributesSurvive is the other half: a redactor that scrubbed
// everything would pass the test above and make the log useless.
func TestOperationalAttributesSurvive(t *testing.T) {
	logger, buf := capture()
	logger.Info("request",
		"request_id", "req-42",
		"route", "/api/v1/secrets/reveal",
		"status", 200,
		"duration_ms", 12,
		"principal", "svc-billing",
		"mrn", "mrn:secret:acme:billing:secret/prod/db/PASSWORD",
	)
	out := buf.String()
	for _, want := range []string{
		"req-42", "/api/v1/secrets/reveal", "200", "12", "svc-billing",
		"mrn:secret:acme:billing:secret/prod/db/PASSWORD",
	} {
		assert.Contains(t, out, want)
	}
}

// TestLongAttributesAreTruncated bounds the damage from a future debug line that logs
// something large. Truncation turns "somebody logged the body" from a disclosure into a
// hint, and the marker says the value was clipped rather than ended.
func TestLongAttributesAreTruncated(t *testing.T) {
	logger, buf := capture()
	logger.Info("large", "note", strings.Repeat("x", maxAttrRunes*2))
	out := buf.String()
	assert.Contains(t, out, truncationSuffix)
	assert.Less(t, len(out), maxAttrRunes*2, "the over-long value was not clipped")
}

func TestIsSensitiveKey(t *testing.T) {
	sensitive := []string{
		"value", "VALUE", " Token ", "authorization", "signing_key",
		"generator.value", "endpoint_signing_key", "root_key", "panic", "body",
	}
	for _, key := range sensitive {
		assert.True(t, IsSensitiveKey(key), key)
	}

	// The list is names, not heuristics: these are operational and must survive.
	safe := []string{"request_id", "kek_id", "keep_versions", "value_type", "status", "route", "mrn"}
	for _, key := range safe {
		assert.False(t, IsSensitiveKey(key), key)
	}
}

// TestEnabledAndWithGroupDelegate keeps the wrapper honest about the handler contract:
// a wrapper that swallowed level filtering would turn a debug-heavy code path into
// production noise.
func TestEnabledAndWithGroupDelegate(t *testing.T) {
	var buf bytes.Buffer
	inner := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})
	h := NewRedactHandler(inner)
	require.NotNil(t, h)

	assert.False(t, h.Enabled(context.Background(), slog.LevelInfo))
	assert.True(t, h.Enabled(context.Background(), slog.LevelError))
	assert.NotNil(t, h.WithGroup("request"))

	assert.Nil(t, NewRedactHandler(nil), "a nil inner handler composes to nil")
}
