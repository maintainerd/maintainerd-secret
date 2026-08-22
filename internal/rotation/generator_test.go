package rotation

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRandomGeneratorDefaults(t *testing.T) {
	spec := Spec{}
	require.NoError(t, spec.Validate(true))
	assert.Equal(t, GeneratorRandom, spec.Type)
	assert.Equal(t, DefaultLength, spec.Length)
	assert.Equal(t, CharsetAlphanumeric, spec.Charset)

	value, err := spec.Generate()
	require.NoError(t, err)
	assert.Len(t, value, DefaultLength)
	for _, b := range value {
		assert.True(t, strings.ContainsRune(alphanumericAlphabet, rune(b)),
			"generated value must stay inside its alphabet")
	}
}

// TestGeneratedValuesAreDistinct is a cheap smoke test that the generator is actually
// random rather than, say, returning a zero-filled buffer.
func TestGeneratedValuesAreDistinct(t *testing.T) {
	spec := Spec{Type: GeneratorRandom, Length: 32, Charset: CharsetAlphanumeric}
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		v, err := spec.Generate()
		require.NoError(t, err)
		assert.False(t, seen[string(v)], "a generator must not repeat itself")
		seen[string(v)] = true
	}
}

func TestEveryCharsetProducesTheRequestedLength(t *testing.T) {
	for _, charset := range []string{CharsetAlphanumeric, CharsetAlphanumericSymbols, CharsetHex, CharsetBase64URL} {
		spec := Spec{Type: GeneratorRandom, Length: 33, Charset: charset}
		require.NoError(t, spec.Validate(true), charset)
		v, err := spec.Generate()
		require.NoError(t, err, charset)
		assert.Len(t, v, 33, charset)
	}
}

// TestSymbolAlphabetExcludesShellBreakers: generated credentials get mangled in shell
// quoting, .env files and YAML, so the symbol set avoids the characters that do it.
func TestSymbolAlphabetExcludesShellBreakers(t *testing.T) {
	for _, bad := range []string{`"`, "'", "`", `\`, "$"} {
		assert.False(t, strings.Contains(symbolAlphabet, bad),
			"symbol alphabet must not contain %q", bad)
	}
}

func TestLengthBounds(t *testing.T) {
	tooShort := Spec{Type: GeneratorRandom, Length: MinLength - 1}
	assert.Error(t, tooShort.Validate(true))

	tooLong := Spec{Type: GeneratorRandom, Length: MaxLength + 1}
	assert.Error(t, tooLong.Validate(true))
}

func TestUnknownGeneratorAndCharsetAreRejected(t *testing.T) {
	unknown := Spec{Type: "magic"}
	assert.Error(t, unknown.Validate(false))

	badCharset := Spec{Type: GeneratorRandom, Charset: "emoji"}
	assert.Error(t, badCharset.Validate(false))
}

// TestSuppliedGeneratorIsRefusedForASchedule: a scheduler has nobody to ask, so a
// policy that requires a supplied value would either stall forever or write a
// placeholder over a live credential.
func TestSuppliedGeneratorIsRefusedForASchedule(t *testing.T) {
	spec := Spec{Type: GeneratorSupplied, Value: "x"}
	assert.NoError(t, spec.Validate(false), "a manual rotation may supply a value")
	assert.Error(t, spec.Validate(true), "a scheduled rotation may not")
}

func TestSuppliedGeneratorReturnsTheSuppliedValue(t *testing.T) {
	spec := Spec{Type: GeneratorSupplied, Value: "rolled-upstream"}
	v, err := spec.Generate()
	require.NoError(t, err)
	assert.Equal(t, "rolled-upstream", string(v))

	empty := Spec{Type: GeneratorSupplied}
	_, err = empty.Generate()
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// Policies
// ---------------------------------------------------------------------------

func TestParsePolicyRoundTrip(t *testing.T) {
	raw := map[string]any{
		"enabled":   true,
		"interval":  "720h",
		"generator": map[string]any{"type": "random", "length": float64(48), "charset": "hex"},
	}
	p, err := ParsePolicy(raw)
	require.NoError(t, err)
	assert.True(t, p.Enabled)
	assert.Equal(t, "720h", p.Interval)
	assert.Equal(t, 48, p.Generator.Length)
	assert.Equal(t, CharsetHex, p.Generator.Charset)

	// Map() renders back to the stored shape and NEVER emits a value.
	rendered := p.Map()
	assert.Equal(t, true, rendered["enabled"])
	assert.Equal(t, "720h", rendered["interval"])
	generator, ok := rendered["generator"].(map[string]any)
	require.True(t, ok)
	_, hasValue := generator["value"]
	assert.False(t, hasValue, "a rendered policy must never carry a value")
}

// TestMalformedPolicyIsAnErrorNotADisabledPolicy is the failure that matters: the
// operator believes a credential rotates every 30 days, and silently it never does.
func TestMalformedPolicyIsAnErrorNotADisabledPolicy(t *testing.T) {
	_, err := ParsePolicy(map[string]any{"enabled": true, "interval": "thirty days"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a duration")

	_, err = ParsePolicy(map[string]any{"enabled": true})
	require.Error(t, err, "an enabled policy without an interval never fires")
}

// TestStoredPolicyMayNotCarryAValue is the backstop for a row that got one by any
// route other than the API.
func TestStoredPolicyMayNotCarryAValue(t *testing.T) {
	_, err := ParsePolicy(map[string]any{
		"enabled":   true,
		"interval":  "24h",
		"generator": map[string]any{"type": "supplied", "value": "hunter2"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must not contain a generator value")
}

// TestIntervalHasAFloor: a one-minute rotation is not a policy, it is a loop that
// destroys the version history it is meant to build.
func TestIntervalHasAFloor(t *testing.T) {
	p := Policy{Enabled: true, Interval: "30s"}
	_, err := p.IntervalDuration()
	require.Error(t, err)
	assert.Contains(t, err.Error(), MinInterval.String())
}

func TestNextDueIsMeasuredFromTheLastRotation(t *testing.T) {
	p := Policy{Enabled: true, Interval: "24h"}
	last := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	due, err := p.NextDue(last)
	require.NoError(t, err)
	assert.Equal(t, last.Add(24*time.Hour), due)
}

func TestDisabledPolicyParsesWithoutAnInterval(t *testing.T) {
	p, err := ParsePolicy(map[string]any{"enabled": false})
	require.NoError(t, err)
	assert.False(t, p.Enabled)

	empty, err := ParsePolicy(nil)
	require.NoError(t, err)
	assert.False(t, empty.Enabled)
}
