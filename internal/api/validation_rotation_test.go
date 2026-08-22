package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/maintainerd/secret/internal/rotation"
)

func TestRotateSecretInput_Validate(t *testing.T) {
	t.Run("the zero generator means a default random value", func(t *testing.T) {
		assert.NoError(t, RotateSecretInput{Address: validAddress()}.Validate())
	})
	t.Run("an explicit random generator", func(t *testing.T) {
		assert.NoError(t, RotateSecretInput{
			Address:   validAddress(),
			Generator: rotation.Spec{Type: rotation.GeneratorRandom, Length: 32, Charset: rotation.CharsetHex},
		}.Validate())
	})
	t.Run("a supplied generator with a value", func(t *testing.T) {
		assert.NoError(t, RotateSecretInput{
			Address:   validAddress(),
			Generator: rotation.Spec{Type: rotation.GeneratorSupplied, Value: "rotated-upstream"},
		}.Validate())
	})

	cases := []struct {
		name    string
		spec    rotation.Spec
		wantSub string
	}{
		{
			"random with a supplied value",
			rotation.Spec{Type: rotation.GeneratorRandom, Value: "hunter2"},
			"generates its own value",
		},
		{
			"the implied random generator with a supplied value",
			rotation.Spec{Value: "hunter2"},
			"generates its own value",
		},
		{
			"supplied with a length",
			rotation.Spec{Type: rotation.GeneratorSupplied, Value: "x", Length: 32},
			"not a length or charset",
		},
		{
			"supplied with a charset",
			rotation.Spec{Type: rotation.GeneratorSupplied, Value: "x", Charset: rotation.CharsetHex},
			"not a length or charset",
		},
		{
			"supplied with no value",
			rotation.Spec{Type: rotation.GeneratorSupplied},
			"requires a value",
		},
		{
			"length below the entropy floor",
			rotation.Spec{Type: rotation.GeneratorRandom, Length: rotation.MinLength - 1},
			"length must be between",
		},
		{
			"length above the ceiling",
			rotation.Spec{Type: rotation.GeneratorRandom, Length: rotation.MaxLength + 1},
			"length must be between",
		},
		{
			"an unknown charset",
			rotation.Spec{Type: rotation.GeneratorRandom, Charset: "emoji"},
			"charset",
		},
		{
			"an unknown generator type",
			rotation.Spec{Type: "hsm"},
			"must be random or supplied",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := RotateSecretInput{Address: validAddress(), Generator: tc.spec}.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantSub)
		})
	}

	t.Run("a bad address is caught alongside a good generator", func(t *testing.T) {
		require.Error(t, RotateSecretInput{Address: SecretAddress{}}.Validate())
	})
}

func TestSetRotationPolicyInput_Validate(t *testing.T) {
	address := validAddress()

	t.Run("a disabled policy needs nothing else", func(t *testing.T) {
		assert.NoError(t, SetRotationPolicyInput{
			Address: address,
			Policy:  rotation.Policy{Enabled: false},
		}.Validate())
	})
	t.Run("an enabled policy with an interval and a random generator", func(t *testing.T) {
		assert.NoError(t, SetRotationPolicyInput{
			Address: address,
			Policy: rotation.Policy{
				Enabled:   true,
				Interval:  "720h",
				Generator: rotation.Spec{Type: rotation.GeneratorRandom, Length: 32},
			},
		}.Validate())
	})

	cases := []struct {
		name    string
		policy  rotation.Policy
		wantSub string
	}{
		{
			"enabled with no interval",
			rotation.Policy{Enabled: true},
			"requires an interval",
		},
		{
			"an unparseable interval",
			rotation.Policy{Enabled: true, Interval: "monthly"},
			"not a duration",
		},
		{
			"an interval below the floor",
			rotation.Policy{Enabled: true, Interval: "1m"},
			"at least",
		},
		{
			// The message must be the SCHEDULE one, not the generic
			// policies-carry-no-values one: it tells the operator what to fix.
			"a scheduled supplied generator",
			rotation.Policy{
				Enabled:   true,
				Interval:  "720h",
				Generator: rotation.Spec{Type: rotation.GeneratorSupplied, Value: "x"},
			},
			"scheduled rotation policy",
		},
		{
			"a disabled policy still may not carry a value",
			rotation.Policy{
				Enabled:   false,
				Generator: rotation.Spec{Type: rotation.GeneratorRandom, Value: "hunter2"},
			},
			"must not carry a generator value",
		},
		{
			"an enabled random policy carrying a value",
			rotation.Policy{
				Enabled:   true,
				Interval:  "720h",
				Generator: rotation.Spec{Type: rotation.GeneratorRandom, Value: "hunter2"},
			},
			"must not carry a generator value",
		},
		{
			"an enabled policy with a sub-floor length",
			rotation.Policy{
				Enabled:   true,
				Interval:  "720h",
				Generator: rotation.Spec{Type: rotation.GeneratorRandom, Length: 4},
			},
			"length must be between",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := SetRotationPolicyInput{Address: address, Policy: tc.policy}.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantSub)
		})
	}
}

// TestRotationSpecNeverRendersItsValue pins the redaction added to rotation.Spec: the
// supplied generator's value is a caller-supplied credential, and a Spec travels
// through error paths and audit metadata as an ordinary struct.
func TestRotationSpecNeverRendersItsValue(t *testing.T) {
	spec := rotation.Spec{Type: rotation.GeneratorSupplied, Value: "hunter2-the-password"}
	rendered := spec.String()
	assert.NotContains(t, rendered, "hunter2")
	assert.Contains(t, rendered, "[REDACTED]")
	assert.NotContains(t, spec.LogValue().String(), "hunter2")

	t.Run("an unset value is reported as unset rather than redacted", func(t *testing.T) {
		assert.Contains(t, rotation.Spec{Type: rotation.GeneratorRandom}.String(), "unset")
	})
}
