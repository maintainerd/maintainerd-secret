package api

import (
	"fmt"

	validation "github.com/go-ozzo/ozzo-validation/v4"

	"github.com/maintainerd/secret/internal/rotation"
)

// Rotation request DTOs.
//
// THE GENERATOR IS WHERE THE MUTUALLY-EXCLUSIVE RULES LIVE. A generator spec has two
// shapes that share one struct, and mixing them is always a mistake with a silent
// failure mode:
//
//	random    — length and charset apply; a supplied value is meaningless and would
//	            be DISCARDED, so a caller that sent one believes it wrote a credential
//	            it did not write.
//	supplied  — the value applies; length and charset are meaningless and a caller
//	            that set them believes the value is being generated to a policy.
//
// Both are refused rather than ignored.

// Validate checks a manual rotation request.
func (in RotateSecretInput) Validate() error {
	return validation.ValidateStruct(&in,
		validation.Field(&in.Address, validation.Required.Error("a secret address is required")),
		validation.Field(&in.Generator, generatorRule(false)),
	)
}

// SetRotationPolicyInput attaches, edits or disables a secret's rotation schedule.
type SetRotationPolicyInput struct {
	Address SecretAddress   `json:"address"`
	Policy  rotation.Policy `json:"policy"`
}

// Validate checks a rotation policy.
//
// Its most important rule is the one that is not about shape at all: a STORED policy
// must not carry a generator value. secrets.rotation_policy is plaintext JSONB,
// readable by every metadata reader and returned in every describe response, so a
// value there is a credential outside encrypted custody. Both transports also refuse
// it at their own boundary; this is the rule that makes the refusal a property of the
// operation rather than of whichever handler happened to remember.
func (in SetRotationPolicyInput) Validate() error {
	return validation.ValidateStruct(&in,
		validation.Field(&in.Address, validation.Required.Error("a secret address is required")),
		validation.Field(&in.Policy, validation.By(func(value any) error {
			policy, ok := value.(rotation.Policy)
			if !ok {
				return nil
			}
			// ORDER MATTERS. The schedule checks run first so that a policy naming the
			// `supplied` generator is told the useful thing — nobody is there to supply
			// a value when the schedule fires — rather than the generic "policies do not
			// carry values", which is true but sends the operator to the wrong fix.
			if policy.Enabled {
				if _, err := policy.IntervalDuration(); err != nil {
					return validation.NewError("validation_rotation_policy", err.Error())
				}
				// scheduled=true: the `supplied` generator is refused here.
				spec := policy.Generator
				if err := spec.Validate(true); err != nil {
					return validation.NewError("validation_rotation_policy", err.Error())
				}
			}
			// Applies to an enabled AND a disabled policy: the row is readable metadata
			// either way, so a value in it is a credential outside encrypted custody.
			if policy.Generator.Value != "" {
				return validation.NewError("validation_rotation_policy",
					"a rotation policy must not carry a generator value: the policy is stored as readable metadata")
			}
			return nil
		})),
	)
}

// generatorRule validates a rotation.Spec, including the two mutual-exclusion rules.
//
// scheduled reports whether the spec will be run by the background rotator, which is
// the one context in which a supplied value is meaningless.
func generatorRule(scheduled bool) validation.Rule {
	return validation.By(func(value any) error {
		spec, ok := value.(rotation.Spec)
		if !ok {
			return nil
		}
		switch spec.Type {
		case rotation.GeneratorSupplied:
			if spec.Length != 0 || spec.Charset != "" {
				return validation.NewError("validation_generator", fmt.Sprintf(
					"generator %q takes a value, not a length or charset: the supplied value is used verbatim",
					rotation.GeneratorSupplied))
			}
		case rotation.GeneratorRandom, "":
			if spec.Value != "" {
				return validation.NewError("validation_generator", fmt.Sprintf(
					"generator %q generates its own value: send %q to supply one",
					rotation.GeneratorRandom, rotation.GeneratorSupplied))
			}
		}
		// Type, length and charset membership come from the generator itself, so the
		// accepted charsets and the length floor are stated in exactly one place.
		// Validate normalizes, so it runs against a copy.
		local := spec
		if err := local.Validate(scheduled); err != nil {
			return validation.NewError("validation_generator", err.Error())
		}
		return nil
	})
}
