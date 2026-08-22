package api

import (
	validation "github.com/go-ozzo/ozzo-validation/v4"
)

// Environment request DTOs.

// maxPosition bounds a display-order value. Position is an ordering hint rendered in a
// console, not an identifier, so it needs a ceiling only to keep a caller from storing
// an arbitrary int32 in a column an operator reads.
const maxPosition = 10000

// Validate checks an environment create.
func (in CreateEnvironmentInput) Validate() error {
	return validation.ValidateStruct(&in,
		validation.Field(&in.Project,
			validation.Required.Error("project is required"),
			slugRule("project"),
		),
		validation.Field(&in.Slug,
			validation.Required.Error("environment slug is required"),
			slugRule("environment slug"),
		),
		validation.Field(&in.Name,
			validation.Length(0, maxDisplayNameLength).
				Error("environment name must be at most 100 characters"),
		),
		validation.Field(&in.Description, descriptionRule()),
		validation.Field(&in.Position, positionRule),
	)
}

// UpdateEnvironmentInput rewrites an environment's descriptive fields. As with a
// project, the slug is the address and is never a new value: environments.slug is
// quoted in MRNs, grants and every consumer's configuration.
type UpdateEnvironmentInput struct {
	Project     string `json:"project"`
	Slug        string `json:"slug"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	Position    int32  `json:"position,omitempty"`
	Status      string `json:"status,omitempty"`
}

// Validate checks an environment update.
func (in UpdateEnvironmentInput) Validate() error {
	return validation.ValidateStruct(&in,
		validation.Field(&in.Project,
			validation.Required.Error("project is required"),
			slugRule("project"),
		),
		validation.Field(&in.Slug,
			validation.Required.Error("environment slug is required"),
			slugRule("environment slug"),
		),
		validation.Field(&in.Name,
			validation.Length(0, maxDisplayNameLength).
				Error("environment name must be at most 100 characters"),
		),
		validation.Field(&in.Description, descriptionRule()),
		validation.Field(&in.Position, positionRule),
		validation.Field(&in.Status, resourceStatusRule),
	)
}

// EnvironmentRef addresses one environment — the read, delete and list paths.
type EnvironmentRef struct {
	Project string `json:"project"`
	Slug    string `json:"slug"`
}

// Validate checks an environment reference.
func (in EnvironmentRef) Validate() error {
	return validation.ValidateStruct(&in,
		validation.Field(&in.Project,
			validation.Required.Error("project is required"),
			slugRule("project"),
		),
		validation.Field(&in.Slug,
			validation.Required.Error("environment slug is required"),
			slugRule("environment slug"),
		),
	)
}

// positionRule bounds a display-order value. It is a single By rule rather than a
// Min/Max pair because ozzo's Field takes a variadic rule list and a package-level
// slice would have to be spread at every call site.
var positionRule = validation.By(func(value any) error {
	position, ok := value.(int32)
	if !ok {
		return nil
	}
	if position < 0 {
		return validation.NewError("validation_position", "position must not be negative")
	}
	if position > maxPosition {
		return validation.NewError("validation_position", "position must be at most 10000")
	}
	return nil
})
