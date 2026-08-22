package api

import (
	validation "github.com/go-ozzo/ozzo-validation/v4"

	"github.com/maintainerd/secret/internal/store"
)

// Project request DTOs.

// maxDisplayNameLength bounds a human-readable name. It is separate from the slug
// bound because a slug is an identifier (63 chars, DNS label) and a name is a label.
const maxDisplayNameLength = 100

// Validate checks a project create.
func (in CreateProjectInput) Validate() error {
	return validation.ValidateStruct(&in,
		validation.Field(&in.Slug,
			validation.Required.Error("project slug is required"),
			slugRule("project slug"),
		),
		validation.Field(&in.Name,
			validation.Length(0, maxDisplayNameLength).
				Error("project name must be at most 100 characters"),
		),
		validation.Field(&in.Description, descriptionRule()),
	)
}

// UpdateProjectInput rewrites a project's descriptive fields.
//
// The slug identifies the project and is NOT editable — it is an MRN segment, and
// renaming it would silently repoint every grant written against the old name. It
// appears here as the address, never as a new value.
type UpdateProjectInput struct {
	Slug        string `json:"slug"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	Status      string `json:"status,omitempty"`
}

// Validate checks a project update.
func (in UpdateProjectInput) Validate() error {
	return validation.ValidateStruct(&in,
		validation.Field(&in.Slug,
			validation.Required.Error("project slug is required"),
			slugRule("project slug"),
		),
		validation.Field(&in.Name,
			validation.Length(0, maxDisplayNameLength).
				Error("project name must be at most 100 characters"),
		),
		validation.Field(&in.Description, descriptionRule()),
		validation.Field(&in.Status, resourceStatusRule),
	)
}

// ProjectRef addresses one project by slug — the read and delete paths.
type ProjectRef struct {
	Slug string `json:"slug"`
}

// Validate checks a project reference.
func (in ProjectRef) Validate() error {
	return validation.ValidateStruct(&in,
		validation.Field(&in.Slug,
			validation.Required.Error("project slug is required"),
			slugRule("project slug"),
		),
	)
}

// ListProjectsInput pages a tenant's projects.
type ListProjectsInput struct {
	Pagination `json:"page"`
}

// Validate checks a project listing request.
func (in ListProjectsInput) Validate() error {
	return validation.ValidateStruct(&in,
		validation.Field(&in.Pagination),
	)
}

// resourceStatusRule restricts a project/environment status to the closed set the
// store accepts. The list comes from store.ResourceStatuses so the API and the
// persistence layer cannot disagree about what a status is.
var resourceStatusRule = validation.By(func(value any) error {
	raw, _ := value.(string)
	if raw == "" {
		return nil // empty means "leave unchanged"; the store resolves it.
	}
	for _, s := range store.ResourceStatuses {
		if raw == s {
			return nil
		}
	}
	return validation.NewError("validation_status",
		"status must be one of "+joinQuoted(store.ResourceStatuses))
})

// joinQuoted renders a closed set for an error message.
func joinQuoted(values []string) string {
	out := ""
	for i, v := range values {
		if i > 0 {
			out += ", "
		}
		out += v
	}
	return out
}
