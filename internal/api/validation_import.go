package api

import (
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"

	"github.com/maintainerd/secret/internal/store"
)

// Scope-import request DTOs.

// Validate checks an import create, including the self-import rule.
//
// A scope that imports ITSELF is refused here rather than left to the store's cycle
// check, because the message matters: "an environment cannot import itself" tells an
// operator what they typed, where "import cycle detected" sends them looking for a
// chain. The store still refuses longer cycles — this is the one-hop case.
//
// The SOURCE may be a different project (the shared-folder pattern) but never a
// different tenant: there is no tenant field, and every query is tenant-scoped, so a
// cross-tenant import is not expressible rather than merely refused.
func (in CreateImportInput) Validate() error {
	return validation.ValidateStruct(&in,
		validation.Field(&in.Project,
			validation.Required.Error("project is required"),
			slugRule("project"),
		),
		validation.Field(&in.Environment,
			validation.Required.Error("environment is required"),
			slugRule("environment"),
		),
		validation.Field(&in.FolderPath, folderPathRule),
		validation.Field(&in.SourceProject,
			validation.Required.Error("source_project is required"),
			slugRule("source project"),
		),
		validation.Field(&in.SourceEnvironment,
			validation.Required.Error("source_environment is required"),
			slugRule("source environment"),
		),
		validation.Field(&in.SourceFolderPath,
			folderPathRule,
			validation.By(func(value any) error {
				sourcePath, serr := store.NormalizePath(toStringValue(value))
				targetPath, terr := store.NormalizePath(in.FolderPath)
				if serr != nil || terr != nil {
					return nil // folderPathRule already reported it.
				}
				if in.SourceProject == in.Project &&
					in.SourceEnvironment == in.Environment &&
					sourcePath == targetPath {
					return validation.NewError("validation_import",
						"a scope cannot import itself")
				}
				return nil
			}),
		),
		validation.Field(&in.Position, positionRule),
	)
}

// ListImportsInput lists one folder's import chain in precedence order.
type ListImportsInput struct {
	Project     string `json:"project"`
	Environment string `json:"environment"`
	FolderPath  string `json:"folder_path,omitempty"`
}

// Validate checks an import listing request.
func (in ListImportsInput) Validate() error {
	return validation.ValidateStruct(&in,
		validation.Field(&in.Project,
			validation.Required.Error("project is required"),
			slugRule("project"),
		),
		validation.Field(&in.Environment,
			validation.Required.Error("environment is required"),
			slugRule("environment"),
		),
		validation.Field(&in.FolderPath, folderPathRule),
	)
}

// UpdateImportInput toggles and reorders an import edge.
type UpdateImportInput struct {
	ImportUUID string `json:"import_uuid"`
	Enabled    bool   `json:"enabled"`
	Position   int32  `json:"position,omitempty"`
}

// Validate checks an import update.
func (in UpdateImportInput) Validate() error {
	return validation.ValidateStruct(&in,
		validation.Field(&in.ImportUUID,
			validation.Required.Error("import_uuid is required"),
			is.UUID.Error("import_uuid must be a valid UUID"),
		),
		validation.Field(&in.Position, positionRule),
	)
}

// ImportRef addresses one import edge — the delete path.
type ImportRef struct {
	ImportUUID string `json:"import_uuid"`
}

// Validate checks an import reference.
func (in ImportRef) Validate() error {
	return validation.ValidateStruct(&in,
		validation.Field(&in.ImportUUID,
			validation.Required.Error("import_uuid is required"),
			is.UUID.Error("import_uuid must be a valid UUID"),
		),
	)
}

// toStringValue renders an ozzo rule's `any` argument as a string, for the rules that
// need the field's own value alongside a sibling's.
func toStringValue(value any) string {
	s, _ := value.(string)
	return s
}
