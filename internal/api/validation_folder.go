package api

import (
	"time"

	validation "github.com/go-ozzo/ozzo-validation/v4"

	"github.com/maintainerd/secret/internal/store"
)

// Folder request DTOs.

// CreateFolderInput creates a folder and any missing ancestors (mkdir -p).
type CreateFolderInput struct {
	Project     string `json:"project"`
	Environment string `json:"environment"`
	Path        string `json:"path"`
}

// Validate checks a folder create. The path is REQUIRED here (unlike a prefix, where
// empty means the root): "create the root folder" is not an operation — the root is
// created with its environment.
func (in CreateFolderInput) Validate() error {
	return validation.ValidateStruct(&in,
		validation.Field(&in.Project,
			validation.Required.Error("project is required"),
			slugRule("project"),
		),
		validation.Field(&in.Environment,
			validation.Required.Error("environment is required"),
			slugRule("environment"),
		),
		validation.Field(&in.Path,
			validation.Required.Error("folder path is required"),
			folderPathRule,
			validation.By(func(value any) error {
				raw, _ := value.(string)
				normalized, err := store.NormalizePath(raw)
				if err != nil {
					return nil // folderPathRule already reported it.
				}
				if normalized == "/" {
					return validation.NewError("validation_folder_path",
						"the root folder is created with its environment and cannot be created again")
				}
				return nil
			}),
		),
	)
}

// ListFoldersInput lists the folder subtree at or under a prefix. An empty prefix is
// the root.
type ListFoldersInput struct {
	Project     string `json:"project"`
	Environment string `json:"environment"`
	Prefix      string `json:"prefix,omitempty"`
}

// Validate checks a folder listing request.
func (in ListFoldersInput) Validate() error {
	return validation.ValidateStruct(&in,
		validation.Field(&in.Project,
			validation.Required.Error("project is required"),
			slugRule("project"),
		),
		validation.Field(&in.Environment,
			validation.Required.Error("environment is required"),
			slugRule("environment"),
		),
		validation.Field(&in.Prefix, folderPathRule),
	)
}

// MoveFolderInput relocates a folder and its whole subtree.
type MoveFolderInput struct {
	Project     string `json:"project"`
	Environment string `json:"environment"`
	From        string `json:"from"`
	To          string `json:"to"`
}

// Validate checks a folder move, including the two cross-field rules.
//
// A move rewrites the MRN of every secret beneath the folder, so the shapes that
// cannot work are refused before any of that starts:
//
//   - from == to is a no-op that still rewrites every descendant MRN and emits an
//     audit row claiming a move happened.
//   - moving a folder INTO ITS OWN SUBTREE detaches the subtree from the tree. The
//     store refuses it too (see store.IsAtOrUnder); refusing it here means the caller
//     gets the reason rather than a constraint error.
func (in MoveFolderInput) Validate() error {
	return validation.ValidateStruct(&in,
		validation.Field(&in.Project,
			validation.Required.Error("project is required"),
			slugRule("project"),
		),
		validation.Field(&in.Environment,
			validation.Required.Error("environment is required"),
			slugRule("environment"),
		),
		validation.Field(&in.From,
			validation.Required.Error("from is required"),
			folderPathRule,
		),
		validation.Field(&in.To,
			validation.Required.Error("to is required"),
			folderPathRule,
			validation.By(func(value any) error {
				to, _ := value.(string)
				toPath, terr := store.NormalizePath(to)
				fromPath, ferr := store.NormalizePath(in.From)
				if terr != nil || ferr != nil {
					return nil // folderPathRule already reported the malformed one.
				}
				if toPath == fromPath {
					return validation.NewError("validation_folder_move",
						"from and to are the same folder: there is nothing to move")
				}
				if store.IsAtOrUnder(toPath, fromPath) {
					return validation.NewError("validation_folder_move",
						"a folder cannot be moved into its own subtree")
				}
				return nil
			}),
		),
	)
}

// DeleteFolderInput soft-deletes a folder, its descendants and every secret inside.
type DeleteFolderInput struct {
	Project     string `json:"project"`
	Environment string `json:"environment"`
	Path        string `json:"path"`
	// RecoveryWindow overrides the service default for the secrets this delete
	// sweeps up. Nil means "use the default".
	RecoveryWindow *time.Duration `json:"recovery_window,omitempty"`
}

// Validate checks a folder delete.
func (in DeleteFolderInput) Validate() error {
	return validation.ValidateStruct(&in,
		validation.Field(&in.Project,
			validation.Required.Error("project is required"),
			slugRule("project"),
		),
		validation.Field(&in.Environment,
			validation.Required.Error("environment is required"),
			slugRule("environment"),
		),
		validation.Field(&in.Path,
			validation.Required.Error("folder path is required"),
			folderPathRule,
		),
		validation.Field(&in.RecoveryWindow, recoveryWindowRule),
	)
}
