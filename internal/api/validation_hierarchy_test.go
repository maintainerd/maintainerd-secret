package api

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/maintainerd/secret/internal/store"
)

// Table tests for the hierarchy DTOs: projects, environments, folders and imports.
// They share this file because the rules are the same three (slug, path, position)
// composed differently, and splitting them would be four files of near-identical
// tables.

// ---------------------------------------------------------------------------
// Projects
// ---------------------------------------------------------------------------

func TestCreateProjectInput_Validate(t *testing.T) {
	valid := CreateProjectInput{Slug: "billing-app", Name: "Billing", Description: "billing service"}
	assert.NoError(t, valid.Validate())

	cases := []struct {
		name    string
		mutate  func(*CreateProjectInput)
		wantSub string
	}{
		{"missing slug", func(in *CreateProjectInput) { in.Slug = "" }, "slug is required"},
		{"uppercase slug", func(in *CreateProjectInput) { in.Slug = "Billing" }, "lowercase"},
		{"slug with a space", func(in *CreateProjectInput) { in.Slug = "billing app" }, "lowercase"},
		{"slug ending in a hyphen", func(in *CreateProjectInput) { in.Slug = "billing-" }, "lowercase"},
		{"slug too long", func(in *CreateProjectInput) { in.Slug = strings.Repeat("a", 64) }, "at most"},
		{"name too long", func(in *CreateProjectInput) {
			in.Name = strings.Repeat("n", maxDisplayNameLength+1)
		}, "at most 100"},
		{"description too long", func(in *CreateProjectInput) {
			in.Description = strings.Repeat("d", CurrentLimits().MaxDescriptionLength+1)
		}, "description must be at most"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := valid
			tc.mutate(&in)
			err := in.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantSub)
		})
	}

	t.Run("name and description are optional", func(t *testing.T) {
		assert.NoError(t, CreateProjectInput{Slug: "billing-app"}.Validate())
	})
}

func TestUpdateProjectInput_Validate(t *testing.T) {
	valid := UpdateProjectInput{Slug: "billing-app", Name: "Billing", Status: store.StatusActive}
	assert.NoError(t, valid.Validate())

	t.Run("every sanctioned status", func(t *testing.T) {
		for _, status := range store.ResourceStatuses {
			in := valid
			in.Status = status
			assert.NoError(t, in.Validate(), status)
		}
	})
	t.Run("empty status means leave unchanged", func(t *testing.T) {
		in := valid
		in.Status = ""
		assert.NoError(t, in.Validate())
	})
	t.Run("an invented status", func(t *testing.T) {
		in := valid
		in.Status = "disabled"
		err := in.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "status must be one of")
	})
	t.Run("the slug is still an address and must be valid", func(t *testing.T) {
		in := valid
		in.Slug = "Not A Slug"
		require.Error(t, in.Validate())
	})
}

func TestProjectRefAndListProjects_Validate(t *testing.T) {
	assert.NoError(t, ProjectRef{Slug: "billing-app"}.Validate())
	require.Error(t, ProjectRef{}.Validate())
	require.Error(t, ProjectRef{Slug: "BILLING"}.Validate())

	assert.NoError(t, ListProjectsInput{}.Validate())
	over := ListProjectsInput{}
	over.Limit = CurrentLimits().MaxPageLimit + 1
	require.Error(t, over.Validate())
}

// ---------------------------------------------------------------------------
// Environments
// ---------------------------------------------------------------------------

func TestCreateEnvironmentInput_Validate(t *testing.T) {
	valid := CreateEnvironmentInput{Project: "billing-app", Slug: "prod", Name: "Production", Position: 1}
	assert.NoError(t, valid.Validate())

	cases := []struct {
		name    string
		mutate  func(*CreateEnvironmentInput)
		wantSub string
	}{
		{"missing project", func(in *CreateEnvironmentInput) { in.Project = "" }, "project is required"},
		{"missing slug", func(in *CreateEnvironmentInput) { in.Slug = "" }, "slug is required"},
		{"uppercase slug", func(in *CreateEnvironmentInput) { in.Slug = "Prod" }, "lowercase"},
		{"negative position", func(in *CreateEnvironmentInput) { in.Position = -1 }, "must not be negative"},
		{"absurd position", func(in *CreateEnvironmentInput) { in.Position = maxPosition + 1 }, "at most"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := valid
			tc.mutate(&in)
			err := in.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantSub)
		})
	}
}

func TestUpdateEnvironmentInputAndRef_Validate(t *testing.T) {
	valid := UpdateEnvironmentInput{Project: "billing-app", Slug: "prod", Status: store.StatusArchived}
	assert.NoError(t, valid.Validate())

	bad := valid
	bad.Status = "retired"
	require.Error(t, bad.Validate())

	assert.NoError(t, EnvironmentRef{Project: "billing-app", Slug: "prod"}.Validate())
	require.Error(t, EnvironmentRef{Project: "billing-app"}.Validate())
	require.Error(t, EnvironmentRef{Slug: "prod"}.Validate())
}

// ---------------------------------------------------------------------------
// Folders
// ---------------------------------------------------------------------------

func TestCreateFolderInput_Validate(t *testing.T) {
	valid := CreateFolderInput{Project: "billing-app", Environment: "prod", Path: "/db/primary"}
	assert.NoError(t, valid.Validate())

	cases := []struct {
		name    string
		mutate  func(*CreateFolderInput)
		wantSub string
	}{
		{"missing path", func(in *CreateFolderInput) { in.Path = "" }, "folder path is required"},
		{"the root cannot be created", func(in *CreateFolderInput) { in.Path = "/" }, "created with its environment"},
		{"the root, spelled oddly", func(in *CreateFolderInput) { in.Path = "//" }, "created with its environment"},
		{"a traversal", func(in *CreateFolderInput) { in.Path = "/db/../etc" }, ".."},
		{"a segment with a slash-forging character", func(in *CreateFolderInput) {
			in.Path = "/db/pri mary"
		}, "alphanumerics"},
		{"missing project", func(in *CreateFolderInput) { in.Project = "" }, "project is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := valid
			tc.mutate(&in)
			err := in.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantSub)
		})
	}

	// '.' segments are CANONICALIZED away rather than refused — "/db/./primary" is
	// "/db/primary", which is a real folder and a legal request. Only '..' is refused,
	// because a path that escapes the root would silently mean something else.
	t.Run("a dot segment is canonicalized, not refused", func(t *testing.T) {
		in := valid
		in.Path = "/db/./primary"
		assert.NoError(t, in.Validate())
	})
}

func TestMoveFolderInput_Validate(t *testing.T) {
	valid := MoveFolderInput{Project: "billing-app", Environment: "prod", From: "/db", To: "/data"}
	assert.NoError(t, valid.Validate())

	t.Run("moving to a differently-spelled same path is refused", func(t *testing.T) {
		in := valid
		in.To = "/db/"
		err := in.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "nothing to move")
	})
	t.Run("moving into its own subtree is refused", func(t *testing.T) {
		in := valid
		in.To = "/db/primary"
		err := in.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "own subtree")
	})
	t.Run("moving a subtree out is allowed", func(t *testing.T) {
		in := valid
		in.From = "/db/primary"
		in.To = "/data"
		assert.NoError(t, in.Validate())
	})
	t.Run("moving to the root is allowed", func(t *testing.T) {
		in := valid
		in.To = "/"
		assert.NoError(t, in.Validate())
	})
	t.Run("moving FROM the root is refused as a self-move", func(t *testing.T) {
		in := valid
		in.From = "/"
		in.To = "/data"
		err := in.Validate()
		require.Error(t, err, "everything is under the root, so this is always a subtree move")
	})
	t.Run("missing from", func(t *testing.T) {
		in := valid
		in.From = ""
		require.Error(t, in.Validate())
	})
}

func TestListAndDeleteFolderInputs_Validate(t *testing.T) {
	assert.NoError(t, ListFoldersInput{Project: "billing-app", Environment: "prod"}.Validate())
	assert.NoError(t, ListFoldersInput{Project: "billing-app", Environment: "prod", Prefix: "/db"}.Validate())
	require.Error(t, ListFoldersInput{Environment: "prod"}.Validate())
	require.Error(t, ListFoldersInput{Project: "billing-app", Environment: "prod", Prefix: "/../x"}.Validate())

	del := DeleteFolderInput{Project: "billing-app", Environment: "prod", Path: "/db"}
	assert.NoError(t, del.Validate())

	negative := -time.Hour
	del.RecoveryWindow = &negative
	require.Error(t, del.Validate())
}

// ---------------------------------------------------------------------------
// Scope imports
// ---------------------------------------------------------------------------

func TestCreateImportInput_Validate(t *testing.T) {
	valid := CreateImportInput{
		Project:           "billing-app",
		Environment:       "staging",
		FolderPath:        "/db",
		SourceProject:     "billing-app",
		SourceEnvironment: "dev",
		SourceFolderPath:  "/db",
	}
	assert.NoError(t, valid.Validate())

	t.Run("a cross-project import is allowed", func(t *testing.T) {
		in := valid
		in.SourceProject = "shared"
		assert.NoError(t, in.Validate())
	})
	t.Run("importing the same scope is refused", func(t *testing.T) {
		in := valid
		in.SourceEnvironment = in.Environment
		err := in.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot import itself")
	})
	t.Run("same environment but a different folder is allowed", func(t *testing.T) {
		in := valid
		in.SourceEnvironment = in.Environment
		in.SourceFolderPath = "/shared"
		assert.NoError(t, in.Validate())
	})
	t.Run("a missing source environment", func(t *testing.T) {
		in := valid
		in.SourceEnvironment = ""
		err := in.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "source_environment is required")
	})
	t.Run("a malformed source path", func(t *testing.T) {
		in := valid
		in.SourceFolderPath = "/db/../../etc"
		require.Error(t, in.Validate())
	})
	t.Run("an absurd position", func(t *testing.T) {
		in := valid
		in.Position = maxPosition + 1
		require.Error(t, in.Validate())
	})
}

func TestImportRefAndUpdate_Validate(t *testing.T) {
	id := uuid.NewString()
	assert.NoError(t, ImportRef{ImportUUID: id}.Validate())
	assert.NoError(t, UpdateImportInput{ImportUUID: id, Enabled: true, Position: 2}.Validate())

	require.Error(t, ImportRef{}.Validate())
	require.Error(t, ImportRef{ImportUUID: "not-a-uuid"}.Validate())
	require.Error(t, UpdateImportInput{ImportUUID: id, Position: -1}.Validate())
}

func TestListImportsInput_Validate(t *testing.T) {
	assert.NoError(t, ListImportsInput{Project: "billing-app", Environment: "prod"}.Validate())
	require.Error(t, ListImportsInput{Project: "billing-app"}.Validate())
	require.Error(t, ListImportsInput{
		Project: "billing-app", Environment: "prod", FolderPath: "/../x",
	}.Validate())
}

func TestListAuditEventsInput_Validate(t *testing.T) {
	assert.NoError(t, ListAuditEventsInput{}.Validate())

	over := ListAuditEventsInput{}
	over.Limit = CurrentLimits().MaxPageLimit + 1
	err := over.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "limit must be at most")
}
