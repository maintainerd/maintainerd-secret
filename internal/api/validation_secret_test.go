package api

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/maintainerd/secret/internal/store"
)

func validAddress() SecretAddress {
	return SecretAddress{
		Project:     "billing-app",
		Environment: "prod",
		FolderPath:  "/db/primary",
		Key:         "DB_PASSWORD",
	}
}

func validPut() PutSecretInput {
	return PutSecretInput{
		Address:     validAddress(),
		Value:       []byte("hunter2-hunter2"),
		ValueType:   store.ValueTypeOpaque,
		Description: "the primary database password",
		Tags:        []string{"prod", "database"},
	}
}

func TestSecretAddress_Validate(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		assert.NoError(t, validAddress().Validate())
	})

	t.Run("root folder path is valid", func(t *testing.T) {
		a := validAddress()
		a.FolderPath = "/"
		assert.NoError(t, a.Validate())
	})

	t.Run("empty folder path means the root", func(t *testing.T) {
		a := validAddress()
		a.FolderPath = ""
		assert.NoError(t, a.Validate())
	})

	cases := []struct {
		name    string
		mutate  func(*SecretAddress)
		wantSub string
	}{
		{"missing project", func(a *SecretAddress) { a.Project = "" }, "project is required"},
		{"uppercase project", func(a *SecretAddress) { a.Project = "Billing" }, "lowercase"},
		{"project with underscore", func(a *SecretAddress) { a.Project = "billing_app" }, "lowercase"},
		{"project with a slash", func(a *SecretAddress) { a.Project = "billing/app" }, "lowercase"},
		{"project too long", func(a *SecretAddress) { a.Project = strings.Repeat("a", 64) }, "at most"},
		{"missing environment", func(a *SecretAddress) { a.Environment = "" }, "environment is required"},
		{"uppercase environment", func(a *SecretAddress) { a.Environment = "PROD" }, "lowercase"},
		{"missing key", func(a *SecretAddress) { a.Key = "" }, "secret key is required"},
		{"key with a slash", func(a *SecretAddress) { a.Key = "db/PASSWORD" }, "slash"},
		{"key too long", func(a *SecretAddress) { a.Key = strings.Repeat("K", 256) }, "at most"},
		{"key starting with a hyphen", func(a *SecretAddress) { a.Key = "-LEADING" }, "alphanumerics"},
		{"folder path with a traversal", func(a *SecretAddress) { a.FolderPath = "/db/../etc" }, ".."},
		{"folder path too deep", func(a *SecretAddress) {
			a.FolderPath = "/" + strings.Repeat("a/", 40)
		}, "levels deep"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := validAddress()
			tc.mutate(&a)
			err := a.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantSub)
		})
	}
}

func TestPutSecretInput_Validate(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		assert.NoError(t, validPut().Validate())
	})

	t.Run("value type may be omitted", func(t *testing.T) {
		in := validPut()
		in.ValueType = ""
		assert.NoError(t, in.Validate())
	})

	t.Run("keep_versions at the floor", func(t *testing.T) {
		in := validPut()
		keep := int32(1)
		in.KeepVersions = &keep
		assert.NoError(t, in.Validate())
	})

	cases := []struct {
		name    string
		mutate  func(*PutSecretInput)
		wantSub string
	}{
		{"missing value", func(in *PutSecretInput) { in.Value = nil }, "value is required"},
		{"empty value", func(in *PutSecretInput) { in.Value = []byte{} }, "value is required"},
		{"value over the limit", func(in *PutSecretInput) {
			in.Value = bytes.Repeat([]byte("a"), CurrentLimits().MaxSecretValueBytes+1)
		}, "at most"},
		{"unknown value type", func(in *PutSecretInput) { in.ValueType = "opaqe" }, "value_type must be one of"},
		{"bad address", func(in *PutSecretInput) { in.Address.Key = "" }, "secret key is required"},
		{"description too long", func(in *PutSecretInput) {
			in.Description = strings.Repeat("x", CurrentLimits().MaxDescriptionLength+1)
		}, "description must be at most"},
		{"too many tags", func(in *PutSecretInput) {
			tags := make([]string, CurrentLimits().MaxTags+1)
			for i := range tags {
				tags[i] = "tag" + string(rune('a'+i%26)) + string(rune('a'+i/26))
			}
			in.Tags = tags
		}, "tags are allowed"},
		{"tag too long", func(in *PutSecretInput) {
			in.Tags = []string{strings.Repeat("t", CurrentLimits().MaxTagLength+1)}
		}, "a tag must be at most"},
		{"empty tag", func(in *PutSecretInput) { in.Tags = []string{"prod", "  "} }, "must not be empty"},
		{"duplicate tag", func(in *PutSecretInput) { in.Tags = []string{"prod", "prod"} }, "duplicated"},
		{"keep_versions zero", func(in *PutSecretInput) {
			keep := int32(0)
			in.KeepVersions = &keep
		}, "at least 1"},
		{"keep_versions negative", func(in *PutSecretInput) {
			keep := int32(-1)
			in.KeepVersions = &keep
		}, "at least 1"},
		{"keep_versions absurd", func(in *PutSecretInput) {
			keep := int32(maxKeepVersions + 1)
			in.KeepVersions = &keep
		}, "at most"},
		{"zero expiry timestamp", func(in *PutSecretInput) {
			zero := time.Time{}
			in.ExpiresAt = &zero
		}, "real timestamp"},
		{"rotation policy with a value", func(in *PutSecretInput) {
			in.RotationPolicy = map[string]any{
				"enabled":   true,
				"interval":  "720h",
				"generator": map[string]any{"type": "supplied", "value": "hunter2"},
			}
		}, "must not contain a generator value"},
		{"rotation policy with a sub-minimum interval", func(in *PutSecretInput) {
			in.RotationPolicy = map[string]any{"enabled": true, "interval": "5m"}
		}, "at least"},
		{"rotation policy with an unparseable interval", func(in *PutSecretInput) {
			in.RotationPolicy = map[string]any{"enabled": true, "interval": "monthly"}
		}, "not a duration"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := validPut()
			tc.mutate(&in)
			err := in.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantSub)
		})
	}
}

// TestPutSecretInput_ReferenceTemplate is the cross-field rule: the template is only
// checked when the value is DECLARED a reference.
func TestPutSecretInput_ReferenceTemplate(t *testing.T) {
	reference := func(template string) PutSecretInput {
		in := validPut()
		in.ValueType = store.ValueTypeReference
		in.Value = []byte(template)
		return in
	}

	t.Run("a well-formed reference", func(t *testing.T) {
		assert.NoError(t, reference("${billing-app/prod/db/PASSWORD}").Validate())
	})

	t.Run("a reference embedded in literal text", func(t *testing.T) {
		assert.NoError(t, reference(
			"postgres://app:${billing-app/prod/db/PASSWORD}@db:5432/app").Validate())
	})

	t.Run("several placeholders in one value", func(t *testing.T) {
		assert.NoError(t, reference(
			"${billing-app/prod/db/USER}:${billing-app/prod/db/PASSWORD}").Validate())
	})

	t.Run("the same text as an opaque value is fine", func(t *testing.T) {
		in := validPut()
		in.ValueType = store.ValueTypeOpaque
		in.Value = []byte("${not-a-reference")
		assert.NoError(t, in.Validate(),
			"the template rule must apply only to reference-typed values")
	})

	cases := []struct {
		name     string
		template string
		wantSub  string
	}{
		{"no placeholder at all", "just-a-password", "at least one"},
		{"unterminated placeholder", "${billing-app/prod/db/PASSWORD", "unterminated"},
		{"no environment segment", "${PASSWORD}", "project/environment"},
		{"only a project", "${billing-app}", "project/environment"},
		{"uppercase project in the address", "${Billing/prod/PASSWORD}", "lowercase"},
		{"key with a traversal", "${billing-app/prod/../PASSWORD}", ".."},
		{"second placeholder is malformed", "${billing-app/prod/A}-${B}", "project/environment"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := reference(tc.template).Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantSub)
		})
	}
}

func TestUpdateSecretMetaInput_Validate(t *testing.T) {
	valid := UpdateSecretMetaInput{Address: validAddress(), Description: "notes"}
	assert.NoError(t, valid.Validate())

	t.Run("no value is required", func(t *testing.T) {
		assert.NoError(t, UpdateSecretMetaInput{Address: validAddress()}.Validate())
	})

	t.Run("rotation policy is still checked", func(t *testing.T) {
		in := valid
		in.RotationPolicy = map[string]any{
			"enabled":   true,
			"interval":  "720h",
			"generator": map[string]any{"type": "supplied", "value": "x"},
		}
		require.Error(t, in.Validate())
	})
}

func TestRevealSecretInput_Validate(t *testing.T) {
	t.Run("version zero means current", func(t *testing.T) {
		assert.NoError(t, RevealSecretInput{Address: validAddress()}.Validate())
	})
	t.Run("a pinned version", func(t *testing.T) {
		assert.NoError(t, RevealSecretInput{Address: validAddress(), Version: 7}.Validate())
	})
	t.Run("a negative version", func(t *testing.T) {
		err := RevealSecretInput{Address: validAddress(), Version: -1}.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must not be negative")
	})
	t.Run("a bad address", func(t *testing.T) {
		require.Error(t, RevealSecretInput{Address: SecretAddress{}}.Validate())
	})
}

func TestRollbackSecretInput_Validate(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		assert.NoError(t, RollbackSecretInput{Address: validAddress(), Version: 3}.Validate())
	})
	t.Run("version zero is refused", func(t *testing.T) {
		err := RollbackSecretInput{Address: validAddress(), Version: 0}.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "version is required")
	})
	t.Run("a negative version is refused", func(t *testing.T) {
		require.Error(t, RollbackSecretInput{Address: validAddress(), Version: -2}.Validate())
	})
}

func TestDeleteSecretInput_Validate(t *testing.T) {
	window := func(d time.Duration) *time.Duration { return &d }

	t.Run("no window means the default", func(t *testing.T) {
		assert.NoError(t, DeleteSecretInput{Address: validAddress()}.Validate())
	})
	t.Run("an explicit window", func(t *testing.T) {
		assert.NoError(t, DeleteSecretInput{
			Address: validAddress(), RecoveryWindow: window(168 * time.Hour),
		}.Validate())
	})
	t.Run("zero is allowed and means immediate", func(t *testing.T) {
		assert.NoError(t, DeleteSecretInput{
			Address: validAddress(), RecoveryWindow: window(0),
		}.Validate())
	})
	t.Run("a negative window is refused", func(t *testing.T) {
		err := DeleteSecretInput{
			Address: validAddress(), RecoveryWindow: window(-time.Hour),
		}.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must not be negative")
	})
	t.Run("an absurd window is refused", func(t *testing.T) {
		err := DeleteSecretInput{
			Address: validAddress(), RecoveryWindow: window(maxRecoveryWindow + time.Hour),
		}.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at most")
	})
}

func TestSecretUUIDInput_Validate(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		assert.NoError(t, SecretUUIDInput{SecretUUID: uuid.NewString()}.Validate())
	})
	t.Run("missing", func(t *testing.T) {
		err := SecretUUIDInput{}.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "required")
	})
	t.Run("not a uuid", func(t *testing.T) {
		err := SecretUUIDInput{SecretUUID: "1234"}.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "valid UUID")
	})
}

func TestListSecretsInput_Validate(t *testing.T) {
	valid := ListSecretsInput{Project: "billing-app", Environment: "prod"}

	t.Run("valid without a page", func(t *testing.T) {
		assert.NoError(t, valid.Validate())
	})
	t.Run("a prefix is optional", func(t *testing.T) {
		in := valid
		in.PathPrefix = "/db"
		assert.NoError(t, in.Validate())
	})
	t.Run("a limit above the cap is refused, not clamped", func(t *testing.T) {
		in := valid
		in.Limit = CurrentLimits().MaxPageLimit + 1
		err := in.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "limit must be at most")
	})
	t.Run("a negative page", func(t *testing.T) {
		in := valid
		in.Page = -1
		require.Error(t, in.Validate())
	})
	t.Run("a malformed prefix", func(t *testing.T) {
		in := valid
		in.PathPrefix = "/db/../etc"
		require.Error(t, in.Validate())
	})
}

func TestListVersionsAndDeletedInputs_Validate(t *testing.T) {
	t.Run("versions valid", func(t *testing.T) {
		assert.NoError(t, ListVersionsInput{Address: validAddress()}.Validate())
	})
	t.Run("versions with an over-large limit", func(t *testing.T) {
		in := ListVersionsInput{Address: validAddress()}
		in.Limit = CurrentLimits().MaxPageLimit + 1
		require.Error(t, in.Validate())
	})
	t.Run("deleted valid", func(t *testing.T) {
		assert.NoError(t, ListDeletedSecretsInput{
			Project: "billing-app", Environment: "prod",
		}.Validate())
	})
	t.Run("deleted without a project", func(t *testing.T) {
		require.Error(t, ListDeletedSecretsInput{Environment: "prod"}.Validate())
	})
}

func TestPagination_Validate(t *testing.T) {
	t.Run("the zero value is valid and means the defaults", func(t *testing.T) {
		p := Pagination{}
		require.NoError(t, p.Validate())
		page, limit := p.resolved()
		assert.Equal(t, 1, page)
		assert.Equal(t, defaultPageLimit, limit)
	})
	t.Run("an explicit page survives", func(t *testing.T) {
		page, limit := Pagination{Page: 3, Limit: 25}.resolved()
		assert.Equal(t, 3, page)
		assert.Equal(t, 25, limit)
	})
	t.Run("the cap is refused rather than clamped", func(t *testing.T) {
		err := Pagination{Limit: CurrentLimits().MaxPageLimit + 1}.Validate()
		require.Error(t, err)
	})
	t.Run("exactly the cap is allowed", func(t *testing.T) {
		assert.NoError(t, Pagination{Limit: CurrentLimits().MaxPageLimit}.Validate())
	})
}
