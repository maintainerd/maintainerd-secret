package api

import (
	"fmt"
	"time"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"

	"github.com/maintainerd/secret/internal/rotation"
	"github.com/maintainerd/secret/internal/store"
)

// Secret request DTOs and their rules.
//
// Every address that reaches the store is checked here first, against the same
// functions the store uses (store.ValidateSlug / ValidateKey / NormalizePath). See
// validation.go for why the rules delegate rather than restate.

// maxKeepVersions bounds a per-secret retention override. Retention is walked on every
// write, and a secret asking to keep a million versions is asking for an unbounded
// table rather than a retention policy.
const maxKeepVersions = 1000

// Validate checks a secret address: project, environment, folder path and key.
func (a SecretAddress) Validate() error {
	return validation.ValidateStruct(&a,
		validation.Field(&a.Project,
			validation.Required.Error("project is required"),
			slugRule("project"),
		),
		validation.Field(&a.Environment,
			validation.Required.Error("environment is required"),
			slugRule("environment"),
		),
		validation.Field(&a.FolderPath, folderPathRule),
		validation.Field(&a.Key,
			validation.Required.Error("secret key is required"),
			keyRule,
		),
	)
}

// RevealSecretInput is a reveal request: an address plus an optional pinned version.
type RevealSecretInput struct {
	Address SecretAddress `json:"address"`
	// Version pins a specific version; 0 means the current one.
	Version int32 `json:"version,omitempty"`
}

// Validate checks a reveal request.
func (r RevealSecretInput) Validate() error {
	return validation.ValidateStruct(&r,
		validation.Field(&r.Address, validation.Required.Error("a secret address is required")),
		validation.Field(&r.Version,
			validation.Min(0).Error("version must not be negative; 0 means the current version"),
		),
	)
}

// Validate checks a list request: the scope, the prefix, and the page.
func (in ListSecretsInput) Validate() error {
	return validation.ValidateStruct(&in,
		validation.Field(&in.Project,
			validation.Required.Error("project is required"),
			slugRule("project"),
		),
		validation.Field(&in.Environment,
			validation.Required.Error("environment is required"),
			slugRule("environment"),
		),
		validation.Field(&in.PathPrefix, folderPathRule),
		validation.Field(&in.Page, validation.Min(0).Error("page must not be negative")),
		validation.Field(&in.Limit,
			validation.Min(0).Error("limit must not be negative"),
			validation.Max(CurrentLimits().MaxPageLimit).
				Error(fmt.Sprintf("limit must be at most %d", CurrentLimits().MaxPageLimit)),
		),
	)
}

// ListVersionsInput pages one secret's version history.
type ListVersionsInput struct {
	Address    SecretAddress `json:"address"`
	Pagination `json:"page"`
}

// Validate checks a version-history request.
func (in ListVersionsInput) Validate() error {
	return validation.ValidateStruct(&in,
		validation.Field(&in.Address, validation.Required.Error("a secret address is required")),
		validation.Field(&in.Pagination),
	)
}

// ListDeletedSecretsInput pages a scope's soft-deleted secrets.
type ListDeletedSecretsInput struct {
	Project     string `json:"project"`
	Environment string `json:"environment"`
	Pagination  `json:"page"`
}

// Validate checks a deleted-secret listing request.
func (in ListDeletedSecretsInput) Validate() error {
	return validation.ValidateStruct(&in,
		validation.Field(&in.Project,
			validation.Required.Error("project is required"),
			slugRule("project"),
		),
		validation.Field(&in.Environment,
			validation.Required.Error("environment is required"),
			slugRule("environment"),
		),
		validation.Field(&in.Pagination),
	)
}

// Validate checks a write.
//
// THE REFERENCE RULE IS THE CROSS-FIELD ONE. A value declared `reference` is a
// template of ${project/environment[/folder...]/KEY} placeholders, so its SHAPE is
// checked at write time — a malformed placeholder that nobody rejects becomes a
// consumer receiving the literal string "${billing/prod/db/PASSWORD" as its database
// password. Resolution, and the per-hop permission check that keeps a reference from
// being an escalation path, still happen at read time.
func (in PutSecretInput) Validate() error {
	return validation.ValidateStruct(&in,
		validation.Field(&in.Address, validation.Required.Error("a secret address is required")),
		validation.Field(&in.Value,
			validation.Required.Error("a secret value is required"),
			secretValueRule,
			validation.When(in.ValueType == store.ValueTypeReference,
				validation.By(func(value any) error {
					raw, _ := value.([]byte)
					return validateReferenceTemplate(raw)
				}),
			),
		),
		validation.Field(&in.ValueType,
			validation.When(in.ValueType != "", valueTypeRule),
		),
		validation.Field(&in.Description, descriptionRule()),
		validation.Field(&in.Tags, tagsRule),
		validation.Field(&in.KeepVersions, keepVersionsRule),
		validation.Field(&in.RotationPolicy, rotationPolicyMapRule),
		validation.Field(&in.ExpiresAt, expiresAtRule),
	)
}

// Validate checks a metadata-only update.
//
// It does NOT require a value, obviously, but it does apply every other bound the
// write path applies: retention, expiry and the rotation policy decide when a value is
// destroyed, so editing them is a write in every sense that matters.
func (in UpdateSecretMetaInput) Validate() error {
	return validation.ValidateStruct(&in,
		validation.Field(&in.Address, validation.Required.Error("a secret address is required")),
		validation.Field(&in.Description, descriptionRule()),
		validation.Field(&in.Tags, tagsRule),
		validation.Field(&in.KeepVersions, keepVersionsRule),
		validation.Field(&in.RotationPolicy, rotationPolicyMapRule),
		validation.Field(&in.ExpiresAt, expiresAtRule),
	)
}

// RollbackSecretInput republishes an older version as current.
type RollbackSecretInput struct {
	Address SecretAddress `json:"address"`
	Version int32         `json:"version"`
}

// Validate checks a rollback. The version is REQUIRED and must be positive: version 0
// means "current" everywhere else in this API, and a rollback to the current version
// is either a no-op or a typo for a real one.
func (in RollbackSecretInput) Validate() error {
	return validation.ValidateStruct(&in,
		validation.Field(&in.Address, validation.Required.Error("a secret address is required")),
		validation.Field(&in.Version,
			validation.Required.Error("version is required"),
			validation.Min(int32(1)).Error("version must be at least 1"),
		),
	)
}

// DeleteSecretInput soft-deletes a secret, optionally overriding the recovery window.
type DeleteSecretInput struct {
	Address SecretAddress `json:"address"`
	// RecoveryWindow overrides the service default. Nil means "use the default".
	RecoveryWindow *time.Duration `json:"recovery_window,omitempty"`
}

// Validate checks a delete. A negative window is refused rather than clamped: it would
// mean a destroy_after in the past, i.e. an immediately destroyable secret, which is
// the one thing the recovery window exists to prevent.
func (in DeleteSecretInput) Validate() error {
	return validation.ValidateStruct(&in,
		validation.Field(&in.Address, validation.Required.Error("a secret address is required")),
		validation.Field(&in.RecoveryWindow, recoveryWindowRule),
	)
}

// SecretUUIDInput addresses a secret by UUID rather than by path — the restore and
// destroy paths, where the address is ambiguous because the uniqueness index covers
// live rows only (see Service.RestoreSecret).
type SecretUUIDInput struct {
	SecretUUID string `json:"secret_uuid"`
}

// Validate checks the UUID.
func (in SecretUUIDInput) Validate() error {
	return validation.ValidateStruct(&in,
		validation.Field(&in.SecretUUID,
			validation.Required.Error("secret_uuid is required"),
			is.UUID.Error("secret_uuid must be a valid UUID"),
		),
	)
}

// ---------------------------------------------------------------------------
// Shared field rules used by more than one secret DTO
// ---------------------------------------------------------------------------

// keepVersionsRule bounds a per-secret retention override.
//
// It is a By rule rather than a Min/Max pair because ozzo's threshold rules SKIP a
// value they consider empty, and 0 is empty — so validation.Min(1) silently accepts
// keep_versions=0, which is precisely the value that must be refused ("keep nothing",
// where the only version there is to delete is the live one). This is the one place
// that distinction bites, and it bites silently, which is why it is spelled out.
var keepVersionsRule = validation.By(func(value any) error {
	keep, ok := value.(*int32)
	if !ok || keep == nil {
		return nil // absent means "use the service default".
	}
	if *keep < 1 {
		return validation.NewError("validation_keep_versions", "keep_versions must be at least 1")
	}
	if *keep > maxKeepVersions {
		return validation.NewError("validation_keep_versions",
			fmt.Sprintf("keep_versions must be at most %d", maxKeepVersions))
	}
	return nil
})

// maxRecoveryWindow bounds a per-delete recovery window. A window measured in years is
// a soft delete that never becomes a delete, which quietly keeps ciphertext for a
// credential an operator believes is gone.
const maxRecoveryWindow = 365 * 24 * time.Hour

var recoveryWindowRule = validation.By(func(value any) error {
	window, ok := value.(*time.Duration)
	if !ok || window == nil {
		return nil
	}
	if *window < 0 {
		return validation.NewError("validation_recovery_window", "recovery_window must not be negative")
	}
	if *window > maxRecoveryWindow {
		return validation.NewError("validation_recovery_window",
			fmt.Sprintf("recovery_window must be at most %s", maxRecoveryWindow))
	}
	return nil
})

// expiresAtRule refuses the zero time, which is what an unparsed or half-built
// timestamp becomes and which the store would otherwise persist as "expired in year 1".
var expiresAtRule = validation.By(func(value any) error {
	at, ok := value.(*time.Time)
	if !ok || at == nil {
		return nil
	}
	if at.IsZero() {
		return validation.NewError("validation_expires_at", "expires_at must be a real timestamp")
	}
	return nil
})

// rotationPolicyMapRule runs the policy parser over the raw JSONB map a caller
// supplied. Parsing IS the validation: rotation.ParsePolicy refuses a malformed
// interval (which would silently mean "never rotates"), an unusable generator, and —
// critically — a policy carrying a generator value, because the policy is stored as
// readable metadata.
var rotationPolicyMapRule = validation.By(func(value any) error {
	raw, ok := value.(map[string]any)
	if !ok || len(raw) == 0 {
		return nil
	}
	if _, err := rotation.ParsePolicy(raw); err != nil {
		return validation.NewError("validation_rotation_policy", err.Error())
	}
	return nil
})
