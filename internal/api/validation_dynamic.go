package api

import (
	"fmt"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"

	"github.com/maintainerd/secret/internal/dynamic"
	"github.com/maintainerd/secret/internal/store"
)

// Dynamic-secret request DTOs.
//
// THE DSN RULE IS THE SECURITY RULE HERE, and it is enforced in three places on
// purpose: this rule (a 400 with a message that explains the model), store's
// ValidateDSNSecretRef (the service-layer refusal), and a CHECK constraint in
// migrations/00012 (which makes a plaintext DSN unstorable even through a code path
// that forgets both). The DSN is the account that can CREATE ROLE, so "it must be a
// reference, never a literal" is worth three walls.
//
// The TEMPLATE rules are shape checks and nothing more — see dynamic.Config.Validate.
// No validator can tell whether a GRANT is wider than its author intended, which is
// exactly why role management is user-only: a human is the check on what the template
// actually authorizes.

// CreateDynamicRoleInput registers a dynamic role on a project.
type CreateDynamicRoleInput struct {
	Project     string `json:"project"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// DSNSecretRef addresses the secret holding the target DSN, in the
	// 'project/environment[/folder...]/KEY' form a reference value uses.
	DSNSecretRef  string `json:"dsn_secret_ref"`
	CreationSQL   string `json:"creation_sql"`
	RevocationSQL string `json:"revocation_sql"`
	// DefaultTTLSeconds and MaxTTLSeconds bound issued leases. Zero takes the
	// package defaults.
	DefaultTTLSeconds int32 `json:"default_ttl_seconds,omitempty"`
	MaxTTLSeconds     int32 `json:"max_ttl_seconds,omitempty"`
	// RoleNamePrefix prefixes generated PostgreSQL role names so an operator reading
	// pg_roles can tell which accounts this service owns. Empty takes the default.
	RoleNamePrefix string `json:"role_name_prefix,omitempty"`
}

// Validate checks a role create.
func (in CreateDynamicRoleInput) Validate() error {
	return validation.ValidateStruct(&in,
		validation.Field(&in.Project,
			validation.Required.Error("project is required"),
			slugRule("project"),
		),
		validation.Field(&in.Name,
			validation.Required.Error("name is required"),
			dynamicRoleNameRule,
		),
		validation.Field(&in.Description, descriptionRule()),
		validation.Field(&in.DSNSecretRef,
			validation.Required.Error("dsn_secret_ref is required: the target DSN must be stored as a secret and referenced here"),
			dsnSecretRefRule,
		),
		validation.Field(&in.CreationSQL,
			validation.Required.Error("creation_sql is required"),
			sqlTemplateRule("creation_sql"),
		),
		validation.Field(&in.RevocationSQL,
			validation.Required.Error("revocation_sql is required"),
			sqlTemplateRule("revocation_sql"),
		),
		validation.Field(&in.DefaultTTLSeconds, leaseTTLSecondsRule("default_ttl_seconds")),
		validation.Field(&in.MaxTTLSeconds, leaseTTLSecondsRule("max_ttl_seconds")),
		validation.Field(&in.RoleNamePrefix, validation.Length(0, 20).
			Error("role_name_prefix must be at most 20 characters")),
	)
}

// UpdateDynamicRoleInput rewrites a role configuration.
//
// The NAME is the address, not a field: it identifies which role is being updated and
// is not itself editable. Renaming a role would silently break every caller that
// issues against the old name, which is a break worth making explicit (delete and
// recreate) rather than silent.
type UpdateDynamicRoleInput struct {
	Project           string `json:"project"`
	Name              string `json:"name"`
	Description       string `json:"description,omitempty"`
	DSNSecretRef      string `json:"dsn_secret_ref"`
	CreationSQL       string `json:"creation_sql"`
	RevocationSQL     string `json:"revocation_sql"`
	DefaultTTLSeconds int32  `json:"default_ttl_seconds,omitempty"`
	MaxTTLSeconds     int32  `json:"max_ttl_seconds,omitempty"`
	Status            string `json:"status,omitempty"`
}

// Validate checks a role update.
func (in UpdateDynamicRoleInput) Validate() error {
	return validation.ValidateStruct(&in,
		validation.Field(&in.Project,
			validation.Required.Error("project is required"),
			slugRule("project"),
		),
		validation.Field(&in.Name,
			validation.Required.Error("name is required"),
			dynamicRoleNameRule,
		),
		validation.Field(&in.Description, descriptionRule()),
		validation.Field(&in.DSNSecretRef,
			validation.Required.Error("dsn_secret_ref is required"),
			dsnSecretRefRule,
		),
		validation.Field(&in.CreationSQL,
			validation.Required.Error("creation_sql is required"),
			sqlTemplateRule("creation_sql"),
		),
		validation.Field(&in.RevocationSQL,
			validation.Required.Error("revocation_sql is required"),
			sqlTemplateRule("revocation_sql"),
		),
		validation.Field(&in.DefaultTTLSeconds, leaseTTLSecondsRule("default_ttl_seconds")),
		validation.Field(&in.MaxTTLSeconds, leaseTTLSecondsRule("max_ttl_seconds")),
		validation.Field(&in.Status, dynamicRoleStatusRule),
	)
}

// DynamicRoleRef addresses one role config — the read, delete and lease-listing path.
type DynamicRoleRef struct {
	Project string `json:"project"`
	Name    string `json:"name"`
}

// Validate checks a role reference.
func (in DynamicRoleRef) Validate() error {
	return validation.ValidateStruct(&in,
		validation.Field(&in.Project,
			validation.Required.Error("project is required"),
			slugRule("project"),
		),
		validation.Field(&in.Name,
			validation.Required.Error("name is required"),
			dynamicRoleNameRule,
		),
	)
}

// ListDynamicRolesInput pages a project's role configs.
type ListDynamicRolesInput struct {
	Project    string `json:"project"`
	Pagination `json:"page"`
}

// Validate checks a role listing request.
func (in ListDynamicRolesInput) Validate() error {
	return validation.ValidateStruct(&in,
		validation.Field(&in.Project,
			validation.Required.Error("project is required"),
			slugRule("project"),
		),
		validation.Field(&in.Pagination),
	)
}

// ListDynamicLeasesInput pages one role's lease history.
type ListDynamicLeasesInput struct {
	Project    string `json:"project"`
	Name       string `json:"name"`
	Pagination `json:"page"`
}

// Validate checks a lease listing request.
func (in ListDynamicLeasesInput) Validate() error {
	return validation.ValidateStruct(&in,
		validation.Field(&in.Project,
			validation.Required.Error("project is required"),
			slugRule("project"),
		),
		validation.Field(&in.Name,
			validation.Required.Error("name is required"),
			dynamicRoleNameRule,
		),
		validation.Field(&in.Pagination),
	)
}

// IssueDynamicCredentialInput asks for one credential.
//
// NOTE WHAT A CALLER CANNOT SUPPLY: the role name, the password, the target DSN, or
// any SQL. The only knob is the TTL, and it is bounded twice (by the role's ceiling and
// by the service limit). Everything else about the credential was decided by whoever
// configured the role — which is what makes it safe to hand this surface to a workload.
type IssueDynamicCredentialInput struct {
	Project string `json:"project"`
	Name    string `json:"name"`
	// TTLSeconds is the lease length requested; zero takes the role's default. An
	// over-long request is refused rather than clamped.
	TTLSeconds int32 `json:"ttl_seconds,omitempty"`
}

// Validate checks a credential request.
func (in IssueDynamicCredentialInput) Validate() error {
	return validation.ValidateStruct(&in,
		validation.Field(&in.Project,
			validation.Required.Error("project is required"),
			slugRule("project"),
		),
		validation.Field(&in.Name,
			validation.Required.Error("name is required"),
			dynamicRoleNameRule,
		),
		validation.Field(&in.TTLSeconds, dynamicRequestedTTLRule),
	)
}

// RevokeDynamicCredentialInput gives one credential up.
type RevokeDynamicCredentialInput struct {
	Project   string `json:"project"`
	Name      string `json:"name"`
	LeaseUUID string `json:"lease_uuid"`
}

// Validate checks a revocation request.
func (in RevokeDynamicCredentialInput) Validate() error {
	return validation.ValidateStruct(&in,
		validation.Field(&in.Project,
			validation.Required.Error("project is required"),
			slugRule("project"),
		),
		validation.Field(&in.Name,
			validation.Required.Error("name is required"),
			dynamicRoleNameRule,
		),
		validation.Field(&in.LeaseUUID,
			validation.Required.Error("lease_uuid is required"),
			is.UUID.Error("lease_uuid must be a valid UUID"),
		),
	)
}

// ---------------------------------------------------------------------------
// Shared dynamic field rules
// ---------------------------------------------------------------------------

// dynamicRoleNameRule runs the same name check the store and the MRN builder use, so a
// name this validator accepts is one the resource path can express.
var dynamicRoleNameRule = validation.By(func(value any) error {
	raw, _ := value.(string)
	if raw == "" {
		return nil
	}
	if err := dynamic.ValidateConfigName(raw); err != nil {
		return validation.NewError("validation_dynamic_role_name", err.Error())
	}
	return nil
})

// dsnSecretRefRule runs the store's DSN policy: an address, never a connection string.
var dsnSecretRefRule = validation.By(func(value any) error {
	raw, _ := value.(string)
	if raw == "" {
		return nil
	}
	if err := store.ValidateDSNSecretRef(raw); err != nil {
		return validation.NewError("validation_dsn_secret_ref", err.Error())
	}
	return nil
})

// sqlTemplateRule bounds a template's length and refuses a NUL byte.
//
// The SHAPE rules (a CREATE ROLE, a DROP ROLE, the required placeholders) are left to
// dynamic.Config.Validate rather than restated here, because they are cross-field —
// which placeholders are required depends on which template this is — and a second
// copy that disagreed with the store's would either reject configs the store accepts
// or accept ones it rejects.
func sqlTemplateRule(field string) validation.Rule {
	return validation.By(func(value any) error {
		raw, _ := value.(string)
		if raw == "" {
			return nil
		}
		if len(raw) > dynamic.MaxTemplateLen {
			return validation.NewError("validation_sql_template",
				fmt.Sprintf("%s must be at most %d characters, got %d", field, dynamic.MaxTemplateLen, len(raw)))
		}
		for i := 0; i < len(raw); i++ {
			if raw[i] == 0 {
				// libpq hands the server a C string, so a NUL would SILENTLY TRUNCATE
				// the statement — turning "CREATE ROLE x; GRANT SELECT" into
				// "CREATE ROLE x" with no error anywhere.
				return validation.NewError("validation_sql_template",
					fmt.Sprintf("%s must not contain a NUL byte", field))
			}
		}
		return nil
	})
}

// dynamicRoleStatusRule restricts a status to the closed set the store accepts.
var dynamicRoleStatusRule = validation.By(func(value any) error {
	raw, _ := value.(string)
	if raw == "" {
		return nil // empty means "active"; the store resolves it.
	}
	for _, s := range store.DynamicRoleStatuses {
		if raw == s {
			return nil
		}
	}
	return validation.NewError("validation_dynamic_role_status",
		"status must be one of "+joinQuoted(store.DynamicRoleStatuses))
})

// leaseTTLSecondsRule bounds a role's configured TTL fields.
func leaseTTLSecondsRule(field string) validation.Rule {
	return validation.By(func(value any) error {
		seconds, ok := value.(int32)
		if !ok || seconds == 0 {
			return nil // zero means "use the default".
		}
		minimum := int32(dynamic.MinTTL.Seconds())
		maximum := int32(dynamic.MaxTTLCeiling.Seconds())
		if seconds < minimum {
			return validation.NewError("validation_lease_ttl",
				fmt.Sprintf("%s must be at least %d", field, minimum))
		}
		if seconds > maximum {
			return validation.NewError("validation_lease_ttl",
				fmt.Sprintf("%s must be at most %d: a longer-lived credential is a static one with a countdown", field, maximum))
		}
		return nil
	})
}

// dynamicRequestedTTLRule bounds the TTL a CALLER may ask for.
//
// This is the second of the two bounds on a lease length, and it is a different
// question from the role's ceiling: the role's ceiling is an operator's choice per
// target database, and this is the service's own refusal to mint a long-lived
// credential no matter what any role config says.
var dynamicRequestedTTLRule = validation.By(func(value any) error {
	seconds, ok := value.(int32)
	if !ok || seconds == 0 {
		return nil // zero means "use the role's default".
	}
	minimum := int32(dynamic.MinTTL.Seconds())
	maximum := int32(CurrentLimits().MaxDynamicLeaseTTLSeconds)
	if seconds < minimum {
		return validation.NewError("validation_ttl_seconds",
			fmt.Sprintf("ttl_seconds must be at least %d", minimum))
	}
	if seconds > maximum {
		return validation.NewError("validation_ttl_seconds",
			fmt.Sprintf("ttl_seconds must be at most %d", maximum))
	}
	return nil
})
