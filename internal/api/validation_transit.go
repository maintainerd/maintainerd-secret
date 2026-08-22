package api

import (
	"fmt"

	validation "github.com/go-ozzo/ozzo-validation/v4"

	"github.com/maintainerd/secret/internal/store"
	"github.com/maintainerd/secret/internal/transit"
)

// Transit request DTOs.
//
// THE PLAINTEXT BOUND IS THE ONE THAT MATTERS. Transit is a DATA PLANE — an
// application calls it on every row it stores — so an unbounded plaintext is an
// unbounded allocation plus an AES pass, per request, from a caller that only needed to
// encrypt a column. The bound is applied to the DECODED bytes, so it bounds the payload
// rather than its base64 rendering and a caller cannot buy a third more room by
// choosing an encoding. Same rule, same reason, as secretValueRule.

// CreateTransitKeyInput registers a transit key on a project.
type CreateTransitKeyInput struct {
	Project     string `json:"project"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// Validate checks a key create.
func (in CreateTransitKeyInput) Validate() error {
	return validation.ValidateStruct(&in,
		validation.Field(&in.Project,
			validation.Required.Error("project is required"),
			slugRule("project"),
		),
		validation.Field(&in.Name,
			validation.Required.Error("name is required"),
			transitKeyNameRule,
		),
		validation.Field(&in.Description, descriptionRule()),
	)
}

// UpdateTransitKeyInput changes a key's description, status and decrypt floor.
//
// THE NAME IS THE ADDRESS AND IS NOT EDITABLE: it travels inside every token ever
// issued under the key, so renaming it would orphan every ciphertext the calling
// application has stored. A "rename" is a new key plus a re-encrypt.
type UpdateTransitKeyInput struct {
	Project     string `json:"project"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Status      string `json:"status,omitempty"`
	// MinDecryptVersion retires compromised material WITHOUT deleting it: a token
	// under a version below this floor is refused, while the version row survives so
	// the decision is reversible. Zero leaves the floor unchanged.
	MinDecryptVersion int32 `json:"min_decrypt_version,omitempty"`
}

// Validate checks a key update.
func (in UpdateTransitKeyInput) Validate() error {
	return validation.ValidateStruct(&in,
		validation.Field(&in.Project,
			validation.Required.Error("project is required"),
			slugRule("project"),
		),
		validation.Field(&in.Name,
			validation.Required.Error("name is required"),
			transitKeyNameRule,
		),
		validation.Field(&in.Description, descriptionRule()),
		validation.Field(&in.Status, transitKeyStatusRule),
		validation.Field(&in.MinDecryptVersion,
			validation.Min(0).Error("min_decrypt_version must not be negative"),
		),
	)
}

// TransitKeyRef addresses one key — the read, rotate and delete path.
type TransitKeyRef struct {
	Project string `json:"project"`
	Name    string `json:"name"`
}

// Validate checks a key reference.
func (in TransitKeyRef) Validate() error {
	return validation.ValidateStruct(&in,
		validation.Field(&in.Project,
			validation.Required.Error("project is required"),
			slugRule("project"),
		),
		validation.Field(&in.Name,
			validation.Required.Error("name is required"),
			transitKeyNameRule,
		),
	)
}

// ListTransitKeysInput pages a project's keys.
type ListTransitKeysInput struct {
	Project    string `json:"project"`
	Pagination `json:"page"`
}

// Validate checks a key listing request.
func (in ListTransitKeysInput) Validate() error {
	return validation.ValidateStruct(&in,
		validation.Field(&in.Project,
			validation.Required.Error("project is required"),
			slugRule("project"),
		),
		validation.Field(&in.Pagination),
	)
}

// ListTransitKeyVersionsInput pages one key's version history.
type ListTransitKeyVersionsInput struct {
	Project    string `json:"project"`
	Name       string `json:"name"`
	Pagination `json:"page"`
}

// Validate checks a version listing request.
func (in ListTransitKeyVersionsInput) Validate() error {
	return validation.ValidateStruct(&in,
		validation.Field(&in.Project,
			validation.Required.Error("project is required"),
			slugRule("project"),
		),
		validation.Field(&in.Name,
			validation.Required.Error("name is required"),
			transitKeyNameRule,
		),
		validation.Field(&in.Pagination),
	)
}

// TransitEncryptInput seals one plaintext.
//
// Plaintext is []byte because both transports decode it before it gets here (base64 in
// JSON, bytes on the wire in gRPC), so the bound below applies to the credential-sized
// thing rather than to its encoding.
type TransitEncryptInput struct {
	Project string `json:"project"`
	Name    string `json:"name"`
	// Plaintext is the value to seal. It is deliberately NOT rendered in any error
	// message this DTO produces — the messages describe its length and nothing else.
	Plaintext []byte `json:"plaintext"`
}

// Validate checks an encrypt request.
func (in TransitEncryptInput) Validate() error {
	return validation.ValidateStruct(&in,
		validation.Field(&in.Project,
			validation.Required.Error("project is required"),
			slugRule("project"),
		),
		validation.Field(&in.Name,
			validation.Required.Error("name is required"),
			transitKeyNameRule,
		),
		validation.Field(&in.Plaintext,
			validation.Required.Error("plaintext is required"),
			transitPlaintextRule,
		),
	)
}

// TransitDecryptInput opens one ciphertext token.
//
// THE KEY NAME IS NOT A FIELD, deliberately: the token carries it, which is the whole
// point of the token format (the caller stores one opaque string and never tracks a key
// version). The PROJECT is a field because it scopes the lookup — a token is a
// reference within a scope, not a self-authorizing capability, so the key it names is
// resolved inside the caller's own tenant and project.
type TransitDecryptInput struct {
	Project string `json:"project"`
	// Ciphertext is the wire token: m9dt:v1:<key>:<version>:<payload>.
	Ciphertext string `json:"ciphertext"`
}

// Validate checks a decrypt request.
func (in TransitDecryptInput) Validate() error {
	return validation.ValidateStruct(&in,
		validation.Field(&in.Project,
			validation.Required.Error("project is required"),
			slugRule("project"),
		),
		validation.Field(&in.Ciphertext,
			validation.Required.Error("ciphertext is required"),
			transitTokenRule,
		),
	)
}

// ---------------------------------------------------------------------------
// Shared transit field rules
// ---------------------------------------------------------------------------

// transitKeyNameRule runs the store's key-name check, which is the same slug rule the
// token format depends on: a name that could contain the token's ':' delimiter would be
// a way to forge a token that resolves to a different key.
var transitKeyNameRule = validation.By(func(value any) error {
	raw, _ := value.(string)
	if raw == "" {
		return nil
	}
	if err := store.ValidateTransitKeyName(raw); err != nil {
		return validation.NewError("validation_transit_key_name", err.Error())
	}
	return nil
})

// transitKeyStatusRule restricts a status to the closed set the store accepts.
var transitKeyStatusRule = validation.By(func(value any) error {
	raw, _ := value.(string)
	if raw == "" {
		return nil // empty leaves the status unchanged.
	}
	for _, s := range store.TransitKeyStatuses {
		if raw == s {
			return nil
		}
	}
	return validation.NewError("validation_transit_key_status",
		"status must be one of "+joinQuoted(store.TransitKeyStatuses))
})

// transitPlaintextRule bounds one Encrypt. See the file comment for why the bound is
// tighter than a secret value's.
var transitPlaintextRule = validation.By(func(value any) error {
	raw, ok := value.([]byte)
	if !ok {
		return nil
	}
	limit := CurrentLimits().MaxTransitPlaintextBytes
	if len(raw) > limit {
		return validation.NewError("validation_transit_plaintext",
			fmt.Sprintf("a transit plaintext must be at most %d bytes, got %d", limit, len(raw)))
	}
	return nil
})

// transitTokenRule parses the token and discards the result.
//
// Parsing here rather than only in the store turns a malformed token into a 400 before
// any database read happens — a syntactically impossible token must not be allowed to
// drive a key lookup. It reaches no key and discloses nothing: the parser's errors
// describe the caller's own string.
var transitTokenRule = validation.By(func(value any) error {
	raw, _ := value.(string)
	if raw == "" {
		return nil
	}
	if len(raw) > transit.MaxCiphertextChars {
		return validation.NewError("validation_transit_ciphertext",
			fmt.Sprintf("a ciphertext token must be at most %d characters", transit.MaxCiphertextChars))
	}
	if _, err := transit.ParseToken(raw); err != nil {
		return validation.NewError("validation_transit_ciphertext", err.Error())
	}
	return nil
})
