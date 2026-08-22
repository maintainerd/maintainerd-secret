// Request validation for the application service.
//
// WHY IT LIVES IN THIS PACKAGE AND NOT IN THE TRANSPORTS. The REST handlers
// (internal/httpapi) and the gRPC service (internal/grpcserver) are thin adapters over
// the methods here, and validation is subject to exactly the argument the package
// comment makes about authorization: duplicating a rule across two transports is how
// one of them ends up missing it. So every request DTO is defined in this package,
// carries its own Validate(), and is validated by the api method itself — which means
// a payload refused on REST is refused on gRPC by construction rather than by
// discipline. There is a test asserting precisely that (validation_parity_test.go).
//
// VALIDATION RUNS BEFORE AUTHORIZATION, deliberately. The guard resolves an MRN, which
// for most operations means a database read; letting a syntactically impossible
// address drive that read is free work for an unauthenticated-adjacent caller. Nothing
// leaks: a validation error describes the caller's own input and says nothing about
// what exists. The audit contract is unchanged — a validation failure is not a denial,
// so it writes no denial row, exactly as the pre-existing NormalizePath rejections did.
//
// STYLE. One file per entity (validation_secret.go, validation_webhook.go, ...), a
// table test beside each, human-readable `.Error(...)` messages, `is.*` helpers for the
// standard formats, and cross-field rules via validation.By. Messages are lowercase to
// match this service's existing error text (apperror, store) rather than auth's
// capitalized style; they are rendered straight into an apperror.ValidationError.
package api

import (
	"fmt"
	"strings"
	"unicode/utf8"

	validation "github.com/go-ozzo/ozzo-validation/v4"

	"github.com/maintainerd/secret/internal/platform/apperror"
	"github.com/maintainerd/secret/internal/store"
)

// validate runs a DTO's Validate and converts a failure into the service's typed
// validation error, so every transport maps it to 400/InvalidArgument through the
// mapping it already has.
//
// A nil DTO error returns nil. An ozzo error is rendered with its own String(), which
// produces "field: message; field: message" — stable enough for a client to display
// and specific enough for an operator to act on.
func validate(v validation.Validatable) error {
	if err := v.Validate(); err != nil {
		return apperror.NewValidation(err.Error())
	}
	return nil
}

// ---------------------------------------------------------------------------
// Shared rules
// ---------------------------------------------------------------------------

// slugRule checks a tenant/project/environment slug against the SAME function the
// store uses (store.ValidateSlug), rather than restating the pattern here.
//
// That reuse is the point: a slug is an MRN segment, and a validator that disagreed
// with the store's would either reject addresses the store accepts (an API that cannot
// reach its own rows) or accept ones it rejects (a 500 where a 400 belongs).
func slugRule(kind string) validation.Rule {
	return validation.By(func(value any) error {
		raw, _ := value.(string)
		if raw == "" {
			return nil // Required is a separate rule; empty is that rule's business.
		}
		if err := store.ValidateSlug(kind, raw); err != nil {
			return validation.NewError("validation_slug", err.Error())
		}
		return nil
	})
}

// keyRule checks a secret key: env-var style, no slash (a key that could smuggle a
// path separator would forge an MRN resource segment).
var keyRule = validation.By(func(value any) error {
	raw, _ := value.(string)
	if raw == "" {
		return nil
	}
	if err := store.ValidateKey(raw); err != nil {
		return validation.NewError("validation_secret_key", err.Error())
	}
	return nil
})

// folderPathRule checks a folder path by running the store's canonicalizer and
// discarding the result. Empty is permitted and means the root — the api layer
// normalizes it downstream.
var folderPathRule = validation.By(func(value any) error {
	raw, _ := value.(string)
	if raw == "" {
		return nil
	}
	if _, err := store.NormalizePath(raw); err != nil {
		return validation.NewError("validation_folder_path", err.Error())
	}
	return nil
})

// tagsRule bounds a tag list: count, per-tag length, no empties, no duplicates.
//
// Tags are plaintext metadata returned in every listing, so an unbounded list is an
// unbounded response; duplicates are refused because a tag set that silently contains
// "prod" twice is a filter that behaves differently from the one the operator wrote.
var tagsRule = validation.By(func(value any) error {
	tags, ok := value.([]string)
	if !ok || len(tags) == 0 {
		return nil
	}
	limits := CurrentLimits()
	if len(tags) > limits.MaxTags {
		return validation.NewError("validation_tags",
			fmt.Sprintf("at most %d tags are allowed, got %d", limits.MaxTags, len(tags)))
	}
	seen := make(map[string]bool, len(tags))
	for _, tag := range tags {
		if strings.TrimSpace(tag) == "" {
			return validation.NewError("validation_tags", "a tag must not be empty")
		}
		if utf8.RuneCountInString(tag) > limits.MaxTagLength {
			return validation.NewError("validation_tags",
				fmt.Sprintf("a tag must be at most %d characters, got %d", limits.MaxTagLength, utf8.RuneCountInString(tag)))
		}
		if seen[tag] {
			return validation.NewError("validation_tags", fmt.Sprintf("tag %q is duplicated", tag))
		}
		seen[tag] = true
	}
	return nil
})

// descriptionRule bounds a free-text description against the configured limit.
func descriptionRule() validation.Rule {
	return validation.Length(0, CurrentLimits().MaxDescriptionLength).
		Error(fmt.Sprintf("description must be at most %d characters", CurrentLimits().MaxDescriptionLength))
}

// secretValueRule bounds a plaintext. It is applied to the DECODED bytes, so the
// bound is on the credential rather than on its base64 rendering — a caller cannot
// buy a third more room by choosing an encoding.
var secretValueRule = validation.By(func(value any) error {
	raw, ok := value.([]byte)
	if !ok {
		return nil
	}
	limit := CurrentLimits().MaxSecretValueBytes
	if len(raw) > limit {
		return validation.NewError("validation_secret_value",
			fmt.Sprintf("a secret value must be at most %d bytes, got %d", limit, len(raw)))
	}
	return nil
})

// valueTypeRule restricts a declared value type to the closed set the store accepts.
// An unknown type is refused here rather than at the insert, because "opaqe" silently
// becoming "opaque" is a reference that never resolves.
var valueTypeRule = validation.In(
	store.ValueTypeOpaque,
	store.ValueTypeJSON,
	store.ValueTypeReference,
).Error(fmt.Sprintf("value_type must be one of %s, %s, %s",
	store.ValueTypeOpaque, store.ValueTypeJSON, store.ValueTypeReference))

// validateReferenceTemplate checks a reference-typed plaintext WITHOUT resolving it.
//
// A `reference` value is a template containing ${project/environment[/folder...]/KEY}
// placeholders. Checking the syntax at write time is what turns "this credential is a
// literal ${...} string" — which is what a consumer receives when a placeholder is
// malformed and nothing rejects it — into a 400 at the moment the mistake is made.
// Resolution (and the per-hop permission check) still happens at read time; this is
// purely a shape check and reaches no other secret.
func validateReferenceTemplate(raw []byte) error {
	text := string(raw)
	if !strings.Contains(text, referenceOpen) {
		return validation.NewError("validation_reference",
			"a reference value must contain at least one ${project/environment/KEY} placeholder")
	}
	rest := text
	for {
		start := strings.Index(rest, referenceOpen)
		if start < 0 {
			return nil
		}
		end := strings.Index(rest[start:], referenceClose)
		if end < 0 {
			return validation.NewError("validation_reference",
				"reference value contains an unterminated ${...} placeholder")
		}
		address := rest[start+len(referenceOpen) : start+end]
		rest = rest[start+end+len(referenceClose):]

		project, environment, folderPath, key, ok := store.SplitReferencePath(address)
		if !ok {
			return validation.NewError("validation_reference",
				fmt.Sprintf("reference %q must be project/environment[/folder...]/KEY", address))
		}
		if err := store.ValidateSlug("reference project", project); err != nil {
			return validation.NewError("validation_reference", err.Error())
		}
		if err := store.ValidateSlug("reference environment", environment); err != nil {
			return validation.NewError("validation_reference", err.Error())
		}
		if _, err := store.NormalizePath(folderPath); err != nil {
			return validation.NewError("validation_reference", err.Error())
		}
		if err := store.ValidateKey(key); err != nil {
			return validation.NewError("validation_reference", err.Error())
		}
	}
}

// ---------------------------------------------------------------------------
// Pagination
// ---------------------------------------------------------------------------

// Pagination is the page selector every list operation takes. It is a DTO of its own
// so the cap is stated once: both transports build one, and neither can widen it.
type Pagination struct {
	Page  int `json:"page"`
	Limit int `json:"limit"`
}

// Validate bounds a page request.
//
// AN OVER-LARGE LIMIT IS REFUSED, NOT CLAMPED. Silently returning 200 rows to a client
// that asked for 10000 makes the client believe it has read everything, which for a
// reconciler walking an environment means it stops early and reports success.
func (p Pagination) Validate() error {
	max := CurrentLimits().MaxPageLimit
	return validation.ValidateStruct(&p,
		validation.Field(&p.Page,
			validation.Min(0).Error("page must not be negative"),
		),
		validation.Field(&p.Limit,
			validation.Min(0).Error("limit must not be negative"),
			validation.Max(max).Error(fmt.Sprintf("limit must be at most %d", max)),
		),
	)
}

// resolved returns the effective page and limit, applying defaults for the zero value.
func (p Pagination) resolved() (page, limit int) {
	page, limit = p.Page, p.Limit
	if page < 1 {
		page = 1
	}
	if limit < 1 {
		limit = defaultPageLimit
	}
	if max := CurrentLimits().MaxPageLimit; limit > max {
		limit = max
	}
	return page, limit
}

// defaultPageLimit is the page size a request that names none receives. It matches the
// REST and gRPC defaults so the two transports paginate identically.
const defaultPageLimit = 50
