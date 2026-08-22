package api

import (
	"fmt"

	validation "github.com/go-ozzo/ozzo-validation/v4"

	"github.com/maintainerd/secret/internal/store"
)

// Bulk request DTOs.
//
// THE BATCH BOUND IS THE SECURITY PROPERTY (see bulk.go): an unbounded batch get is a
// bulk-decryption endpoint — one request that reveals an entire environment, held in
// memory at once, with a single audit timestamp. It is stated here, once, and both
// transports funnel through it.

// BatchGetInput is a bulk reveal.
type BatchGetInput struct {
	Items []BatchGetItem `json:"items"`
}

// Validate checks a batch get: the bound, and every item's address.
func (in BatchGetInput) Validate() error {
	return validation.ValidateStruct(&in,
		validation.Field(&in.Items,
			validation.Required.Error("a batch get needs at least one item"),
			batchSizeRule("batch get"),
			validation.Each(),
		),
	)
}

// Validate checks one requested reveal.
func (i BatchGetItem) Validate() error {
	return validation.ValidateStruct(&i,
		validation.Field(&i.Address, validation.Required.Error("a secret address is required")),
		validation.Field(&i.Version,
			validation.Min(int32(0)).Error("version must not be negative; 0 means the current version"),
		),
	)
}

// BatchPutInput is a bulk write.
type BatchPutInput struct {
	Items []BatchPutItem `json:"items"`
}

// Validate checks a batch put: the bound, every item, and the duplicate-address rule.
//
// DUPLICATE ADDRESSES ARE REFUSED. The items are written in order and each is its own
// transaction, so two items naming one secret produce two versions and the winner is
// whichever the caller happened to list last — a silent last-write-wins inside a single
// request. A reconciler that builds its batch from a map with a collision is exactly
// the case, and it should learn about it.
func (in BatchPutInput) Validate() error {
	return validation.ValidateStruct(&in,
		validation.Field(&in.Items,
			validation.Required.Error("a batch put needs at least one item"),
			batchSizeRule("batch put"),
			validation.Each(),
			validation.By(func(value any) error {
				items, ok := value.([]BatchPutItem)
				if !ok {
					return nil
				}
				seen := make(map[SecretAddress]bool, len(items))
				for _, item := range items {
					if seen[item.Address] {
						return validation.NewError("validation_batch", fmt.Sprintf(
							"address %s/%s%s/%s appears more than once in the batch",
							item.Address.Project, item.Address.Environment,
							item.Address.FolderPath, item.Address.Key))
					}
					seen[item.Address] = true
				}
				return nil
			}),
		),
	)
}

// Validate checks one requested write. It applies the same value, type, tag and
// reference rules a single put applies — a batch is a transport optimisation, not a
// weaker contract.
func (i BatchPutItem) Validate() error {
	return validation.ValidateStruct(&i,
		validation.Field(&i.Address, validation.Required.Error("a secret address is required")),
		validation.Field(&i.Value,
			validation.Required.Error("a secret value is required"),
			secretValueRule,
			validation.When(i.ValueType == store.ValueTypeReference,
				validation.By(func(value any) error {
					raw, _ := value.([]byte)
					return validateReferenceTemplate(raw)
				}),
			),
		),
		validation.Field(&i.ValueType,
			validation.When(i.ValueType != "", valueTypeRule),
		),
		validation.Field(&i.Description, descriptionRule()),
		validation.Field(&i.Tags, tagsRule),
	)
}

// batchSizeRule enforces the configured item bound. `kind` names the operation so the
// message reads as the caller's own request.
func batchSizeRule(kind string) validation.Rule {
	return validation.By(func(value any) error {
		var count int
		switch items := value.(type) {
		case []BatchGetItem:
			count = len(items)
		case []BatchPutItem:
			count = len(items)
		default:
			return nil
		}
		max := CurrentLimits().MaxBatchItems
		if count > max {
			return validation.NewError("validation_batch",
				fmt.Sprintf("a %s is limited to %d items, got %d", kind, max, count))
		}
		return nil
	})
}
