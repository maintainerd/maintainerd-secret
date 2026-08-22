package api

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/maintainerd/secret/internal/store"
)

func getItems(n int) []BatchGetItem {
	items := make([]BatchGetItem, 0, n)
	for i := 0; i < n; i++ {
		items = append(items, BatchGetItem{Address: validAddress()})
	}
	return items
}

func putItems(n int) []BatchPutItem {
	items := make([]BatchPutItem, 0, n)
	for i := 0; i < n; i++ {
		address := validAddress()
		// Distinct keys, because duplicate addresses in one batch are refused.
		address.Key = "KEY_" + string(rune('A'+i%26)) + string(rune('A'+i/26))
		items = append(items, BatchPutItem{Address: address, Value: []byte("value")})
	}
	return items
}

func TestBatchGetInput_Validate(t *testing.T) {
	t.Run("a single item", func(t *testing.T) {
		assert.NoError(t, BatchGetInput{Items: getItems(1)}.Validate())
	})
	t.Run("exactly the bound", func(t *testing.T) {
		assert.NoError(t, BatchGetInput{Items: getItems(CurrentLimits().MaxBatchItems)}.Validate())
	})
	t.Run("an empty batch", func(t *testing.T) {
		err := BatchGetInput{}.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at least one item")
	})
	t.Run("one over the bound", func(t *testing.T) {
		err := BatchGetInput{Items: getItems(CurrentLimits().MaxBatchItems + 1)}.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "limited to")
	})
	t.Run("one malformed item fails the whole batch", func(t *testing.T) {
		items := getItems(3)
		items[1].Address.Key = "db/PASSWORD"
		err := BatchGetInput{Items: items}.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "slash")
	})
	t.Run("a negative version in an item", func(t *testing.T) {
		items := getItems(1)
		items[0].Version = -1
		require.Error(t, BatchGetInput{Items: items}.Validate())
	})
}

func TestBatchPutInput_Validate(t *testing.T) {
	t.Run("a single item", func(t *testing.T) {
		assert.NoError(t, BatchPutInput{Items: putItems(1)}.Validate())
	})
	t.Run("exactly the bound", func(t *testing.T) {
		assert.NoError(t, BatchPutInput{Items: putItems(CurrentLimits().MaxBatchItems)}.Validate())
	})
	t.Run("an empty batch", func(t *testing.T) {
		err := BatchPutInput{}.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at least one item")
	})
	t.Run("one over the bound", func(t *testing.T) {
		err := BatchPutInput{Items: putItems(CurrentLimits().MaxBatchItems + 1)}.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "limited to")
	})

	// The duplicate rule matters because each item is its own transaction: two items
	// naming one secret write two versions and the winner is whichever was listed
	// last, which is a silent last-write-wins inside a single request.
	t.Run("a duplicated address is refused", func(t *testing.T) {
		items := putItems(2)
		items[1].Address = items[0].Address
		err := BatchPutInput{Items: items}.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "more than once")
	})
	t.Run("the same key in a different folder is not a duplicate", func(t *testing.T) {
		items := putItems(2)
		items[1].Address = items[0].Address
		items[1].Address.FolderPath = "/db/replica"
		assert.NoError(t, BatchPutInput{Items: items}.Validate())
	})

	t.Run("an item with no value", func(t *testing.T) {
		items := putItems(1)
		items[0].Value = nil
		err := BatchPutInput{Items: items}.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "value is required")
	})
	t.Run("an item over the value limit", func(t *testing.T) {
		items := putItems(1)
		items[0].Value = bytes.Repeat([]byte("a"), CurrentLimits().MaxSecretValueBytes+1)
		require.Error(t, BatchPutInput{Items: items}.Validate())
	})
	t.Run("an item with an unknown value type", func(t *testing.T) {
		items := putItems(1)
		items[0].ValueType = "binary"
		require.Error(t, BatchPutInput{Items: items}.Validate())
	})

	// A batch is a transport optimisation, not a weaker contract: the reference rule
	// applies to a batched write exactly as it does to a single one.
	t.Run("an item with a malformed reference template", func(t *testing.T) {
		items := putItems(1)
		items[0].ValueType = store.ValueTypeReference
		items[0].Value = []byte("${PASSWORD}")
		err := BatchPutInput{Items: items}.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "project/environment")
	})
	t.Run("an item with a well-formed reference template", func(t *testing.T) {
		items := putItems(1)
		items[0].ValueType = store.ValueTypeReference
		items[0].Value = []byte("${billing-app/prod/db/PASSWORD}")
		assert.NoError(t, BatchPutInput{Items: items}.Validate())
	})
	t.Run("an item with duplicate tags", func(t *testing.T) {
		items := putItems(1)
		items[0].Tags = []string{"prod", "prod"}
		require.Error(t, BatchPutInput{Items: items}.Validate())
	})
}
