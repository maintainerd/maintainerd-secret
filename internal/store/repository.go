// Package store is the durable secret store: the repository seam over the
// generated queries, plus the service layer that holds the rules.
//
// This package replaces the prototype's in-memory map[string][]byte, in which
// every secret was lost on restart. The shape follows core (repository.go carrying
// the data contract, service.go carrying the rules), with two additions the
// prototype had no need for:
//
//   - A TRANSACTION SEAM. Several operations here are only correct as a unit: a
//     write reads current_version under a row lock and then inserts the next one; a
//     folder move rewrites paths and the MRNs derived from them; a retention prune
//     sets a transaction-local GUC and then deletes. Half of any of those is a
//     corrupt store.
//   - THE KEY RING. Reads must resolve the root key that wrapped the specific
//     version being read, not "the" root key, because a store mid-rotation holds
//     several.
package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/maintainerd/secret/internal/storage"
)

// Repository is the data contract for this package: every generated query.
//
// It is the full Querier rather than a hand-narrowed subset because the store uses
// nearly all of it, and a narrowed interface that has to be edited on every new
// query is a interface that drifts. *storage.Queries satisfies it; tests pass a
// fake.
type Repository interface {
	storage.Querier
}

// TxRepository is a Repository that can run work inside a database transaction.
//
// InTx takes a callback rather than exposing Begin/Commit because the callers that
// need a transaction need it for correctness, and an API that can be misused by
// forgetting to commit is the wrong API for that. Rollback on error and on panic is
// the implementation's problem, not each caller's.
type TxRepository interface {
	Repository
	InTx(ctx context.Context, fn func(Repository) error) error
}

// PgRepository is the Postgres implementation: a *storage.Queries bound to a pool,
// able to hand out transaction-scoped Queries.
type PgRepository struct {
	*storage.Queries
	pool *pgxpool.Pool
}

// NewPgRepository builds the repository over a pgx pool.
func NewPgRepository(pool *pgxpool.Pool) *PgRepository {
	return &PgRepository{Queries: storage.New(pool), pool: pool}
}

// InTx runs fn inside a transaction, committing on success and rolling back on
// error or panic.
//
// The deferred rollback is unconditional and its error is discarded on purpose:
// after a successful commit the rollback is a no-op that returns
// pgx.ErrTxClosed, and treating that as a failure would turn every successful
// transaction into a reported error.
func (r *PgRepository) InTx(ctx context.Context, fn func(Repository) error) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := fn(&txRepository{Queries: r.Queries.WithTx(tx), tx: tx}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	return nil
}

// txRepository is a Repository bound to an open transaction.
//
// Nesting is flattened rather than forbidden: a nested InTx runs the callback on
// the same transaction. Postgres savepoints would give real nesting, but the store
// has no operation that wants a partial rollback — every composite operation here
// is all-or-nothing — and silently converting a nested call into a savepoint would
// invent a semantic nobody asked for.
type txRepository struct {
	*storage.Queries
	tx pgx.Tx
}

func (r *txRepository) InTx(ctx context.Context, fn func(Repository) error) error {
	return fn(r)
}

// Compile-time proof that both implementations satisfy the seam.
var (
	_ TxRepository = (*PgRepository)(nil)
	_ TxRepository = (*txRepository)(nil)
)
