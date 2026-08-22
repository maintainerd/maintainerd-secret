package middleware

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// The shared side of the rate limiter: the thing that makes one budget span every
// replica. The design, the bound it guarantees and the trade-off it accepts are all
// documented on Limiter in rate_limit.go; this file is the storage.

// ReservationStore hands out slices of a window's budget.
//
// It is an interface for two reasons that both matter. The limiter's properties — a
// shared ceiling, a fast path, degradation on failure — are properties of the
// RESERVATION PROTOCOL and not of PostgreSQL, so they are worth testing without a
// database. And a deployment that later wants to meter at a different layer replaces
// this one type instead of the limiter.
type ReservationStore interface {
	// Reserve asks for up to slice units of the budget for (key, windowStart) and
	// returns how many were actually granted.
	//
	// THE CONTRACT THE LIMITER'S BOUND RESTS ON:
	//
	//   - The total granted for one (key, windowStart), summed over every caller and
	//     every replica, must never exceed limit. This is the whole guarantee.
	//   - A return of 0 means the budget is fully reserved. It is NOT an error: it is
	//     the normal answer once a window is spent, and the limiter uses it to stop
	//     asking for the rest of the window.
	//   - A return between 1 and slice-1 means this caller took the last of the
	//     budget.
	//   - It must be atomic against concurrent callers. Two replicas asking at the
	//     same instant must not both be told they got the same units.
	//
	// window is passed so an implementation can set an expiry; the PostgreSQL one
	// derives retention from windowStart instead and ignores it.
	Reserve(ctx context.Context, key string, windowStart time.Time, window time.Duration, limit, slice int64) (int64, error)
}

// PgReservationStore meters through the PostgreSQL database this service already
// requires.
//
// WHY THE DATABASE AND NOT REDIS: a shared counter needs a shared store, and adding
// Redis would mean the vault's rate limiter depends on a system that can be down while
// PostgreSQL is up — a new failure domain in front of the reveal path. This service
// cannot serve a single secret without PostgreSQL, so metering there adds none.
//
// WHY RAW SQL RATHER THAN A GENERATED QUERY IN internal/storage: rate_limit_buckets is
// not a domain entity. It holds no secret, has no tenant, is not addressable by an MRN,
// is never audited, and is truncatable at any moment with no consequence beyond one
// window of per-replica metering. Routing it through the domain repository would put a
// hot infrastructure table into the same surface as secrets and version history, and
// would make it reachable from code that has no business touching it.
type PgReservationStore struct {
	pool *pgxpool.Pool
}

// NewPgReservationStore builds the shared store.
func NewPgReservationStore(pool *pgxpool.Pool) *PgReservationStore {
	return &PgReservationStore{pool: pool}
}

// reserveSQL takes up to `slice` more units of `limit` and returns THIS CALL'S grant.
//
// THE last_grant COLUMN EXISTS BECAUSE OF A POSTGRESQL LIMITATION, and it is worth
// being explicit rather than leaving a reader to wonder why a counter table has a
// scratch column. `INSERT ... ON CONFLICT DO UPDATE ... RETURNING` can return the NEW
// row but has no way to return the row as it was BEFORE the update — and the grant is
// exactly that difference. Writing the delta into a column during the same update makes
// it returnable.
//
// It is correct under concurrency because ON CONFLICT DO UPDATE takes a row-level lock:
// concurrent reservers on the same key serialize, each sees the other's committed
// `reserved`, and each RETURNING sees the row as its own statement wrote it. LEAST
// clamps the running total to `limit`, so the sum of every grant for a window can never
// exceed it — which is the bound the limiter's guarantee rests on.
const reserveSQL = `
INSERT INTO rate_limit_buckets (bucket_key, window_start, reserved, last_grant, updated_at)
VALUES ($1, $2, LEAST($3::bigint, $4::bigint), LEAST($3::bigint, $4::bigint), now())
ON CONFLICT (bucket_key, window_start) DO UPDATE
   SET reserved   = LEAST($4::bigint, rate_limit_buckets.reserved + $3::bigint),
       last_grant = LEAST($4::bigint, rate_limit_buckets.reserved + $3::bigint) - rate_limit_buckets.reserved,
       updated_at = now()
RETURNING last_grant`

// Reserve implements ReservationStore.
func (s *PgReservationStore) Reserve(ctx context.Context, key string, windowStart time.Time, _ time.Duration, limit, slice int64) (int64, error) {
	if s == nil || s.pool == nil {
		return 0, errors.New("middleware: rate limit store has no database pool")
	}
	if limit <= 0 {
		return 0, nil
	}
	if slice < 1 {
		slice = 1
	}
	if slice > limit {
		slice = limit
	}

	var granted int64
	// windowStart arrives ALREADY ALIGNED to an absolute window boundary (the limiter
	// truncates it — see bucketLocked), and it is stored verbatim. That alignment is
	// what makes the row shared: every replica computes the same boundary for the same
	// instant, so they contend for one row instead of each creating their own and
	// each drawing a full budget. Normalising to UTC here only guarantees the
	// TIMESTAMPTZ comparison is against a single representation.
	if err := s.pool.QueryRow(ctx, reserveSQL,
		key, windowStart.UTC(), slice, limit,
	).Scan(&granted); err != nil {
		return 0, fmt.Errorf("reserve rate limit budget: %w", err)
	}
	if granted < 0 {
		granted = 0
	}
	return granted, nil
}

// Prune deletes bucket rows for windows that have closed.
//
// IT IS LEADER-ONLY WORK. Every replica could safely run this — a DELETE of expired
// rows is idempotent — but N replicas running it is N times the write load for exactly
// the same result, so cmd/secretd gates it on the leader lock along with the rotator
// (see internal/leader.RunPeriodic).
//
// The rows are worthless the moment their window closes: the limiter never reads a
// closed window, so an unpruned row is pure waste. `before` should be comfortably older
// than one window (cmd/secretd uses several) so a clock skew between replicas can never
// delete a window that one of them still considers live.
//
// NOTE ON CONTENT: a bucket key contains a class and a PRINCIPAL identifier (a token
// subject, or a peer address on the setup surface). No secret, no value, no plaintext —
// but it is a record of who was calling, so pruning promptly is a privacy measure as
// well as a hygiene one.
func (s *PgReservationStore) Prune(ctx context.Context, before time.Time) (int64, error) {
	if s == nil || s.pool == nil {
		return 0, errors.New("middleware: rate limit store has no database pool")
	}
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM rate_limit_buckets WHERE window_start < $1`, before.UTC())
	if err != nil {
		return 0, fmt.Errorf("prune rate limit buckets: %w", err)
	}
	return tag.RowsAffected(), nil
}
