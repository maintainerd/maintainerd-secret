package leader

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// LockNamespace prefixes every lock name before it is hashed into a key.
//
// It is what keeps this service's locks from colliding with another maintainerd
// service's, because advisory locks are scoped to the DATABASE and not to a
// schema or a table. Two services sharing one database would otherwise be able to
// pick the same 63-bit number from the same short name ("background-workers" is
// not a name only this service would choose).
const LockNamespace = "maintainerd.secret/"

// LockKey derives the advisory-lock key from a lock name.
//
// WHY A HASH RATHER THAN A HAND-PICKED CONSTANT: a magic number in the source is a
// number somebody eventually reuses, and there is no way to look at 4919 and know
// what holds it. Hashing a namespaced name means the name is the identifier, the
// key is derivable by anyone (including an operator, in SQL, when they want to
// query pg_locks), and two different names can never be given the same constant by
// mistake.
//
// The top bit is cleared so the key is always non-negative. That is cosmetic
// rather than semantic — PostgreSQL accepts the full signed range — but a negative
// key in a log line next to a pg_locks row an operator is trying to match is a
// distraction during an incident, and 63 bits of SHA-256 is not a collision risk
// for a handful of names.
func LockKey(name string) int64 {
	sum := sha256.Sum256([]byte(LockNamespace + name))
	return int64(binary.BigEndian.Uint64(sum[:8]) & 0x7fffffffffffffff)
}

// Locker takes the lock. It is the seam that keeps this package testable without
// a database — see New.
type Locker interface {
	// TryLock attempts to take key without blocking.
	//
	// The three-value return separates the two outcomes that must never be
	// conflated: (session, true, nil) is a won election, (nil, false, nil) is a
	// LOST one (another replica holds it, which is entirely normal), and
	// (nil, false, err) is "unknown" — the database could not be asked. A caller
	// that treated the third as the second would report a healthy follower when
	// what it actually has is no answer.
	TryLock(ctx context.Context, key int64) (Session, bool, error)
}

// Session is a held lock. It lives exactly as long as the database session that
// owns it.
type Session interface {
	// Ping reports whether the owning session is still alive.
	Ping(ctx context.Context) error
	// Release unlocks and disposes of the session.
	Release(ctx context.Context) error
}

// PgLocker takes advisory locks on a pgx pool.
type PgLocker struct {
	pool *pgxpool.Pool
}

// NewPgLocker builds the production Locker.
func NewPgLocker(pool *pgxpool.Pool) *PgLocker { return &PgLocker{pool: pool} }

// TryLock acquires a pooled connection and takes the lock ON THAT CONNECTION.
//
// THE CONNECTION IS THEN HELD FOR THE WHOLE LEADERSHIP, and that is not an
// oversight — it is the mechanism. pg_try_advisory_lock is SESSION-scoped: the
// lock belongs to the backend that took it and is released when that backend
// goes away. Returning the connection to the pool would either hand the lock to
// the next borrower (pgxpool does not reset session state on release, so the lock
// would simply still be held by whatever code ran next on that connection) or,
// if the pool later recycled it, silently drop the leadership.
//
// The cost is one connection out of DB_MAX_OPEN_CONNS on exactly one replica,
// permanently. That is the trade documented in the package comment.
func (p *PgLocker) TryLock(ctx context.Context, key int64) (Session, bool, error) {
	if p == nil || p.pool == nil {
		return nil, false, errors.New("leader: no database pool")
	}
	conn, err := p.pool.Acquire(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("acquire a connection for the advisory lock: %w", err)
	}

	var acquired bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", key).Scan(&acquired); err != nil {
		conn.Release()
		return nil, false, fmt.Errorf("pg_try_advisory_lock(%d): %w", key, err)
	}
	if !acquired {
		// No lock was taken, so this connection carries no session state and is
		// safe to return to the pool.
		conn.Release()
		return nil, false, nil
	}
	return &pgSession{conn: conn, key: key}, true, nil
}

// pgSession is a held advisory lock plus the connection that owns it.
type pgSession struct {
	conn *pgxpool.Conn
	key  int64
}

// Ping proves the owning session is still alive, which is sufficient to prove the
// lock is still held.
//
// THE ARGUMENT FOR `SELECT 1` RATHER THAN AN INSPECTION OF pg_locks: a
// session-scoped advisory lock can only be released by the session that took it,
// or by that session ending. This process never unlocks except through Release,
// so if the session is alive the lock is held — there is no third state. Querying
// pg_locks would additionally have to reassemble the bigint key from the classid
// and objid columns, which is sign-extension arithmetic that can be wrong in a
// way `SELECT 1` cannot.
//
// A terminated backend (pg_terminate_backend, a database restart, a dropped
// connection) surfaces here as an error, because pgx does not transparently
// reconnect a broken connection — it fails the query and marks the connection bad.
// That failure is exactly the signal Heartbeat needs.
func (s *pgSession) Ping(ctx context.Context) error {
	var one int
	if err := s.conn.QueryRow(ctx, "SELECT 1").Scan(&one); err != nil {
		return fmt.Errorf("advisory-lock session is not alive: %w", err)
	}
	return nil
}

// Release unlocks and returns the connection to the pool.
//
// IF THE UNLOCK FAILS THE CONNECTION IS DESTROYED, NOT RETURNED. That branch is
// the important one. pgxpool does not reset session state on release, so a
// connection that may still hold the lock would hand it to whatever borrows it
// next — the lock would appear held forever, by nobody, and no replica would ever
// run the background work again. Destroying the connection instead ends the
// session, and ending the session is precisely what releases a session-scoped
// advisory lock. So the failure path reaches the same end state as the success
// path, more abruptly.
//
// This is also what makes the shutdown path correct on an already-cancelled
// context: the unlock query fails immediately, the connection is closed, and the
// lock is freed anyway.
func (s *pgSession) Release(ctx context.Context) error {
	var unlocked bool
	err := s.conn.QueryRow(ctx, "SELECT pg_advisory_unlock($1)", s.key).Scan(&unlocked)
	if err != nil {
		if raw := s.conn.Hijack(); raw != nil {
			// WithoutCancel: ctx is very likely the cancelled shutdown context that
			// just failed the unlock, and Close on a cancelled context would leave
			// the socket to be reaped instead of closed now.
			_ = raw.Close(context.WithoutCancel(ctx))
		}
		return fmt.Errorf("pg_advisory_unlock(%d): %w", s.key, err)
	}
	s.conn.Release()
	if !unlocked {
		// pg_advisory_unlock returns false when this session did not hold the lock.
		// Reaching that means the session was recycled underneath us — worth
		// surfacing, and harmless, because the lock is not held either way.
		return fmt.Errorf("leader: pg_advisory_unlock(%d) reported the lock was not held by this session", s.key)
	}
	return nil
}
