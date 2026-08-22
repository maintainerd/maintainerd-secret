package dynamic

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Provisioner runs a role config's rendered SQL against the TARGET PostgreSQL
// database — the only thing in this repo that opens a connection to a database this
// service does not own.
//
// IT IS AN INTERFACE BECAUSE THE INTERESTING LOGIC MUST BE TESTABLE WITHOUT A SECOND
// DATABASE. Everything that decides what happens — resolving the DSN from a secret
// reference, generating the name and password, rendering the templates, writing the
// lease row in the same transaction, auditing, revoking on expiry — lives in
// internal/store and internal/api and is exercised against a fake implementation of
// these two methods. What the real implementation adds is a network connection and
// nothing else, which is the smallest seam the feature can have.
//
// A nil Provisioner is a DOCUMENTED, EXPLICIT unavailability rather than a silent
// no-op: api.IssueDynamicCredential returns Unavailable, so an operator who has not
// configured outbound provisioning gets told so instead of receiving a lease for a
// credential that was never created.
type Provisioner interface {
	// Create opens a connection to dsn and runs createSQL inside ONE transaction. A
	// non-nil error means nothing was created — see the implementation for why that
	// is a hard requirement rather than a best effort.
	Create(ctx context.Context, dsn, createSQL string) error
	// Revoke opens a connection to dsn and runs revokeSQL inside one transaction.
	Revoke(ctx context.Context, dsn, revokeSQL string) error
}

// DefaultConnectTimeout bounds a connection to a target database.
//
// Both call sites are on a request path or a reaper tick, and a target database that
// has gone away must not hold either open. It is short on purpose: provisioning is a
// handful of DDL statements against a database that is normally in the same network.
const DefaultConnectTimeout = 10 * time.Second

// DefaultStatementTimeout bounds the DDL itself. CREATE ROLE and GRANT are fast; a
// statement that takes longer than this is blocked on a lock, and waiting on it would
// hold a request open behind somebody else's DDL.
const DefaultStatementTimeout = 15 * time.Second

// PgProvisioner is the pgx implementation.
type PgProvisioner struct {
	connectTimeout   time.Duration
	statementTimeout time.Duration
}

// NewPgProvisioner builds the real provisioner. Zero timeouts take the defaults.
func NewPgProvisioner(connectTimeout, statementTimeout time.Duration) *PgProvisioner {
	if connectTimeout <= 0 {
		connectTimeout = DefaultConnectTimeout
	}
	if statementTimeout <= 0 {
		statementTimeout = DefaultStatementTimeout
	}
	return &PgProvisioner{connectTimeout: connectTimeout, statementTimeout: statementTimeout}
}

// Compile-time proof the implementation satisfies the seam.
var _ Provisioner = (*PgProvisioner)(nil)

// Create runs the creation SQL in one transaction.
//
// WHY ONE TRANSACTION IS A CORRECTNESS REQUIREMENT AND NOT TIDINESS. A creation
// template is normally several statements: CREATE ROLE, then the GRANTs that decide
// what the credential can actually do. Run without a transaction, a failure between
// them leaves a role that can log in and has no privileges — or, far worse in the
// other direction, a role that was granted membership of something before the
// statement that was supposed to narrow it. PostgreSQL supports transactional DDL, so
// there is no reason to accept a partial credential: either the whole account exists
// as the operator described it, or none of it does.
//
// The statements are sent as ONE simple-protocol Exec because the template is
// multi-statement text. That is safe here for a reason worth stating: the ONLY
// interpolations into it are a role name this package generated and validated against
// an identifier allowlist (see ValidateRoleName), and values rendered as quoted SQL
// literals by Render. There is no caller-supplied text in the string. The template
// itself is operator-authored SQL and is trusted as such — writing it requires
// secret:ManageDynamicRole, which is user-only precisely so that a human reviews what
// this executes.
func (p *PgProvisioner) Create(ctx context.Context, dsn, createSQL string) error {
	return p.run(ctx, dsn, createSQL, "create")
}

// Revoke runs the revocation SQL in one transaction.
//
// The same transactional argument applies with the sides reversed: a revocation is
// normally REASSIGN OWNED / DROP OWNED and then DROP ROLE, and a failure part-way
// through leaves an account that still exists. Because the lease row is only marked
// revoked when this returns nil (see internal/store), a partial revocation stays on
// the reaper's queue and is retried, which is the behaviour that keeps an orphaned
// account from becoming permanent.
func (p *PgProvisioner) Revoke(ctx context.Context, dsn, revokeSQL string) error {
	return p.run(ctx, dsn, revokeSQL, "revoke")
}

// run is the shared connect-begin-exec-commit path.
func (p *PgProvisioner) run(ctx context.Context, dsn, sql, op string) error {
	if dsn == "" {
		return fmt.Errorf("dynamic: no target database DSN was resolved")
	}
	if sql == "" {
		return fmt.Errorf("dynamic: no %s statement to run", op)
	}

	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		// The DSN came out of a secret, so its contents must not reach the caller or
		// the log. The parse error from pgx can quote the malformed string, so it is
		// deliberately NOT wrapped: the fact that matters is "the stored DSN is not a
		// valid connection string", and the operator fixes it by looking at the
		// secret, not at this message.
		return fmt.Errorf("dynamic: the target database DSN stored for this role is not a valid PostgreSQL connection string")
	}

	connectCtx, cancelConnect := context.WithTimeout(ctx, p.connectTimeout)
	defer cancelConnect()
	conn, err := pgx.ConnectConfig(connectCtx, config)
	if err != nil {
		// pgx's connect error can include the host and user from the DSN. That is
		// operational detail about a target the CALLER does not administer and may
		// hold no grant on, so it is reduced to the one fact the caller can act on.
		return fmt.Errorf("dynamic: could not reach the target database to %s a credential", op)
	}
	defer func() {
		closeCtx, cancelClose := context.WithTimeout(context.Background(), p.connectTimeout)
		defer cancelClose()
		_ = conn.Close(closeCtx)
	}()

	execCtx, cancelExec := context.WithTimeout(ctx, p.statementTimeout)
	defer cancelExec()

	tx, err := conn.Begin(execCtx)
	if err != nil {
		return fmt.Errorf("dynamic: begin %s transaction on the target database: %w", op, sanitized(err))
	}
	// Unconditional rollback, error discarded: after a successful commit this is a
	// no-op returning pgx.ErrTxClosed, and treating that as a failure would turn every
	// successful provision into a reported error. Same pattern as
	// store.PgRepository.InTx.
	defer func() { _ = tx.Rollback(context.Background()) }()

	// The simple protocol, because the template is multi-statement text. See Create
	// for why that is safe here.
	if _, err := tx.Exec(execCtx, sql, pgx.QueryExecModeSimpleProtocol); err != nil {
		return fmt.Errorf("dynamic: the target database refused the %s statement: %w", op, sanitized(err))
	}
	if err := tx.Commit(execCtx); err != nil {
		return fmt.Errorf("dynamic: commit the %s transaction on the target database: %w", op, sanitized(err))
	}
	return nil
}

// sanitized strips a driver error down to something safe to surface and to audit.
//
// A PostgreSQL error can quote the statement that failed, and the rendered creation
// statement CONTAINS THE GENERATED PASSWORD. Propagating a raw driver error would
// therefore write a live credential into an error response, a server log and an audit
// row — three places it must never be, and the audit row is append-only, so it could
// not be taken back.
//
// The message is reduced to the SQLSTATE and the server's message, which name the
// failure (duplicate role, insufficient privilege, syntax error) without quoting the
// statement. Everything else is dropped.
func sanitized(err error) error {
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return fmt.Errorf("%s: %s", pgErr.Code, scrubbed(pgErr.Message))
	}
	return errors.New(scrubbed(err.Error()))
}

// scrubbed replaces the contents of every single-quoted run in a message with a
// redaction marker.
//
// It is the second belt behind sanitized: a driver, a pooler or a proxy error this
// package does not recognise may still have quoted the statement, and the rendered
// creation statement contains the generated password as a quoted literal. Rather than
// guessing which errors are safe, every quoted run is elided — which costs a little
// detail in a message nobody was going to parse and removes the whole class of leak.
//
// A message with an odd number of quotes is treated as if the last one opened a run
// that reaches the end, which is the conservative reading.
func scrubbed(msg string) string {
	if !strings.Contains(msg, "'") {
		return msg
	}
	var b strings.Builder
	b.Grow(len(msg))
	inLiteral := false
	for i := 0; i < len(msg); i++ {
		if msg[i] == '\'' {
			b.WriteByte('\'')
			if !inLiteral {
				b.WriteString(redactionMarker)
			}
			inLiteral = !inLiteral
			continue
		}
		if !inLiteral {
			b.WriteByte(msg[i])
		}
	}
	if inLiteral {
		b.WriteByte('\'')
	}
	return b.String()
}

// redactionMarker is what an elided quoted run renders as. It matches crypto.Redacted
// in spirit; it is restated rather than imported because this package deliberately
// depends on nothing that touches key material.
const redactionMarker = "[REDACTED]"
