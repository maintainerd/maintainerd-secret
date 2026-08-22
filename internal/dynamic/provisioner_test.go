package dynamic

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// The fake seam
// ---------------------------------------------------------------------------
//
// THE POINT OF THE Provisioner INTERFACE IS THAT NO TEST NEEDS A SECOND DATABASE.
// Everything that decides what happens — generating the name and password, rendering
// the templates, deciding when to revoke — is exercised against this fake; what the
// real implementation adds is a network connection and nothing else.
//
// The fake models the two properties the feature's correctness rests on, rather than
// echoing calls back:
//
//	TRANSACTIONAL DDL   a failed Create leaves NO role. PostgreSQL supports
//	                    transactional DDL, so a partial credential — a role that can
//	                    log in with none of its GRANTs, or with a membership the
//	                    narrowing statement never removed — is never acceptable.
//	FAILED REVOKE KEEPS the role. A revocation the target refused has not happened,
//	                    and the account still exists.

// createRolePattern extracts the role name a statement creates, so the fake can model
// a pg_roles table rather than a call counter.
var createRolePattern = regexp.MustCompile(`(?i)CREATE\s+ROLE\s+([a-z_][a-z0-9_]*)`)

// dropRolePattern extracts the role name a statement drops.
var dropRolePattern = regexp.MustCompile(`(?i)DROP\s+ROLE\s+(?:IF\s+EXISTS\s+)?([a-z_][a-z0-9_]*)`)

// fakeProvisioner stands in for the target PostgreSQL database.
type fakeProvisioner struct {
	mu sync.Mutex
	// roles is the fake's pg_roles.
	roles map[string]struct{}
	// createCalls and revokeCalls count what reached the "network".
	createCalls, revokeCalls int
	// failCreate and failRevoke make the target refuse the statement.
	failCreate, failRevoke error
	// sawCreateSQL and sawRevokeSQL record the last statement, so a test can assert
	// what would actually have been executed.
	sawCreateSQL, sawRevokeSQL string
	// sawDSN records the DSN, so a test can prove it never reaches a caller.
	sawDSN string
}

func newFakeProvisioner() *fakeProvisioner {
	return &fakeProvisioner{roles: map[string]struct{}{}}
}

var _ Provisioner = (*fakeProvisioner)(nil)

func (f *fakeProvisioner) Create(_ context.Context, dsn, createSQL string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.createCalls++
	f.sawCreateSQL, f.sawDSN = createSQL, dsn
	if f.failCreate != nil {
		// ONE TRANSACTION: a non-nil error means nothing was created.
		return f.failCreate
	}
	m := createRolePattern.FindStringSubmatch(createSQL)
	if m == nil {
		return errors.New("fake target: the statement creates no role")
	}
	f.roles[m[1]] = struct{}{}
	return nil
}

func (f *fakeProvisioner) Revoke(_ context.Context, dsn, revokeSQL string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revokeCalls++
	f.sawRevokeSQL, f.sawDSN = revokeSQL, dsn
	if f.failRevoke != nil {
		// The account still exists, so the lease that demands its revocation must
		// survive — the fake keeps the role to make that observable.
		return f.failRevoke
	}
	m := dropRolePattern.FindStringSubmatch(revokeSQL)
	if m == nil {
		return errors.New("fake target: the statement drops no role")
	}
	// DROP ROLE IF EXISTS on an absent role is a success, which is what makes a
	// re-run of a revocation safe.
	delete(f.roles, m[1])
	return nil
}

func (f *fakeProvisioner) hasRole(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.roles[name]
	return ok
}

func (f *fakeProvisioner) roleCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.roles)
}

func (f *fakeProvisioner) counts() (create, revoke int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.createCalls, f.revokeCalls
}

func (f *fakeProvisioner) setFailRevoke(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failRevoke = err
}

// testTemplates are representative operator-written templates.
const (
	testCreationSQL = "CREATE ROLE {{name}} LOGIN PASSWORD {{password}} VALID UNTIL {{expiration}}; " +
		"GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}};"
	testRevocationSQL = "REASSIGN OWNED BY {{name}} TO postgres; DROP OWNED BY {{name}}; DROP ROLE IF EXISTS {{name}};"
)

// issueThrough performs the full issue path against a fake target: generate, render,
// create. It is the sequence internal/store runs, minus the storage.
func issueThrough(t *testing.T, prov Provisioner, prefix string) string {
	t.Helper()
	name, err := NewRoleName(prefix)
	require.NoError(t, err)
	password, err := NewPassword()
	require.NoError(t, err)
	sql, err := Render(testCreationSQL, name, password, time.Now().Add(time.Hour))
	require.NoError(t, err)
	require.NoError(t, prov.Create(context.Background(), "postgres://admin@target/db", sql))
	return name
}

// revokeThrough performs the revocation path: render, revoke.
func revokeThrough(prov Provisioner, name string) error {
	sql, err := Render(testRevocationSQL, name, "", time.Now())
	if err != nil {
		return err
	}
	return prov.Revoke(context.Background(), "postgres://admin@target/db", sql)
}

// ---------------------------------------------------------------------------
// The seam's contract
// ---------------------------------------------------------------------------

// TestIssuingProducesADistinctAccountPerRequest is the whole promise of the feature:
// no two consumers ever hold the same account, which is what makes attribution free
// and revocation a real operation rather than a coordinated rotation.
func TestIssuingProducesADistinctAccountPerRequest(t *testing.T) {
	prov := newFakeProvisioner()

	const issues = 64
	names := make(map[string]struct{}, issues)
	for i := 0; i < issues; i++ {
		name := issueThrough(t, prov, "m9d")
		_, dup := names[name]
		require.False(t, dup, "two issues produced the same account")
		names[name] = struct{}{}
		assert.True(t, prov.hasRole(name))
	}
	assert.Equal(t, issues, prov.roleCount(), "every issue must be its own account")
}

// TestRevocationIsIdempotent. A caller retrying a revoke, or a reaper racing an
// explicit one, must see success — reporting a conflict would make the SAFE action
// (revoke again if unsure) look like a failure, and would train an operator to stop
// doing it.
func TestRevocationIsIdempotent(t *testing.T) {
	prov := newFakeProvisioner()
	name := issueThrough(t, prov, "m9d")
	require.True(t, prov.hasRole(name))

	require.NoError(t, revokeThrough(prov, name), "the first revocation must succeed")
	assert.False(t, prov.hasRole(name))

	// Twice more, because a reaper retrying a lease whose row was never closed is the
	// realistic case, not a contrived one.
	require.NoError(t, revokeThrough(prov, name), "revoking twice must not be an error")
	require.NoError(t, revokeThrough(prov, name), "revoking a third time must not be an error")
	assert.False(t, prov.hasRole(name))

	// The idempotency comes from the template's IF EXISTS reaching the target, not from
	// a short-circuit that never asks — an operator template without IF EXISTS would
	// fail here, which is the loud failure the docs want.
	_, revokes := prov.counts()
	assert.Equal(t, 3, revokes, "each revocation must really be attempted")
}

// TestAFailedCreateLeavesNoAccount. A creation template is normally several
// statements — CREATE ROLE, then the GRANTs that decide what the credential can do.
// Run without a transaction, a failure between them leaves a role that can log in and
// has no privileges, or (far worse) a role granted membership of something before the
// statement meant to narrow it ever ran.
func TestAFailedCreateLeavesNoAccount(t *testing.T) {
	prov := newFakeProvisioner()
	prov.failCreate = errors.New("42501: insufficient privilege")

	name, err := NewRoleName("m9d")
	require.NoError(t, err)
	password, err := NewPassword()
	require.NoError(t, err)
	sql, err := Render(testCreationSQL, name, password, time.Now().Add(time.Hour))
	require.NoError(t, err)

	require.Error(t, prov.Create(context.Background(), "dsn", sql))
	assert.False(t, prov.hasRole(name), "a partial credential must never exist")
	assert.Zero(t, prov.roleCount())
}

// TestAFailedRevokeLeavesTheAccountForRetry is the failure that matters most in this
// package. A revocation the target database refused HAS NOT HAPPENED. If the lease
// were marked revoked anyway, the only record that a live account needs dropping
// would be gone — and the account would be permanent.
func TestAFailedRevokeLeavesTheAccountForRetry(t *testing.T) {
	prov := newFakeProvisioner()
	name := issueThrough(t, prov, "m9d")

	prov.setFailRevoke(errors.New("57P01: terminating connection due to administrator command"))
	require.Error(t, revokeThrough(prov, name))
	assert.True(t, prov.hasRole(name), "the account survives a refused revocation, so the lease must too")

	// Once the target recovers, the retry succeeds. That is the sequence that keeps an
	// outage from turning into a permanently orphaned role.
	prov.setFailRevoke(nil)
	require.NoError(t, revokeThrough(prov, name))
	assert.False(t, prov.hasRole(name))
}

// TestARevocationNeedsOnlyTheRoleName, which is the whole reason the password never
// has to be stored: there is no column for it, it is returned once, and revocation
// does not need it.
func TestARevocationNeedsOnlyTheRoleName(t *testing.T) {
	prov := newFakeProvisioner()
	name := issueThrough(t, prov, "m9d")

	// The password from the issue is long gone; the revocation still works.
	require.NoError(t, revokeThrough(prov, name))
	assert.False(t, prov.hasRole(name))
	assert.NotContains(t, prov.sawRevokeSQL, "PASSWORD",
		"a revocation statement must carry no password at all")
}

// TestTheRenderedCreationStatementCarriesTheGeneratedCredential. This is the fact
// every redaction rule in this file exists for: the statement sent to the target
// CONTAINS the live password, so anything that can quote a statement can leak one.
func TestTheRenderedCreationStatementCarriesTheGeneratedCredential(t *testing.T) {
	password, err := NewPassword()
	require.NoError(t, err)
	sql, err := Render(testCreationSQL, "m9d_abc", password, time.Now())
	require.NoError(t, err)

	require.Contains(t, sql, password,
		"the premise of sanitized/scrubbed: the rendered statement holds the credential")
	assert.Contains(t, sql, "'"+password+"'", "and it holds it as a quoted literal, which is what makes eliding quoted runs sufficient")
}

// ---------------------------------------------------------------------------
// run's guards — reached without a network
// ---------------------------------------------------------------------------

func TestTheProvisionerRefusesToRunWithNothingToRunAgainst(t *testing.T) {
	p := NewPgProvisioner(0, 0)
	ctx := context.Background()

	t.Run("an unresolved DSN", func(t *testing.T) {
		// A nil/empty DSN means the secret reference did not resolve. Attempting a
		// connection would produce a confusing driver error instead of naming the cause.
		err := p.Create(ctx, "", "CREATE ROLE m9d_a")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no target database DSN was resolved")

		err = p.Revoke(ctx, "", "DROP ROLE m9d_a")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no target database DSN was resolved")
	})

	t.Run("an empty statement", func(t *testing.T) {
		// Naming the operation matters: "no create statement" and "no revoke statement"
		// point an operator at different template columns.
		err := p.Create(ctx, "postgres://u@h/d", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no create statement")

		err = p.Revoke(ctx, "postgres://u@h/d", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no revoke statement")
	})
}

// TestAMalformedDSNIsReportedWithoutEchoingIt. The DSN came out of a secret, so its
// contents must not reach the caller or the log — and pgx's own parse error QUOTES
// THE MALFORMED STRING VERBATIM for keyword/value DSNs, password included. That is
// why run replaces the error rather than wrapping it, and this test is what keeps a
// future `%w` from silently undoing it.
func TestAMalformedDSNIsReportedWithoutEchoingIt(t *testing.T) {
	p := NewPgProvisioner(time.Second, time.Second)
	ctx := context.Background()

	const password = "hunter2-THE-ADMIN-PASSWORD"
	unparseable := map[string]string{
		"a keyword/value DSN with a bad port": fmt.Sprintf("host=target port=notaport user=admin password=%s", password),
		"a URL DSN with a bad port":           fmt.Sprintf("postgres://admin:%s@target:notaport/db", password),
		"junk with a password in it":          "==== " + password,
	}
	for name, dsn := range unparseable {
		t.Run(name, func(t *testing.T) {
			err := p.Create(ctx, dsn, "CREATE ROLE m9d_a LOGIN PASSWORD 'x'")
			require.Error(t, err, "a DSN that cannot be parsed must not be dialled")
			assert.Contains(t, err.Error(), "not a valid PostgreSQL connection string")
			assert.NotContains(t, err.Error(), password, "the admin password must not reach the caller")
			assert.NotContains(t, err.Error(), dsn, "the DSN must not be echoed")
			assert.NotContains(t, err.Error(), "admin", "nor the admin user it names")
		})
	}

	// A DSN that PARSES but cannot be reached takes the other branch, and it has the
	// same obligation: pgx's connect error can include the host and the user, which is
	// operational detail about a target the CALLER does not administer and may hold no
	// grant on.
	t.Run("a parseable DSN that cannot be reached", func(t *testing.T) {
		dsn := fmt.Sprintf("host=127.0.0.1 port=1 user=admin password=%s dbname=d sslmode=disable", password)
		err := p.Create(ctx, dsn, "CREATE ROLE m9d_a LOGIN PASSWORD 'x'")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "could not reach the target database")
		assert.NotContains(t, err.Error(), password)
		assert.NotContains(t, err.Error(), "127.0.0.1")
		assert.NotContains(t, err.Error(), "admin")
	})
}

// ---------------------------------------------------------------------------
// sanitized — the redaction that keeps a credential out of an audit row
// ---------------------------------------------------------------------------

// TestSanitizedKeepsAPasswordOutOfADriverError is the property with the least
// recoverable failure mode in this package. A PostgreSQL error can quote the statement
// that failed, and the rendered creation statement CONTAINS THE GENERATED PASSWORD —
// so propagating a raw driver error writes a live credential into an error response, a
// server log AND an append-only audit row, which cannot be taken back.
func TestSanitizedKeepsAPasswordOutOfADriverError(t *testing.T) {
	// Generated rather than hardcoded, for two reasons. It exercises the shape the
	// service actually produces — full length, real charset — instead of a shorter
	// hand-picked stand-in that might be redacted by luck. And a high-entropy literal
	// committed to a secret manager's own repository is what its secret scanner exists
	// to flag; a fake one is indistinguishable from a real one to the scanner, so it
	// would have to be permanently excepted, and every such exception is a place a real
	// credential could later hide.
	password, err := NewPassword()
	require.NoError(t, err)
	statement := fmt.Sprintf("CREATE ROLE m9d_abc LOGIN PASSWORD '%s' VALID UNTIL '2026-08-22T15:00:00Z'", password)

	cases := map[string]error{
		"a PgError quoting the statement": &pgconn.PgError{
			Code:    "42710",
			Message: fmt.Sprintf(`role "m9d_abc" already exists while running %s`, statement),
		},
		"a PgError hiding it in Detail": &pgconn.PgError{
			Code:    "42601",
			Message: "syntax error",
			Detail:  statement,
			Hint:    statement,
			Where:   statement,
		},
		"a PgError hiding it in InternalQuery": &pgconn.PgError{
			Code:          "XX000",
			Message:       "internal error",
			InternalQuery: statement,
		},
		"a plain driver error": errors.New("failed to send statement: " + statement),
		"a wrapped PgError": fmt.Errorf("exec: %w", &pgconn.PgError{
			Code:    "42501",
			Message: "permission denied while running " + statement,
		}),
		"a pooler error": errors.New("pgbouncer: query failed: " + statement),
	}
	for name, err := range cases {
		t.Run(name, func(t *testing.T) {
			got := sanitized(err)
			require.Error(t, got)
			msg := got.Error()

			assert.NotContains(t, msg, password, "the generated password reached an error message")
			// Every plausible re-encoding, in case a driver ever hex- or base64-encodes
			// a parameter it is reporting on.
			assert.NotContains(t, msg, hex.EncodeToString([]byte(password)))
			assert.NotContains(t, msg, base64.StdEncoding.EncodeToString([]byte(password)))
			assert.NotEmpty(t, msg, "the message must still name the failure")
		})
	}
}

// TestSanitizedKeepsTheSQLSTATEAndTheServerMessage. The message is reduced, not
// removed: SQLSTATE plus the server's own message names the failure (duplicate role,
// insufficient privilege, syntax error) without quoting the statement, and that is
// what an operator diagnoses from.
func TestSanitizedKeepsTheSQLSTATEAndTheServerMessage(t *testing.T) {
	got := sanitized(&pgconn.PgError{Code: "42710", Message: `role "m9d_abc" already exists`})
	require.Error(t, got)
	assert.Equal(t, `42710: role "m9d_abc" already exists`, got.Error())

	// The SQLSTATE is what makes a failure classifiable without parsing prose.
	assert.True(t, strings.HasPrefix(got.Error(), "42710: "))
}

func TestSanitizedPassesANilErrorThrough(t *testing.T) {
	assert.NoError(t, sanitized(nil), "a nil error must not become a non-nil one")
}

// ---------------------------------------------------------------------------
// scrubbed — the second belt
// ---------------------------------------------------------------------------

func TestScrubbedElidesEveryQuotedRun(t *testing.T) {
	cases := map[string]struct {
		in   string
		want string
	}{
		"no quotes at all":       {"permission denied for schema public", "permission denied for schema public"},
		"one quoted run":         {"PASSWORD 'hunter2'", "PASSWORD '[REDACTED]'"},
		"two quoted runs":        {"PASSWORD 'a' UNTIL 'b'", "PASSWORD '[REDACTED]' UNTIL '[REDACTED]'"},
		"an empty quoted run":    {"PASSWORD ''", "PASSWORD '[REDACTED]'"},
		"a doubled quote inside": {"PASSWORD 'ab''cd'", "PASSWORD '[REDACTED]''[REDACTED]'"},
		"text after the run":     {"'secret' was refused", "'[REDACTED]' was refused"},
		// A message with an odd number of quotes is treated as if the last one opened a
		// run reaching the end, which is the conservative reading: guessing the other way
		// would emit the tail verbatim.
		"an unterminated run":   {"PASSWORD 'hunter2", "PASSWORD '[REDACTED]'"},
		"a lone trailing quote": {"refused: '", "refused: '[REDACTED]'"},
		"a lone leading quote":  {"'refused", "'[REDACTED]'"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, scrubbed(tc.in))
		})
	}
}

// TestScrubbedNeverLeavesTheContentOfAQuotedRun sweeps rather than enumerating: any
// message quoting a CORRECTLY rendered statement must lose the credential, whatever
// surrounds the quotes.
//
// "Correctly rendered" is the load-bearing qualifier, and the reason is in
// TestAnOverQuotedTemplateDefeatsTheRedaction below: Render owns the quoting, so a
// statement it produced holds the password in exactly one single-quoted run, and
// eliding every such run is therefore sufficient. A template that adds its own quotes
// breaks that premise, which is a separate finding rather than a case for this sweep.
func TestScrubbedNeverLeavesTheContentOfAQuotedRun(t *testing.T) {
	const secret = "SUPER-SECRET-GENERATED-PASSWORD"
	for _, format := range []string{
		"PASSWORD '%s'",
		"'%s'",
		"prefix '%s' suffix",
		"'%s",
		"a '%s' b '%s' c",
		"CREATE ROLE r PASSWORD '%s' VALID UNTIL '2026-01-01T00:00:00Z'",
		// A password containing a quote is doubled by quoteLiteral, so both halves land
		// inside runs. Not reachable with today's alphanumeric generator; covered because
		// quoteLiteral exists precisely for a future one.
		"PASSWORD 'ab''%s''cd'",
	} {
		msg := strings.ReplaceAll(format, "%s", secret)
		assert.NotContains(t, scrubbed(msg), secret, "scrubbed(%q) leaked the value", msg)
	}
}

// TestAnOverQuotedTemplateDefeatsTheRedaction DOCUMENTS A REAL DEFECT rather than
// endorsing the behaviour. It is pinned here so the gap is visible in the suite
// instead of implied by its absence.
//
// THE PREMISE scrubbed RESTS ON. Render owns the quoting, so a statement it produced
// holds the password inside exactly one single-quoted run — and eliding every
// single-quoted run therefore removes it. Render's own doc acknowledges the failure
// mode and dismisses it: a template that quotes the placeholder as well "would produce
// `PASSWORD ”abc”`, which is a syntax error rather than a vulnerability, so the
// failure mode of getting this wrong is loud".
//
// IT IS NOT LOUD, AND IT IS NOT ONLY A SYNTAX ERROR. `”abc”` lexes as an empty
// literal, then the BARE token abc, then another empty literal — so the password sits
// OUTSIDE any quoted run, and both redaction paths pass it straight through:
//
//  1. Any driver, pooler or proxy error that echoes the rendered statement verbatim
//     keeps the password, because scrubbed elides the two empty runs and emits the
//     token between them.
//  2. PostgreSQL's own syntax error for that statement is
//     `syntax error at or near "abc"` — the password in DOUBLE quotes, which scrubbed
//     does not touch (a double-quoted run is normally an identifier such as the role
//     name, which is useful non-secret detail worth keeping).
//
// Either way the live credential reaches the error response, the server log and the
// APPEND-ONLY audit row, which cannot be taken back. Config.Validate does not refuse a
// template that quotes the placeholder, so the only thing preventing this is that
// nobody has written one that way.
//
// The fix belongs in validation — refuse a creation template whose {{password}} is
// already quoted — not in scrubbed, whose single-quote rule is correct for every
// statement Render actually produces. Config.Validate now enforces exactly that, and
// this test holds both halves: the refusal, and the disclosure that justifies it.
func TestAnOverQuotedTemplateIsRefusedBecauseItDefeatsTheRedaction(t *testing.T) {
	// Generated rather than hardcoded, for two reasons. It exercises the shape the
	// service actually produces — full length, real charset — instead of a shorter
	// hand-picked stand-in that might be redacted by luck. And a high-entropy literal
	// committed to a secret manager's own repository is what its secret scanner exists
	// to flag; a fake one is indistinguishable from a real one to the scanner, so it
	// would have to be permanently excepted, and every such exception is a place a real
	// credential could later hide.
	password, err := NewPassword()
	require.NoError(t, err)

	// THE REFUSAL. An over-quoted placeholder is unstorable, on either side of the
	// placeholder and for the expiration literal as well — the same lexing argument
	// applies to any value Render quotes for the caller.
	for _, template := range []string{
		"CREATE ROLE {{name}} LOGIN PASSWORD '{{password}}'",
		"CREATE ROLE {{name}} LOGIN PASSWORD '{{password}}",
		"CREATE ROLE {{name}} LOGIN PASSWORD {{password}}'",
		"CREATE ROLE {{name}} LOGIN PASSWORD {{password}} VALID UNTIL '{{expiration}}'",
	} {
		cfg := validConfig()
		cfg.CreationSQL = template
		err := cfg.Validate()
		require.Error(t, err, "template %q must be refused", template)
		assert.Contains(t, err.Error(), "must not put quotes around",
			"the refusal must say what to change, not merely that the template is invalid")
	}

	// WHY IT IS REFUSED AT WRITE TIME rather than left to fail at run time. Rendering
	// one anyway — which is what storing it would eventually cause — puts the password
	// outside every quoted run, and both redaction paths then pass it through. The
	// statement also fails, but the failure is recoverable and the disclosure is not:
	// the value reaches the append-only audit row, where it cannot be taken back.
	overQuoted, err := Render("CREATE ROLE {{name}} LOGIN PASSWORD '{{password}}'", "m9d_abc", password, time.Now())
	require.NoError(t, err)
	require.Contains(t, overQuoted, "''"+password+"''",
		"the doubled quotes leave the password outside any literal")

	// Path 1: an error echoing the rendered statement verbatim. scrubbed elides the two
	// empty quoted runs and emits the bare token between them.
	assert.Contains(t, sanitized(errors.New("pgbouncer: query failed: "+overQuoted)).Error(), password,
		"this is the disclosure the validation rule exists to prevent")

	// Path 2: PostgreSQL's own syntax error names the token in DOUBLE quotes, which
	// scrubbed deliberately preserves (a double-quoted run is normally the role name).
	assert.Contains(t, sanitized(&pgconn.PgError{
		Code:    "42601",
		Message: fmt.Sprintf(`syntax error at or near "%s"`, password),
	}).Error(), password,
		"and this is the second path, which is why the fix is in validation rather than in scrubbed")

	// THE PREMISE HOLDS for every template Validate now accepts: quoting left to Render
	// means the password sits in exactly one single-quoted run, and both paths redact it.
	correct := validConfig()
	require.NoError(t, correct.Validate(), "the canonical template must remain storable")
	rendered, err := Render(correct.CreationSQL, "m9d_abc", password, time.Now())
	require.NoError(t, err)
	assert.NotContains(t, sanitized(errors.New("pgbouncer: query failed: "+rendered)).Error(), password)
	assert.NotContains(t, sanitized(&pgconn.PgError{
		Code:    "42601",
		Message: fmt.Sprintf("syntax error at or near '%s'", password),
	}).Error(), password)
}

// ---------------------------------------------------------------------------
// Timeouts
// ---------------------------------------------------------------------------

// TestTheProvisionerDefaultsItsTimeouts. Both call sites are on a request path or a
// reaper tick, and a target database that has gone away must not hold either open.
func TestTheProvisionerDefaultsItsTimeouts(t *testing.T) {
	p := NewPgProvisioner(0, 0)
	assert.Equal(t, DefaultConnectTimeout, p.connectTimeout)
	assert.Equal(t, DefaultStatementTimeout, p.statementTimeout)

	p = NewPgProvisioner(-time.Second, -time.Second)
	assert.Equal(t, DefaultConnectTimeout, p.connectTimeout, "a negative timeout is not an unbounded one")
	assert.Equal(t, DefaultStatementTimeout, p.statementTimeout)

	p = NewPgProvisioner(time.Second, 2*time.Second)
	assert.Equal(t, time.Second, p.connectTimeout)
	assert.Equal(t, 2*time.Second, p.statementTimeout)

	// CREATE ROLE and GRANT are fast; a statement slower than this is blocked on a
	// lock, and waiting on it would hold a request open behind somebody else's DDL.
	assert.LessOrEqual(t, DefaultConnectTimeout, 30*time.Second)
	assert.LessOrEqual(t, DefaultStatementTimeout, 30*time.Second)
}

// TestAnAlreadyCancelledContextDoesNotReachTheTarget. A reaper tick whose context is
// gone must not start a connection it cannot finish.
func TestAnAlreadyCancelledContextDoesNotReachTheTarget(t *testing.T) {
	p := NewPgProvisioner(time.Second, time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Port 1 on loopback so that even if the deadline were ignored the dial fails
	// immediately rather than waiting on the network.
	err := p.Create(ctx, "host=127.0.0.1 port=1 user=admin dbname=d sslmode=disable", "CREATE ROLE m9d_a")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not reach the target database",
		"a connection failure must be reduced to the one fact the caller can act on")
	assert.NotContains(t, err.Error(), "127.0.0.1", "the target's address is not the caller's business")
	assert.NotContains(t, err.Error(), "admin")
}
