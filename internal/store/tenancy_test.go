package store

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The tests in this file assert on the SQL TEXT rather than on behaviour.
//
// That is deliberate and it complements the service tests rather than duplicating
// them. Two of this store's most important guarantees — "no code path can read
// across tenants" and "a listing never carries a payload" — are properties of the
// queries themselves, and the fake repository in these tests necessarily
// reimplements them. A behavioural test against the fake proves the service passes
// the right tenant id; only reading the SQL proves the query would actually use it.
// Without these, a query could quietly lose its tenant predicate and every other
// test would still pass.

func queriesDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join("..", "storage", "queries")
	entries, err := os.ReadDir(dir)
	require.NoError(t, err, "the sqlc query directory must be readable from the store package")
	require.NotEmpty(t, entries)
	return dir
}

// readQueries splits a .sql file into its named statements, stripping comments so
// only executable SQL is inspected. A tenant predicate mentioned in a comment must
// not satisfy these assertions.
func readQueries(t *testing.T, file string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(queriesDir(t), file))
	require.NoError(t, err)

	nameRe := regexp.MustCompile(`^--\s*name:\s*(\w+)\s*:\w+`)
	out := map[string]string{}
	current := ""
	var body strings.Builder
	flush := func() {
		if current != "" {
			out[current] = body.String()
		}
		body.Reset()
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if m := nameRe.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			flush()
			current = m[1]
			continue
		}
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "--") {
			continue
		}
		body.WriteString(" ")
		body.WriteString(trimmed)
	}
	flush()
	require.NotEmpty(t, out, "no named queries found in %s", file)
	return out
}

// TestEverySecretQueryIsTenantScoped is the structural guarantee behind
// "no cross-tenant reads".
//
// A service-layer check is one forgotten early return away from leaking. A tenant_id
// predicate baked into the query is not: sqlc will not compile a call that omits the
// parameter. This test enforces that every statement touching `secrets` carries one.
func TestEverySecretQueryIsTenantScoped(t *testing.T) {
	queries := readQueries(t, "secret.sql")

	// ListSecretsDueForDestruction is the one deliberate exception: it is the
	// platform-wide destruction sweeper, which by definition runs across tenants and
	// returns only ids for a subsequent tenant-scoped destroy. It reads no secret
	// value and no name.
	exempt := map[string]string{
		"ListSecretsDueForDestruction": "platform-wide sweeper; returns ids only, destroy is tenant-scoped",
	}

	for name, sql := range queries {
		if reason, ok := exempt[name]; ok {
			assert.NotContains(t, sql, "key", "exempt query %s must not select a secret name (%s)", name, reason)
			continue
		}
		assert.Contains(t, sql, "tenant_id",
			"query %s touches secrets without a tenant_id predicate; that is a cross-tenant read waiting to happen", name)
	}
	// Sanity: the parser found the real statements, not an empty map.
	assert.Contains(t, queries, "GetSecretByAddress")
	assert.Contains(t, queries, "ListSecretMetaBySubtree")
	assert.Contains(t, queries, "HardDeleteSecret")
}

// TestNoListingQuerySelectsAPayload is the structural guarantee behind
// "list returns metadata ONLY, no ciphertext, ever".
func TestNoListingQuerySelectsAPayload(t *testing.T) {
	payloadColumns := []string{"ciphertext", "dek_wrapped", "dek_nonce"}

	// Nothing in secret.sql may mention a payload column at all: `secrets` has none,
	// so a reference could only come from a join into secret_versions.
	for name, sql := range readQueries(t, "secret.sql") {
		for _, col := range payloadColumns {
			assert.NotContains(t, sql, col,
				"secret query %s references %s; secret listings and metadata reads must never touch a payload", name, col)
		}
	}

	// In secret_version.sql, only the explicitly value-bearing statements may.
	allowed := map[string]bool{
		"CreateSecretVersion":    true, // the write
		"GetLatestSecretVersion": true, // SELECT * for a decrypt
		"GetSecretVersion":       true, // SELECT * for a decrypt
		"ListVersionWrapsByKEK":  true, // rewrap: wrapped DEK only, never ciphertext
		"RewrapSecretVersion":    true, // rewrap: wrapped DEK only, never ciphertext
	}
	for name, sql := range readQueries(t, "secret_version.sql") {
		if allowed[name] {
			continue
		}
		for _, col := range payloadColumns {
			assert.NotContains(t, sql, col,
				"version query %s references %s but is not a value-bearing statement", name, col)
		}
	}

	// The two rewrap statements must not touch ciphertext even though they are
	// allowed to touch the wrapped DEK — that separation IS envelope encryption.
	for _, name := range []string{"ListVersionWrapsByKEK", "RewrapSecretVersion"} {
		sql := readQueries(t, "secret_version.sql")[name]
		assert.NotContains(t, sql, "ciphertext",
			"%s must not read or write ciphertext; a rewrap only re-wraps the DEK", name)
	}

	// The metadata listing must not select the payload columns either.
	meta := readQueries(t, "secret_version.sql")["ListSecretVersionMeta"]
	require.NotEmpty(t, meta)
	for _, col := range append(payloadColumns, "nonce") {
		assert.NotContains(t, meta, col, "version history must not be a bulk decryption endpoint")
	}
}

// TestVersionDeletesGoThroughTheSanctionedGUC checks the append-only contract is
// expressed in SQL: a DELETE on secret_versions exists, and so does the statement
// that authorizes it.
func TestVersionDeletesGoThroughTheSanctionedGUC(t *testing.T) {
	queries := readQueries(t, "secret_version.sql")

	require.Contains(t, queries, "AllowSecretVersionDelete")
	assert.Contains(t, queries["AllowSecretVersionDelete"], "maintainerd.allow_secret_version_delete")
	// is_local => true, so the permission dies with the transaction.
	assert.Contains(t, queries["AllowSecretVersionDelete"], "true")

	require.Contains(t, queries, "AllowSecretVersionRewrap")
	assert.Contains(t, queries["AllowSecretVersionRewrap"], "maintainerd.allow_secret_version_rewrap")

	// The only UPDATE on the table is the rewrap, and it is guarded on the source key
	// so a row already moved is not moved twice.
	require.Contains(t, queries, "RewrapSecretVersion")
	assert.Contains(t, queries["RewrapSecretVersion"], "from_kek_id")
	for name, sql := range queries {
		if name == "RewrapSecretVersion" {
			continue
		}
		assert.NotContains(t, strings.ToUpper(sql), "UPDATE SECRET_VERSIONS",
			"query %s updates secret_versions; the only sanctioned update is the rewrap", name)
	}
}

// TestHardDeleteGuardsTheRecoveryWindowInSQL checks the destroy guard is in the
// statement and reads the database's own clock, not a value from the caller.
func TestHardDeleteGuardsTheRecoveryWindowInSQL(t *testing.T) {
	sql := readQueries(t, "secret.sql")["HardDeleteSecret"]
	require.NotEmpty(t, sql)
	assert.Contains(t, sql, "deleted_at IS NOT NULL")
	assert.Contains(t, sql, "destroy_after IS NOT NULL")
	assert.Contains(t, sql, "destroy_after <= now()",
		"the window must be compared against the database clock, not a caller-supplied timestamp")
	assert.Contains(t, sql, "tenant_id")
}

// TestSetupLockIsSingleUseInSQL checks the one-shot guard that replaces the
// prototype's in-memory lock.
func TestSetupLockIsSingleUseInSQL(t *testing.T) {
	sql := readQueries(t, "setup_state.sql")["CompleteSetup"]
	require.NotEmpty(t, sql)
	assert.Contains(t, sql, "ON CONFLICT")
	assert.Contains(t, sql, "completed_at IS NULL",
		"the update branch must be guarded so a second caller updates nothing and receives no row")
}

// TestRootKeyRetirementCannotTargetTheActiveKey checks the guard is in the WHERE
// clause rather than in Go, so retiring the key new writes depend on is not
// expressible.
func TestRootKeyRetirementCannotTargetTheActiveKey(t *testing.T) {
	queries := readQueries(t, "root_key.sql")
	sql := queries["RetireRootKey"]
	require.NotEmpty(t, sql)
	assert.Contains(t, sql, "state <> 'active'")

	// And the demotion step exists, because uq_root_keys_single_active permits only
	// one active row.
	assert.Contains(t, queries, "MarkOtherRootKeysRetiring")
}

// TestListPrunableVersionsProtectsTheCurrentVersionTwice checks both guards are
// present in the query: retention that ate the live credential would be
// catastrophic, so it is prevented by name AND by the newest-N window.
func TestListPrunableVersionsProtectsTheCurrentVersionTwice(t *testing.T) {
	sql := readQueries(t, "secret_version.sql")["ListPrunableVersions"]
	require.NotEmpty(t, sql)
	assert.Contains(t, sql, "current_version", "the current version must be excluded by name")
	assert.Contains(t, sql, "NOT IN", "the newest-N window must also exclude it")
	assert.Contains(t, sql, "ORDER BY keep.version DESC")
	assert.Contains(t, sql, "LIMIT")
}

// The create-only rule and goose statement fencing are asserted in the migrations
// package, next to the files they describe (see migrations/migrations_test.go).

// TestImmutabilityTriggersExist checks the append-only tables really carry a trigger
// — the guarantee that history cannot be rewritten belongs to the database, not to
// the application.
func TestImmutabilityTriggersExist(t *testing.T) {
	for file, table := range map[string]string{
		"00007_create_secret_versions.sql": "secret_versions",
		"00008_create_audit_log.sql":       "audit_log",
	} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "migrations", file))
		require.NoError(t, err)
		sql := string(raw)

		assert.Contains(t, sql, "CREATE TRIGGER", "%s must have an immutability trigger", table)
		assert.Contains(t, sql, "BEFORE UPDATE OR DELETE ON "+table)
		assert.Contains(t, sql, "RAISE EXCEPTION")
		assert.Contains(t, sql, "current_setting(",
			"%s deletion must be gated on a transaction-local GUC", table)
		// goose needs the plpgsql body wrapped or it splits on semicolons.
		assert.Contains(t, sql, "-- +goose StatementBegin")
		assert.Contains(t, sql, "-- +goose StatementEnd")
	}
}

// TestAuditLogRecordsReads checks the schema and the action vocabulary treat a read
// as a first-class audited event. For a secret store the read IS the sensitive
// event, so an audit table without it would miss the point.
func TestAuditLogRecordsReads(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "migrations", "00008_create_audit_log.sql"))
	require.NoError(t, err)
	sql := string(raw)
	for _, col := range []string{"actor_subject", "actor_kind", "action", "resource_mrn", "outcome", "ip_address", "user_agent", "request_id"} {
		assert.Contains(t, sql, col)
	}
	// tenant_id must be nullable for pre-tenant setup events.
	assert.NotContains(t, sql, "tenant_id     BIGINT NOT NULL")

	assert.Equal(t, "secret.read", ActionRead)
	assert.Equal(t, "secret.reveal", ActionReveal)
	assert.NotEqual(t, ActionRead, ActionReveal,
		"metadata access and value access are different grants and must be separately reviewable")
}
