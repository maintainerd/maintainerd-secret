package migrations

import (
	"strings"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// readAll returns every embedded migration keyed by filename.
func readAll(t *testing.T) map[string]string {
	t.Helper()
	entries, err := FS.ReadDir(".")
	require.NoError(t, err)

	out := map[string]string{}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		raw, err := FS.ReadFile(e.Name())
		require.NoError(t, err)
		out[e.Name()] = string(raw)
	}
	require.NotEmpty(t, out, "no migrations were embedded; check the //go:embed directive")
	return out
}

// TestGooseCollectsEveryMigration runs goose's own collector over the embedded FS.
// It catches a malformed or duplicated version prefix — which would otherwise
// surface as a boot failure on a live database rather than here.
func TestGooseCollectsEveryMigration(t *testing.T) {
	goose.SetBaseFS(FS)
	t.Cleanup(func() { goose.SetBaseFS(nil) })
	require.NoError(t, goose.SetDialect("postgres"))

	collected, err := goose.CollectMigrations(".", 0, int64(1<<62))
	require.NoError(t, err)

	files := readAll(t)
	assert.Len(t, collected, len(files), "goose must collect every embedded migration")

	// Versions must be strictly increasing with no duplicates.
	seen := map[int64]bool{}
	for _, m := range collected {
		assert.False(t, seen[m.Version], "duplicate migration version %d", m.Version)
		seen[m.Version] = true
	}
}

// TestEveryMigrationHasUpAndDown checks the annotations goose needs.
func TestEveryMigrationHasUpAndDown(t *testing.T) {
	for name, sql := range readAll(t) {
		assert.Contains(t, sql, "-- +goose Up", "%s has no Up section", name)
		assert.Contains(t, sql, "-- +goose Down", "%s has no Down section", name)
		assert.Less(t, strings.Index(sql, "-- +goose Up"), strings.Index(sql, "-- +goose Down"),
			"%s declares Down before Up", name)
	}
}

// TestDollarQuotedBodiesAreWrappedForGoose is the one that matters most in this
// repo, because the failure it prevents is silent and only shows up on a real
// database.
//
// goose splits a migration into statements on semicolons. A plpgsql function body
// is full of semicolons INSIDE its $$ ... $$ quoting, so an unwrapped
// CREATE FUNCTION is chopped into fragments and the migration fails — or worse,
// partially applies. The fix is to fence the whole thing in
// `-- +goose StatementBegin` / `-- +goose StatementEnd`, and this asserts every
// dollar-quoted body is fenced.
//
// The append-only triggers on secret_versions and audit_log are exactly this shape,
// and they are the mechanism that makes secret history unrewritable — so a
// migration that quietly failed to install them would remove a core guarantee
// while looking like a successful deploy.
func TestDollarQuotedBodiesAreWrappedForGoose(t *testing.T) {
	for name, sql := range readAll(t) {
		if !strings.Contains(sql, "$$") {
			continue
		}
		lines := strings.Split(sql, "\n")
		inBlock := false
		fencedDollars := 0
		unfencedDollars := 0

		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(trimmed, "-- +goose StatementBegin"):
				assert.False(t, inBlock, "%s: nested StatementBegin", name)
				inBlock = true
				continue
			case strings.HasPrefix(trimmed, "-- +goose StatementEnd"):
				assert.True(t, inBlock, "%s: StatementEnd without StatementBegin", name)
				inBlock = false
				continue
			}
			count := strings.Count(line, "$$")
			if count == 0 {
				continue
			}
			if inBlock {
				fencedDollars += count
			} else {
				unfencedDollars += count
			}
		}

		assert.False(t, inBlock, "%s: unterminated StatementBegin block", name)
		assert.Zero(t, unfencedDollars,
			"%s has %d dollar-quote marker(s) outside a StatementBegin/StatementEnd fence; goose will split the function body on its internal semicolons",
			name, unfencedDollars)
		// Balanced open/close markers inside the fences.
		assert.Zero(t, fencedDollars%2, "%s has unbalanced $$ markers", name)
	}
}

// TestMigrationsAreCreateOnly enforces the repo-wide rule: one create file per
// table, edited in place while the schema is under development, never an ALTER.
// Development databases are recreated rather than migrated forward.
func TestMigrationsAreCreateOnly(t *testing.T) {
	files := readAll(t)
	for name, sql := range files {
		assert.Contains(t, name, "_create_",
			"migration %s is not a create migration; this repo never writes ALTER migrations", name)
		assert.NotContains(t, strings.ToUpper(sql), "ALTER TABLE",
			"migration %s contains ALTER TABLE; edit the create migration in place instead", name)
	}
	assert.Len(t, files, 9, "the schema is nine create migrations; update this count deliberately")
}

// TestDownSectionsDropWhatTheyCreated is a cheap symmetry check: a Down that
// forgets the trigger function leaves a stale function behind on a rollback.
func TestDownSectionsDropWhatTheyCreated(t *testing.T) {
	for name, sql := range readAll(t) {
		parts := strings.SplitN(sql, "-- +goose Down", 2)
		require.Len(t, parts, 2, name)
		up, down := parts[0], parts[1]

		if strings.Contains(up, "CREATE OR REPLACE FUNCTION") {
			assert.Contains(t, down, "DROP FUNCTION", "%s creates a function but never drops it", name)
		}
		if strings.Contains(up, "CREATE TRIGGER") {
			assert.Contains(t, down, "DROP TRIGGER", "%s creates a trigger but never drops it", name)
		}
		assert.Contains(t, down, "DROP TABLE", "%s does not drop its table", name)
	}
}
