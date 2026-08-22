package dynamic

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Adversarial inputs, shared
// ---------------------------------------------------------------------------

// injectionPayloads is the corpus every identifier and literal path is fed. Each entry
// is something that, interpolated raw into DDL, either terminates the current token or
// smuggles a second statement. A role name is a PostgreSQL IDENTIFIER and therefore
// CANNOT be a bind parameter — it has to be interpolated as text — so this corpus is
// the actual threat model for this package rather than a formality.
func injectionPayloads() map[string]string {
	return map[string]string{
		"a single quote":             "role'",
		"a closing single quote":     "'; DROP ROLE postgres; --",
		"a double quote":             `role"`,
		"a quoted identifier":        `"postgres"`,
		"a statement separator":      "role; DROP ROLE postgres",
		"a line comment":             "role--comment",
		"a block comment":            "role/*comment*/",
		"a backslash":                `role\'`,
		"a doubled backslash":        `role\\`,
		"a dollar-quoted string":     "role$$x$$",
		"a backtick":                 "role`",
		"a space":                    "role name",
		"a tab":                      "role\tname",
		"a newline":                  "role\nDROP ROLE postgres",
		"a carriage return":          "role\rDROP ROLE postgres",
		"a NUL byte":                 "role\x00name",
		"uppercase":                  "Role",
		"a hyphen":                   "role-name",
		"a dot":                      "role.name",
		"a unicode letter":           "rolé",
		"a unicode homoglyph":        "rоle", // Cyrillic 'о'
		"a right-to-left override":   "role\u202ename",
		"a zero-width space":         "role\u200bname",
		"a full-width semicolon":     "role；DROP ROLE postgres",
		"a parenthesis":              "role()",
		"a percent":                  "role%s",
		"a placeholder for the name": PlaceholderName,
		"a placeholder for the pass": PlaceholderPassword,
		"a positional parameter":     "role$1",
	}
}

// ---------------------------------------------------------------------------
// ValidateRoleName — the injection boundary
// ---------------------------------------------------------------------------

// TestValidateRoleNameIsAnAllowlistNotAnEscaper. This function is the injection
// boundary for the whole feature, because a role name cannot be parameterised. It is
// written as an allowlist deliberately: a name that passes contains no quote, no
// semicolon, no whitespace and no comment marker, so there is NOTHING LEFT TO ESCAPE
// downstream. An escaper would have to be right about every dialect quirk; an
// allowlist only has to be right about what it admits.
func TestValidateRoleNameIsAnAllowlistNotAnEscaper(t *testing.T) {
	for name, payload := range injectionPayloads() {
		t.Run("rejects "+name, func(t *testing.T) {
			err := ValidateRoleName(payload)
			require.Error(t, err, "ValidateRoleName(%q) must be refused", payload)
		})
	}

	t.Run("rejects an empty name", func(t *testing.T) {
		require.Error(t, ValidateRoleName(""))
	})

	t.Run("rejects a name not starting with a letter or underscore", func(t *testing.T) {
		// A PostgreSQL identifier cannot start with a digit, so a name that did would
		// have to be double-quoted at every use site — and the whole point of the
		// allowlist is that no use site needs quoting logic.
		for _, bad := range []string{"1role", "9", "0abc"} {
			require.Error(t, ValidateRoleName(bad), "ValidateRoleName(%q) must be refused", bad)
		}
	})

	t.Run("rejects a name past PostgreSQL's identifier limit", func(t *testing.T) {
		// THE DANGEROUS FAILURE, and the reason this is a length check rather than a
		// truncation: PostgreSQL silently truncates past NAMEDATALEN-1, so two leases
		// would collide on ONE role and revoking either would break the other.
		atLimit := "m9d_" + strings.Repeat("a", RoleNameMaxLen-4)
		require.Len(t, atLimit, RoleNameMaxLen)
		require.NoError(t, ValidateRoleName(atLimit), "exactly at the limit must be accepted")

		err := ValidateRoleName(atLimit + "a")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "collide", "the message must say why length matters")
	})

	t.Run("accepts the shapes this package generates", func(t *testing.T) {
		for _, good := range []string{
			"m9d_abc123",
			"_leading_underscore",
			"a",
			"_",
			"role_with_digits_0123456789",
			strings.Repeat("z", RoleNameMaxLen),
		} {
			require.NoError(t, ValidateRoleName(good), "ValidateRoleName(%q) must be accepted", good)
		}
	})
}

// ---------------------------------------------------------------------------
// NewRoleName / NewPassword — the generated credential
// ---------------------------------------------------------------------------

// TestNewRoleNameIsUniquePerIssue. The random suffix is what carries uniqueness; a
// timestamp would collide under concurrency AND would leak issue times into pg_roles.
// A collision here is not cosmetic: two leases sharing one role means revoking either
// one kills the other's live credential.
func TestNewRoleNameIsUniquePerIssue(t *testing.T) {
	const draws = 512
	seen := make(map[string]struct{}, draws)
	for i := 0; i < draws; i++ {
		name, err := NewRoleName("m9d")
		require.NoError(t, err)

		_, dup := seen[name]
		require.False(t, dup, "two issues produced the same role name: %q", name)
		seen[name] = struct{}{}

		// Every generated name must survive the very wall that guards interpolation.
		require.NoError(t, ValidateRoleName(name), "a generated name must pass the allowlist")
		assert.True(t, strings.HasPrefix(name, "m9d_"),
			"the prefix carries attribution, so a reaper never touches a role it did not create")
		assert.Len(t, name, len("m9d_")+suffixLength)
		assert.LessOrEqual(t, len(name), RoleNameMaxLen)
	}
	assert.Len(t, seen, draws)
}

func TestNewRoleNameDefaultsItsPrefix(t *testing.T) {
	name, err := NewRoleName("")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(name, DefaultRoleNamePrefix+"_"))
}

// TestNewRoleNameRefusesAPrefixThatWouldPoisonTheIdentifier. The prefix is
// operator-chosen and becomes part of a PostgreSQL identifier, so it is the one part
// of a generated name that is not generated — which makes it the only place caller
// intent reaches the interpolated string.
func TestNewRoleNameRefusesAPrefixThatWouldPoisonTheIdentifier(t *testing.T) {
	for name, payload := range injectionPayloads() {
		if payload == PlaceholderName || payload == PlaceholderPassword {
			// Braces are covered by the generic rejection below; keep the case list
			// meaningful rather than duplicated.
			continue
		}
		t.Run("rejects "+name, func(t *testing.T) {
			_, err := NewRoleName(payload)
			require.Error(t, err, "NewRoleName(%q) must be refused", payload)
			assert.Contains(t, err.Error(), "role_name_prefix")
		})
	}

	t.Run("rejects a prefix starting with a digit", func(t *testing.T) {
		_, err := NewRoleName("1app")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must not start with a digit")
	})

	t.Run("rejects a prefix that would eat the suffix budget", func(t *testing.T) {
		// A prefix that consumed the budget would turn uniqueness into a collision.
		_, err := NewRoleName(strings.Repeat("a", prefixMaxLen+1))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at most")
	})

	t.Run("accepts a prefix at the bound", func(t *testing.T) {
		name, err := NewRoleName(strings.Repeat("a", prefixMaxLen))
		require.NoError(t, err)
		assert.LessOrEqual(t, len(name), RoleNameMaxLen,
			"the longest legal prefix plus the suffix must still fit a PostgreSQL identifier")
	})

	t.Run("accepts underscores and digits", func(t *testing.T) {
		name, err := NewRoleName("app_1")
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(name, "app_1_"))
	})
}

// TestNewPasswordIsLongUniqueAndTransportSafe. Entropy is bought with LENGTH rather
// than punctuation on purpose: a generated password travels through a DSN, a shell, a
// .env file, a YAML value and a copy-paste before it reaches a driver, and punctuation
// is what breaks all five.
func TestNewPasswordIsLongUniqueAndTransportSafe(t *testing.T) {
	const draws = 512
	seen := make(map[string]struct{}, draws)
	charsUsed := map[rune]struct{}{}

	for i := 0; i < draws; i++ {
		password, err := NewPassword()
		require.NoError(t, err)
		require.Len(t, password, PasswordLength, "a short password is the one thing length was supposed to buy")

		_, dup := seen[password]
		require.False(t, dup, "two issues produced the same password")
		seen[password] = struct{}{}

		for _, c := range password {
			assert.True(t,
				(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'),
				"password %q contains %q, which does not survive a DSN or a shell", password, c)
			charsUsed[c] = struct{}{}
		}
	}
	assert.Len(t, seen, draws)
	// A generator stuck on a narrow alphabet would still pass every check above while
	// producing far less entropy than the length implies.
	assert.Greater(t, len(charsUsed), 50, "the draw must span the alphabet, not a corner of it")
}

// TestAGeneratedPasswordCannotCarryATemplatePlaceholder is the guard behind Render's
// substitution order. Today's alphanumeric generator cannot emit '{', so a generated
// password is never rescanned as a placeholder — and if that ever changes, this fails
// before the ordering does.
func TestAGeneratedPasswordCannotCarryATemplatePlaceholder(t *testing.T) {
	for i := 0; i < 128; i++ {
		password, err := NewPassword()
		require.NoError(t, err)
		assert.NotContains(t, password, "{")
		assert.NotContains(t, password, "}")
		assert.NotContains(t, password, PlaceholderExpiration)
		assert.NotContains(t, password, PlaceholderName)
	}
}

// ---------------------------------------------------------------------------
// Render — the one place this package interpolates into SQL
// ---------------------------------------------------------------------------

func TestRenderSubstitutesEveryPlaceholder(t *testing.T) {
	expires := time.Date(2026, 8, 22, 15, 4, 5, 0, time.UTC)
	out, err := Render(
		"CREATE ROLE {{name}} LOGIN PASSWORD {{password}} VALID UNTIL {{expiration}}; GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}};",
		"m9d_abc", "s3cret", expires)
	require.NoError(t, err)

	assert.Equal(t,
		"CREATE ROLE m9d_abc LOGIN PASSWORD 's3cret' VALID UNTIL '2026-08-22T15:04:05Z'; "+
			"GRANT SELECT ON ALL TABLES IN SCHEMA public TO m9d_abc;",
		out)
	// Every placeholder is consumed, or the statement reaches the server with a literal
	// `{{name}}` in it and fails in a way that names our template rather than the bug.
	assert.NotContains(t, out, "{{")
}

// TestRenderQuotesThePasswordItselfRatherThanTrustingTheTemplate. The quoting lives
// here and not in the operator's template so there is ONE place to be right about it.
func TestRenderQuotesThePasswordItselfRatherThanTrustingTheTemplate(t *testing.T) {
	out, err := Render("CREATE ROLE {{name}} PASSWORD {{password}}", "m9d_a", "plain", time.Now())
	require.NoError(t, err)
	assert.Contains(t, out, "PASSWORD 'plain'", "the template writes no quotes of its own")
}

// TestRenderNeutralisesAnAdversarialPassword. The generated password contains no
// quote to escape, so the doubling is for a FUTURE generator (or a caller-supplied
// value, if one is ever permitted) rather than for today's. Leaving it untested would
// make that future change a SQL-injection bug in a file nobody would think to re-read.
func TestRenderNeutralisesAnAdversarialPassword(t *testing.T) {
	const template = "CREATE ROLE {{name}} LOGIN PASSWORD {{password}}"

	for name, payload := range injectionPayloads() {
		if strings.ContainsRune(payload, 0) {
			// A NUL is refused at template-validation time rather than escaped, because
			// there IS no escape for it — libpq would truncate the statement at that
			// byte. It is covered by TestValidateRefusesANULByte.
			continue
		}
		t.Run(name, func(t *testing.T) {
			out, err := Render(template, "m9d_a", payload, time.Now())
			require.NoError(t, err)

			literal := strings.TrimPrefix(out, "CREATE ROLE m9d_a LOGIN PASSWORD ")
			assert.True(t, strings.HasPrefix(literal, "'") && strings.HasSuffix(literal, "'"),
				"the value must be delimited as a string literal: %q", literal)

			// The load-bearing property: a value can only escape a PostgreSQL literal by
			// closing it, and an unescaped quote is the only way to do that. Every quote
			// inside must therefore be doubled, which leaves an EVEN count overall.
			assert.Zero(t, strings.Count(out, "'")%2,
				"an odd number of quotes means the literal was closed early: %q", out)

			// And the payload's own quotes are doubled rather than passed through.
			if strings.Contains(payload, "'") {
				assert.Contains(t, out, strings.ReplaceAll(payload, "'", "''"))
			}
		})
	}
}

// TestRenderRefusesAnAdversarialRoleName. Render calls the allowlist before it
// interpolates, so a name that should never have been generated cannot reach a
// statement even if a future code path starts accepting one from a caller.
func TestRenderRefusesAnAdversarialRoleName(t *testing.T) {
	const template = "CREATE ROLE {{name}} LOGIN PASSWORD {{password}}"

	for name, payload := range injectionPayloads() {
		t.Run(name, func(t *testing.T) {
			out, err := Render(template, payload, "pw", time.Now())
			require.Error(t, err, "Render must refuse the role name %q", payload)
			assert.Empty(t, out, "a refused render must produce no statement at all")
		})
	}

	// Including the degenerate one: an empty name would render `CREATE ROLE  LOGIN`.
	_, err := Render(template, "", "pw", time.Now())
	require.Error(t, err)
}

// TestRenderSubstitutesTheExpirationBeforeThePassword pins Render's substitution
// order, which is a security property rather than a style choice.
//
// Every substitution rescans the whole string, so a value injected early is still
// subject to the later passes. If the password went in before the expiration, a
// password containing the literal `{{expiration}}` would have that placeholder
// replaced INSIDE its own quoted literal — the injected instant's quotes would close
// the literal and the remainder would become executable SQL. Today's generator cannot
// emit a brace, so this is defence in depth for the caller-supplied password the doc
// on quoteLiteral explicitly anticipates.
func TestRenderSubstitutesTheExpirationBeforeThePassword(t *testing.T) {
	expires := time.Date(2026, 8, 22, 15, 4, 5, 0, time.UTC)
	hostile := "abc" + PlaceholderExpiration + "def"

	out, err := Render("CREATE ROLE {{name}} PASSWORD {{password}}", "m9d_a", hostile, expires)
	require.NoError(t, err)

	// The placeholder survives verbatim inside the literal: nothing rescanned it.
	assert.Equal(t, "CREATE ROLE m9d_a PASSWORD 'abc{{expiration}}def'", out)
	assert.Zero(t, strings.Count(out, "'")%2, "the literal must not have been closed early")
	assert.NotContains(t, out, expires.Format(time.RFC3339),
		"the password must not be rescanned for the expiration placeholder")
}

// TestRenderIsUnaffectedByAPlaceholderInTheExpirationSlot is the mirror: the
// expiration is an RFC3339 instant, so it can carry no placeholder of its own, and
// the name is allowlisted so it cannot either.
func TestRenderIsUnaffectedByAPlaceholderInTheExpirationSlot(t *testing.T) {
	out, err := Render("CREATE ROLE {{name}} VALID UNTIL {{expiration}} PASSWORD {{password}}",
		"m9d_a", "pw", time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	require.NoError(t, err)
	assert.Equal(t, "CREATE ROLE m9d_a VALID UNTIL '2026-01-02T03:04:05Z' PASSWORD 'pw'", out)
}

// TestRenderNormalisesTheExpirationToUTC. Two operators in two timezones must read
// the same instant out of a statement and out of pg_roles.
func TestRenderNormalisesTheExpirationToUTC(t *testing.T) {
	loc := time.FixedZone("UTC+9", 9*60*60)
	local := time.Date(2026, 8, 22, 23, 0, 0, 0, loc)

	out, err := Render("CREATE ROLE {{name}} VALID UNTIL {{expiration}}", "m9d_a", "", local)
	require.NoError(t, err)
	assert.Contains(t, out, "'2026-08-22T14:00:00Z'")
}

// TestRenderAcceptsAnEmptyPasswordForARevocation. A revocation template may not carry
// a password placeholder at all (Validate refuses one), so the empty string passed on
// that path must never produce a rendered literal.
func TestRenderAcceptsAnEmptyPasswordForARevocation(t *testing.T) {
	out, err := Render("REASSIGN OWNED BY {{name}} TO postgres; DROP OWNED BY {{name}}; DROP ROLE IF EXISTS {{name}};",
		"m9d_abc", "", time.Now())
	require.NoError(t, err)
	assert.Equal(t,
		"REASSIGN OWNED BY m9d_abc TO postgres; DROP OWNED BY m9d_abc; DROP ROLE IF EXISTS m9d_abc;",
		out)
	assert.NotContains(t, out, "''", "an unused password placeholder must leave no empty literal behind")
}

// ---------------------------------------------------------------------------
// Config.ResolveTTL
// ---------------------------------------------------------------------------

func TestConfigResolveTTLBoundaries(t *testing.T) {
	cases := []struct {
		name      string
		config    Config
		requested time.Duration
		want      time.Duration
		wantErr   string
	}{
		{"an absent request takes the default", Config{DefaultTTL: 2 * time.Hour, MaxTTL: 6 * time.Hour}, 0, 2 * time.Hour, ""},
		{"a negative request takes the default", Config{DefaultTTL: 2 * time.Hour, MaxTTL: 6 * time.Hour}, -time.Hour, 2 * time.Hour, ""},
		{"a zero config default falls back to the package default", Config{}, 0, DefaultTTL, ""},

		// A dynamic credential with no TTL is a permanent database account created by an
		// API call, which is the opposite of this feature — so the floor is real.
		{"below the floor is refused", Config{DefaultTTL: time.Hour, MaxTTL: 6 * time.Hour}, time.Second, 0, "minimum"},
		{"one nanosecond below the floor is refused", Config{DefaultTTL: time.Hour, MaxTTL: 6 * time.Hour}, MinTTL - time.Nanosecond, 0, "minimum"},
		{"exactly at the floor is accepted", Config{DefaultTTL: time.Hour, MaxTTL: 6 * time.Hour}, MinTTL, MinTTL, ""},

		// Over-long is REFUSED, not clamped: a caller that asked for 24 hours and
		// silently got one will discover the difference when its credential stops
		// working mid-job, and will look everywhere except at the request it made.
		{"exactly at the ceiling", Config{DefaultTTL: time.Hour, MaxTTL: 6 * time.Hour}, 6 * time.Hour, 6 * time.Hour, ""},
		{"one nanosecond past the ceiling", Config{DefaultTTL: time.Hour, MaxTTL: 6 * time.Hour}, 6*time.Hour + time.Nanosecond, 0, "maximum"},
		{"well past the ceiling", Config{DefaultTTL: time.Hour, MaxTTL: 6 * time.Hour}, 24 * time.Hour, 0, "maximum"},

		// An absent ceiling is the DEFAULT, never infinity.
		{"an absent ceiling is the default TTL", Config{DefaultTTL: time.Hour}, 2 * time.Hour, 0, "maximum"},
		{"a zero ceiling is the default TTL", Config{DefaultTTL: time.Hour, MaxTTL: 0}, 2 * time.Hour, 0, "maximum"},
		{"a negative ceiling is the default TTL", Config{DefaultTTL: time.Hour, MaxTTL: -time.Hour}, 2 * time.Hour, 0, "maximum"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.config.ResolveTTL(tc.requested)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				assert.Zero(t, got, "a refused TTL must not also return a usable duration")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
			assert.GreaterOrEqual(t, got, MinTTL, "an issued lease must never be shorter than the floor")
		})
	}
}

// TestResolveTTLEnforcesTheHardCeilingOnAStoredConfig.
//
// MaxTTLCeiling is "a hard ceiling ... deliberately not configurable upward", and
// Validate enforces it AT PERSIST TIME. That is not sufficient on its own: Validate
// only runs when a config is written, so a stored row can carry a larger MaxTTL by
// three routes — it predates the ceiling, an operator lowered the ceiling in a later
// release, or the row was edited directly in the database. If ResolveTTL trusted the
// row, the bound that is "deliberately not configurable upward" would be exceeded by
// any config that never passes through Validate again, and the credential granted
// would be a static password with a long countdown.
//
// The ceiling is clamped rather than the request, which is what keeps BOTH properties:
// the hard bound holds, and a caller asking for more than it can have is still refused
// with the real limit instead of silently downgraded.
func TestResolveTTLEnforcesTheHardCeilingOnAStoredConfig(t *testing.T) {
	stale := Config{DefaultTTL: time.Hour, MaxTTL: 30 * 24 * time.Hour}
	require.Greater(t, stale.MaxTTL, MaxTTLCeiling, "the fixture must exceed the hard ceiling to be meaningful")

	// Asking for the stored (over-long) maximum is refused, and the message names the
	// ceiling actually in force rather than the row's value.
	_, err := stale.ResolveTTL(30 * 24 * time.Hour)
	require.Error(t, err)
	assert.Contains(t, err.Error(), MaxTTLCeiling.Round(time.Second).String(),
		"the refusal must state the bound in force, or an operator will keep retrying the stored value")

	// Exactly the ceiling is still grantable — the clamp is a ceiling, not an off-by-one.
	granted, err := stale.ResolveTTL(MaxTTLCeiling)
	require.NoError(t, err)
	assert.Equal(t, MaxTTLCeiling, granted)

	// A default above the ceiling is clamped too, not just an explicit request: an
	// issue call that names no TTL takes the default, so leaving that path unclamped
	// would make "ask for nothing" the way to exceed the bound.
	staleDefault := Config{DefaultTTL: 30 * 24 * time.Hour, MaxTTL: 30 * 24 * time.Hour}
	granted, err = staleDefault.ResolveTTL(0)
	require.NoError(t, err)
	assert.Equal(t, MaxTTLCeiling, granted, "the implicit default must not exceed the hard ceiling either")

	// Validate remains the persist-time half, so a NEW config above the ceiling is
	// refused outright rather than quietly clamped on every issue.
	cfg := stale
	cfg.Name = "app-reader"
	cfg.CreationSQL = "CREATE ROLE {{name}} LOGIN PASSWORD {{password}}"
	cfg.RevocationSQL = "DROP ROLE IF EXISTS {{name}}"
	err = cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "static one with a countdown")
}

// ---------------------------------------------------------------------------
// Config.Validate
// ---------------------------------------------------------------------------

// validConfig is a configuration that passes, so each case below mutates exactly one
// thing and the failure names that thing.
func validConfig() Config {
	return Config{
		Name:          "app-reader",
		CreationSQL:   "CREATE ROLE {{name}} LOGIN PASSWORD {{password}} VALID UNTIL {{expiration}}",
		RevocationSQL: "DROP ROLE IF EXISTS {{name}}",
		DefaultTTL:    time.Hour,
		MaxTTL:        6 * time.Hour,
	}
}

func TestValidateAcceptsAWorkableConfigAndFillsItsDefaults(t *testing.T) {
	cfg := Config{
		Name:          "app-reader",
		CreationSQL:   "CREATE ROLE {{name}} LOGIN PASSWORD {{password}}",
		RevocationSQL: "DROP ROLE IF EXISTS {{name}}",
	}
	require.NoError(t, cfg.Validate())

	// Validate normalises in place, so a caller that stores the struct stores a
	// configuration that can actually issue a credential.
	assert.Equal(t, DefaultRoleNamePrefix, cfg.RoleNamePrefix, "a role with no prefix must still be attributable")
	assert.Equal(t, DefaultTTL, cfg.DefaultTTL)
	assert.Equal(t, DefaultTTL, cfg.MaxTTL, "an absent ceiling becomes the default, never infinity")
}

func TestValidateRejectsTheConfigurationsThatCannotWork(t *testing.T) {
	cases := map[string]struct {
		mutate  func(*Config)
		wantMsg string
	}{
		"no name":            {func(c *Config) { c.Name = "" }, "required"},
		"an uppercase name":  {func(c *Config) { c.Name = "AppReader" }, "lowercase"},
		"an underscore name": {func(c *Config) { c.Name = "app_reader" }, "lowercase"},
		"a leading hyphen":   {func(c *Config) { c.Name = "-app" }, "lowercase"},
		"a trailing hyphen":  {func(c *Config) { c.Name = "app-" }, "lowercase"},
		"an over-long name":  {func(c *Config) { c.Name = strings.Repeat("a", 64) }, "at most 63"},

		"a bad prefix":        {func(c *Config) { c.RoleNamePrefix = "app-reader" }, "role_name_prefix"},
		"a numeric prefix":    {func(c *Config) { c.RoleNamePrefix = "1app" }, "must not start with a digit"},
		"an over-long prefix": {func(c *Config) { c.RoleNamePrefix = strings.Repeat("a", prefixMaxLen+1) }, "role_name_prefix"},

		// A default below the floor would issue a credential that expires before a
		// consumer can finish using it, and would make the reaper churn.
		"a sub-minute default": {func(c *Config) { c.DefaultTTL = time.Second }, "at least"},
		// A ceiling below the default is a configuration nobody means: the default
		// itself could not be issued.
		"a ceiling below the default": {func(c *Config) { c.MaxTTL = time.Minute }, "must not be shorter"},
		// A 30-day dynamic credential is a static credential with a countdown, which is
		// the entire argument for the feature reversed.
		"a ceiling past the hard limit": {func(c *Config) { c.MaxTTL = MaxTTLCeiling + time.Hour }, "static one with a countdown"},

		"no creation sql":             {func(c *Config) { c.CreationSQL = "" }, "creation_sql is required"},
		"a stub creation sql":         {func(c *Config) { c.CreationSQL = "CREATE" }, "creation_sql is required"},
		"no revocation sql":           {func(c *Config) { c.RevocationSQL = "" }, "revocation_sql is required"},
		"creation without the verb":   {func(c *Config) { c.CreationSQL = "GRANT SELECT TO {{name}} PASSWORD {{password}}" }, "CREATE ROLE"},
		"revocation without the verb": {func(c *Config) { c.RevocationSQL = "REASSIGN OWNED BY {{name}} TO postgres" }, "DROP ROLE"},

		// Without the name placeholder every issued credential would share ONE role
		// name — so the second issue would fail and revoking one would kill them all.
		"creation without the name placeholder":   {func(c *Config) { c.CreationSQL = "CREATE ROLE fixed LOGIN PASSWORD {{password}}" }, PlaceholderName},
		"revocation without the name placeholder": {func(c *Config) { c.RevocationSQL = "DROP ROLE IF EXISTS fixed" }, PlaceholderName},

		// A role created without a password cannot be used to log in, so the credential
		// this feature exists to hand out would be unusable.
		"creation without the password placeholder": {func(c *Config) { c.CreationSQL = "CREATE ROLE {{name}} LOGIN" }, PlaceholderPassword},
		// A revocation needs a NAME, never a password. A template asking for one was
		// written by an author who expects the password to have been stored, which it
		// never is.
		"revocation asking for the password": {func(c *Config) {
			c.RevocationSQL = "DROP ROLE IF EXISTS {{name}} PASSWORD {{password}}"
		}, "not its password"},

		"an over-long creation template": {func(c *Config) {
			c.CreationSQL = "CREATE ROLE {{name}} PASSWORD {{password}} -- " + strings.Repeat("x", MaxTemplateLen)
		}, "at most"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig()
			tc.mutate(&cfg)
			err := cfg.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantMsg)
		})
	}
}

// TestValidateRefusesANULByte. A NUL terminates the C string libpq hands the server,
// so a template containing one would be SILENTLY TRUNCATED at the driver boundary —
// turning "CREATE ROLE x; GRANT SELECT" into "CREATE ROLE x" with no error anywhere.
// That is a credential with the wrong privileges and a clean success response.
func TestValidateRefusesANULByte(t *testing.T) {
	t.Run("in the creation template", func(t *testing.T) {
		cfg := validConfig()
		cfg.CreationSQL = "CREATE ROLE {{name}} PASSWORD {{password}}\x00; GRANT ALL TO {{name}}"
		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "NUL")
	})
	t.Run("in the revocation template", func(t *testing.T) {
		cfg := validConfig()
		cfg.RevocationSQL = "DROP ROLE IF EXISTS {{name}}\x00"
		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "NUL")
	})
}

// TestValidateIsShapeOnlyAndSaysSo. The doc is explicit that this is not a SQL parser
// and cannot refuse a template that grants more than the operator intended — that is
// a review question, and the user-only actor constraint on role management is what
// makes sure a human answers it. Pinning it here keeps a future reader from mistaking
// Validate for a privilege check.
func TestValidateIsShapeOnlyAndSaysSo(t *testing.T) {
	cfg := validConfig()
	cfg.CreationSQL = "CREATE ROLE {{name}} LOGIN SUPERUSER PASSWORD {{password}}"
	assert.NoError(t, cfg.Validate(),
		"Validate is a SHAPE check: a wildly over-privileged template passes, and human review is the control")
}

func TestValidateTemplateLengthBoundaries(t *testing.T) {
	t.Run("exactly at the minimum", func(t *testing.T) {
		cfg := validConfig()
		// Ten characters is MinTemplateLen; the verb and placeholder checks still apply,
		// so the shortest workable template is well above the floor.
		cfg.RevocationSQL = "drop role {{name}}"
		require.GreaterOrEqual(t, len(cfg.RevocationSQL), MinTemplateLen)
		assert.NoError(t, cfg.Validate())
	})
	t.Run("the verb is matched case-insensitively", func(t *testing.T) {
		cfg := validConfig()
		cfg.CreationSQL = "create role {{name}} login password {{password}}"
		cfg.RevocationSQL = "Drop Role If Exists {{name}}"
		assert.NoError(t, cfg.Validate())
	})
	t.Run("surrounding whitespace does not count towards the bounds", func(t *testing.T) {
		cfg := validConfig()
		cfg.RevocationSQL = "   \n DROP ROLE IF EXISTS {{name}} \n  "
		assert.NoError(t, cfg.Validate())
	})
}

// ---------------------------------------------------------------------------
// ValidateConfigName
// ---------------------------------------------------------------------------

// TestValidateConfigNameIsADNSStyleSlug. The name appears in an MRN resource path and
// in a URL, so anything needing escaping in either would break both.
func TestValidateConfigNameIsADNSStyleSlug(t *testing.T) {
	for _, good := range []string{"app", "app-reader", "a1", "1a", "a-b-c", strings.Repeat("a", 63)} {
		assert.NoError(t, ValidateConfigName(good), "ValidateConfigName(%q) must be accepted", good)
	}
	for _, bad := range []string{
		"",
		"App",
		"app_reader",
		"-app",
		"app-",
		"-",
		"app reader",
		"app.reader",
		"app/reader",
		"app:reader",
		"app%2f",
		"appé",
		"app\x00",
		strings.Repeat("a", 64),
	} {
		assert.Error(t, ValidateConfigName(bad), "ValidateConfigName(%q) must be refused", bad)
	}
}

// TestValidateConfigNameErrorNamesTheOffender so an operator can see which of a batch
// of names was rejected.
func TestValidateConfigNameErrorNamesTheOffender(t *testing.T) {
	err := ValidateConfigName("App_Reader")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "App_Reader")
}

// ---------------------------------------------------------------------------
// Constants that other packages and migrations depend on
// ---------------------------------------------------------------------------

// TestTheTTLBoundsAreOrderedAndUsable. These four constants are a contract with
// migrations/00012 and with internal/store; an inversion between them would make some
// configuration simultaneously required and refused.
func TestTheTTLBoundsAreOrderedAndUsable(t *testing.T) {
	assert.Less(t, MinTTL, DefaultTTL, "the default lease must be longer than the floor")
	assert.Less(t, DefaultTTL, MaxTTLCeiling, "the default must fit under the hard ceiling")
	assert.Equal(t, time.Minute, MinTTL)
	assert.Equal(t, 7*24*time.Hour, MaxTTLCeiling)
}

// TestAGeneratedRoleNameAlwaysFitsPostgresAtEveryLegalPrefix sweeps the prefix bound
// rather than sampling it, because silent truncation at NAMEDATALEN is the one naming
// failure that collides two live leases onto one account.
func TestAGeneratedRoleNameAlwaysFitsPostgresAtEveryLegalPrefix(t *testing.T) {
	for n := 1; n <= prefixMaxLen; n++ {
		prefix := strings.Repeat("p", n)
		name, err := NewRoleName(prefix)
		require.NoError(t, err, "prefix of %d characters", n)
		assert.LessOrEqual(t, len(name), RoleNameMaxLen,
			fmt.Sprintf("a %d-character prefix produced a %d-character identifier", n, len(name)))
		require.NoError(t, ValidateRoleName(name))
	}
}
