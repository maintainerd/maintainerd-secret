// Package dynamic is on-demand PostgreSQL credentials with a TTL: the naming, the
// credential generation, and the SQL-template rendering. It holds no storage and no
// authorization — internal/store owns the role configuration and the lease rows,
// internal/api owns the guard and the audit trail, and Provisioner (provisioner.go) is
// the only thing here that touches a target database.
//
// # Why this is the feature worth having
//
// A static database password is a long-lived shared value. Every consumer holds the
// same one, a leak is compromising until somebody notices and rotates, and "which
// consumer leaked it" is unanswerable because they all held the same string.
//
// A dynamic credential is minted per request, valid for an hour, and revoked
// automatically. A leaked one is worth what is left of its TTL. Attribution is free,
// because no two consumers ever hold the same account. And revocation is a real
// operation rather than a coordinated rotation across every consumer at once.
//
// # Why it is implementable here and needs no plugin system
//
// Vault needs a plugin per database engine because it must speak to whatever a tenant
// happens to run. maintainerd made PostgreSQL a platform decision — every service in
// the fleet is PostgreSQL-backed, by design and not by accident — so the creation and
// revocation statements are PostgreSQL DDL and nothing else. There is no driver
// abstraction to build, no per-engine capability matrix to maintain, and no lowest
// common denominator to design to. That is the whole reason this was deferrable until
// the platform decision was settled, and buildable once it was.
//
// # The privilege boundary, stated explicitly
//
// The target DSN is a PRIVILEGED credential: it is the account that can CREATE ROLE.
// It is never stored literally (see migrations/00012 — the column holds a secret
// REFERENCE and a check constraint refuses anything DSN-shaped), it is resolved
// internally at issue time, and it is NEVER returned to a caller by any path.
//
// A caller holding secret:IssueDynamicCredential therefore obtains a DERIVED, expiring
// credential without holding any grant on the DSN secret itself. That is deliberate
// and it is the point of a credential broker — requiring the caller to be able to read
// the admin DSN would mean every consumer held the admin DSN, which is the situation
// dynamic secrets exist to end. The privilege that matters is the one that configures
// the role (secret:ManageDynamicRole, user-only): whoever writes the creation template
// decides exactly what an issued credential can do, and that is where a reviewer
// should look.
package dynamic

import (
	"fmt"
	"strings"
	"time"

	"github.com/maintainerd/secret/internal/rotation"
)

// TTL bounds. A dynamic credential with no TTL is a permanent database account created
// by an API call, which is the opposite of this feature, so the floor is real rather
// than defensive.
const (
	// MinTTL floors a lease. Below a minute the credential expires before a consumer
	// can finish using it, and the reaper churns.
	MinTTL = time.Minute
	// DefaultTTL is the lease length a role that names none issues.
	DefaultTTL = time.Hour
	// MaxTTLCeiling is the hard ceiling on a role's configured max_ttl. It is a
	// compile-time constant and deliberately not configurable upward: a 30-day
	// dynamic credential is a static credential with a countdown, and the entire
	// argument for this feature is that the window is short.
	MaxTTLCeiling = 7 * 24 * time.Hour
)

// Credential generation.
const (
	// PasswordLength is the generated password length. 40 alphanumeric characters is
	// ~238 bits — far beyond what a bounded-lifetime credential needs, and the excess
	// is free.
	PasswordLength = 40
	// RoleNameMaxLen is PostgreSQL's identifier limit (NAMEDATALEN-1). A generated
	// name that exceeded it would be SILENTLY TRUNCATED by the server, which is the
	// dangerous failure: two leases would collide on one truncated role, and
	// revoking either would break the other.
	RoleNameMaxLen = 63
	// prefixMaxLen bounds the operator-chosen prefix so the random suffix always has
	// room. The suffix is what makes the name unique; a prefix that ate the budget
	// would turn uniqueness into a collision.
	prefixMaxLen = 20
	// suffixLength is the random part of a generated role name.
	suffixLength = 20
)

// DefaultRoleNamePrefix is used when a role config names none.
const DefaultRoleNamePrefix = "m9d"

// Template placeholders. They are `{{name}}`-style rather than `$1` positional
// parameters for a reason that is easy to get wrong: CREATE ROLE and GRANT are DDL,
// and PostgreSQL does not accept a bind parameter where an IDENTIFIER goes. A role
// name cannot be parameterised, so it has to be interpolated — which is exactly why
// ValidateRoleName below is strict and why the generated name is produced by this
// package rather than accepted from a caller.
const (
	// PlaceholderName is replaced with the generated role name.
	PlaceholderName = "{{name}}"
	// PlaceholderPassword is replaced with the generated password.
	PlaceholderPassword = "{{password}}"
	// PlaceholderExpiration is replaced with the lease expiry as an ISO-8601 literal,
	// for a template that uses VALID UNTIL.
	PlaceholderExpiration = "{{expiration}}"
)

// Template length bounds. A template is operator-written SQL, so it is generous, but
// unbounded text in a config column is an unbounded statement sent to a database.
const (
	MinTemplateLen = 10
	MaxTemplateLen = 8 << 10 // 8 KiB
)

// Config is a role configuration as this package needs it: the two templates, the TTLs
// and the naming prefix. It is a value type with no storage identity, so the rendering
// and validation below are testable without a database or a store.
type Config struct {
	// Name is the role config's own name — the handle a caller issues against.
	Name string
	// CreationSQL and RevocationSQL are the operator-written templates.
	CreationSQL   string
	RevocationSQL string
	// DefaultTTL is the lease length issued when the caller requests none.
	DefaultTTL time.Duration
	// MaxTTL is the ceiling on a caller-requested TTL.
	MaxTTL time.Duration
	// RoleNamePrefix prefixes every generated role name, so an operator reading
	// pg_roles can tell which accounts this service owns.
	RoleNamePrefix string
}

// ResolveTTL returns the lease length to issue.
//
// An over-long request is REFUSED rather than clamped, for the same reason an
// over-large page limit is: a caller that asked for 24 hours and silently got one will
// discover the difference when its credential stops working mid-job, and will look
// everywhere except at the request it made.
func (c Config) ResolveTTL(requested time.Duration) (time.Duration, error) {
	def := c.DefaultTTL
	if def <= 0 {
		def = DefaultTTL
	}
	ceiling := c.MaxTTL
	if ceiling <= 0 {
		ceiling = def
	}
	if requested <= 0 {
		return def, nil
	}
	if requested < MinTTL {
		return 0, fmt.Errorf("a lease of %s was requested but the minimum is %s",
			requested.Round(time.Second), MinTTL)
	}
	if requested > ceiling {
		return 0, fmt.Errorf("a lease of %s was requested but this role's maximum is %s",
			requested.Round(time.Second), ceiling.Round(time.Second))
	}
	return requested, nil
}

// Validate checks a role configuration before it is persisted.
//
// The template checks are SHAPE checks, not a SQL parser, and the doc says so rather
// than implying more: this refuses the templates that obviously cannot work (no
// CREATE ROLE, no DROP ROLE, no {{name}} placeholder, a password placeholder missing
// from a creation statement that needs one) and it cannot refuse a template that
// grants more than the operator intended. THAT is a review question, and the
// user-only actor constraint on role management is what makes sure a human is the one
// answering it.
func (c *Config) Validate() error {
	if err := ValidateConfigName(c.Name); err != nil {
		return err
	}
	if c.RoleNamePrefix == "" {
		c.RoleNamePrefix = DefaultRoleNamePrefix
	}
	if err := validatePrefix(c.RoleNamePrefix); err != nil {
		return err
	}
	if c.DefaultTTL <= 0 {
		c.DefaultTTL = DefaultTTL
	}
	if c.DefaultTTL < MinTTL {
		return fmt.Errorf("the default lease TTL must be at least %s, got %s", MinTTL, c.DefaultTTL)
	}
	if c.MaxTTL <= 0 {
		c.MaxTTL = c.DefaultTTL
	}
	if c.MaxTTL < c.DefaultTTL {
		return fmt.Errorf("the maximum lease TTL (%s) must not be shorter than the default (%s)",
			c.MaxTTL.Round(time.Second), c.DefaultTTL.Round(time.Second))
	}
	if c.MaxTTL > MaxTTLCeiling {
		return fmt.Errorf("the maximum lease TTL must be at most %s, got %s: a longer-lived credential is a static one with a countdown",
			MaxTTLCeiling, c.MaxTTL.Round(time.Second))
	}
	if err := validateTemplate("creation_sql", c.CreationSQL, "create role"); err != nil {
		return err
	}
	if err := validateTemplate("revocation_sql", c.RevocationSQL, "drop role"); err != nil {
		return err
	}
	if !strings.Contains(c.CreationSQL, PlaceholderPassword) {
		return fmt.Errorf("creation_sql must contain the %s placeholder: a role created without a password cannot be used to log in", PlaceholderPassword)
	}
	if strings.Contains(c.RevocationSQL, PlaceholderPassword) {
		// A revocation needs a name, never a password — and a template that asked for
		// one would be a template whose author expects the password to have been
		// stored, which it never is.
		return fmt.Errorf("revocation_sql must not contain %s: revoking a credential needs its role name, not its password", PlaceholderPassword)
	}
	return nil
}

// validateTemplate applies the shared shape rules to one template.
func validateTemplate(field, sql, requiredVerb string) error {
	trimmed := strings.TrimSpace(sql)
	if len(trimmed) < MinTemplateLen {
		return fmt.Errorf("%s is required and must be a SQL statement", field)
	}
	if len(trimmed) > MaxTemplateLen {
		return fmt.Errorf("%s must be at most %d characters, got %d", field, MaxTemplateLen, len(trimmed))
	}
	if !strings.Contains(strings.ToLower(trimmed), requiredVerb) {
		return fmt.Errorf("%s must contain a %s statement", field, strings.ToUpper(requiredVerb))
	}
	if !strings.Contains(trimmed, PlaceholderName) {
		return fmt.Errorf("%s must contain the %s placeholder, or every issued credential would share one role name",
			field, PlaceholderName)
	}
	// A NUL byte terminates a C string, which is what libpq hands the server. A
	// template containing one would be silently truncated at the driver boundary —
	// turning "CREATE ROLE x; GRANT SELECT" into "CREATE ROLE x" without any error.
	if strings.ContainsRune(trimmed, 0) {
		return fmt.Errorf("%s must not contain a NUL byte", field)
	}
	return nil
}

// ValidateConfigName checks a role configuration's name: a DNS-style slug, because it
// appears in an MRN resource path and in a URL.
func ValidateConfigName(name string) error {
	if name == "" {
		return fmt.Errorf("dynamic role name is required")
	}
	if len(name) > 63 {
		return fmt.Errorf("dynamic role name must be at most 63 characters, got %d", len(name))
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-' && i > 0 && i < len(name)-1:
		default:
			return fmt.Errorf("dynamic role name %q must be lowercase alphanumerics and internal hyphens", name)
		}
	}
	return nil
}

func validatePrefix(prefix string) error {
	if len(prefix) > prefixMaxLen {
		return fmt.Errorf("role_name_prefix must be at most %d characters, got %d", prefixMaxLen, len(prefix))
	}
	for i := 0; i < len(prefix); i++ {
		c := prefix[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' {
			continue
		}
		return fmt.Errorf("role_name_prefix %q must be lowercase alphanumerics and underscores: it becomes part of a PostgreSQL identifier", prefix)
	}
	if prefix != "" && prefix[0] >= '0' && prefix[0] <= '9' {
		return fmt.Errorf("role_name_prefix %q must not start with a digit: a PostgreSQL identifier cannot", prefix)
	}
	return nil
}

// Credential is one issued credential. It exists for exactly as long as the response
// that carries it.
//
// THE PASSWORD IS NEVER PERSISTED. There is no column for it (see migrations/00012),
// it is returned once, and revocation does not need it. Password is a plain string
// rather than a crypto.Plaintext because it has to be JSON-encoded into the issue
// response — the one place it legitimately leaves this service — and Zero below is
// what the caller uses to overwrite it afterwards.
type Credential struct {
	// RoleName is the PostgreSQL role that was created.
	RoleName string `json:"role_name"`
	// Password is the generated password, disclosed exactly once.
	Password string `json:"password"`
	// ExpiresAt is when the lease ends and the role is dropped.
	ExpiresAt time.Time `json:"expires_at"`
}

// ValidateRoleName is the guard on the ONE place this package interpolates into SQL.
//
// Because a role name is a PostgreSQL IDENTIFIER, it cannot be a bind parameter, so it
// is substituted into the statement as text. That makes this function the injection
// boundary for the whole feature, and it is written as an ALLOWLIST rather than as an
// escaper: lowercase letters, digits and underscores, starting with a letter or
// underscore, bounded to PostgreSQL's identifier length. A name that passes contains
// no quote, no semicolon, no whitespace and no comment marker, so there is nothing to
// escape.
//
// It is applied to names this package GENERATED, not to caller input — a caller cannot
// supply a role name at all. Checking anyway is the cheap belt: a future code path that
// starts accepting one meets this wall instead of the database.
func ValidateRoleName(name string) error {
	if name == "" {
		return fmt.Errorf("dynamic: a generated role name is empty")
	}
	if len(name) > RoleNameMaxLen {
		return fmt.Errorf("dynamic: role name %q is %d characters; PostgreSQL truncates past %d, which would let two leases collide on one account",
			name, len(name), RoleNameMaxLen)
	}
	first := name[0]
	if !((first >= 'a' && first <= 'z') || first == '_') {
		return fmt.Errorf("dynamic: role name %q must start with a lowercase letter or underscore", name)
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' {
			continue
		}
		return fmt.Errorf("dynamic: role name %q must contain only lowercase letters, digits and underscores", name)
	}
	return nil
}

// NewRoleName generates a unique PostgreSQL role name for one lease.
//
// The shape is `<prefix>_<random>`. The random part carries the uniqueness — a
// timestamp would collide under concurrency and would leak issue times into pg_roles —
// and the prefix carries the attribution, so an operator scanning pg_roles can tell
// which accounts this service owns and a reaper never touches one it did not create.
func NewRoleName(prefix string) (string, error) {
	if prefix == "" {
		prefix = DefaultRoleNamePrefix
	}
	if err := validatePrefix(prefix); err != nil {
		return "", err
	}
	spec := rotation.Spec{
		Type:   rotation.GeneratorRandom,
		Length: suffixLength,
		// Lowercase-only is not available as a charset, so the alphanumeric draw is
		// lowercased below. Doing it this way rather than adding a charset keeps the
		// generator package — which every rotation in the service runs through —
		// unchanged for a caller-specific formatting need.
		Charset: rotation.CharsetAlphanumeric,
	}
	suffix, err := spec.Generate()
	if err != nil {
		return "", fmt.Errorf("dynamic: generate role name: %w", err)
	}
	name := prefix + "_" + strings.ToLower(string(suffix))
	if err := ValidateRoleName(name); err != nil {
		return "", err
	}
	return name, nil
}

// NewPassword generates a credential password.
//
// The alphanumeric charset is the deliberate choice: a generated password travels
// through a DSN, a shell, a .env file, a YAML value and a copy-paste before it reaches
// a driver, and punctuation is what breaks all five. Entropy is bought with LENGTH
// instead, which costs nothing.
func NewPassword() (string, error) {
	spec := rotation.Spec{
		Type:    rotation.GeneratorRandom,
		Length:  PasswordLength,
		Charset: rotation.CharsetAlphanumeric,
	}
	raw, err := spec.Generate()
	if err != nil {
		return "", fmt.Errorf("dynamic: generate password: %w", err)
	}
	return string(raw), nil
}

// Render substitutes the placeholders in a template.
//
// THE PASSWORD IS RENDERED AS A QUOTED SQL STRING LITERAL, with embedded quotes
// doubled — the correct escaping for a PostgreSQL literal, applied here rather than
// trusted to the template author. The generated alphanumeric password contains no
// quote to escape, so the doubling is for a future generator (or a caller-supplied
// value, if one is ever permitted) rather than for today's; leaving it out would make
// that future change a SQL-injection bug in a file nobody would think to re-read.
//
// The template writes `PASSWORD {{password}}` — WITHOUT its own quotes — because the
// quoting is this function's job. A template that quoted it as well would produce
// `PASSWORD ”abc”`, which is a syntax error rather than a vulnerability, so the
// failure mode of getting this wrong is loud.
func Render(template, roleName, password string, expiresAt time.Time) (string, error) {
	if err := ValidateRoleName(roleName); err != nil {
		return "", err
	}
	out := strings.ReplaceAll(template, PlaceholderName, roleName)
	out = strings.ReplaceAll(out, PlaceholderPassword, quoteLiteral(password))
	out = strings.ReplaceAll(out, PlaceholderExpiration, quoteLiteral(expiresAt.UTC().Format(time.RFC3339)))
	return out, nil
}

// quoteLiteral renders a value as a PostgreSQL string literal.
//
// Single quotes are doubled, which is the standard escaping. A backslash needs no
// special handling because standard_conforming_strings has been on by default since
// PostgreSQL 9.1 — but a NUL is refused outright by the callers above rather than
// escaped, because there is no escape for it: libpq would truncate the statement at
// that byte.
func quoteLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
