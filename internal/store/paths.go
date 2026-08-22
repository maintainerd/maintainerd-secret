package store

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

// Limits. These are schema limits mirrored in Go so a bad input fails as a
// validation error with a useful message rather than as a constraint violation.
const (
	maxSlugLen       = 63   // matches VARCHAR(63) and the DNS label limit
	maxFolderNameLen = 255  // matches folders.name VARCHAR(255)
	maxKeyLen        = 255  // matches secrets.key VARCHAR(255)
	maxPathLen       = 1024 // folders.path is TEXT; this bounds the materialized path
	maxPathDepth     = 32
)

var (
	// slugPattern is a DNS label: lowercase alphanumerics and internal hyphens.
	// Tenant names, project slugs and environment slugs all use it because all
	// three appear in MRNs, and one of them (the tenant name) is also a subdomain
	// elsewhere in the platform.
	slugPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

	// folderNamePattern is deliberately wider than a slug — folder names are
	// organizational labels, not identifiers in a URL — but still excludes '/'
	// (which would forge a path segment) and anything non-printable.
	folderNamePattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]{0,253}[A-Za-z0-9])?$`)

	// keyPattern is the env-var-style secret name. Letters, digits, underscore,
	// dot and hyphen; must start alphanumeric or underscore. Excludes '/' so a key
	// can never smuggle a folder separator into an MRN resource path.
	keyPattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,254}$`)
)

// ValidateSlug checks a tenant name, project slug or environment slug.
func ValidateSlug(kind, s string) error {
	if s == "" {
		return fmt.Errorf("%s is required", kind)
	}
	if len(s) > maxSlugLen {
		return fmt.Errorf("%s must be at most %d characters, got %d", kind, maxSlugLen, len(s))
	}
	if !slugPattern.MatchString(s) {
		return fmt.Errorf("%s %q must be lowercase alphanumerics and hyphens, starting and ending alphanumeric", kind, s)
	}
	return nil
}

// ValidateFolderName checks a single folder name (not a path).
func ValidateFolderName(name string) error {
	if name == "" {
		return fmt.Errorf("folder name is required")
	}
	if len(name) > maxFolderNameLen {
		return fmt.Errorf("folder name must be at most %d characters, got %d", maxFolderNameLen, len(name))
	}
	if name == "." || name == ".." {
		return fmt.Errorf("folder name %q is reserved", name)
	}
	if !folderNamePattern.MatchString(name) {
		return fmt.Errorf("folder name %q must be alphanumerics, dots, hyphens or underscores and must not contain a slash", name)
	}
	return nil
}

// ValidateKey checks a secret key.
func ValidateKey(key string) error {
	if key == "" {
		return fmt.Errorf("secret key is required")
	}
	if len(key) > maxKeyLen {
		return fmt.Errorf("secret key must be at most %d characters, got %d", maxKeyLen, len(key))
	}
	if !keyPattern.MatchString(key) {
		return fmt.Errorf("secret key %q must be alphanumerics, underscores, dots or hyphens and must not contain a slash", key)
	}
	return nil
}

// NormalizePath returns the canonical absolute folder path for p: '/' for the
// root, and otherwise a slash-prefixed path with no trailing slash, no empty
// segments and no '.' or '..'.
//
// Canonicalizing here rather than trusting the caller is what lets the database
// treat folders.path as an exact, comparable value: '/db/', '//db' and '/db'
// must not be three different folders, and '/db/../etc' must not be a path at all.
// The check constraint on the column enforces the shape; this produces it.
func NormalizePath(p string) (string, error) {
	s := strings.TrimSpace(p)
	if s == "" || s == "/" {
		return "/", nil
	}
	if !strings.HasPrefix(s, "/") {
		s = "/" + s
	}
	// path.Clean removes duplicate slashes, trailing slashes and resolves '.'/'..'.
	// Resolving '..' is not enough on its own, because a path that escapes the root
	// ("/../x") cleans to "/x" and would silently mean something else — so the
	// pre-clean string is checked for '..' segments and rejected outright.
	for _, seg := range strings.Split(s, "/") {
		if seg == ".." {
			return "", fmt.Errorf("folder path %q must not contain '..'", p)
		}
	}
	cleaned := path.Clean(s)
	if cleaned == "/" {
		return "/", nil
	}
	if len(cleaned) > maxPathLen {
		return "", fmt.Errorf("folder path must be at most %d characters, got %d", maxPathLen, len(cleaned))
	}

	segments := strings.Split(strings.TrimPrefix(cleaned, "/"), "/")
	if len(segments) > maxPathDepth {
		return "", fmt.Errorf("folder path must be at most %d levels deep, got %d", maxPathDepth, len(segments))
	}
	for _, seg := range segments {
		if err := ValidateFolderName(seg); err != nil {
			return "", fmt.Errorf("folder path %q: %w", p, err)
		}
	}
	return cleaned, nil
}

// SplitPath returns the parent path and the final segment of a normalized path.
// The root has no parent and returns ("", "").
func SplitPath(normalized string) (parent, name string) {
	if normalized == "/" {
		return "", ""
	}
	i := strings.LastIndexByte(normalized, '/')
	if i <= 0 {
		return "/", normalized[1:]
	}
	return normalized[:i], normalized[i+1:]
}

// JoinPath appends a name to a parent path, producing a normalized path.
func JoinPath(parent, name string) string {
	if parent == "" || parent == "/" {
		return "/" + name
	}
	return parent + "/" + name
}

// IsAtOrUnder reports whether candidate is path itself or a descendant of it.
// Used to reject moving a folder into its own subtree, which would detach the
// subtree from the tree entirely.
func IsAtOrUnder(candidate, ancestor string) bool {
	if candidate == ancestor {
		return true
	}
	if ancestor == "/" {
		return true
	}
	return strings.HasPrefix(candidate, ancestor+"/")
}

// SubtreePattern returns the SQL LIKE pattern matching every DESCENDANT of path
// (not the path itself — queries compare that separately with equality).
//
// This function exists for two reasons, both of which are bugs if handled inline:
//
//  1. THE ROOT. The root folder's path is '/', so the obvious path+'/%' yields
//     '//%', which matches none of its children. The root's descendants are '/%'.
//  2. LIKE WILDCARDS IN THE PATH. '_' and '%' are LIKE metacharacters, and '_' is
//     a legal character in a folder name. Without escaping, listing '/my_folder'
//     would also return everything under '/myXfolder' — a cross-folder read caused
//     by string handling. Every segment is escaped with the SQL default '\'.
func SubtreePattern(p string) string {
	if p == "/" {
		return "/%"
	}
	return escapeLike(p) + "/%"
}

// escapeLike escapes the LIKE metacharacters, using the SQL standard default
// escape character.
func escapeLike(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' || c == '%' || c == '_' {
			b.WriteByte('\\')
		}
		b.WriteByte(c)
	}
	return b.String()
}

// mrnResourcePath builds the materialized MRN resource segment for a secret:
// 'secret/<environment>/<folder path>/<key>'.
//
// This MUST match the SQL expression in RefreshSecretMrnPathsInSubtree exactly. If
// the two ever disagree, a folder move would rewrite MRNs into a shape the write
// path never produces, and policy evaluation would silently stop matching. There is
// a test asserting the two agree.
func mrnResourcePath(environmentSlug, folderPath, key string) string {
	if folderPath == "/" {
		return "secret/" + environmentSlug + "/" + key
	}
	return "secret/" + environmentSlug + folderPath + "/" + key
}

// mrn renders the full presentation MRN. Policy compares the parsed columns, not
// this string — it exists for audit rows, logs and console display.
func mrn(tenantName, projectSlug, resourcePath string) string {
	return "mrn:secret:" + tenantName + ":" + projectSlug + ":" + resourcePath
}
