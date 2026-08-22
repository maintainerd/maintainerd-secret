package mrn

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These mirror maintainerd-auth's own MRN cases. The two implementations must agree
// exactly: a pattern that matches in Auth's policy engine and not here is a locked-out
// operator, and one that matches here but not there is an unauthorized read.

func TestParseRoundTrips(t *testing.T) {
	m, err := Parse("mrn:secret:acme:billing-app:secret/prod/db/primary/PASSWORD")
	require.NoError(t, err)
	assert.Equal(t, "secret", m.Service)
	assert.Equal(t, "acme", m.Tenant)
	assert.Equal(t, "billing-app", m.Project)
	assert.Equal(t, "secret/prod/db/primary/PASSWORD", m.ResourcePath)
	assert.Equal(t, "mrn:secret:acme:billing-app:secret/prod/db/primary/PASSWORD", m.String())
}

func TestParseRejectsMalformed(t *testing.T) {
	for _, bad := range []string{
		"",
		"secret:acme:billing:x",             // no scheme
		"mrn:secret:acme:billing",           // four parts
		"mrn::acme:billing:secret/x",        // empty service
		"mrn:secret:ACME:billing:secret/x",  // uppercase segment
		"mrn:secret:acme:billing:/secret/x", // leading slash
		"mrn:secret:acme:billing:secret/*",  // a concrete resource that looks like a pattern
		"mrn:secret:acme:billing:",          // empty resource path
	} {
		_, err := Parse(bad)
		assert.Error(t, err, "Parse(%q) must fail", bad)
	}
}

// TestWildcardNeverSpansAColon is the property that makes an MRN pattern usable as a
// tenant-isolation boundary. A flat glob would let "acme*" reach "acmecorp".
func TestWildcardNeverSpansAColon(t *testing.T) {
	matched, err := Match("mrn:secret:acme:*:*", "mrn:secret:acmecorp:billing:secret/prod/X")
	require.NoError(t, err)
	assert.False(t, matched, "a grant for tenant acme must not reach tenant acmecorp")
}

// TestEmptyPatternSegmentIsAScopeBoundary: an empty segment matches ONLY an empty
// segment. Treating it as a wildcard would turn "narrower scope" into "broader grant".
func TestEmptyPatternSegmentIsAScopeBoundary(t *testing.T) {
	// A tenant-scoped pattern (empty project) speaks only for tenant-scoped resources.
	matched, err := Match("mrn:secret:acme::project", "mrn:secret:acme::project")
	require.NoError(t, err)
	assert.True(t, matched)

	matched, err = Match("mrn:secret:acme::project", "mrn:secret:acme:billing:project")
	require.NoError(t, err)
	assert.False(t, matched, "an empty project segment must not leak into a named project")

	// "*" does match an empty segment, which is the documented asymmetry.
	matched, err = Match("mrn:secret:acme:*:project", "mrn:secret:acme::project")
	require.NoError(t, err)
	assert.True(t, matched)
}

// TestResourcePathPrefixMatching is the "may read staging, not prod" grant, in its
// raw form.
func TestResourcePathPrefixMatching(t *testing.T) {
	const staging = "mrn:secret:acme:billing:secret/staging/*"

	matched, err := Match(staging, "mrn:secret:acme:billing:secret/staging/db/PASSWORD")
	require.NoError(t, err)
	assert.True(t, matched)

	matched, err = Match(staging, "mrn:secret:acme:billing:secret/prod/db/PASSWORD")
	require.NoError(t, err)
	assert.False(t, matched)
}

// TestFolderPathsAreDisjointFromSecretPaths: a grant over secrets must not carry the
// ability to move the folders those secrets live in, because a move rewrites the MRNs
// of everything beneath it.
func TestFolderPathsAreDisjointFromSecretPaths(t *testing.T) {
	matched, err := Match("mrn:secret:acme:billing:secret/prod/*", "mrn:secret:acme:billing:folder/prod/db")
	require.NoError(t, err)
	assert.False(t, matched)
}

// TestMidPathWildcardsAreRejectedAtParseTime: rejecting them where they are written
// beats mis-matching them where they are evaluated, which would be invisible.
func TestMidPathWildcardsAreRejectedAtParseTime(t *testing.T) {
	_, err := ParsePattern("mrn:secret:acme:billing:secret/*/PASSWORD")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mid-path wildcards")

	_, err = ParsePattern("mrn:secret:acme:billing:secret/prod/*/*")
	require.Error(t, err)
}

// TestMatchReportsEvaluationFailureRatherThanFalse lets a caller distinguish "does not
// match" from "cannot be evaluated" and fail closed on the latter.
func TestMatchReportsEvaluationFailureRatherThanFalse(t *testing.T) {
	_, err := Match("not-an-mrn", "mrn:secret:acme:billing:secret/prod/X")
	assert.Error(t, err)

	_, err = Match("mrn:secret:acme:billing:*", "not-an-mrn")
	assert.Error(t, err)
}

func TestBareWildcardMatchesEverything(t *testing.T) {
	matched, err := Match("mrn:secret:*:*:*", "mrn:secret:acme:billing:secret/prod/db/X")
	require.NoError(t, err)
	assert.True(t, matched)
}

func TestNewBuildsThisServicesMRN(t *testing.T) {
	m := New("acme", "billing", "secret/prod/X")
	assert.Equal(t, "mrn:secret:acme:billing:secret/prod/X", m.String())
	assert.True(t, IsMRN(m.String()))
}
