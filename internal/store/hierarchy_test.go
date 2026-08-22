package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/maintainerd/secret/internal/platform/apperror"
)

// ---------------------------------------------------------------------------
// Slug, name, key and path validation
// ---------------------------------------------------------------------------

func TestValidateSlug(t *testing.T) {
	valid := []string{"a", "acme", "billing-app", "prod", "a1", "x-9", strings.Repeat("a", 63)}
	for _, s := range valid {
		assert.NoError(t, ValidateSlug("slug", s), s)
	}
	invalid := map[string]string{
		"empty":           "",
		"uppercase":       "Acme",
		"leading hyphen":  "-acme",
		"trailing hyphen": "acme-",
		"underscore":      "acme_corp",
		"dot":             "acme.corp",
		"slash":           "acme/corp",
		"space":           "acme corp",
		"too long":        strings.Repeat("a", 64),
	}
	for name, s := range invalid {
		assert.Error(t, ValidateSlug("slug", s), name)
	}
}

func TestValidateKey(t *testing.T) {
	valid := []string{"DB_PASSWORD", "db-password", "token", "API.KEY", "_private", "K1", strings.Repeat("k", 255)}
	for _, k := range valid {
		assert.NoError(t, ValidateKey(k), k)
	}
	invalid := map[string]string{
		"empty":        "",
		"slash":        "db/password",
		"space":        "db password",
		"leading dot":  ".hidden",
		"leading dash": "-dash",
		"too long":     strings.Repeat("k", 256),
		"newline":      "TOKEN\n",
	}
	for name, k := range invalid {
		assert.Error(t, ValidateKey(k), name)
	}
}

func TestNormalizePath(t *testing.T) {
	cases := map[string]string{
		"":               "/",
		"/":              "/",
		"db":             "/db",
		"/db":            "/db",
		"/db/":           "/db",
		"//db//primary/": "/db/primary",
		"/db/primary":    "/db/primary",
		"  /db  ":        "/db",
		"/db/./primary":  "/db/primary",
	}
	for in, want := range cases {
		got, err := NormalizePath(in)
		require.NoError(t, err, in)
		assert.Equal(t, want, got, in)
	}

	// '..' is rejected outright rather than resolved. A path that escapes the root
	// ("/../x") would clean to "/x" and silently mean something the caller did not
	// ask for.
	for _, bad := range []string{"/..", "/db/../etc", "..", "/db/../../root"} {
		_, err := NormalizePath(bad)
		require.Error(t, err, bad)
		assert.Contains(t, err.Error(), "..")
	}
	for _, bad := range []string{"/db/pri mary", "/db/-bad", "/" + strings.Repeat("a", 300)} {
		_, err := NormalizePath(bad)
		require.Error(t, err, bad)
	}
	// Depth limit.
	_, err := NormalizePath("/" + strings.Repeat("a/", 40) + "z")
	require.Error(t, err)
}

func TestSplitAndJoinPath(t *testing.T) {
	parent, name := SplitPath("/db/primary")
	assert.Equal(t, "/db", parent)
	assert.Equal(t, "primary", name)

	parent, name = SplitPath("/db")
	assert.Equal(t, "/", parent)
	assert.Equal(t, "db", name)

	parent, name = SplitPath("/")
	assert.Equal(t, "", parent)
	assert.Equal(t, "", name)

	assert.Equal(t, "/db", JoinPath("/", "db"))
	assert.Equal(t, "/db", JoinPath("", "db"))
	assert.Equal(t, "/db/primary", JoinPath("/db", "primary"))
}

func TestSubtreePatternEscapesLikeWildcards(t *testing.T) {
	// The root case: '/' + '/%' would be '//%', which matches none of its children.
	assert.Equal(t, "/%", SubtreePattern("/"))
	assert.Equal(t, "/db/%", SubtreePattern("/db"))
	// '_' and '%' are LIKE metacharacters and '_' is legal in a folder name, so both
	// must be escaped or a prefix listing silently reaches into sibling folders.
	assert.Equal(t, `/my\_folder/%`, SubtreePattern("/my_folder"))
	assert.Equal(t, `/a\%b/%`, SubtreePattern("/a%b"))
	assert.Equal(t, `/a\\b/%`, SubtreePattern(`/a\b`))
}

func TestIsAtOrUnder(t *testing.T) {
	assert.True(t, IsAtOrUnder("/db", "/db"))
	assert.True(t, IsAtOrUnder("/db/primary", "/db"))
	assert.True(t, IsAtOrUnder("/anything", "/"))
	assert.False(t, IsAtOrUnder("/database", "/db"))
	assert.False(t, IsAtOrUnder("/cache", "/db"))
}

// ---------------------------------------------------------------------------
// Tenants, projects, environments
// ---------------------------------------------------------------------------

func TestCreateEnvironmentAlsoCreatesTheRootFolder(t *testing.T) {
	// An environment without a root folder accepts no writes while appearing to
	// exist, so both must land in one transaction.
	fx := newFixture(t)
	folders, err := fx.svc.ListFolders(context.Background(), fx.tenant.UUID, "billing-app", "prod", "/")
	require.NoError(t, err)
	require.Len(t, folders, 1)
	assert.Equal(t, "/", folders[0].Path)

	// And a write at the root works immediately.
	fx.put("/", "TOKEN", "v")
}

func TestDuplicateSlugsAreConflicts(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()

	_, err := fx.svc.CreateTenant(ctx, CreateTenantInput{Name: "acme"})
	assert.True(t, apperror.IsConflict(err))

	_, err = fx.svc.CreateProject(ctx, CreateProjectInput{TenantUUID: fx.tenant.UUID, Slug: "billing-app"})
	assert.True(t, apperror.IsConflict(err))

	_, err = fx.svc.CreateEnvironment(ctx, CreateEnvironmentInput{
		TenantUUID: fx.tenant.UUID, Project: "billing-app", Slug: "prod",
	})
	assert.True(t, apperror.IsConflict(err))
}

func TestInvalidSlugsAreRejectedBeforeTheDatabase(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()

	_, err := fx.svc.CreateTenant(ctx, CreateTenantInput{Name: "Not A Slug"})
	assert.True(t, apperror.IsValidation(err))

	_, err = fx.svc.CreateProject(ctx, CreateProjectInput{TenantUUID: fx.tenant.UUID, Slug: "Bad_Slug"})
	assert.True(t, apperror.IsValidation(err))

	_, err = fx.svc.CreateEnvironment(ctx, CreateEnvironmentInput{
		TenantUUID: fx.tenant.UUID, Project: "billing-app", Slug: "PROD",
	})
	assert.True(t, apperror.IsValidation(err))
}

func TestCreateProjectRequiresAnExistingTenant(t *testing.T) {
	fx := newFixture(t)
	_, err := fx.svc.CreateProject(context.Background(), CreateProjectInput{
		TenantUUID: uuid.New(), Slug: "orphan",
	})
	require.Error(t, err)
	assert.True(t, apperror.IsNotFound(err))
}

func TestListEnvironmentsIsInDisplayOrder(t *testing.T) {
	// Environments are inherently ordered (dev before prod) and alphabetical order
	// gets that wrong every time, which is why position is stored.
	fx := newFixture(t)
	ctx := context.Background()
	for slug, pos := range map[string]int32{"dev": 0, "staging": 1} {
		_, err := fx.svc.CreateEnvironment(ctx, CreateEnvironmentInput{
			TenantUUID: fx.tenant.UUID, Project: "billing-app", Slug: slug, Position: pos,
		})
		require.NoError(t, err)
	}
	// "prod" was created by the fixture with position 0; give the others explicit
	// ordering and check the sort is by position first.
	envs, err := fx.svc.ListEnvironments(ctx, fx.tenant.UUID, "billing-app")
	require.NoError(t, err)
	require.Len(t, envs, 3)
	assert.LessOrEqual(t, envs[0].Position, envs[1].Position)
	assert.LessOrEqual(t, envs[1].Position, envs[2].Position)
}

// ---------------------------------------------------------------------------
// Folders
// ---------------------------------------------------------------------------

func TestCreateFolderIsIdempotentAndCreatesAncestors(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()

	leaf, err := fx.svc.CreateFolder(ctx, fx.tenant.UUID, "billing-app", "prod", "/a/b/c")
	require.NoError(t, err)
	assert.Equal(t, "/a/b/c", leaf.Path)
	assert.Equal(t, "c", leaf.Name)

	// mkdir -p: every ancestor exists, with correct parent links.
	folders, err := fx.svc.ListFolders(ctx, fx.tenant.UUID, "billing-app", "prod", "/")
	require.NoError(t, err)
	paths := []string{}
	for _, f := range folders {
		paths = append(paths, f.Path)
	}
	assert.ElementsMatch(t, []string{"/", "/a", "/a/b", "/a/b/c"}, paths)

	// Repeating the call is a no-op returning the same folder.
	again, err := fx.svc.CreateFolder(ctx, fx.tenant.UUID, "billing-app", "prod", "/a/b/c")
	require.NoError(t, err)
	assert.Equal(t, leaf.UUID, again.UUID)
}

func TestMoveFolderRewritesSubtreePathsAndMRNs(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()

	fx.put("/db", "DB_KEY", "a")
	fx.put("/db/primary", "PRIMARY_KEY", "b")
	fx.put("/db/primary/deep", "DEEP_KEY", "c")
	fx.put("/other", "OTHER_KEY", "d")

	moved, err := fx.svc.MoveFolder(ctx, fx.tenant.UUID, "billing-app", "prod", "/db", "/data")
	require.NoError(t, err)
	assert.Equal(t, "/data", moved.Path)
	assert.Equal(t, "data", moved.Name)

	// Every descendant path was rewritten by prefix substitution.
	folders, err := fx.svc.ListFolders(ctx, fx.tenant.UUID, "billing-app", "prod", "/")
	require.NoError(t, err)
	paths := []string{}
	for _, f := range folders {
		paths = append(paths, f.Path)
	}
	assert.ElementsMatch(t, []string{"/", "/data", "/data/primary", "/data/primary/deep", "/other"}, paths)

	// The MRN resource paths derived from those folders were refreshed. A stale MRN
	// is an authorization bug, not a display bug.
	mrns := map[string]string{}
	for _, s := range fx.repo.secrets {
		mrns[s.Key] = s.MrnResourcePath
	}
	assert.Equal(t, "secret/prod/data/DB_KEY", mrns["DB_KEY"])
	assert.Equal(t, "secret/prod/data/primary/PRIMARY_KEY", mrns["PRIMARY_KEY"])
	assert.Equal(t, "secret/prod/data/primary/deep/DEEP_KEY", mrns["DEEP_KEY"])
	// An untouched subtree keeps its MRN.
	assert.Equal(t, "secret/prod/other/OTHER_KEY", mrns["OTHER_KEY"])

	// The secrets are still readable at their NEW addresses, and no longer at the
	// old ones. The AAD binds the folder path, so this also proves the identity used
	// on read is derived from the current path.
	got, err := fx.svc.GetSecret(ctx, fx.ref("/data/primary", "PRIMARY_KEY"))
	require.NoError(t, err)
	got.Zero()
	_, err = fx.svc.GetSecret(ctx, fx.ref("/db/primary", "PRIMARY_KEY"))
	assert.True(t, apperror.IsNotFound(err))
}

func TestMoveFolderRefusesInvalidMoves(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()
	_, err := fx.svc.CreateFolder(ctx, fx.tenant.UUID, "billing-app", "prod", "/db/primary")
	require.NoError(t, err)
	_, err = fx.svc.CreateFolder(ctx, fx.tenant.UUID, "billing-app", "prod", "/cache")
	require.NoError(t, err)

	cases := map[string]struct{ from, to string }{
		"root cannot move":      {"/", "/elsewhere"},
		"onto the root":         {"/db", "/"},
		"same path":             {"/db", "/db"},
		"into its own subtree":  {"/db", "/db/primary/deeper"},
		"onto itself nested":    {"/db", "/db/child"},
		"destination exists":    {"/db", "/cache"},
		"source does not exist": {"/nope", "/elsewhere"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := fx.svc.MoveFolder(ctx, fx.tenant.UUID, "billing-app", "prod", tc.from, tc.to)
			require.Error(t, err)
		})
	}
}

func TestMoveFolderIntoANewParentCreatesIt(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()
	fx.put("/db", "KEY", "v")

	moved, err := fx.svc.MoveFolder(ctx, fx.tenant.UUID, "billing-app", "prod", "/db", "/infra/storage/db")
	require.NoError(t, err)
	assert.Equal(t, "/infra/storage/db", moved.Path)

	folders, err := fx.svc.ListFolders(ctx, fx.tenant.UUID, "billing-app", "prod", "/infra")
	require.NoError(t, err)
	paths := []string{}
	for _, f := range folders {
		paths = append(paths, f.Path)
	}
	assert.ElementsMatch(t, []string{"/infra", "/infra/storage", "/infra/storage/db"}, paths)
}

func TestDeleteFolderCascadesToSecretsWithARecoveryWindow(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()
	fx.put("/db", "DB_KEY", "a")
	fx.put("/db/primary", "PRIMARY_KEY", "b")
	fx.put("/keep", "KEEP_KEY", "c")

	deleted, err := fx.svc.DeleteFolder(ctx, fx.tenant.UUID, "billing-app", "prod", "/db", nil)
	require.NoError(t, err)
	assert.EqualValues(t, 2, deleted, "both secrets in the subtree are deleted")

	// The folder subtree is gone from listings.
	folders, err := fx.svc.ListFolders(ctx, fx.tenant.UUID, "billing-app", "prod", "/")
	require.NoError(t, err)
	paths := []string{}
	for _, f := range folders {
		paths = append(paths, f.Path)
	}
	assert.ElementsMatch(t, []string{"/", "/keep"}, paths)

	// Each deleted secret got its own recovery window — a mistaken folder delete is
	// as recoverable as a mistaken secret delete.
	pending, err := fx.svc.ListDeletedSecrets(ctx, fx.tenant.UUID, "billing-app", "prod", 1, 50)
	require.NoError(t, err)
	require.Len(t, pending, 2)
	for _, p := range pending {
		require.NotNil(t, p.DestroyAfter)
		assert.Equal(t, fx.clock.Add(30*24*time.Hour), *p.DestroyAfter)
	}
	// Nothing was destroyed.
	assert.Len(t, fx.repo.versions, 3)

	// The sibling subtree is untouched.
	kept, err := fx.svc.GetSecret(ctx, fx.ref("/keep", "KEEP_KEY"))
	require.NoError(t, err)
	kept.Zero()
}

func TestDeleteFolderRefusesTheRoot(t *testing.T) {
	fx := newFixture(t)
	_, err := fx.svc.DeleteFolder(context.Background(), fx.tenant.UUID, "billing-app", "prod", "/", nil)
	require.Error(t, err)
	assert.True(t, apperror.IsForbidden(err))
}

func TestFolderOperationsAreTenantScoped(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()
	other, err := fx.svc.CreateTenant(ctx, CreateTenantInput{Name: "globex"})
	require.NoError(t, err)

	_, err = fx.svc.CreateFolder(ctx, fx.tenant.UUID, "billing-app", "prod", "/db")
	require.NoError(t, err)

	// The other tenant has no such project, so nothing about this folder is
	// reachable — not the listing, not the move, not the delete.
	_, err = fx.svc.ListFolders(ctx, other.UUID, "billing-app", "prod", "/db")
	assert.True(t, apperror.IsNotFound(err))
	_, err = fx.svc.MoveFolder(ctx, other.UUID, "billing-app", "prod", "/db", "/data")
	assert.True(t, apperror.IsNotFound(err))
	_, err = fx.svc.DeleteFolder(ctx, other.UUID, "billing-app", "prod", "/db", nil)
	assert.True(t, apperror.IsNotFound(err))
}

// ---------------------------------------------------------------------------
// Flat-key compatibility shim
// ---------------------------------------------------------------------------

func TestFlatRefMapsOntoTheHierarchy(t *testing.T) {
	repo := newFakeRepo()
	svc, err := NewService(repo, mustKeyRing(t, 0x03), Policy{
		KeepVersions: 3, DefaultTenant: "default", DefaultProject: "default", DefaultEnvironment: "default",
	})
	require.NoError(t, err)
	ctx := context.Background()
	_, err = svc.EnsureActiveRootKey(ctx)
	require.NoError(t, err)
	_, err = svc.EnsureDefaultScope(ctx)
	require.NoError(t, err)

	cases := map[string]struct{ folder, key string }{
		"TOKEN":             {"/", "TOKEN"},
		"db/password":       {"/db", "password"},
		"db/primary/passwd": {"/db/primary", "passwd"},
		"/leading":          {"/", "leading"},
	}
	for flat, want := range cases {
		t.Run(flat, func(t *testing.T) {
			ref, err := svc.FlatRef(ctx, flat)
			require.NoError(t, err)
			assert.Equal(t, want.folder, ref.FolderPath)
			assert.Equal(t, want.key, ref.Key)
			assert.Equal(t, "default", ref.Project)
			assert.Equal(t, "default", ref.Environment)
		})
	}

	_, err = svc.FlatRef(ctx, "")
	assert.True(t, apperror.IsValidation(err))
	_, err = svc.FlatRef(ctx, "db/")
	assert.True(t, apperror.IsValidation(err))
}

func TestEnsureDefaultScopeIsIdempotent(t *testing.T) {
	repo := newFakeRepo()
	svc, err := NewService(repo, mustKeyRing(t, 0x04), Policy{
		KeepVersions: 3, DefaultTenant: "default", DefaultProject: "default", DefaultEnvironment: "default",
	})
	require.NoError(t, err)
	ctx := context.Background()
	_, err = svc.EnsureActiveRootKey(ctx)
	require.NoError(t, err)

	for i := 0; i < 3; i++ {
		_, err := svc.EnsureDefaultScope(ctx)
		require.NoError(t, err, "boot must be repeatable")
	}
	assert.Len(t, repo.tenants, 1)
	assert.Len(t, repo.projects, 1)
	assert.Len(t, repo.environments, 1)
	assert.Len(t, repo.folders, 1, "exactly one root folder")

	// And the flat surface works end to end over it.
	ref, err := svc.FlatRef(ctx, "db/password")
	require.NoError(t, err)
	_, err = svc.PutSecret(ctx, PutSecretInput{Ref: ref, Value: []byte("v"), CreateFolders: true})
	require.NoError(t, err)
	got, err := svc.GetSecret(ctx, ref)
	require.NoError(t, err)
	assert.Equal(t, "v", string(got.Value.Bytes()))
	got.Zero()
}

func TestFlatKeyRoundTrip(t *testing.T) {
	assert.Equal(t, "TOKEN", FlatKey(SecretMeta{FolderPath: "/", Key: "TOKEN"}))
	assert.Equal(t, "db/primary/passwd", FlatKey(SecretMeta{FolderPath: "/db/primary", Key: "passwd"}))
}
