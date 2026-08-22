package grpcserver

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	sdkauthz "github.com/maintainerd/sdk/authz"
	secretv1 "github.com/maintainerd/secret/gen/maintainerd/secret/v1"
	"github.com/maintainerd/secret/internal/platform/permissions"
)

// These tests pin the gRPC surface's BEHAVIOUR, not its implementation. The
// decision path now lives in github.com/maintainerd/sdk/authz; what remains this
// service's responsibility — and what these assert — is that the permissions.Map
// driving it describes this service's RPCs correctly and completely.

// ---------------------------------------------------------------------------
// The allowlist is complete
// ---------------------------------------------------------------------------

// TestEveryRegisteredRPCHasAPermissionMapping is the anti-drift test that makes the
// allowlist meaningful.
//
// The allowlist only fails closed if it is COMPLETE: a method missing from the map is
// denied to every caller, which ships as a 403 nobody can explain. Enumerating the
// generated service descriptor means adding an RPC to the proto without deciding its
// permission fails HERE, in CI, rather than in production.
//
// The exhaustive version — every REST route AND every RPC on every registered
// service, against the Map and the exemption set — is in permissions_audit_test.go.
// This one stays because it is the fastest signal for the surface an RPC author is
// actually editing.
func TestEveryRegisteredRPCHasAPermissionMapping(t *testing.T) {
	m := permissions.Map()
	for _, method := range secretv1.SecretService_ServiceDesc.Methods {
		full := secretService + method.MethodName
		if m.IsExempt(sdkauthz.Surface{FullMethod: full}) {
			continue // Ping and the legacy Setup carry their own gate — see permissions.Map.
		}
		_, mapped := m.Methods[full]
		assert.True(t, mapped, "RPC %s has no permission mapping", method.MethodName)
	}
}

// TestNoStaleMappings is the other half: a permission for an RPC that no longer
// exists is dead weight that makes the map harder to audit.
func TestNoStaleMappings(t *testing.T) {
	live := map[string]bool{}
	for _, method := range secretv1.SecretService_ServiceDesc.Methods {
		live[secretService+method.MethodName] = true
	}
	for mapped := range permissions.Map().Methods {
		assert.True(t, live[mapped], "%s is mapped but not registered", mapped)
	}
}

// TestRevealAndMetadataRPCsCarryDifferentPermissions is the contract's distinct-grant
// requirement, checked on the gRPC surface.
func TestRevealAndMetadataRPCsCarryDifferentPermissions(t *testing.T) {
	m := permissions.Map().Methods
	assert.Equal(t, permissions.PermGetSecret, m[secretService+"GetSecret"])
	assert.Equal(t, permissions.PermReadMetadata, m[secretService+"DescribeSecret"])
	assert.Equal(t, permissions.PermGetSecret, m[secretService+"Get"],
		"the legacy flat Get is a reveal and carries the reveal permission")
}

// TestSelfGuardedRPCsAreExactlyTheDocumentedSet. Every entry is a method no token
// protects, so the list must not grow by accident. It is matched EXACTLY rather than
// by service prefix, which is what makes a NEW SetupService RPC fail closed instead
// of silently inheriting the exemption its neighbours have.
func TestSelfGuardedRPCsAreExactlyTheDocumentedSet(t *testing.T) {
	assert.ElementsMatch(t, []string{
		healthServicePrefix + "Check",
		healthServicePrefix + "Watch",
		secretService + "Ping",
		secretService + "Setup",
		setupServicePrefix + "GetSetupStatus",
		setupServicePrefix + "Setup",
		setupServicePrefix + "CompleteSetup",
	}, permissions.Map().ExemptMethods)
}

func TestMappedMethodsIsSorted(t *testing.T) {
	methods := MappedMethods()
	require.NotEmpty(t, methods)
	for i := 1; i < len(methods); i++ {
		assert.LessOrEqual(t, methods[i-1], methods[i])
	}
}

// ---------------------------------------------------------------------------
// Interceptor behaviour
// ---------------------------------------------------------------------------

func handlerReached() (grpc.UnaryHandler, *bool) {
	reached := false
	return func(ctx context.Context, _ any) (any, error) {
		reached = true
		return "ok", nil
	}, &reached
}

func info(method string) *grpc.UnaryServerInfo {
	return &grpc.UnaryServerInfo{FullMethod: method}
}

func ctxWithToken(token string) context.Context {
	return metadata.NewIncomingContext(context.Background(),
		metadata.Pairs("authorization", "Bearer "+token))
}

// guardWith builds the guard the bootstrap builds, with a stub verifier.
func guardWith(mode sdkauthz.Mode, claims *sdkauthz.Claims) sdkauthz.Guard {
	return sdkauthz.Guard{
		Mode:        mode,
		Permissions: permissions.Map(),
		Service:     permissions.ServiceName,
		Verify: func(_ context.Context, token string) (*sdkauthz.Claims, error) {
			if token != "good" {
				return nil, errors.New("bad token")
			}
			return claims, nil
		},
	}
}

func enforcedGuard(claims *sdkauthz.Claims) sdkauthz.Guard {
	return guardWith(sdkauthz.ModeEnforced, claims)
}

func TestHealthIsTheOnlyUnauthenticatedSurface(t *testing.T) {
	h, reached := handlerReached()
	interceptor := AuthUnaryInterceptor(enforcedGuard(nil))

	_, err := interceptor(context.Background(), nil, info(healthServicePrefix+"Check"), h)
	require.NoError(t, err)
	assert.True(t, *reached)
}

// TestReflectionIsDevelopmentOnly. Reflection is neither mapped nor exempt, so under
// enforcement the allowlist denies it, and under ModeDevOpen the guard admits every
// caller before it consults the map. Same posture as the hand-rolled interceptor had,
// reached through the shared ladder instead of a special case.
func TestReflectionIsDevelopmentOnly(t *testing.T) {
	h, _ := handlerReached()
	const reflectionMethod = "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo"

	_, err := AuthUnaryInterceptor(enforcedGuard(&sdkauthz.Claims{
		Grants: []sdkauthz.Grant{{Action: permissions.PermAdmin}},
	}))(ctxWithToken("good"), nil, info(reflectionMethod), h)
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	_, err = AuthUnaryInterceptor(guardWith(sdkauthz.ModeDevOpen, nil))(
		context.Background(), nil, info(reflectionMethod), h)
	require.NoError(t, err)

	assert.True(t, strings.HasPrefix(reflectionMethod, reflectionServicePrefix))
}

func TestMissingAndInvalidTokensAreUnauthenticated(t *testing.T) {
	h, reached := handlerReached()
	interceptor := AuthUnaryInterceptor(enforcedGuard(&sdkauthz.Claims{}))

	_, err := interceptor(context.Background(), nil, info(secretService+"GetSecret"), h)
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	assert.False(t, *reached)

	_, err = interceptor(ctxWithToken("forged"), nil, info(secretService+"GetSecret"), h)
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	assert.NotContains(t, err.Error(), "bad token",
		"the verify error is never echoed — it is oracle material")
}

func TestUnmappedMethodIsDenied(t *testing.T) {
	h, reached := handlerReached()
	interceptor := AuthUnaryInterceptor(enforcedGuard(&sdkauthz.Claims{
		Grants: []sdkauthz.Grant{{Action: permissions.PermAdmin}},
	}))
	_, err := interceptor(ctxWithToken("good"), nil, info(secretService+"BrandNewRPC"), h)
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Contains(t, err.Error(), "no permission mapping")
	assert.False(t, *reached)
}

func TestBaselinePermissionIsEnforced(t *testing.T) {
	metadataOnly := &sdkauthz.Claims{Grants: []sdkauthz.Grant{{Action: permissions.PermReadMetadata}}}
	interceptor := AuthUnaryInterceptor(enforcedGuard(metadataOnly))

	h, reached := handlerReached()
	_, err := interceptor(ctxWithToken("good"), nil, info(secretService+"DescribeSecret"), h)
	require.NoError(t, err)
	assert.True(t, *reached)

	h, reached = handlerReached()
	_, err = interceptor(ctxWithToken("good"), nil, info(secretService+"GetSecret"), h)
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Contains(t, err.Error(), permissions.PermGetSecret)
	assert.False(t, *reached)
}

// TestAdminIsBlanketOnTheWire. secret:Admin is this service's vocabulary, not the
// SDK's, so it only covers other actions because the guard copies Map.BlanketActions
// onto every principal it verifies. If that wiring is ever dropped, an
// administrator's token silently stops authorizing anything.
func TestAdminIsBlanketOnTheWire(t *testing.T) {
	adminOnly := &sdkauthz.Claims{Grants: []sdkauthz.Grant{{Action: permissions.PermAdmin}}}
	h, reached := handlerReached()

	_, err := AuthUnaryInterceptor(enforcedGuard(adminOnly))(
		ctxWithToken("good"), nil, info(secretService+"GetSecret"), h)
	require.NoError(t, err)
	assert.True(t, *reached)
}

// TestModeUnavailableServesHealthOnly: outside development a missing auth
// configuration disables the API rather than quietly serving it open.
func TestModeUnavailableServesHealthOnly(t *testing.T) {
	guard := sdkauthz.Guard{
		Mode:        sdkauthz.ModeUnavailable,
		Reason:      "AUTH_ISSUER not set",
		Permissions: permissions.Map(),
	}
	interceptor := AuthUnaryInterceptor(guard)

	h, _ := handlerReached()
	_, err := interceptor(context.Background(), nil, info(secretService+"ListSecrets"), h)
	require.Error(t, err)
	assert.Equal(t, codes.Unavailable, status.Code(err))
	assert.Contains(t, err.Error(), "AUTH_ISSUER not set")

	h, reached := handlerReached()
	_, err = interceptor(context.Background(), nil, info(healthServicePrefix+"Check"), h)
	require.NoError(t, err)
	assert.True(t, *reached, "health stays reachable so an orchestrator can still probe")
}

// TestSetupServiceIsSelfGuarded: the controlled setup surface must work before Auth
// exists, so the guard lets it through and the handler checks the setup token.
func TestSetupServiceIsSelfGuarded(t *testing.T) {
	for _, method := range []string{"GetSetupStatus", "Setup", "CompleteSetup"} {
		h, reached := handlerReached()
		interceptor := AuthUnaryInterceptor(enforcedGuard(nil))
		_, err := interceptor(context.Background(), nil, info(setupServicePrefix+method), h)
		require.NoError(t, err, method)
		assert.True(t, *reached, method)
	}
}

// TestANewSetupServiceRPCWouldFailClosed. The exemption is an exact method list, not
// the service prefix, so a fourth SetupService RPC is denied until somebody decides
// what gates it. The previous implementation exempted the whole prefix.
func TestANewSetupServiceRPCWouldFailClosed(t *testing.T) {
	h, reached := handlerReached()
	_, err := AuthUnaryInterceptor(enforcedGuard(&sdkauthz.Claims{
		Grants: []sdkauthz.Grant{{Action: permissions.PermAdmin}},
	}))(ctxWithToken("good"), nil, info(setupServicePrefix+"ResetEverything"), h)
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.False(t, *reached)
}

func TestDevOpenAttachesBlanketClaims(t *testing.T) {
	var seen *sdkauthz.Claims
	h := grpc.UnaryHandler(func(ctx context.Context, _ any) (any, error) {
		c, ok := sdkauthz.FromContext(ctx)
		require.True(t, ok)
		seen = c
		return "ok", nil
	})
	_, err := AuthUnaryInterceptor(guardWith(sdkauthz.ModeDevOpen, nil))(
		context.Background(), nil, info(secretService+"GetSecret"), h)
	require.NoError(t, err)
	require.NotNil(t, seen)
	assert.Equal(t, "development-open", seen.Subject)
}

// ---------------------------------------------------------------------------
// Streaming
// ---------------------------------------------------------------------------

// fakeStream is the minimum grpc.ServerStream a StreamServerInterceptor touches.
type fakeStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *fakeStream) Context() context.Context { return s.ctx }

// TestStreamingRPCsAreGuardedToo is the regression test for a hole that was invisible
// because nothing exercised it: the server used to install ONLY a
// UnaryServerInterceptor, so any server-streaming or bidi RPC added to
// maintainerd.secret.v1 would have shipped with no token check, no permission check
// and no allowlist at all. grpc-go dispatches the two through separate chains and
// silently applies neither to the other.
func TestStreamingRPCsAreGuardedToo(t *testing.T) {
	reached := false
	handler := func(any, grpc.ServerStream) error { reached = true; return nil }
	stream := &fakeStream{ctx: context.Background()}

	interceptor := AuthStreamInterceptor(enforcedGuard(&sdkauthz.Claims{}))

	err := interceptor(nil, stream, &grpc.StreamServerInfo{
		FullMethod: secretService + "WatchSecrets",
	}, handler)
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	assert.False(t, reached, "an unauthenticated stream must never reach the handler")

	t.Run("the streaming health probe stays exempt", func(t *testing.T) {
		reached = false
		err := interceptor(nil, stream, &grpc.StreamServerInfo{
			FullMethod: healthServicePrefix + "Watch",
		}, handler)
		require.NoError(t, err)
		assert.True(t, reached)
	})
}

func TestMetadataHelpers(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"authorization", "Bearer abc",
		TenantMetadataKey, " acme ",
	))
	assert.Equal(t, "abc", bearerFromMD(ctx))
	assert.Equal(t, "acme", metadataValue(ctx, TenantMetadataKey))
	assert.Equal(t, "", metadataValue(context.Background(), TenantMetadataKey))
	assert.True(t, strings.HasPrefix(secretService, "/maintainerd.secret.v1."))
}

// ---------------------------------------------------------------------------
// Service-to-service vs browser-to-backend, through the real interceptor
// ---------------------------------------------------------------------------

// TestTheActorConstraintIsEnforcedByTheUnaryInterceptor drives the constraint through
// the interceptor this service actually installs, rather than through the Map alone.
//
// gRPC is the transport a stolen m2m credential would reach for: it is what the
// workload was already using, so nothing about the connection looks new. The
// administrative RPCs must refuse it even though its grants are real — a caller
// holding secret:Admin is refused here purely for being the wrong CLASS of caller.
func TestTheActorConstraintIsEnforcedByTheUnaryInterceptor(t *testing.T) {
	principal := func(kind string) *sdkauthz.Principal {
		return &sdkauthz.Principal{
			Subject:        "principal-1",
			Kind:           kind,
			Grants:         []sdkauthz.Grant{{Action: permissions.PermAdmin}},
			BlanketActions: permissions.BlanketActions(),
		}
	}
	guardFor := func(kind string) sdkauthz.Guard {
		return sdkauthz.Guard{
			Mode:        sdkauthz.ModeEnforced,
			Permissions: permissions.Map(),
			Verify: func(context.Context, string) (*sdkauthz.Principal, error) {
				return principal(kind), nil
			},
		}
	}
	call := func(t *testing.T, kind, method string) error {
		t.Helper()
		ctx := metadata.NewIncomingContext(context.Background(),
			metadata.Pairs("authorization", "Bearer good"))
		_, err := AuthUnaryInterceptor(guardFor(kind))(ctx, nil,
			&grpc.UnaryServerInfo{FullMethod: method},
			func(context.Context, any) (any, error) { return "reached", nil })
		return err
	}

	consoleRPCs := []string{
		"CreateProject", "UpdateProject", "DeleteProject",
		"CreateEnvironment", "UpdateEnvironment", "DeleteEnvironment",
		"CreateFolder", "MoveFolder", "DeleteFolder",
		"CreateImport", "UpdateImport", "DeleteImport",
		"SetRotationPolicy",
		"CreateWebhookEndpoint", "UpdateWebhookEndpoint", "DeleteWebhookEndpoint",
		"RestoreSecret", "DestroySecret",
		"ListAuditEvents",
	}
	for _, name := range consoleRPCs {
		t.Run("service is refused on "+name, func(t *testing.T) {
			err := call(t, sdkauthz.ActorKindService, secretService+name)
			require.Error(t, err, "a workload must not drive the administrative console surface")
			assert.Equal(t, codes.PermissionDenied, status.Code(err))
			assert.Contains(t, status.Convert(err).Message(), "user principals only")

			assert.NoError(t, call(t, sdkauthz.ActorKindUser, secretService+name),
				"the same RPC driven by a human must be allowed through")
		})
	}

	// The workload surface — the reason this service exists — stays open to both.
	workloadRPCs := []string{
		"Get", "Put", "List", "Delete",
		"GetSecret", "DescribeSecret", "ListSecrets", "ListSecretVersions", "ListDeletedSecrets",
		"PutSecret", "UpdateSecretMetadata", "RollbackSecret", "RotateSecret", "DeleteSecret",
		"BatchGetSecrets", "BatchPutSecrets",
		"ListProjects", "GetProject", "ListEnvironments", "GetEnvironment",
		"ListFolders", "ListImports", "ListWebhookEndpoints", "ListWebhookDeliveries",
	}
	for _, name := range workloadRPCs {
		t.Run("both classes reach "+name, func(t *testing.T) {
			for _, kind := range []string{sdkauthz.ActorKindService, sdkauthz.ActorKindUser} {
				assert.NoError(t, call(t, kind, secretService+name),
					"%s principals must reach %s", kind, name)
			}
		})
	}
}

// TestAnUnclassifiedPrincipalIsRefusedOnAConsoleRPC. Failing closed on "we could not
// tell what this caller is" is the only safe reading for a surface somebody restricted.
func TestAnUnclassifiedPrincipalIsRefusedOnAConsoleRPC(t *testing.T) {
	guard := sdkauthz.Guard{
		Mode:        sdkauthz.ModeEnforced,
		Permissions: permissions.Map(),
		Verify: func(context.Context, string) (*sdkauthz.Principal, error) {
			return &sdkauthz.Principal{
				Subject:        "unknown-1",
				Grants:         []sdkauthz.Grant{{Action: permissions.PermAdmin}},
				BlanketActions: permissions.BlanketActions(),
			}, nil
		},
	}
	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs("authorization", "Bearer good"))
	_, err := AuthUnaryInterceptor(guard)(ctx, nil,
		&grpc.UnaryServerInfo{FullMethod: secretService + "CreateProject"},
		func(context.Context, any) (any, error) { return nil, errors.New("the handler must not run") })
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}
