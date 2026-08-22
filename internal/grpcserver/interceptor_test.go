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

	secretv1 "github.com/maintainerd/secret/gen/maintainerd/secret/v1"
	"github.com/maintainerd/secret/internal/platform/authz"
)

// TestEveryRegisteredRPCHasAPermissionMapping is the anti-drift test that makes the
// allowlist meaningful.
//
// The allowlist only fails closed if it is COMPLETE: a method missing from the map is
// denied to every caller, which ships as a 403 nobody can explain. Enumerating the
// generated service descriptor means adding an RPC to the proto without deciding its
// permission fails HERE, in CI, rather than in production.
func TestEveryRegisteredRPCHasAPermissionMapping(t *testing.T) {
	for _, m := range secretv1.SecretService_ServiceDesc.Methods {
		full := secretService + m.MethodName
		if selfGuardedMethods[full] {
			continue // Ping and the legacy Setup carry their own gate — see the map's doc.
		}
		_, mapped := methodPermissions[full]
		assert.True(t, mapped, "RPC %s has no permission mapping", m.MethodName)
	}
}

// TestNoStaleMappings is the other half: a permission for an RPC that no longer
// exists is dead weight that makes the map harder to audit.
func TestNoStaleMappings(t *testing.T) {
	live := map[string]bool{}
	for _, m := range secretv1.SecretService_ServiceDesc.Methods {
		live[secretService+m.MethodName] = true
	}
	for mapped := range methodPermissions {
		assert.True(t, live[mapped], "%s is mapped but not registered", mapped)
	}
}

// TestRevealAndMetadataRPCsCarryDifferentPermissions is the contract's distinct-grant
// requirement, checked on the gRPC surface.
func TestRevealAndMetadataRPCsCarryDifferentPermissions(t *testing.T) {
	assert.Equal(t, authz.PermGetSecret, methodPermissions[secretService+"GetSecret"])
	assert.Equal(t, authz.PermReadMetadata, methodPermissions[secretService+"DescribeSecret"])
	assert.Equal(t, authz.PermGetSecret, methodPermissions[secretService+"Get"],
		"the legacy flat Get is a reveal and carries the reveal permission")
}

// TestSelfGuardedMethodsAreExactlyTheTwoDocumented. Anything on that list is a method
// no token protects, so the list must not grow by accident.
func TestSelfGuardedMethodsAreExactlyTheTwoDocumented(t *testing.T) {
	assert.Len(t, selfGuardedMethods, 2)
	assert.True(t, selfGuardedMethods[secretService+"Ping"])
	assert.True(t, selfGuardedMethods[secretService+"Setup"])
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

func enforcedGuard(claims *authz.Claims) authz.Guard {
	return authz.Guard{
		Mode: authz.ModeEnforced,
		Verify: func(_ context.Context, token string) (*authz.Claims, error) {
			if token != "good" {
				return nil, errors.New("bad token")
			}
			return claims, nil
		},
	}
}

func TestHealthIsTheOnlyUnauthenticatedSurface(t *testing.T) {
	h, reached := handlerReached()
	interceptor := AuthUnaryInterceptor(enforcedGuard(nil))

	_, err := interceptor(context.Background(), nil, info("/grpc.health.v1.Health/Check"), h)
	require.NoError(t, err)
	assert.True(t, *reached)
}

func TestReflectionIsDevelopmentOnly(t *testing.T) {
	h, _ := handlerReached()

	_, err := AuthUnaryInterceptor(enforcedGuard(nil))(
		context.Background(), nil, info("/grpc.reflection.v1.ServerReflection/ServerReflectionInfo"), h)
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	_, err = AuthUnaryInterceptor(authz.Guard{Mode: authz.ModeDevOpen})(
		context.Background(), nil, info("/grpc.reflection.v1.ServerReflection/ServerReflectionInfo"), h)
	require.NoError(t, err)
}

func TestMissingAndInvalidTokensAreUnauthenticated(t *testing.T) {
	h, reached := handlerReached()
	interceptor := AuthUnaryInterceptor(enforcedGuard(&authz.Claims{}))

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
	interceptor := AuthUnaryInterceptor(enforcedGuard(&authz.Claims{
		Grants: []authz.Grant{{Action: authz.PermAdmin}},
	}))
	_, err := interceptor(ctxWithToken("good"), nil, info(secretService+"BrandNewRPC"), h)
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Contains(t, err.Error(), "no permission mapping")
	assert.False(t, *reached)
}

func TestBaselinePermissionIsEnforced(t *testing.T) {
	metadataOnly := &authz.Claims{Grants: []authz.Grant{{Action: authz.PermReadMetadata}}}
	interceptor := AuthUnaryInterceptor(enforcedGuard(metadataOnly))

	h, reached := handlerReached()
	_, err := interceptor(ctxWithToken("good"), nil, info(secretService+"DescribeSecret"), h)
	require.NoError(t, err)
	assert.True(t, *reached)

	h, reached = handlerReached()
	_, err = interceptor(ctxWithToken("good"), nil, info(secretService+"GetSecret"), h)
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Contains(t, err.Error(), authz.PermGetSecret)
	assert.False(t, *reached)
}

// TestModeUnavailableServesHealthOnly: outside development a missing auth
// configuration disables the API rather than quietly serving it open.
func TestModeUnavailableServesHealthOnly(t *testing.T) {
	guard := authz.Guard{Mode: authz.ModeUnavailable, Reason: "AUTH_ISSUER not set"}
	interceptor := AuthUnaryInterceptor(guard)

	h, _ := handlerReached()
	_, err := interceptor(context.Background(), nil, info(secretService+"ListSecrets"), h)
	require.Error(t, err)
	assert.Equal(t, codes.Unavailable, status.Code(err))
	assert.Contains(t, err.Error(), "AUTH_ISSUER not set")

	h, reached := handlerReached()
	_, err = interceptor(context.Background(), nil, info("/grpc.health.v1.Health/Check"), h)
	require.NoError(t, err)
	assert.True(t, *reached, "health stays reachable so an orchestrator can still probe")
}

// TestSetupServiceIsSelfGuarded: the controlled setup surface must work before Auth
// exists, so the interceptor lets it through and the handler checks the setup token.
func TestSetupServiceIsSelfGuarded(t *testing.T) {
	h, reached := handlerReached()
	interceptor := AuthUnaryInterceptor(enforcedGuard(nil))
	_, err := interceptor(context.Background(), nil,
		info("/maintainerd.secret.v1.SetupService/GetSetupStatus"), h)
	require.NoError(t, err)
	assert.True(t, *reached)
}

func TestDevOpenAttachesBlanketClaims(t *testing.T) {
	var seen *authz.Claims
	h := grpc.UnaryHandler(func(ctx context.Context, _ any) (any, error) {
		c, ok := authz.FromContext(ctx)
		require.True(t, ok)
		seen = c
		return "ok", nil
	})
	_, err := AuthUnaryInterceptor(authz.Guard{Mode: authz.ModeDevOpen})(
		context.Background(), nil, info(secretService+"GetSecret"), h)
	require.NoError(t, err)
	require.NotNil(t, seen)
	assert.Equal(t, "development-open", seen.Subject)
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
