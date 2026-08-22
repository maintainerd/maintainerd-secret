package grpcserver

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/maintainerd/secret/internal/platform/authz"
	mw "github.com/maintainerd/secret/internal/platform/middleware"
)

// ---------------------------------------------------------------------------
// Recovery
// ---------------------------------------------------------------------------

// TestRecoveryInterceptorContainsAPanic. grpc-go recovers NOTHING by default: an
// unrecovered panic in a handler goroutine crashes the server, so a malformed request
// that trips a nil dereference in one code path would be a whole-vault outage.
func TestRecoveryInterceptorContainsAPanic(t *testing.T) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	interceptor := RecoveryUnaryInterceptor()
	panicking := func(context.Context, any) (any, error) {
		panic("nil map write while handling hunter2-the-password")
	}

	var (
		resp any
		err  error
	)
	require.NotPanics(t, func() {
		resp, err = interceptor(context.Background(), nil, info(secretService+"GetSecret"), panicking)
	})

	assert.Nil(t, resp)
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
	assert.Equal(t, "internal error", status.Convert(err).Message(),
		"the detail in a panic describes the store protecting the credentials")
	assert.NotContains(t, err.Error(), "hunter2")
	assert.NotContains(t, err.Error(), "nil map write")
}

func TestRecoveryInterceptorPassesThroughANormalCall(t *testing.T) {
	interceptor := RecoveryUnaryInterceptor()
	out, err := interceptor(context.Background(), nil, info(secretService+"Ping"),
		func(context.Context, any) (any, error) { return "pong", nil })
	require.NoError(t, err)
	assert.Equal(t, "pong", out)
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

func callN(t *testing.T, interceptor grpc.UnaryServerInterceptor, ctx context.Context, method string, n int) []error {
	t.Helper()
	errs := make([]error, 0, n)
	for i := 0; i < n; i++ {
		_, err := interceptor(ctx, nil, info(method),
			func(context.Context, any) (any, error) { return struct{}{}, nil })
		errs = append(errs, err)
	}
	return errs
}

func principalCtx(subject string) context.Context {
	return authz.NewContext(context.Background(), &authz.Claims{Subject: subject})
}

func TestGRPCRateLimitMetersTheRevealSurface(t *testing.T) {
	limiter := mw.NewLimiter(time.Minute)
	interceptor := RateLimitUnaryInterceptor(limiter, RateLimitOptions{Reveal: 2, Write: 10, Setup: 5})

	errs := callN(t, interceptor, principalCtx("svc-a"), secretService+"GetSecret", 3)
	assert.NoError(t, errs[0])
	assert.NoError(t, errs[1])
	require.Error(t, errs[2])
	assert.Equal(t, codes.ResourceExhausted, status.Code(errs[2]))
}

func TestGRPCRateLimitClassesAreSeparate(t *testing.T) {
	limiter := mw.NewLimiter(time.Minute)
	interceptor := RateLimitUnaryInterceptor(limiter, RateLimitOptions{Reveal: 1, Write: 1, Setup: 1})
	ctx := principalCtx("svc-a")

	require.NoError(t, callN(t, interceptor, ctx, secretService+"GetSecret", 1)[0])
	require.Error(t, callN(t, interceptor, ctx, secretService+"GetSecret", 1)[0])

	assert.NoError(t, callN(t, interceptor, ctx, secretService+"PutSecret", 1)[0],
		"the write budget is a separate counter from the reveal one")
}

// TestGRPCRateLimitSharesTheRESTBudget is the point of passing one Limiter to both
// transports: a per-transport budget is not a budget, because a client that exhausted
// its reveal allowance over REST would open a gRPC channel and spend another one.
func TestGRPCRateLimitSharesTheRESTBudget(t *testing.T) {
	limiter := mw.NewLimiter(time.Minute)
	interceptor := RateLimitUnaryInterceptor(limiter, RateLimitOptions{Reveal: 2})

	// Spend the whole budget the way the REST middleware would: same class, same key.
	allowed, _ := limiter.Allow("reveal|sub:svc-a", 2)
	require.True(t, allowed)
	allowed, _ = limiter.Allow("reveal|sub:svc-a", 2)
	require.True(t, allowed)

	err := callN(t, interceptor, principalCtx("svc-a"), secretService+"GetSecret", 1)[0]
	require.Error(t, err, "gRPC must not hand out a second budget for the same principal")
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))
}

// TestGRPCRateLimitNeverMetersHealth: an orchestrator's probe loop must not consume a
// budget, and must not be starvable by an attacker sharing its key.
func TestGRPCRateLimitNeverMetersHealth(t *testing.T) {
	limiter := mw.NewLimiter(time.Minute)
	interceptor := RateLimitUnaryInterceptor(limiter, RateLimitOptions{Reveal: 1, Write: 1, Setup: 1})

	for _, err := range callN(t, interceptor, context.Background(), healthServicePrefix+"Check", 20) {
		require.NoError(t, err)
	}
}

// TestGRPCRateLimitKeysSetupByAddress: the setup surface runs before a principal
// exists, and it compares a bootstrap token, so it is metered per peer address.
func TestGRPCRateLimitKeysSetupByAddress(t *testing.T) {
	limiter := mw.NewLimiter(time.Minute)
	interceptor := RateLimitUnaryInterceptor(limiter, RateLimitOptions{Setup: 2})

	errs := callN(t, interceptor, context.Background(), setupServicePrefix+"Setup", 3)
	assert.NoError(t, errs[0])
	assert.NoError(t, errs[1])
	require.Error(t, errs[2])
	assert.Equal(t, codes.ResourceExhausted, status.Code(errs[2]))

	t.Run("the legacy flat Setup RPC shares that budget", func(t *testing.T) {
		err := callN(t, interceptor, context.Background(), secretService+"Setup", 1)[0]
		require.Error(t, err, "both first-run surfaces gate on the same token")
	})
}

func TestGRPCRateLimitIsAPassThroughWhenDisabled(t *testing.T) {
	interceptor := RateLimitUnaryInterceptor(nil, RateLimitOptions{Reveal: 1})
	for _, err := range callN(t, interceptor, principalCtx("svc-a"), secretService+"GetSecret", 10) {
		require.NoError(t, err)
	}
}

// TestEveryRevealRPCIsMetered is the drift guard: a new RPC that returns a plaintext
// and is not in revealMethods would silently get the larger write budget, or none.
func TestEveryRevealRPCIsMetered(t *testing.T) {
	for _, method := range []string{
		secretService + "GetSecret",
		secretService + "BatchGetSecrets",
		secretService + "Get",
	} {
		class, limit, _ := classify(context.Background(), method, RateLimitOptions{Reveal: 5, Write: 5})
		assert.Equal(t, "reveal", class, method)
		assert.Equal(t, 5, limit, method)
	}
}

// TestEveryMutatingRPCIsMetered walks the interceptor's own permission map and requires
// that every method carrying a write-shaped permission also carries a write budget.
// Deriving the expectation from methodPermissions rather than a second hand-written
// list is what keeps this honest when an RPC is added.
func TestEveryMutatingRPCIsMetered(t *testing.T) {
	mutatingPermissions := map[string]bool{
		authz.PermPutSecret:         true,
		authz.PermDeleteSecret:      true,
		authz.PermRotateSecret:      true,
		authz.PermManageProject:     true,
		authz.PermManageEnvironment: true,
		authz.PermManageFolder:      true,
	}
	// The read RPCs that legitimately carry a management permission because their
	// SEGMENT does, not because they mutate anything.
	readsUnderAManagementPermission := map[string]bool{
		secretService + "ListImports":           true,
		secretService + "ListSecrets":           true,
		secretService + "ListDeletedSecrets":    true,
		secretService + "ListWebhookEndpoints":  true,
		secretService + "ListWebhookDeliveries": true,
		secretService + "List":                  true,
	}

	for method, permission := range methodPermissions {
		if !mutatingPermissions[permission] || readsUnderAManagementPermission[method] {
			continue
		}
		if revealMethods[method] {
			continue // metered, under the stricter budget
		}
		assert.True(t, writeMethods[method],
			"%s mutates (requires %s) but carries no write budget", method, permission)
	}
}
