package grpcserver

import (
	"context"
	"log/slog"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sdkauthz "github.com/maintainerd/sdk/authz"
	mw "github.com/maintainerd/secret/internal/platform/middleware"
)

// The gRPC twin of the HTTP rate limiter, sharing its Limiter so THE TWO TRANSPORTS
// SPEND ONE BUDGET.
//
// That sharing is the point. A per-transport budget is not a budget: a client that has
// exhausted its reveal allowance over REST simply opens a gRPC channel and spends
// another one. Both surfaces reach the same secrets with the same grants, so they are
// metered against the same counter, keyed by the same principal.
//
// The single-node caveat is unchanged and is documented in full in
// internal/platform/middleware/rate_limit.go: the counters are per-process.

// RateLimitOptions are the per-class budgets, mirroring the REST server's.
type RateLimitOptions struct {
	// Reveal budgets the RPCs that return a decrypted value.
	Reveal int
	// Write budgets every mutating RPC.
	Write int
	// Setup budgets the self-guarded setup surface, keyed by peer address.
	Setup int
}

// revealMethods are the RPCs that hand back a plaintext. They are enumerated rather
// than pattern-matched on the name, for the same reason methodPermissions is: a new RPC
// that returns a value and is not on this list would silently get the (larger) write
// budget, and "silently" is how a reveal path loses its meter.
var revealMethods = map[string]bool{
	secretService + "GetSecret":       true,
	secretService + "BatchGetSecrets": true,
	// The legacy flat-key Get is a reveal in every sense that matters.
	secretService + "Get": true,
}

// writeMethods are the mutating RPCs.
var writeMethods = map[string]bool{
	secretService + "Put":                   true,
	secretService + "Delete":                true,
	secretService + "PutSecret":             true,
	secretService + "UpdateSecretMetadata":  true,
	secretService + "RollbackSecret":        true,
	secretService + "RotateSecret":          true,
	secretService + "SetRotationPolicy":     true,
	secretService + "DeleteSecret":          true,
	secretService + "RestoreSecret":         true,
	secretService + "DestroySecret":         true,
	secretService + "BatchPutSecrets":       true,
	secretService + "CreateProject":         true,
	secretService + "UpdateProject":         true,
	secretService + "DeleteProject":         true,
	secretService + "CreateEnvironment":     true,
	secretService + "UpdateEnvironment":     true,
	secretService + "DeleteEnvironment":     true,
	secretService + "CreateFolder":          true,
	secretService + "MoveFolder":            true,
	secretService + "DeleteFolder":          true,
	secretService + "CreateImport":          true,
	secretService + "UpdateImport":          true,
	secretService + "DeleteImport":          true,
	secretService + "CreateWebhookEndpoint": true,
	secretService + "UpdateWebhookEndpoint": true,
	secretService + "DeleteWebhookEndpoint": true,
}

// RateLimitUnaryInterceptor meters RPCs against the shared limiter.
//
// A nil limiter is a pass-through, which is what SECRET_RATE_LIMIT_ENABLED=false
// produces. Health checks are never metered: an orchestrator's probe loop would
// otherwise consume a budget and, worse, could be starved out of it by an attacker
// sharing its key.
func RateLimitUnaryInterceptor(l *mw.Limiter, opts RateLimitOptions) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if l == nil {
			return handler(ctx, req)
		}
		method := info.FullMethod
		if strings.HasPrefix(method, healthServicePrefix) {
			return handler(ctx, req)
		}

		class, limit, key := classify(ctx, method, opts)
		if limit <= 0 {
			return handler(ctx, req)
		}
		allowed, retryAfter := l.Allow(class+"|"+key, limit)
		if !allowed {
			slog.Warn("rate limit exceeded",
				"transport", "grpc", "class", class, "limit", limit, "method", method)
			return nil, status.Errorf(codes.ResourceExhausted,
				"rate limit exceeded — try again in %ds", int(retryAfter.Seconds())+1)
		}
		return handler(ctx, req)
	}
}

// classify picks the budget and the key for one RPC.
//
// The setup surfaces are keyed by PEER ADDRESS because they run before a principal
// exists; everything else is keyed by the authenticated subject, falling back to the
// peer address. The interceptor runs after AuthUnaryInterceptor, so the claims are in
// the context by the time this reads them.
func classify(ctx context.Context, method string, opts RateLimitOptions) (class string, limit int, key string) {
	if strings.HasPrefix(method, setupServicePrefix) || method == secretService+"Setup" {
		return "setup", opts.Setup, "ip:" + peerIP(ctx)
	}
	switch {
	case revealMethods[method]:
		class, limit = "reveal", opts.Reveal
	case writeMethods[method]:
		class, limit = "write", opts.Write
	default:
		// Reads and everything else are unmetered by class. They are still bounded by
		// the surface allowlist and by pagination; adding a third budget here would be
		// a knob nobody tunes.
		return "", 0, ""
	}
	return class, limit, principalKey(ctx)
}

// principalKey derives the limiter key from the verified claims, falling back to the
// peer address before authentication has run.
func principalKey(ctx context.Context) string {
	if claims, ok := sdkauthz.FromContext(ctx); ok && claims != nil && claims.Subject != "" {
		return "sub:" + claims.Subject
	}
	return "ip:" + peerIP(ctx)
}
