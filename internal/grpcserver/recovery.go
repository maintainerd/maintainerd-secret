package grpcserver

import (
	"context"
	"runtime"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/maintainerd/secret/internal/platform/response"
)

// maxStackBytes bounds the stack captured on a panic, matching the HTTP side.
const maxStackBytes = 8 << 10

// RecoveryUnaryInterceptor turns a panic in an RPC handler into codes.Internal.
//
// WITHOUT IT, A PANIC IN ONE RPC TAKES THE PROCESS DOWN. grpc-go recovers nothing by
// default: an unrecovered panic in a handler goroutine crashes the server, so a
// malformed request that trips a nil dereference in one code path is a whole-vault
// outage. That is a materially worse failure mode here than on the HTTP side, where
// net/http would have contained it.
//
// The client is told "internal error" and nothing else — same reasoning as toStatus:
// the detail in a panic describes the store that is protecting the credentials. The
// panic value and stack go to the server log, through slog, so the redacting handler in
// internal/platform/logging scrubs them: a panic value is an arbitrary Go value and on
// this service could be a []byte holding a plaintext.
//
// It must be the OUTERMOST interceptor, so it also covers a panic inside the auth
// interceptor or the rate limiter rather than only inside the handler.
func RecoveryUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		defer func() {
			if rec := recover(); rec != nil {
				stack := make([]byte, maxStackBytes)
				stack = stack[:runtime.Stack(stack, false)]
				// Logged under the "panic" key, which the redactor scrubs.
				response.LoggerFromContext(ctx).Error("rpc handler panicked",
					"panic", rec,
					"method", info.FullMethod,
					"stack", string(stack),
				)
				resp = nil
				err = status.Error(codes.Internal, "internal error")
			}
		}()
		return handler(ctx, req)
	}
}
