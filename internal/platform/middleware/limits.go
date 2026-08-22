package middleware

import (
	"context"
	"net/http"
	"time"
)

// BodyLimit caps a request body with http.MaxBytesReader.
//
// APPLIED TO EVERY ROUTE, including GET and DELETE and including the routes the guard
// will refuse. That ordering is the point: the guard cannot run until the request has
// arrived, so a cap installed inside the guarded group would leave the unauthenticated
// window — and the setup surface, which is unauthenticated by design — uncapped.
//
// MaxBytesReader rather than a Content-Length check: a chunked request has no
// Content-Length, so a length check is a cap an attacker opts out of by not declaring
// one. MaxBytesReader counts bytes actually read and makes the reader fail, which is
// also what turns an over-large body into a 413 from net/http rather than an OOM.
func BodyLimit(maxBytes int64) Middleware {
	return func(next http.Handler) http.Handler {
		if maxBytes <= 0 {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Timeout gives every request a context deadline.
//
// WHAT IT ACTUALLY BUYS. It does not stop a handler — Go has no way to do that — it
// cancels the CONTEXT, and everything downstream that respects a context stops: the pgx
// query releases its pool connection, the outbound webhook POST aborts, the reference
// resolver stops walking. Without it, one query that will never return holds a pool
// connection forever, and enough of those exhaust the pool while the process still
// answers /healthz.
//
// WHY IT DOES NOT WRITE THE TIMEOUT RESPONSE ITSELF. The obvious implementation runs
// the handler on a second goroutine and answers 503 from the first when the deadline
// fires. It is also what net/http's own TimeoutHandler does — by BUFFERING the entire
// response so the two goroutines never touch the ResponseWriter at once. Neither half
// is acceptable here:
//
//   - Racing the handler for the ResponseWriter is a data race, and the thing being
//     raced over on this service is a decrypted credential mid-write.
//   - Buffering every response holds every revealed value in a second copy, in a buffer
//     this package owns, for the lifetime of the request. The reveal path goes to
//     considerable trouble to zeroize its one copy (see httpapi.revealSecret); handing
//     a second, un-zeroized copy to a middleware would undo that.
//
// So the deadline is COOPERATIVE: it propagates, the handler's next context-aware call
// fails with context.DeadlineExceeded, and response.ServiceError renders that as a 503.
// Every I/O path this service takes on a request — pgx, the outbound webhook client —
// is context-aware, so "cooperative" covers everything except a pure CPU loop. The hard
// backstop for that is the server's WriteTimeout, which config keeps strictly longer
// than this deadline so the ordered outcome is: deadline fires, handler unwinds, 503;
// and only if it does not unwind does the connection get closed.
//
// /healthz and /readyz are mounted OUTSIDE this middleware: a liveness probe that
// inherits a 30-second budget is a liveness probe that can take 30 seconds to answer,
// and those handlers carry their own, much shorter, bound.
func Timeout(d time.Duration) Middleware {
	return func(next http.Handler) http.Handler {
		if d <= 0 {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), d)
			defer cancel()
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
