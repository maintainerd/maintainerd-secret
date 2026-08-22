// Package middleware is this service's HTTP cross-cutting layer: security headers,
// panic recovery, request logging with redaction, request timeouts, body-size caps and
// the in-process rate limiter.
//
// It mirrors maintainerd-auth's internal/platform/middleware in shape and in the
// headers it sets, so a reverse proxy or a security review that already knows Auth's
// responses recognises these. Where it differs, it differs for a stated reason — the
// rate limiter is the significant one: Auth meters through Redis, and this service has
// no Redis, so the limiter here is per-process. See rate_limit.go.
//
// NOTHING IN THIS PACKAGE MAY LOG A REQUEST OR RESPONSE BODY. A body on this service
// is a credential — in the clear on the way in, in the clear on the way out. The
// request logger records the request id, the principal, the route, the status and the
// duration, and nothing that came off the wire.
package middleware

import "net/http"

// Middleware is the common HTTP middleware shape, matching Auth's.
type Middleware func(http.Handler) http.Handler

// Chain composes middleware so that the FIRST argument is the OUTERMOST wrapper — the
// order they are listed is the order a request passes through them.
//
// The order is load-bearing at the call site (see internal/httpapi.Router): recovery
// has to be outside the logger so a panic is still logged with its request id, and the
// body cap has to be outside every handler because the guard runs after the body has
// started arriving.
func Chain(mws ...Middleware) Middleware {
	return func(next http.Handler) http.Handler {
		handler := next
		for i := len(mws) - 1; i >= 0; i-- {
			if mws[i] != nil {
				handler = mws[i](handler)
			}
		}
		return handler
	}
}

// statusRecorder captures the status code and byte count for the request logger.
//
// It is the minimal wrapper on purpose: it does NOT buffer the body. Buffering would
// put a decrypted secret in a byte slice this package owns, which is exactly the thing
// the package comment forbids.
type statusRecorder struct {
	http.ResponseWriter
	status  int
	written int64
	// wroteHeader guards against a handler that calls WriteHeader twice, which would
	// otherwise record the second (and log a status the client never saw).
	wroteHeader bool
}

func (w *statusRecorder) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusRecorder) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(b)
	w.written += int64(n)
	return n, err
}

// Flush forwards to the underlying writer when it supports flushing, so wrapping does
// not silently disable streaming.
func (w *statusRecorder) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
