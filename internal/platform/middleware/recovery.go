package middleware

import (
	"errors"
	"net/http"
	"runtime"

	"github.com/maintainerd/secret/internal/platform/response"
)

// maxStackBytes bounds the stack captured on a panic. A goroutine dump is useful; an
// unbounded one in a log line is how a single panic loop fills a disk.
const maxStackBytes = 8 << 10

// Recovery turns a panic in a handler into a 500 with a generic body, and logs the
// panic value and stack server-side.
//
// WHY NOT chi's Recoverer. Two differences that matter here:
//
//  1. chi's writes the panic and stack to STDERR directly, outside slog, which means it
//     bypasses the redacting handler in internal/platform/logging. A panic value is an
//     arbitrary Go value — on this service it could be a []byte holding a plaintext, or
//     a struct containing one — and the one place it must not go unfiltered is the log.
//     Routing it through slog puts it behind the redactor.
//  2. In development chi RE-PANICS for http.ErrAbortHandler and prints a colourised
//     stack to the response in some configurations. A stack trace in a response body is
//     a map of this service's internals handed to whoever provoked the panic.
//
// The response says "internal error" and nothing else, for the same reason
// apperror.InternalError's cause never reaches a client: the detail describes the store
// that is protecting the credentials.
//
// http.ErrAbortHandler is re-panicked rather than swallowed, because it is the
// sanctioned way for a handler to abandon a response and net/http expects to see it.
func Recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			rec := recover()
			if rec == nil {
				return
			}
			if err, ok := rec.(error); ok && errors.Is(err, http.ErrAbortHandler) {
				panic(rec)
			}

			stack := make([]byte, maxStackBytes)
			stack = stack[:runtime.Stack(stack, false)]

			// The panic value is logged under a key the redactor scrubs, so a
			// plaintext that ended up in a panic message does not end up in a log
			// line. The stack is structural and carries no request data.
			response.LoggerFromContext(r.Context()).Error("handler panicked",
				"panic", rec,
				"method", r.Method,
				"path", r.URL.Path,
				"stack", string(stack),
			)
			response.Error(w, http.StatusInternalServerError, "internal error")
		}()
		next.ServeHTTP(w, r)
	})
}
