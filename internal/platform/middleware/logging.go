package middleware

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	sdkauthz "github.com/maintainerd/sdk/authz"
	"github.com/maintainerd/secret/internal/platform/response"
)

// RequestLogger emits one structured line per request and seeds the request-scoped
// logger every handler and every service error uses.
//
// WHAT IT RECORDS, and why each field earns its place:
//
//	request_id  correlates this line with the internal-error line a handler emitted,
//	            and with the audit row (audit_log.request_id carries the same value).
//	method      · route · status · duration_ms — the operational four.
//	principal   the token's subject. This is what makes the log answerable to "who was
//	            hammering the reveal endpoint at 03:00" without reading audit_log.
//	tenant      the resolved tenant slug, for a multi-tenant deployment.
//	client_ip   the PEER address, never a forwarded header (see httpapi.clientIP).
//	bytes       the response size — a number, never the response.
//
// WHAT IT DOES NOT RECORD, and this is the important half:
//
//	the request body     it is a credential on the write paths
//	the response body    it is a credential on the reveal paths
//	the query string     a caller can put anything in it; logging it means logging
//	                     whatever a mistaken client put there
//	the Authorization header, obviously.
//
// ROUTE, NOT PATH. The logged route is chi's matched PATTERN ("/api/v1/webhooks/
// {endpointUUID}") rather than the concrete URL. That keeps identifiers out of the log
// and makes the lines aggregatable, which is what an operator actually wants from a
// request log. The concrete path is recoverable from the audit row's resource MRN when
// it matters, and that row is access-controlled; the log is not.
func RequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		requestID := chimw.GetReqID(r.Context())

		logger := slog.With(
			"request_id", requestID,
			"method", r.Method,
			"path", r.URL.Path,
		)
		ctx := response.WithLogger(r.Context(), logger)
		r = r.WithContext(ctx)

		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)

		attrs := []any{
			"request_id", requestID,
			"method", r.Method,
			"route", routePattern(r),
			"status", recorder.status,
			"duration_ms", time.Since(start).Milliseconds(),
			"bytes", recorder.written,
			"client_ip", PeerIP(r),
		}
		if claims, ok := sdkauthz.FromContext(r.Context()); ok && claims != nil {
			attrs = append(attrs, "principal", claims.Subject, "principal_kind", claims.Kind)
			if claims.Tenant != "" {
				attrs = append(attrs, "tenant", claims.Tenant)
			}
		}

		// A 5xx is an operator's problem and logs at error; a 4xx is a caller's and
		// logs at warn, so a client looping on a 403 is visible without turning every
		// ordinary rejection into an alarm.
		switch {
		case recorder.status >= 500:
			slog.Error("request failed", attrs...)
		case recorder.status >= 400:
			slog.Warn("request refused", attrs...)
		default:
			slog.Info("request", attrs...)
		}
	})
}

// routePattern returns chi's matched route pattern, falling back to the raw path when
// no route matched (a 404, where there is no pattern to report).
func routePattern(r *http.Request) string {
	if rctx := chi.RouteContext(r.Context()); rctx != nil {
		if pattern := rctx.RoutePattern(); pattern != "" {
			return pattern
		}
	}
	return r.URL.Path
}
