// Package response is the HTTP envelope and error mapping for this service's REST
// API — the same contract core uses (core internal/platform/response), trimmed to
// what a secret store needs and with one rule added.
//
// THE RULE: nothing written by this package may carry a secret value. Handlers pass
// domain types that structurally cannot hold one (store.SecretMeta and friends), and
// the one type that can (store.RevealedSecret) is never handed to a helper here —
// the reveal handler encodes its own body, deliberately, so that "which responses
// can contain a value" is answerable by grep rather than by reasoning.
//
// Internal errors are logged server-side and reported generically. That split
// matters more here than in an ordinary service: the detail inside an internal error
// describes the store's structure, and a caller who cannot read a secret should not
// learn the shape of the thing protecting it.
package response

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/maintainerd/secret/internal/platform/apperror"
)

// StatusClientClosedRequest is nginx's 499. Go has no constant for it because it is not
// in any RFC, but it is what a log pipeline expects to see when the client hung up, and
// it keeps those out of the 5xx bucket an operator alerts on.
const StatusClientClosedRequest = 499

// Envelope is the shape every REST response takes.
type Envelope struct {
	Success bool   `json:"success"`
	Data    any    `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
	Code    string `json:"code,omitempty"`
	Meta    *Page  `json:"meta,omitempty"`
}

// Page is the pagination block on a list response.
type Page struct {
	Page  int   `json:"page"`
	Limit int   `json:"limit"`
	Total int64 `json:"total"`
}

type loggerKey struct{}

// WithLogger returns a copy of ctx carrying a request-scoped logger (seeded with
// the request id by the middleware).
func WithLogger(ctx context.Context, l *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey{}, l)
}

// LoggerFromContext returns the request-scoped logger, falling back to the default.
func LoggerFromContext(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(loggerKey{}).(*slog.Logger); ok && l != nil {
		return l
	}
	return slog.Default()
}

// OK writes a 200 with data.
func OK(w http.ResponseWriter, data any, message string) {
	writeJSON(w, http.StatusOK, Envelope{Success: true, Data: data, Message: message})
}

// Created writes a 201 with data.
func Created(w http.ResponseWriter, data any, message string) {
	writeJSON(w, http.StatusCreated, Envelope{Success: true, Data: data, Message: message})
}

// List writes a 200 with a pagination block.
func List(w http.ResponseWriter, data any, page, limit int, total int64) {
	writeJSON(w, http.StatusOK, Envelope{
		Success: true,
		Data:    data,
		Meta:    &Page{Page: page, Limit: limit, Total: total},
	})
}

// NoContent writes a 204.
func NoContent(w http.ResponseWriter) { w.WriteHeader(http.StatusNoContent) }

// Error writes a failure envelope.
func Error(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, Envelope{Success: false, Error: message})
}

// ErrorWithCode writes a failure envelope carrying a stable machine-readable code
// alongside the human message, so a client can branch on the code without
// string-matching the message.
func ErrorWithCode(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, Envelope{Success: false, Error: message, Code: code})
}

// BadRequestBody is the standard malformed-JSON answer.
func BadRequestBody(w http.ResponseWriter) {
	Error(w, http.StatusBadRequest, "invalid request body")
}

// ServiceError maps a typed service error onto a status code.
//
// Note what is NOT distinguished: a cross-tenant read and a genuinely missing
// secret both arrive here as NotFound, because the store deliberately produces the
// same error for both (a distinct "exists but not yours" confirms the existence of
// another tenant's secret).
func ServiceError(w http.ResponseWriter, r *http.Request, fallback string, err error) {
	var pgErr *pgconn.PgError
	switch {
	case apperror.IsNotFound(err):
		Error(w, http.StatusNotFound, err.Error())
	case apperror.IsValidation(err):
		Error(w, http.StatusBadRequest, err.Error())
	case apperror.IsConflict(err):
		Error(w, http.StatusConflict, err.Error())
	case apperror.IsForbidden(err):
		Error(w, http.StatusForbidden, err.Error())
	case apperror.IsUnavailable(err):
		Error(w, http.StatusServiceUnavailable, err.Error())
	// Constraint violations are matched BEFORE the internal case because the store
	// wraps driver errors in an InternalError and InternalError unwraps — so the
	// pgconn error reaches here nested. They are the backstop when a service-level
	// uniqueness pre-check loses a race with a concurrent writer: 409/400, not 500.
	case errors.As(err, &pgErr) && pgErr.Code == "23505":
		Error(w, http.StatusConflict, "a record with these values already exists")
	case errors.As(err, &pgErr) && pgErr.Code == "23503":
		Error(w, http.StatusBadRequest, "a referenced record does not exist")
	// A request that blew its per-request deadline (middleware.Timeout) is a 503 with
	// a Retry-After-shaped meaning, not a 500: nothing is broken, the work did not fit
	// in the budget. Matched before the internal case so it does not fill the log with
	// "internal service error" lines during a slow-database incident.
	case errors.Is(err, context.DeadlineExceeded):
		ErrorWithCode(w, http.StatusServiceUnavailable, "request_timeout",
			"the request exceeded its time budget and was abandoned")
	// The CLIENT went away. There is nobody to answer and nothing to alarm about, so
	// this writes a status the connection will never carry and logs at debug.
	case errors.Is(err, context.Canceled):
		LoggerFromContext(r.Context()).Debug("request cancelled by the client")
		Error(w, StatusClientClosedRequest, "the request was cancelled")
	default:
		LoggerFromContext(r.Context()).Error("internal service error", "error", err.Error())
		Error(w, http.StatusInternalServerError, fallback)
	}
}

// PageParams reads ?page and ?limit, applying the defaults for an absent or
// unparseable value.
//
// IT DOES NOT CLAMP THE UPPER BOUND, and that is a deliberate change from the obvious
// implementation. Clamping here would mean a client asking for 10000 rows silently
// receives 200 and believes it has read everything — which for a reconciler walking an
// environment means it stops early and reports success. The cap is enforced by the API
// layer's Pagination DTO instead (internal/api/validation.go), which REFUSES an
// over-large limit with a message naming the maximum, and which both transports funnel
// through so the two cannot disagree about the number.
func PageParams(r *http.Request) (page, limit int) {
	page = atoiDefault(r.URL.Query().Get("page"), 1)
	limit = atoiDefault(r.URL.Query().Get("limit"), 50)
	if page < 1 {
		page = 1
	}
	if limit < 1 {
		limit = 50
	}
	return page, limit
}

func atoiDefault(raw string, def int) int {
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	return n
}

func writeJSON(w http.ResponseWriter, status int, payload Envelope) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
