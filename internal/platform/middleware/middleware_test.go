package middleware

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sdkauthz "github.com/maintainerd/sdk/authz"
	"github.com/maintainerd/secret/internal/platform/logging"
)

func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	os.Exit(m.Run())
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
}

// ---------------------------------------------------------------------------
// Security headers
// ---------------------------------------------------------------------------

func TestSecurityHeaders(t *testing.T) {
	serve := func(production bool, tls bool) http.Header {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets", nil)
		if tls {
			req.Header.Set("X-Forwarded-Proto", "https")
		}
		w := httptest.NewRecorder()
		SecurityHeaders(production)(okHandler()).ServeHTTP(w, req)
		return w.Header()
	}

	t.Run("the always-on set", func(t *testing.T) {
		h := serve(false, false)
		assert.Equal(t, "nosniff", h.Get("X-Content-Type-Options"))
		assert.Equal(t, "DENY", h.Get("X-Frame-Options"))
		assert.Equal(t, "no-referrer", h.Get("Referrer-Policy"))
		assert.Equal(t, "no-store", h.Get("Cache-Control"))
		assert.Equal(t, "same-origin", h.Get("Cross-Origin-Resource-Policy"))

		csp := h.Get("Content-Security-Policy")
		assert.Contains(t, csp, "default-src 'none'",
			"an API response loads nothing, so the honest policy is nothing")
		assert.Contains(t, csp, "frame-ancestors 'none'")
	})

	// HSTS over plaintext is ignored by browsers by specification, and from a dev
	// instance on localhost it poisons the developer's browser for the whole domain.
	t.Run("HSTS only in production over TLS", func(t *testing.T) {
		assert.Empty(t, serve(false, false).Get("Strict-Transport-Security"))
		assert.Empty(t, serve(false, true).Get("Strict-Transport-Security"),
			"development never sends HSTS")
		assert.Empty(t, serve(true, false).Get("Strict-Transport-Security"),
			"HSTS over plaintext is meaningless")

		hsts := serve(true, true).Get("Strict-Transport-Security")
		assert.Contains(t, hsts, "max-age=31536000")
		assert.Contains(t, hsts, "includeSubDomains")
	})

	// The headers must be set before ANY response can be written, including an error
	// one — a header that is only on the happy path is a header an attacker routes
	// around by provoking a failure.
	t.Run("set on an error response too", func(t *testing.T) {
		failing := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "boom", http.StatusInternalServerError)
		})
		w := httptest.NewRecorder()
		SecurityHeaders(true)(failing).ServeHTTP(w,
			httptest.NewRequest(http.MethodGet, "/api/v1/secrets", nil))
		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	})
}

// ---------------------------------------------------------------------------
// Recovery
// ---------------------------------------------------------------------------

func TestRecovery(t *testing.T) {
	const value = "hunter2-the-password"

	panicking := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("nil map write while handling " + value)
	})

	var buf bytes.Buffer
	slog.SetDefault(slog.New(logging.NewRedactHandler(
		slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))))
	t.Cleanup(func() { slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil))) })

	w := httptest.NewRecorder()
	require.NotPanics(t, func() {
		Recovery(panicking).ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/secrets", nil))
	})

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "internal error")
	assert.NotContains(t, w.Body.String(), "nil map write",
		"a panic message must not reach the client")
	assert.NotContains(t, w.Body.String(), "goroutine",
		"a stack trace must not reach the client")

	// The panic goes to the log under a key the redactor scrubs, because a panic value
	// is an arbitrary Go value and on this service could be holding a plaintext.
	assert.NotContains(t, buf.String(), value)
	assert.Contains(t, buf.String(), "handler panicked")
}

func TestRecoveryRepanicsOnAbortHandler(t *testing.T) {
	aborting := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic(http.ErrAbortHandler)
	})
	assert.Panics(t, func() {
		Recovery(aborting).ServeHTTP(httptest.NewRecorder(),
			httptest.NewRequest(http.MethodGet, "/", nil))
	}, "ErrAbortHandler is net/http's sanctioned abandon signal and must reach it")
}

// ---------------------------------------------------------------------------
// Body limit
// ---------------------------------------------------------------------------

func TestBodyLimit(t *testing.T) {
	echo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	t.Run("a body within the cap", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("0123456789"))
		w := httptest.NewRecorder()
		BodyLimit(64)(echo).ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("a body over the cap", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("a", 200)))
		w := httptest.NewRecorder()
		BodyLimit(64)(echo).ServeHTTP(w, req)
		assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
	})

	// A chunked request declares no Content-Length, so a length check would be a cap
	// the caller opts out of. MaxBytesReader counts bytes actually read.
	t.Run("a chunked body over the cap is still capped", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("a", 200)))
		req.ContentLength = -1
		w := httptest.NewRecorder()
		BodyLimit(64)(echo).ServeHTTP(w, req)
		assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
	})
}

// ---------------------------------------------------------------------------
// Timeout
// ---------------------------------------------------------------------------

func TestTimeoutPropagatesADeadline(t *testing.T) {
	var (
		hadDeadline bool
		deadline    time.Time
	)
	inspect := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deadline, hadDeadline = r.Context().Deadline()
		w.WriteHeader(http.StatusOK)
	})

	w := httptest.NewRecorder()
	Timeout(50*time.Millisecond)(inspect).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	require.True(t, hadDeadline, "the handler must inherit a deadline")
	assert.WithinDuration(t, time.Now().Add(50*time.Millisecond), deadline, 40*time.Millisecond)
}

// The deadline is COOPERATIVE: it cancels the context so context-aware I/O unwinds. It
// deliberately does not race the handler for the ResponseWriter — see the doc comment
// on Timeout for why buffering or racing is unacceptable on this service.
func TestTimeoutCancelsTheContextForASlowHandler(t *testing.T) {
	observed := make(chan error, 1)
	slowHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
		observed <- r.Context().Err()
		w.WriteHeader(http.StatusServiceUnavailable)
	})

	w := httptest.NewRecorder()
	Timeout(10*time.Millisecond)(slowHandler).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	select {
	case err := <-observed:
		assert.ErrorIs(t, err, context.DeadlineExceeded)
	case <-time.After(time.Second):
		t.Fatal("the handler never observed its deadline")
	}
}

func TestTimeoutAndBodyLimitArePassThroughWhenUnset(t *testing.T) {
	w := httptest.NewRecorder()
	Timeout(0)(okHandler()).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Equal(t, http.StatusOK, w.Code)

	w = httptest.NewRecorder()
	BodyLimit(0)(okHandler()).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Equal(t, http.StatusOK, w.Code)
}

// ---------------------------------------------------------------------------
// Request logging
// ---------------------------------------------------------------------------

// TestRequestLoggerLogsNoPayload is the redaction guarantee at the request level: the
// logger records the operational fields and nothing that came off the wire.
func TestRequestLoggerLogsNoPayload(t *testing.T) {
	const value = "hunter2-the-production-password"

	var buf bytes.Buffer
	slog.SetDefault(slog.New(logging.NewRedactHandler(
		slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))))
	t.Cleanup(func() { slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil))) })

	echoingHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		// The reveal path writes a decrypted value into the response. The logger must
		// count the bytes and record nothing else about them.
		_, _ = w.Write([]byte(`{"value":"` + value + `"}`))
	})

	body := strings.NewReader(`{"key":"DB_PASSWORD","value":"` + value + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets?tenant="+value, body)
	req.Header.Set("Authorization", "Bearer "+value)
	req = req.WithContext(sdkauthz.NewContext(req.Context(), &sdkauthz.Claims{
		Subject: "svc-billing", Kind: sdkauthz.ActorKindService, Tenant: "acme",
	}))

	RequestLogger(echoingHandler).ServeHTTP(httptest.NewRecorder(), req)

	out := buf.String()
	assert.NotContains(t, out, value,
		"the request logger leaked a payload: %s", out)
	assert.Contains(t, out, "svc-billing", "the principal is what makes the log answerable")
	assert.Contains(t, out, "status=200")
	assert.Contains(t, out, "tenant=acme")
}

func TestRequestLoggerLevelsBySeverity(t *testing.T) {
	statuses := map[int]string{
		http.StatusOK:                  "level=INFO",
		http.StatusForbidden:           "level=WARN",
		http.StatusInternalServerError: "level=ERROR",
	}
	for status, wantLevel := range statuses {
		var buf bytes.Buffer
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
		handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
		})
		RequestLogger(handler).ServeHTTP(httptest.NewRecorder(),
			httptest.NewRequest(http.MethodGet, "/api/v1/secrets", nil))
		assert.Contains(t, buf.String(), wantLevel, "status %d", status)
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
}
