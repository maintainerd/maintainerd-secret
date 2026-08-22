package httpapi

import (
	"io"
	"log/slog"
	"os"
	"testing"
)

// TestMain silences the request logger for the whole package.
//
// These tests drive the real router, which logs a line per request, and several of them
// deliberately provoke panics and 500s. Without this, a passing run buries its result
// under a hundred ERROR lines and a stack trace, which trains everyone reading CI to
// ignore them. The logging behaviour itself is asserted directly in
// internal/platform/logging and internal/platform/middleware.
func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	os.Exit(m.Run())
}
