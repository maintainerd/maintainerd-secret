// Package logging installs this service's structured logger and the redaction that
// makes it safe to run at debug level in production.
//
// THE PROBLEM IT SOLVES. Most of this service's leak-proofing is structural: a
// decrypted value is a crypto.Plaintext, which renders as "[REDACTED]" through
// fmt.Stringer, slog.LogValuer, encoding/json and encoding.TextMarshaler, so it cannot
// reach a log by inattention. But four things on this service are ordinary Go strings
// and bytes, and cannot be Plaintext without changing contracts outside it:
//
//	the bootstrap token       a config string, compared in constant time
//	the Authorization header  arrives as a raw header
//	a webhook signing key     a base64 string in exactly one response body
//	a supplied generator value a rotation.Spec field, which arrives as JSON
//
// RedactHandler is the backstop for those: a slog.Handler that scrubs an attribute
// whose KEY names a credential, whatever the value's type, and truncates any long
// string so a body that reached a log line as one attribute is not a body in the log.
//
// It is a backstop, not the mechanism. The mechanism is that nothing logs a body; this
// is what makes "nothing logs a body" survive the next person who adds a debug line.
package logging

import (
	"context"
	"log/slog"
	"strings"

	"github.com/maintainerd/kit/log"

	"github.com/maintainerd/secret/internal/crypto"
)

// maxAttrRunes truncates a long string attribute.
//
// The bound is what turns "somebody logged the request body" from a disclosure into a
// hint. It is generous enough that MRNs, URLs and error messages survive intact — the
// longest legitimate attribute this service emits is an MRN chain from a reference
// resolution — and short enough that a PEM bundle or a base64 payload does not.
const maxAttrRunes = 512

// truncationSuffix marks a value the handler shortened, so an operator reading a
// clipped line knows it was clipped rather than assuming the value ended there.
const truncationSuffix = "…[truncated]"

// sensitiveKeys are attribute names whose VALUE is redacted outright, matched
// case-insensitively against the full key and against the segment after the last '_'
// or '.'.
//
// The list is names, not heuristics on the value, because a heuristic that inspects
// values is a function that touches every credential in every log call and gets one
// wrong. A name-based denylist is boring and auditable: to leak, someone has to pick a
// key that is not on this list AND log a credential under it, which is a deliberate
// act rather than an accident.
var sensitiveKeys = map[string]bool{
	"authorization":     true,
	"bearer":            true,
	"token":             true,
	"bootstrap_token":   true,
	"setup_token":       true,
	"access_token":      true,
	"refresh_token":     true,
	"assertion":         true,
	"secret":            true,
	"secret_value":      true,
	"value":             true,
	"plaintext":         true,
	"password":          true,
	"credential":        true,
	"credentials":       true,
	"signing_key":       true,
	"root_key":          true,
	"rootkey":           true,
	"kek":               true,
	"dek":               true,
	"key_material":      true,
	"private_key":       true,
	"panic":             true,
	"body":              true,
	"request_body":      true,
	"response_body":     true,
	"cookie":            true,
	"set-cookie":        true,
	"x-setup-token":     true,
	"rotation_policy":   true,
	"generator_value":   true,
	"signature":         true,
	"client_secret":     true,
	"connection_string": true,
	"dsn":               true,
}

// RedactHandler wraps another slog.Handler.
type RedactHandler struct {
	inner slog.Handler
}

// NewRedactHandler wraps inner. A nil inner returns nil so a caller can compose
// conditionally without a branch.
func NewRedactHandler(inner slog.Handler) slog.Handler {
	if inner == nil {
		return nil
	}
	return &RedactHandler{inner: inner}
}

// Enabled delegates.
func (h *RedactHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

// Handle scrubs the record's attributes and forwards it.
func (h *RedactHandler) Handle(ctx context.Context, rec slog.Record) error {
	clean := slog.NewRecord(rec.Time, rec.Level, rec.Message, rec.PC)
	rec.Attrs(func(a slog.Attr) bool {
		clean.AddAttrs(redactAttr(a))
		return true
	})
	return h.inner.Handle(ctx, clean)
}

// WithAttrs scrubs the pre-bound attributes too — a logger built with
// slog.With("token", ...) must not carry the token into every subsequent line.
func (h *RedactHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	cleaned := make([]slog.Attr, 0, len(attrs))
	for _, a := range attrs {
		cleaned = append(cleaned, redactAttr(a))
	}
	return &RedactHandler{inner: h.inner.WithAttrs(cleaned)}
}

// WithGroup delegates.
func (h *RedactHandler) WithGroup(name string) slog.Handler {
	return &RedactHandler{inner: h.inner.WithGroup(name)}
}

// redactAttr applies the policy to one attribute, recursing into groups.
func redactAttr(a slog.Attr) slog.Attr {
	if IsSensitiveKey(a.Key) {
		return slog.String(a.Key, crypto.Redacted)
	}
	// Resolve() runs LogValuer, which is what turns a crypto.Plaintext into
	// "[REDACTED]" before the value is inspected or truncated below.
	value := a.Value.Resolve()
	switch value.Kind() {
	case slog.KindGroup:
		attrs := value.Group()
		cleaned := make([]slog.Attr, 0, len(attrs))
		for _, inner := range attrs {
			cleaned = append(cleaned, redactAttr(inner))
		}
		return slog.Attr{Key: a.Key, Value: slog.GroupValue(cleaned...)}
	case slog.KindString:
		return slog.Attr{Key: a.Key, Value: slog.StringValue(truncate(value.String()))}
	default:
		// Anything else renders through its own String(), which for this service's
		// secret-bearing types is already redacted. Truncating the rendering bounds
		// the rest.
		return slog.Attr{Key: a.Key, Value: slog.StringValue(truncate(value.String()))}
	}
}

// IsSensitiveKey reports whether an attribute name is one whose value must never be
// logged. Exported so a test can assert the list rather than restate it.
func IsSensitiveKey(key string) bool {
	lower := strings.ToLower(strings.TrimSpace(key))
	if sensitiveKeys[lower] {
		return true
	}
	// Then EVERY suffix that starts after a '_' or '.', longest first, so
	// "generator.value" matches "value" and "endpoint_signing_key" matches
	// "signing_key" — without listing every prefix anyone might choose. Checking only
	// the LAST segment would miss the second of those, because "key" alone is too
	// broad to put on the list (it would swallow "kek_id" and "keep_versions" the
	// moment either grew a prefix).
	for i := 0; i < len(lower); i++ {
		if lower[i] != '_' && lower[i] != '.' {
			continue
		}
		if i+1 < len(lower) && sensitiveKeys[lower[i+1:]] {
			return true
		}
	}
	return false
}

// truncate shortens an over-long rendering.
func truncate(s string) string {
	if len(s) <= maxAttrRunes {
		return s
	}
	runes := []rune(s)
	if len(runes) <= maxAttrRunes {
		return s
	}
	return string(runes[:maxAttrRunes]) + truncationSuffix
}

// Setup installs the kit logger at the configured level and wraps it in the redactor.
//
// It is called once, immediately after config.Init, so that every line this process
// emits after that point — including the boot banner and any panic — passes through
// the filter. Anything logged BEFORE it (a config error) is emitted by the default
// handler and carries no request data by construction.
func Setup(level string) {
	log.Setup(level)
	slog.SetDefault(slog.New(NewRedactHandler(slog.Default().Handler())))
}
