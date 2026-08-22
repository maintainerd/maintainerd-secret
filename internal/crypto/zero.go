package crypto

import "log/slog"

// Zero overwrites b with zeroes.
//
// Go gives no guarantee that this cannot be optimised away, and there is no
// memset_s to reach for. What it does buy is real all the same: it shortens the
// window in which a plaintext or a DEK is sitting in a heap buffer that will be
// reused, handed to the GC, or captured in a core dump. Every function in this
// package that materialises key material or plaintext calls it on the way out,
// which is why decrypt paths use defer rather than trusting a happy-path return.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Plaintext is a decrypted secret value.
//
// It exists so that the accidental ways a value escapes are closed by default. A
// []byte in a struct gets logged by slog, marshalled into a JSON error body, and
// printed by %v in a debug line that outlives the debugging session. Plaintext
// answers all three with "[REDACTED]", so leaking a value takes a deliberate call
// to Bytes() rather than a moment of inattention.
//
// It is NOT a security boundary — Bytes() hands over the slice, and it must. It is
// a default that fails safe.
type Plaintext []byte

// Redacted is what every stringly rendering of a Plaintext produces.
const Redacted = "[REDACTED]"

// String implements fmt.Stringer.
func (Plaintext) String() string { return Redacted }

// GoString implements fmt.GoStringer, covering the %#v verb.
func (Plaintext) GoString() string { return "crypto.Plaintext(" + Redacted + ")" }

// LogValue implements slog.LogValuer, so a Plaintext passed to a structured logger
// as a value or an attribute renders redacted.
func (Plaintext) LogValue() slog.Value { return slog.StringValue(Redacted) }

// MarshalJSON keeps a Plaintext out of any JSON response or log payload it is
// embedded in.
func (Plaintext) MarshalJSON() ([]byte, error) { return []byte(`"` + Redacted + `"`), nil }

// MarshalText covers encoding.TextMarshaler consumers.
func (Plaintext) MarshalText() ([]byte, error) { return []byte(Redacted), nil }

// Bytes exposes the underlying value. Calling this is the deliberate act of
// handling a secret; the caller owns zeroizing it when done.
func (p Plaintext) Bytes() []byte { return p }

// Len reports the value's length. Safe to log: a length is not a value.
func (p Plaintext) Len() int { return len(p) }

// Zero overwrites the value in place.
func (p Plaintext) Zero() { Zero(p) }
