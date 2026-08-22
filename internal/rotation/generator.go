// Package rotation owns the value GENERATOR and the rotation-policy format: what a
// rotated secret's new value is, and when a secret is due.
//
// It is deliberately pure — no store, no database, no context. Everything here is a
// function of its input, which is what lets the interval arithmetic and the charset
// handling be tested exhaustively without a database, and what keeps the background
// loop that drives it (internal/rotator) free of any opinion about what a good
// credential looks like.
package rotation

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Generator types.
const (
	// GeneratorRandom produces a fresh random string of the configured length and
	// charset. This is the useful case: a rotation whose new value the service
	// invents needs no round trip to whoever owns the credential.
	GeneratorRandom = "random"
	// GeneratorSupplied takes the value from the caller. It exists because most real
	// rotations are two-sided — the new database password has to be set ON the
	// database — so the caller rotates the upstream credential and hands the result
	// here. A scheduled policy may NOT use it (see Spec.Validate): a scheduler with
	// nobody to ask would either stall forever or, worse, write a placeholder over a
	// live credential.
	GeneratorSupplied = "supplied"
)

// Charsets a random generator may draw from. Each exists for a concrete
// interoperability reason rather than as a preference.
const (
	// CharsetAlphanumeric is the safe default: it survives shell quoting, URL
	// embedding, YAML, .env files and copy-paste, which is where generated
	// credentials actually get mangled.
	CharsetAlphanumeric = "alphanumeric"
	// CharsetAlphanumericSymbols adds punctuation for systems that demand a symbol.
	// The symbol set excludes quotes, backslash, backtick and dollar — the
	// characters that break exactly the contexts above.
	CharsetAlphanumericSymbols = "alphanumeric-symbols"
	// CharsetHex is for consumers that require hex (keys, tokens with a fixed
	// alphabet).
	CharsetHex = "hex"
	// CharsetBase64URL is for consumers that want maximum entropy per character
	// without needing URL escaping.
	CharsetBase64URL = "base64url"
)

const (
	alphanumericAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	symbolAlphabet       = "!#%&()*+,-.:;<=>?@[]^_{|}~"
)

// Length bounds. The minimum is a floor on entropy — a 12-character alphanumeric
// value is ~71 bits, which is the least this service is willing to call a
// credential. The maximum bounds the response and the ciphertext.
const (
	MinLength     = 12
	MaxLength     = 512
	DefaultLength = 32
)

// Spec describes how to produce a new value.
type Spec struct {
	Type    string `json:"type"`
	Length  int    `json:"length,omitempty"`
	Charset string `json:"charset,omitempty"`
	// Value is the caller-supplied plaintext for GeneratorSupplied. It is a string
	// because it arrives as one (a JSON request body); it is never logged, and the
	// only thing done with it is a byte copy into the write path.
	Value string `json:"value,omitempty"`
}

// Validate normalizes the spec and rejects the shapes that cannot work.
//
// scheduled reports whether this spec will be run by the background rotator, which
// is the one context in which a supplied value is meaningless.
func (s *Spec) Validate(scheduled bool) error {
	if s.Type == "" {
		s.Type = GeneratorRandom
	}
	switch s.Type {
	case GeneratorRandom:
		if s.Length == 0 {
			s.Length = DefaultLength
		}
		if s.Length < MinLength || s.Length > MaxLength {
			return fmt.Errorf("generated value length must be between %d and %d, got %d", MinLength, MaxLength, s.Length)
		}
		if s.Charset == "" {
			s.Charset = CharsetAlphanumeric
		}
		if _, err := alphabet(s.Charset); err != nil {
			return err
		}
		return nil
	case GeneratorSupplied:
		if scheduled {
			return fmt.Errorf("a scheduled rotation policy cannot use the %q generator: there is nobody to supply a value when the schedule fires", GeneratorSupplied)
		}
		if s.Value == "" {
			return fmt.Errorf("generator %q requires a value", GeneratorSupplied)
		}
		return nil
	default:
		return fmt.Errorf("generator type %q must be %s or %s", s.Type, GeneratorRandom, GeneratorSupplied)
	}
}

// Generate produces the new plaintext. The caller owns zeroizing it.
func (s Spec) Generate() ([]byte, error) {
	switch s.Type {
	case GeneratorSupplied:
		if s.Value == "" {
			return nil, fmt.Errorf("generator %q requires a value", GeneratorSupplied)
		}
		return []byte(s.Value), nil
	case GeneratorRandom, "":
		length := s.Length
		if length == 0 {
			length = DefaultLength
		}
		return randomString(s.Charset, length)
	default:
		return nil, fmt.Errorf("generator type %q is not supported", s.Type)
	}
}

// randomString draws length characters from the named charset using crypto/rand.
//
// The alphabet cases use REJECTION-FREE modular sampling via rand.Int over a
// big.Int bound, not `b % len(alphabet)`. The modulo version is biased whenever the
// alphabet size does not divide 256 — which it never does for these alphabets — and
// while the bias is small it is a self-inflicted reduction in the entropy of every
// credential this service generates, for no gain.
func randomString(charset string, length int) ([]byte, error) {
	switch charset {
	case CharsetHex:
		// Hex and base64 are generated from raw bytes rather than by sampling an
		// alphabet, because their encodings are exactly "N random bytes rendered" —
		// sampling the character set instead would produce the same alphabet with
		// less entropy per character than the encoding implies.
		raw := make([]byte, (length+1)/2)
		if _, err := rand.Read(raw); err != nil {
			return nil, fmt.Errorf("read random bytes: %w", err)
		}
		return []byte(hex.EncodeToString(raw)[:length]), nil
	case CharsetBase64URL:
		raw := make([]byte, length)
		if _, err := rand.Read(raw); err != nil {
			return nil, fmt.Errorf("read random bytes: %w", err)
		}
		encoded := base64.RawURLEncoding.EncodeToString(raw)
		return []byte(encoded[:length]), nil
	}

	alpha, err := alphabet(charset)
	if err != nil {
		return nil, err
	}
	bound := big.NewInt(int64(len(alpha)))
	out := make([]byte, length)
	for i := range out {
		n, err := rand.Int(rand.Reader, bound)
		if err != nil {
			return nil, fmt.Errorf("read random index: %w", err)
		}
		out[i] = alpha[n.Int64()]
	}
	return out, nil
}

func alphabet(charset string) (string, error) {
	switch charset {
	case CharsetAlphanumeric, "":
		return alphanumericAlphabet, nil
	case CharsetAlphanumericSymbols:
		return alphanumericAlphabet + symbolAlphabet, nil
	case CharsetHex, CharsetBase64URL:
		// Handled by randomString before it gets here; listed so the validator
		// accepts them.
		return "", nil
	default:
		return "", fmt.Errorf("charset %q must be one of %s, %s, %s, %s",
			charset, CharsetAlphanumeric, CharsetAlphanumericSymbols, CharsetHex, CharsetBase64URL)
	}
}

// Policy is a secret's rotation schedule, as stored in secrets.rotation_policy.
type Policy struct {
	Enabled bool `json:"enabled"`
	// Interval is a Go duration string ("720h", "30m"). A duration rather than a
	// cron expression on purpose: "every 90 days" is what a credential policy
	// actually says, and a cron expression invites "rotate at 03:00 on the first of
	// the month", which stampedes every secret in the store into one minute.
	Interval  string `json:"interval,omitempty"`
	Generator Spec   `json:"generator,omitempty"`
}

// MinInterval floors how often a policy may fire. A one-minute rotation is not a
// policy, it is a loop: every rotation writes a version, wakes every subscribed
// consumer, and prunes history, so a too-small interval quietly destroys the version
// history it is supposed to be building.
const MinInterval = time.Hour

// ParsePolicy reads a policy out of the JSONB map the store holds.
//
// A policy that does not parse is reported as an ERROR rather than as "disabled".
// Treating a malformed policy as disabled is the failure that matters here: the
// operator believes the credential rotates every 30 days, and it silently never
// rotates at all.
func ParsePolicy(raw map[string]any) (Policy, error) {
	var p Policy
	if len(raw) == 0 {
		return p, nil
	}
	switch v := raw["enabled"].(type) {
	case bool:
		p.Enabled = v
	case string:
		p.Enabled = strings.EqualFold(v, "true")
	case nil:
	default:
		return Policy{}, fmt.Errorf("rotation policy 'enabled' must be a boolean")
	}
	if s, ok := raw["interval"].(string); ok {
		p.Interval = s
	}
	if g, ok := raw["generator"].(map[string]any); ok {
		if t, ok := g["type"].(string); ok {
			p.Generator.Type = t
		}
		if c, ok := g["charset"].(string); ok {
			p.Generator.Charset = c
		}
		switch l := g["length"].(type) {
		case float64: // JSON numbers decode as float64
			p.Generator.Length = int(l)
		case int:
			p.Generator.Length = l
		}
		if v, ok := g["value"].(string); ok && v != "" {
			// A stored policy must NEVER carry a value: secrets.rotation_policy is
			// plaintext JSONB, readable by every metadata reader and returned in
			// every describe response, so a value there is a credential outside
			// encrypted custody. Writes are refused at the API boundary; this is the
			// backstop for a row that got one by any other route, and it refuses
			// loudly rather than quietly using it.
			return Policy{}, fmt.Errorf("rotation policy must not contain a generator value: the policy is stored as readable metadata")
		}
	}
	if !p.Enabled {
		return p, nil
	}
	if _, err := p.IntervalDuration(); err != nil {
		return Policy{}, err
	}
	if err := p.Generator.Validate(true); err != nil {
		return Policy{}, err
	}
	return p, nil
}

// IntervalDuration parses and bounds the interval.
func (p Policy) IntervalDuration() (time.Duration, error) {
	if p.Interval == "" {
		return 0, fmt.Errorf("an enabled rotation policy requires an interval (a duration such as \"720h\")")
	}
	d, err := time.ParseDuration(p.Interval)
	if err != nil {
		return 0, fmt.Errorf("rotation interval %q is not a duration (try \"720h\")", p.Interval)
	}
	if d < MinInterval {
		return 0, fmt.Errorf("rotation interval must be at least %s, got %s", MinInterval, d)
	}
	return d, nil
}

// NextDue returns when a secret last rotated (or created) at `last` becomes due.
//
// `last` is the LAST ROTATION if there is one, and the CREATION time otherwise. A
// secret that has never rotated must still become due — otherwise attaching a policy
// to an existing secret would never fire, and the operator would believe a
// credential is on a schedule it has never been on.
func (p Policy) NextDue(last time.Time) (time.Time, error) {
	d, err := p.IntervalDuration()
	if err != nil {
		return time.Time{}, err
	}
	return last.Add(d), nil
}

// Map renders the policy back into the JSONB shape, so a round trip through the
// store preserves it exactly. Omitting a zero generator keeps a hand-written policy
// from acquiring fields its author never set.
//
// Generator.Value is NEVER emitted — see the refusal in ParsePolicy for why a value
// may not live in stored policy metadata.
func (p Policy) Map() map[string]any {
	out := map[string]any{"enabled": p.Enabled}
	if p.Interval != "" {
		out["interval"] = p.Interval
	}
	if p.Generator.Type != "" || p.Generator.Length != 0 || p.Generator.Charset != "" {
		g := map[string]any{}
		if p.Generator.Type != "" {
			g["type"] = p.Generator.Type
		}
		if p.Generator.Length != 0 {
			g["length"] = p.Generator.Length
		}
		if p.Generator.Charset != "" {
			g["charset"] = p.Generator.Charset
		}
		out["generator"] = g
	}
	return out
}
