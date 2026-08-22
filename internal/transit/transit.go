// Package transit is encryption as a service: the token format, and the AES-256-GCM
// seal and open that produce and consume it. It holds no storage — internal/store owns
// the key rows and their envelope-wrapped material, and internal/api owns
// authorization and the audit trail.
//
// # What it is for
//
// An application that needs to encrypt a column — a national id, a bank account
// number, a clinical note — has to hold a key to do it. Once it does, that key is in
// the application's memory, its configuration, its crash dumps, its container image
// and its developers' laptops, and every service that must decrypt gets a copy. The
// key stops being a secret and becomes a distribution problem.
//
// Transit inverts it. The application holds NO key. It calls Encrypt with a key NAME
// and gets a token back; it calls Decrypt with the token and gets its plaintext. The
// key material exists only inside this service, sealed under the root key exactly as a
// secret version is, and rotating it is an operation the application never learns
// about.
//
// # THERE IS NO EXPORT OPERATION, AND THAT IS THE DESIGN
//
// This package deliberately provides no way to read key material out — no Export, no
// "backup" mode, no admin escape hatch, and no query in internal/storage that selects
// the material columns outside the two the seal and open paths need. An exportable
// transit key is an ordinary secret with extra steps: the moment the material can be
// fetched, every argument above collapses, because the key is in the caller's memory
// again and this service is just a slower way to have distributed it.
//
// If a caller genuinely needs to hold a key, it should store one as a secret and say
// so. Conflating the two would mean an operator who chose transit for its central
// custody property could lose it to a single API call somebody added later.
//
// # The token format
//
// A token is ASCII, single-line, safe in JSON, a URL and a database column:
//
//	m9dt:v1:<key-name>:<key-version>:<base64url-nopad(nonce || ciphertext)>
//
//	m9dt          a fixed prefix, so a token is recognisable in a log or a column
//	              and cannot be confused with any other opaque string the platform
//	              emits.
//	v1            the FORMAT version, not the key version. It is what lets the
//	              encoding change later without a migration: a v2 encoder emits v2
//	              and a v1 token keeps being read by the v1 decoder.
//	key-name      the transit key the caller encrypted under. Bounded to a slug by
//	              the store, so it cannot contain the ':' delimiter.
//	key-version   the KEY's version. THIS IS THE FIELD THE WHOLE FORMAT EXISTS FOR:
//	              a rotated key keeps its old versions, and decrypt has to open the
//	              version that sealed this token. Carrying it in the token means the
//	              CALLER never has to track key versions — it stores one opaque
//	              string and this service works out which material to use. Without
//	              it, rotation would either break every stored ciphertext or force
//	              every application to maintain a version column beside every
//	              encrypted column.
//	payload       the GCM nonce followed by the ciphertext, base64url without
//	              padding. Unpadded because '=' is awkward in a URL and in a shell;
//	              url-safe because a token belongs in a path or a query without
//	              re-encoding.
//
// Note what the token does NOT carry: no tenant, no project, no key UUID. Those are
// resolved from the CALLER's authenticated context on decrypt, never from the token,
// so a token cannot name a key in a tenant its holder has no grant in. A token is a
// reference within a scope, not a self-authorizing capability.
//
// # AAD
//
// Every seal binds (tenant UUID, key UUID, key version) as additional authenticated
// data, for the reason internal/crypto binds a secret's identity: without it a
// ciphertext is a free-floating blob that could be replayed under a different key or a
// different version. Because the AAD is rebuilt from the ROW the decrypt path
// resolved — not from the token — a token whose key name or version has been edited
// fails authentication rather than opening under the wrong material.
package transit

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/maintainerd/secret/internal/crypto"
)

// Token format constants.
const (
	// TokenPrefix is the fixed leader every token carries.
	TokenPrefix = "m9dt"
	// TokenFormatV1 is the current encoding version. It is the FORMAT's version and
	// has nothing to do with a key's version.
	TokenFormatV1 = "v1"
	// tokenSeparator is ':'. Every field before the payload is constrained (a slug, a
	// decimal integer, a fixed literal) so none of them can contain it.
	tokenSeparator = ":"
	// tokenFields is the number of ':'-separated fields in a v1 token.
	tokenFields = 5
)

// MaxCiphertextChars bounds the encoded payload a Decrypt will even attempt to parse.
//
// It is a parser bound, not a policy bound: the plaintext size limit lives in
// internal/api (where every request limit lives, so one transport cannot have a
// different one). This exists so a caller cannot make the base64 decoder allocate an
// arbitrary buffer before any limit has been consulted.
const MaxCiphertextChars = 1 << 20 // 1 MiB of base64, ~768 KiB of payload

// tokenEncoding is base64url without padding — url-safe because a token belongs in a
// path or a query string, unpadded because '=' is awkward in both.
var tokenEncoding = base64.RawURLEncoding

// aadDomain is a version tag on the AAD construction, so a future encoding change
// gets a new tag and rows written under v1 keep opening under v1. Same discipline as
// internal/crypto's aadDomain, and deliberately a DIFFERENT string: a transit AAD and
// a secret-version AAD must never collide, or key material and a secret value could
// be swapped for one another.
const aadDomain = "maintainerd-secret/transit/aad/v1"

// Identity is the coordinate a transit ciphertext is bound to.
type Identity struct {
	// TenantUUID is the tenant's stable UUID. A ciphertext cannot be moved across
	// tenants even by an operator with a psql prompt.
	TenantUUID string
	// KeyUUID is the transit key's stable UUID, not its name: names are renameable
	// and a rename must not invalidate every token ever issued under the key.
	KeyUUID string
	// KeyVersion is the key version that sealed the payload.
	KeyVersion int32
}

// AAD renders the identity into the exact bytes bound to a ciphertext.
//
// Fields are LENGTH-PREFIXED rather than delimiter-joined, for the reason
// crypto.Identity.AAD is: with a separator, ("a", "b|c") and ("a|b", "c") produce
// identical AAD and one key's ciphertext would open under another's. Length prefixes
// make the encoding injective.
func (id Identity) AAD() []byte {
	var b strings.Builder
	b.WriteString(aadDomain)
	for _, field := range []string{id.TenantUUID, id.KeyUUID} {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(field)))
		b.Write(n[:])
		b.WriteString(field)
	}
	var v [4]byte
	binary.BigEndian.PutUint32(v[:], uint32(id.KeyVersion))
	b.Write(v[:])
	return []byte(b.String())
}

// Token is a parsed ciphertext token.
type Token struct {
	// KeyName is the transit key the payload was sealed under.
	KeyName string
	// KeyVersion is the key version that sealed it — the field that makes rotation
	// invisible to the caller.
	KeyVersion int32
	// Nonce is the GCM nonce.
	Nonce []byte
	// Ciphertext is the sealed payload.
	Ciphertext []byte
}

// String renders the token in wire form.
func (t Token) String() string {
	payload := make([]byte, 0, len(t.Nonce)+len(t.Ciphertext))
	payload = append(payload, t.Nonce...)
	payload = append(payload, t.Ciphertext...)
	return strings.Join([]string{
		TokenPrefix,
		TokenFormatV1,
		t.KeyName,
		strconv.FormatInt(int64(t.KeyVersion), 10),
		tokenEncoding.EncodeToString(payload),
	}, tokenSeparator)
}

// ParseToken reads a wire token.
//
// EVERY FAILURE HERE IS THE SAME ERROR CLASS on purpose: a malformed token, an unknown
// format version and a truncated payload are all "this is not a token I issued", and
// distinguishing them for the caller would turn the parser into an oracle a probing
// attacker can walk. The messages are specific enough for an engineer holding the
// token to fix their own bug and say nothing about any key.
func ParseToken(raw string) (Token, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Token{}, fmt.Errorf("transit: a ciphertext token is required")
	}
	if len(raw) > MaxCiphertextChars {
		return Token{}, fmt.Errorf("transit: ciphertext token is longer than %d characters", MaxCiphertextChars)
	}
	parts := strings.Split(raw, tokenSeparator)
	if len(parts) != tokenFields {
		return Token{}, fmt.Errorf("transit: ciphertext token must have the form %s:%s:<key>:<version>:<payload>",
			TokenPrefix, TokenFormatV1)
	}
	if parts[0] != TokenPrefix {
		return Token{}, fmt.Errorf("transit: ciphertext token does not carry the %s prefix", TokenPrefix)
	}
	if parts[1] != TokenFormatV1 {
		return Token{}, fmt.Errorf("transit: ciphertext token format %q is not supported", parts[1])
	}
	if parts[2] == "" {
		return Token{}, fmt.Errorf("transit: ciphertext token names no key")
	}
	version, err := strconv.ParseInt(parts[3], 10, 32)
	if err != nil || version < 1 {
		return Token{}, fmt.Errorf("transit: ciphertext token key version %q is not a positive integer", parts[3])
	}
	payload, err := tokenEncoding.DecodeString(parts[4])
	if err != nil {
		return Token{}, fmt.Errorf("transit: ciphertext token payload is not valid base64url")
	}
	// A payload has to be at least a nonce plus GCM's 16-byte tag. Checking the floor
	// here keeps Open from having to defend against a negative slice bound.
	if len(payload) < NonceSize+gcmTagSize {
		return Token{}, fmt.Errorf("transit: ciphertext token payload is too short to be a sealed value")
	}
	return Token{
		KeyName:    parts[2],
		KeyVersion: int32(version),
		Nonce:      payload[:NonceSize],
		Ciphertext: payload[NonceSize:],
	}, nil
}

// NonceSize is AES-GCM's standard 96-bit nonce, in bytes. Fixed rather than read from
// the cipher because it is part of the token FORMAT: a parser has to know where the
// nonce ends before it has built a cipher.
const NonceSize = 12

// gcmTagSize is AES-GCM's authentication tag length in bytes.
const gcmTagSize = 16

// Seal encrypts plaintext under the given key material and returns a token.
//
// The material is the transit key version's own 32-byte key, decrypted from its
// envelope by the store immediately before this call. It is NOT zeroized here — the
// caller owns it and reuses it across a batch — which is why every caller in this
// repo defers crypto.Zero on it.
func Seal(material []byte, keyName string, id Identity, plaintext []byte) (Token, error) {
	if len(material) != crypto.KeySize {
		return Token{}, fmt.Errorf("transit: key material must be %d bytes, got %d", crypto.KeySize, len(material))
	}
	if id.KeyVersion < 1 {
		return Token{}, fmt.Errorf("transit: key version must be at least 1, got %d", id.KeyVersion)
	}
	if plaintext == nil {
		return Token{}, fmt.Errorf("transit: a plaintext is required")
	}
	aead, err := newAEAD(material)
	if err != nil {
		return Token{}, err
	}
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return Token{}, fmt.Errorf("transit: read nonce: %w", err)
	}
	return Token{
		KeyName:    keyName,
		KeyVersion: id.KeyVersion,
		Nonce:      nonce,
		Ciphertext: aead.Seal(nil, nonce, plaintext, id.AAD()),
	}, nil
}

// Open reverses Seal.
//
// A failure is reported as an authentication failure without elaboration, exactly as
// crypto.Open is: wrong key, wrong version, tampered ciphertext and a token moved
// between tenants are all "this does not belong to this identity under this key", and
// telling them apart would hand an attacker a probing oracle.
//
// THE IDENTITY COMES FROM THE RESOLVED ROW, NOT FROM THE TOKEN. The caller looks the
// key up by name within its own authenticated tenant and project, reads the version
// the token names, and builds the identity from what it found. A token whose name or
// version was edited therefore meets an AAD it was not sealed under and fails here.
func Open(material []byte, id Identity, t Token) (crypto.Plaintext, error) {
	if len(material) != crypto.KeySize {
		return nil, fmt.Errorf("transit: key material must be %d bytes, got %d", crypto.KeySize, len(material))
	}
	aead, err := newAEAD(material)
	if err != nil {
		return nil, err
	}
	if len(t.Nonce) != NonceSize {
		return nil, fmt.Errorf("transit: nonce must be %d bytes, got %d", NonceSize, len(t.Nonce))
	}
	plaintext, err := aead.Open(nil, t.Nonce, t.Ciphertext, id.AAD())
	if err != nil {
		return nil, fmt.Errorf("transit: decrypting under key %s version %d failed authentication",
			t.KeyName, t.KeyVersion)
	}
	return plaintext, nil
}

// newAEAD builds the AES-256-GCM AEAD for a piece of key material.
func newAEAD(material []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(material)
	if err != nil {
		return nil, fmt.Errorf("transit: build cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("transit: build gcm: %w", err)
	}
	return aead, nil
}

// SameToken reports whether two tokens are byte-identical, in constant time over the
// payload.
//
// It exists for tests and for a caller that wants to check "did re-encrypting produce
// the same token" without a timing side channel on the ciphertext. Two seals of the
// same plaintext are NEVER equal in practice — the nonce is random per call — so a
// caller using this as a plaintext-equality test is making a mistake, and the doc says
// so rather than the function pretending to be one.
func SameToken(a, b Token) bool {
	if a.KeyName != b.KeyName || a.KeyVersion != b.KeyVersion {
		return false
	}
	return subtle.ConstantTimeCompare(a.Nonce, b.Nonce) == 1 &&
		subtle.ConstantTimeCompare(a.Ciphertext, b.Ciphertext) == 1
}
