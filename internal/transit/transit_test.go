package transit

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"io"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/maintainerd/secret/internal/crypto"
)

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const (
	testTenantUUID = "6f1a0a1e-0000-4000-8000-000000000001"
	testKeyUUID    = "9c2b7d34-0000-4000-8000-0000000000aa"
	testKeyName    = "billing-pii"
)

// testMaterial builds deterministic key material, so a failure is reproducible.
func testMaterial(b byte) []byte { return bytes.Repeat([]byte{b}, crypto.KeySize) }

// randomMaterial is used where a test searches error messages for the key: a
// repeating byte pattern could coincidentally appear in a message and pass trivially.
func randomMaterial(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, crypto.KeySize)
	_, err := io.ReadFull(rand.Reader, k)
	require.NoError(t, err)
	return k
}

func testID(version int32) Identity {
	return Identity{TenantUUID: testTenantUUID, KeyUUID: testKeyUUID, KeyVersion: version}
}

// ---------------------------------------------------------------------------
// Round trip
// ---------------------------------------------------------------------------

func TestSealOpenRoundTrip(t *testing.T) {
	material := testMaterial(0x11)
	id := testID(1)
	plaintext := []byte("4111-1111-1111-1111")

	token, err := Seal(material, testKeyName, id, plaintext)
	require.NoError(t, err)

	// The token is the whole external surface, so the value must not be recoverable
	// from it without the key: a token lands in a database column, a URL and a log.
	assert.NotContains(t, token.String(), string(plaintext))
	assert.Len(t, token.Nonce, NonceSize)
	assert.Equal(t, testKeyName, token.KeyName)
	assert.EqualValues(t, 1, token.KeyVersion)

	got, err := Open(material, id, token)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got.Bytes())
}

func TestRoundTripPreservesEveryPlaintextShape(t *testing.T) {
	material := testMaterial(0x22)
	id := testID(3)

	for name, plaintext := range map[string][]byte{
		"empty":     {},
		"binary":    {0x00, 0xff, 0x7f, 0x80, 0x00},
		"multibyte": []byte("pässwörd-日本語"),
		"newline":   []byte("\n"),
		"long":      bytes.Repeat([]byte("a"), 64<<10),
	} {
		t.Run(name, func(t *testing.T) {
			token, err := Seal(material, testKeyName, id, plaintext)
			require.NoError(t, err)
			got, err := Open(material, id, token)
			require.NoError(t, err)
			// bytes.Equal rather than assert.Equal: GCM returns a nil slice for a
			// zero-length plaintext, and nil-versus-empty is not a difference in the
			// value a caller stored.
			assert.True(t, bytes.Equal(plaintext, got.Bytes()), "the round trip must preserve the value")
		})
	}
}

func TestTheWireFormRoundTripsThroughTheParser(t *testing.T) {
	// The token is the only thing the caller keeps. If String and ParseToken ever
	// disagreed, every stored ciphertext in the platform would become unreadable.
	material := testMaterial(0x33)
	id := testID(7)

	token, err := Seal(material, testKeyName, id, []byte("value"))
	require.NoError(t, err)

	raw := token.String()
	assert.True(t, strings.HasPrefix(raw, TokenPrefix+":"+TokenFormatV1+":"))
	assert.Len(t, strings.Split(raw, ":"), tokenFields)

	parsed, err := ParseToken(raw)
	require.NoError(t, err)
	assert.True(t, SameToken(token, parsed), "a parsed token must be identical to the one that was rendered")

	got, err := Open(material, id, parsed)
	require.NoError(t, err)
	assert.Equal(t, []byte("value"), got.Bytes())
}

// TestSealProducesAFreshNonceForIdenticalPlaintext is the one property whose loss is
// catastrophic rather than merely wrong: AES-GCM reusing a nonce under the same key
// leaks the XOR of the two plaintexts AND the authentication subkey, which lets an
// attacker forge tokens for that key version outright.
func TestSealProducesAFreshNonceForIdenticalPlaintext(t *testing.T) {
	material := testMaterial(0x44)
	id := testID(1)
	plaintext := []byte("the-same-value-every-time")

	const draws = 256
	nonces := make(map[string]struct{}, draws)
	ciphertexts := make(map[string]struct{}, draws)
	for i := 0; i < draws; i++ {
		token, err := Seal(material, testKeyName, id, plaintext)
		require.NoError(t, err)
		require.Len(t, token.Nonce, NonceSize)
		nonces[string(token.Nonce)] = struct{}{}
		ciphertexts[string(token.Ciphertext)] = struct{}{}
	}
	assert.Len(t, nonces, draws, "a repeated nonce under one key breaks GCM entirely")
	assert.Len(t, ciphertexts, draws, "two encryptions of one value must not be equal on the wire")
}

// ---------------------------------------------------------------------------
// Strict parsing
// ---------------------------------------------------------------------------

// TestParseTokenRefusesEveryMalformedShape. The parser is reachable by anyone who can
// call Decrypt, so it is the service's most exposed surface: it must refuse rather
// than panic, and it must refuse without telling a prober which field it disliked in
// terms that map to key state.
func TestParseTokenRefusesEveryMalformedShape(t *testing.T) {
	valid, err := Seal(testMaterial(0x55), testKeyName, testID(1), []byte("v"))
	require.NoError(t, err)
	payload := strings.Split(valid.String(), ":")[4]

	cases := map[string]string{
		"empty":                      "",
		"whitespace only":            "   \n\t ",
		"arbitrary garbage":          "not-a-token-at-all",
		"a bare uuid":                "9c2b7d34-0000-4000-8000-0000000000aa",
		"too few fields":             "m9dt:v1:key:1",
		"too many fields":            "m9dt:v1:key:1:" + payload + ":extra",
		"wrong prefix":               "m9db:v1:key:1:" + payload,
		"empty prefix":               ":v1:key:1:" + payload,
		"unsupported format":         "m9dt:v2:key:1:" + payload,
		"empty format":               "m9dt::key:1:" + payload,
		"no key named":               "m9dt:v1::1:" + payload,
		"non-numeric version":        "m9dt:v1:key:one:" + payload,
		"zero version":               "m9dt:v1:key:0:" + payload,
		"negative version":           "m9dt:v1:key:-1:" + payload,
		"empty version":              "m9dt:v1:key::" + payload,
		"version beyond int32":       "m9dt:v1:key:2147483648:" + payload,
		"padded base64":              "m9dt:v1:key:1:YWJjZA==",
		"standard base64 alphabet":   "m9dt:v1:key:1:a+b/cd",
		"not base64 at all":          "m9dt:v1:key:1:!!!!!!",
		"empty payload":              "m9dt:v1:key:1:",
		"payload shorter than nonce": "m9dt:v1:key:1:" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, NonceSize-1)),
		"payload with no tag":        "m9dt:v1:key:1:" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, NonceSize)),
		"payload one byte short":     "m9dt:v1:key:1:" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, NonceSize+gcmTagSize-1)),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			require.NotPanics(t, func() {
				token, err := ParseToken(raw)
				assert.Error(t, err, "ParseToken(%q) must be refused", raw)
				assert.Zero(t, token, "a refused token must not be partially populated")
			})
		})
	}
}

// TestParseTokenBoundsThePayloadBeforeDecoding. The length check exists so a caller
// cannot make the base64 decoder allocate an arbitrary buffer before any request
// limit has been consulted.
func TestParseTokenBoundsThePayloadBeforeDecoding(t *testing.T) {
	oversized := "m9dt:v1:key:1:" + strings.Repeat("A", MaxCiphertextChars)
	_, err := ParseToken(oversized)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "longer than")

	// And a payload exactly at the bound is a parse decision, not a length refusal.
	atBound := strings.Repeat("A", MaxCiphertextChars-len("m9dt:v1:key:1:"))
	_, err = ParseToken("m9dt:v1:key:1:" + atBound)
	if err != nil {
		assert.NotContains(t, err.Error(), "longer than", "a token at the bound must not be refused for length")
	}
}

func TestParseTokenTolerateSurroundingWhitespace(t *testing.T) {
	// A token travels through a shell, a YAML value and a copy-paste before it comes
	// back, and every one of those can add a newline.
	token, err := Seal(testMaterial(0x56), testKeyName, testID(1), []byte("v"))
	require.NoError(t, err)

	parsed, err := ParseToken("  " + token.String() + "\n")
	require.NoError(t, err)
	assert.True(t, SameToken(token, parsed))
}

// TestAKeyNameCarryingTheSeparatorCannotRoundTrip pins a dependency this format
// rests on: the store bounds a key name to a slug, so it cannot contain ':'. If that
// bound were ever relaxed, tokens would silently re-parse into a DIFFERENT key name
// and version — so the failure mode is asserted here to be loud rather than silent.
func TestAKeyNameCarryingTheSeparatorCannotRoundTrip(t *testing.T) {
	token, err := Seal(testMaterial(0x57), "billing:pii", testID(1), []byte("v"))
	require.NoError(t, err)

	_, err = ParseToken(token.String())
	require.Error(t, err, "a ':' in a key name must break parsing, not silently re-split the token")
}

// ---------------------------------------------------------------------------
// The identity binding
// ---------------------------------------------------------------------------

// TestOpenRefusesAnotherKeysMaterial. A token is a reference within a scope, not a
// self-authorizing capability: the material comes from the row the caller's own
// tenant resolved, so a token cannot be redeemed against a key it was not sealed
// under even if an attacker guesses the name.
func TestOpenRefusesAnotherKeysMaterial(t *testing.T) {
	keyA := testMaterial(0x61)
	keyB := testMaterial(0x62)
	id := testID(1)

	token, err := Seal(keyA, testKeyName, id, []byte("cardholder-name"))
	require.NoError(t, err)

	_, err = Open(keyB, id, token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed authentication")

	// And the right material still opens it, so the refusal above is about the key.
	_, err = Open(keyA, id, token)
	require.NoError(t, err)
}

// TestOpenRefusesAMismatchedIdentity is the attack the AAD exists to stop. Because
// the identity is rebuilt from the ROW the decrypt path resolved and never from the
// token, a token whose name or version was edited meets an AAD it was not sealed
// under. Without this, an edited token would decrypt under the wrong key version —
// or a ciphertext could be replayed into another tenant's row by anyone with a psql
// prompt.
func TestOpenRefusesAMismatchedIdentity(t *testing.T) {
	material := testMaterial(0x63)
	written := testID(4)
	token, err := Seal(material, testKeyName, written, []byte("staging-value"))
	require.NoError(t, err)

	mutations := map[string]func(Identity) Identity{
		"a different tenant":   func(id Identity) Identity { id.TenantUUID = "00000000-0000-4000-8000-000000000999"; return id },
		"a different key uuid": func(id Identity) Identity { id.KeyUUID = "00000000-0000-4000-8000-000000000abc"; return id },
		"an older version":     func(id Identity) Identity { id.KeyVersion = 3; return id },
		"a newer version":      func(id Identity) Identity { id.KeyVersion = 5; return id },
		"an empty tenant":      func(id Identity) Identity { id.TenantUUID = ""; return id },
		"an empty key uuid":    func(id Identity) Identity { id.KeyUUID = ""; return id },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			_, err := Open(material, mutate(written), token)
			require.Error(t, err, "a ciphertext must not open under a different identity")
			assert.Contains(t, err.Error(), "failed authentication")
		})
	}
}

// TestAVersionSegmentNamingAnotherVersionFailsAuthentication is the rotation
// property stated end to end: the caller stores one opaque string and never tracks
// key versions, so the token's version segment steers which material the store
// resolves. Editing that segment must fail the MAC rather than decrypt.
func TestAVersionSegmentNamingAnotherVersionFailsAuthentication(t *testing.T) {
	// Two versions of one key, as a rotation produces.
	v1Material := testMaterial(0x71)
	v2Material := testMaterial(0x72)

	token, err := Seal(v1Material, testKeyName, testID(1), []byte("pre-rotation-value"))
	require.NoError(t, err)

	// An attacker rewrites the version segment to 2, hoping the newer material opens
	// it. The store resolves v2's material and v2's AAD; both are wrong.
	edited := strings.Split(token.String(), ":")
	edited[3] = "2"
	parsed, err := ParseToken(strings.Join(edited, ":"))
	require.NoError(t, err, "the edit is well-formed, so it must reach the AEAD rather than the parser")
	assert.EqualValues(t, 2, parsed.KeyVersion)

	_, err = Open(v2Material, testID(2), parsed)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed authentication")

	// Even holding the ORIGINAL material, the rebuilt AAD names version 2 and fails.
	_, err = Open(v1Material, testID(2), parsed)
	require.Error(t, err)

	// The unedited token still opens under the version that sealed it.
	_, err = Open(v1Material, testID(1), token)
	require.NoError(t, err)
}

// TestAADIsInjective. Length-prefixing rather than delimiter-joining: with a
// separator these two identities would render identical AAD, and one key's
// ciphertext would open in the other's row.
func TestAADIsInjective(t *testing.T) {
	a := Identity{TenantUUID: "t", KeyUUID: "a|b", KeyVersion: 1}
	b := Identity{TenantUUID: "t|a", KeyUUID: "b", KeyVersion: 1}
	assert.NotEqual(t, a.AAD(), b.AAD())

	// The version participates, so a token cannot be rolled onto another version.
	assert.NotEqual(t, testID(1).AAD(), testID(2).AAD())

	// And the domain tag is present, so a transit AAD can never collide with the
	// secret-version AAD in internal/crypto — swapping those would let key material
	// and a secret value be opened as one another.
	assert.Contains(t, string(testID(1).AAD()), aadDomain)
	assert.Equal(t, testID(1).AAD(), testID(1).AAD(), "the rendering must be deterministic")
}

// ---------------------------------------------------------------------------
// Tamper detection
// ---------------------------------------------------------------------------

// TestOpenDetectsTampering. A token sits in a column an application owns, so its
// bytes are attacker-reachable in any deployment where the application is. Every
// modification must be a refusal, never a decryption of something adjacent.
func TestOpenDetectsTampering(t *testing.T) {
	material := testMaterial(0x81)
	id := testID(1)
	plaintext := []byte("tamper-me-please")

	tamper := map[string]func(*Token){
		"first ciphertext byte flipped": func(tk *Token) { tk.Ciphertext[0] ^= 0x01 },
		"last ciphertext byte flipped":  func(tk *Token) { tk.Ciphertext[len(tk.Ciphertext)-1] ^= 0x80 },
		"middle ciphertext byte":        func(tk *Token) { tk.Ciphertext[len(tk.Ciphertext)/2] ^= 0xff },
		"first nonce byte flipped":      func(tk *Token) { tk.Nonce[0] ^= 0x01 },
		"last nonce byte flipped":       func(tk *Token) { tk.Nonce[NonceSize-1] ^= 0x01 },
		"nonce zeroed":                  func(tk *Token) { copy(tk.Nonce, make([]byte, NonceSize)) },
		"ciphertext truncated":          func(tk *Token) { tk.Ciphertext = tk.Ciphertext[:len(tk.Ciphertext)-1] },
		"ciphertext extended":           func(tk *Token) { tk.Ciphertext = append(tk.Ciphertext, 0x00) },
		"tag stripped":                  func(tk *Token) { tk.Ciphertext = tk.Ciphertext[:len(tk.Ciphertext)-gcmTagSize] },
	}
	for name, mutate := range tamper {
		t.Run(name, func(t *testing.T) {
			token, err := Seal(material, testKeyName, id, plaintext)
			require.NoError(t, err)
			// Clone the slices so a mutation cannot alias the fixture.
			token.Nonce = bytes.Clone(token.Nonce)
			token.Ciphertext = bytes.Clone(token.Ciphertext)
			mutate(&token)

			_, err = Open(material, id, token)
			require.Error(t, err, "authenticated encryption must reject a modified token")
		})
	}
}

// TestEveryFlippedBitIsDetected sweeps the whole payload rather than sampling it, so
// a partial MAC (a tag covering only part of the ciphertext, say) cannot pass.
func TestEveryFlippedBitIsDetected(t *testing.T) {
	material := testMaterial(0x82)
	id := testID(1)
	token, err := Seal(material, testKeyName, id, []byte("short-value"))
	require.NoError(t, err)

	for i := range token.Ciphertext {
		mutated := token
		mutated.Ciphertext = bytes.Clone(token.Ciphertext)
		mutated.Ciphertext[i] ^= 0x01
		_, err := Open(material, id, mutated)
		require.Error(t, err, "flipping ciphertext byte %d must be detected", i)
	}
	for i := range token.Nonce {
		mutated := token
		mutated.Nonce = bytes.Clone(token.Nonce)
		mutated.Nonce[i] ^= 0x01
		_, err := Open(material, id, mutated)
		require.Error(t, err, "flipping nonce byte %d must be detected", i)
	}
}

// ---------------------------------------------------------------------------
// Input validation
// ---------------------------------------------------------------------------

func TestSealRefusesUnusableInput(t *testing.T) {
	id := testID(1)

	t.Run("material of the wrong length", func(t *testing.T) {
		for _, size := range []int{0, 1, 16, 31, 33, 64} {
			_, err := Seal(make([]byte, size), testKeyName, id, []byte("v"))
			require.Error(t, err, "AES-256 needs exactly %d bytes, not %d", crypto.KeySize, size)
		}
	})
	t.Run("nil material", func(t *testing.T) {
		_, err := Seal(nil, testKeyName, id, []byte("v"))
		require.Error(t, err)
	})
	t.Run("a version below one", func(t *testing.T) {
		// A version of zero is an unset field, and sealing under it would produce a
		// token whose version segment can never resolve a row.
		for _, v := range []int32{0, -1} {
			_, err := Seal(testMaterial(0x91), testKeyName, testID(v), []byte("v"))
			require.Error(t, err)
		}
	})
	t.Run("a nil plaintext", func(t *testing.T) {
		// Distinct from an empty one: nil is a caller that forgot a field, and empty
		// is a caller that meant it.
		_, err := Seal(testMaterial(0x91), testKeyName, id, nil)
		require.Error(t, err)

		_, err = Seal(testMaterial(0x91), testKeyName, id, []byte{})
		require.NoError(t, err, "an empty value is a value")
	})
}

func TestOpenRefusesUnusableInput(t *testing.T) {
	material := testMaterial(0x92)
	id := testID(1)
	token, err := Seal(material, testKeyName, id, []byte("v"))
	require.NoError(t, err)

	for _, size := range []int{0, 16, 31, 33} {
		_, err := Open(make([]byte, size), id, token)
		require.Error(t, err, "material of %d bytes must be refused", size)
	}

	// A nonce of the wrong length is refused before the AEAD is asked, so Open never
	// has to defend against a slice bound it did not choose.
	for _, size := range []int{0, 1, NonceSize - 1, NonceSize + 1} {
		short := token
		short.Nonce = make([]byte, size)
		_, err := Open(material, id, short)
		require.Error(t, err, "a nonce of %d bytes must be refused", size)
	}
}

// ---------------------------------------------------------------------------
// Errors carry nothing
// ---------------------------------------------------------------------------

// TestErrorsCarryNoPlaintextOrKeyMaterial sweeps every error-producing path in this
// package. Errors are the most common accidental exfiltration route in a secret
// store: they land in logs, in traces, in a 500 body, and in a bug report pasted
// into a ticket — and here the two things that must never appear are the value the
// caller encrypted and the key it was encrypted under.
func TestErrorsCarryNoPlaintextOrKeyMaterial(t *testing.T) {
	const plaintext = "TOP-SECRET-CARDHOLDER-VALUE"
	material := randomMaterial(t)
	other := randomMaterial(t)
	id := testID(1)

	token, err := Seal(material, testKeyName, id, []byte(plaintext))
	require.NoError(t, err)

	tampered := token
	tampered.Ciphertext = bytes.Clone(token.Ciphertext)
	tampered.Ciphertext[0] ^= 0xff

	wrongIdentity := id
	wrongIdentity.KeyUUID = "00000000-0000-4000-8000-00000000ffff"

	shortNonce := token
	shortNonce.Nonce = token.Nonce[:4]

	errs := map[string]error{}
	collect := func(name string, err error) {
		require.Error(t, err, name+" was expected to fail")
		errs[name] = err
	}

	_, err = Open(other, id, token)
	collect("wrong key material", err)
	_, err = Open(material, wrongIdentity, token)
	collect("identity mismatch", err)
	_, err = Open(material, id, tampered)
	collect("tampered ciphertext", err)
	_, err = Open(material, id, shortNonce)
	collect("short nonce", err)
	_, err = Open(material[:16], id, token)
	collect("truncated material on open", err)
	_, err = Seal(material[:16], testKeyName, id, []byte(plaintext))
	collect("truncated material on seal", err)
	_, err = Seal(material, testKeyName, testID(0), []byte(plaintext))
	collect("bad version", err)
	_, err = Seal(material, testKeyName, id, nil)
	collect("nil plaintext", err)
	_, err = ParseToken(token.String() + ":extra")
	collect("malformed token", err)
	_, err = ParseToken("m9dt:v1:" + testKeyName + ":1:" + base64.RawURLEncoding.EncodeToString([]byte(plaintext)))
	collect("a token whose payload is the plaintext", err)

	forbidden := map[string]string{
		"plaintext":             plaintext,
		"plaintext hex":         hex.EncodeToString([]byte(plaintext)),
		"plaintext base64":      base64.StdEncoding.EncodeToString([]byte(plaintext)),
		"plaintext base64url":   base64.RawURLEncoding.EncodeToString([]byte(plaintext)),
		"key material":          string(material),
		"key material hex":      hex.EncodeToString(material),
		"key material base64":   base64.StdEncoding.EncodeToString(material),
		"key material b64url":   base64.RawURLEncoding.EncodeToString(material),
		"other key material":    string(other),
		"other material hex":    hex.EncodeToString(other),
		"first half of the key": hex.EncodeToString(material[:16]),
	}
	for name, err := range errs {
		msg := err.Error()
		for label, secret := range forbidden {
			assert.NotContains(t, msg, secret, "error %q leaked the %s", name, label)
		}
		// Sanity: the assertions above would pass trivially on an empty message.
		assert.NotEmpty(t, msg, "error %q must still say something an engineer can act on", name)
	}
}

// TestOpenIsNotAProbingOracle. Wrong key, wrong version, a tampered payload and a
// token moved between tenants all read the same, so a prober learns nothing about
// which part of its guess was wrong.
func TestOpenIsNotAProbingOracle(t *testing.T) {
	material := testMaterial(0xa1)
	id := testID(2)
	token, err := Seal(material, testKeyName, id, []byte("v"))
	require.NoError(t, err)

	wrongKey := testID(2)
	wrongTenant := id
	wrongTenant.TenantUUID = "00000000-0000-4000-8000-000000000999"
	tampered := token
	tampered.Ciphertext = bytes.Clone(token.Ciphertext)
	tampered.Ciphertext[0] ^= 0xff

	_, errWrongKey := Open(testMaterial(0xa2), wrongKey, token)
	_, errWrongTenant := Open(material, wrongTenant, token)
	_, errTampered := Open(material, id, tampered)

	require.Error(t, errWrongKey)
	require.Error(t, errWrongTenant)
	require.Error(t, errTampered)
	assert.Equal(t, errWrongKey.Error(), errWrongTenant.Error())
	assert.Equal(t, errWrongKey.Error(), errTampered.Error())
}

// ---------------------------------------------------------------------------
// SameToken
// ---------------------------------------------------------------------------

// TestSameTokenComparesTokensNotPlaintexts. The doc warns that two seals of one
// value are never equal; a caller reaching for this as a value-equality test would
// get a permanent false, so the property is pinned rather than left to the comment.
func TestSameTokenComparesTokensNotPlaintexts(t *testing.T) {
	material := testMaterial(0xb1)
	id := testID(1)

	first, err := Seal(material, testKeyName, id, []byte("same"))
	require.NoError(t, err)
	second, err := Seal(material, testKeyName, id, []byte("same"))
	require.NoError(t, err)

	assert.True(t, SameToken(first, first))
	assert.False(t, SameToken(first, second), "a random nonce per call means two seals are never equal")

	// Every field participates, so a token differing only in its metadata is not the
	// same token.
	renamed := first
	renamed.KeyName = "other-key"
	assert.False(t, SameToken(first, renamed))

	reversioned := first
	reversioned.KeyVersion = first.KeyVersion + 1
	assert.False(t, SameToken(first, reversioned))

	shortened := first
	shortened.Ciphertext = first.Ciphertext[:len(first.Ciphertext)-1]
	assert.False(t, SameToken(first, shortened), "a length difference must not compare equal")

	assert.True(t, SameToken(Token{}, Token{}), "the zero token must not panic the comparison")
}

// TestTokenVersionRendersAsADecimalInteger guards the one field the parser reads
// back with strconv: a rendering change here would make every existing token
// unparseable.
func TestTokenVersionRendersAsADecimalInteger(t *testing.T) {
	for _, version := range []int32{1, 9, 10, 4095, 2147483647} {
		token := Token{
			KeyName:    testKeyName,
			KeyVersion: version,
			Nonce:      make([]byte, NonceSize),
			Ciphertext: make([]byte, gcmTagSize),
		}
		parts := strings.Split(token.String(), ":")
		require.Len(t, parts, tokenFields)
		assert.Equal(t, strconv.FormatInt(int64(version), 10), parts[3])

		parsed, err := ParseToken(token.String())
		require.NoError(t, err)
		assert.Equal(t, version, parsed.KeyVersion)
	}
}
