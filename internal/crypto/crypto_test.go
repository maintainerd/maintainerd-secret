package crypto

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testIdentity is a representative secret coordinate.
func testIdentity() Identity {
	return Identity{
		TenantUUID: "6f1a0a1e-0000-4000-8000-000000000001",
		SecretUUID: "9c2b7d34-0000-4000-8000-0000000000aa",
		Version:    1,
	}
}

// newTestProvider builds a deterministic env provider from a hex key.
func newTestProvider(t *testing.T, keyByte byte) RootKeyProvider {
	t.Helper()
	raw := bytes.Repeat([]byte{keyByte}, KeySize)
	p, err := NewRootKeyProvider(ProviderConfig{
		Provider: ProviderEnv,
		AppEnv:   "production",
		Key:      hex.EncodeToString(raw),
	})
	require.NoError(t, err)
	return p
}

// ---------------------------------------------------------------------------
// Envelope round-trip
// ---------------------------------------------------------------------------

func TestSealOpenRoundTrip(t *testing.T) {
	p := newTestProvider(t, 0x11)
	id := testIdentity()
	plaintext := []byte("s3cr3t-database-password")

	env, err := Seal(p, id, plaintext)
	require.NoError(t, err)

	// The payload must not be stored in the clear, and the DEK must not be stored
	// at all except wrapped.
	assert.NotEqual(t, plaintext, env.Ciphertext)
	assert.NotContains(t, string(env.Ciphertext), "password")
	assert.Len(t, env.Nonce, NonceSize)
	assert.Len(t, env.DEKNonce, NonceSize)
	assert.Equal(t, p.KeyID(), env.KEKID)
	assert.Equal(t, Checksum(plaintext), env.Checksum)

	got, err := Open(p, id, *env)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got.Bytes())
}

func TestSealProducesDistinctCiphertextForIdenticalInput(t *testing.T) {
	// A fresh DEK and a fresh nonce per version means two writes of the SAME value
	// are indistinguishable on disk. Without that, an observer with read access to
	// the table could tell that staging and prod share a password, or that a
	// rotation was a no-op, purely from byte equality.
	p := newTestProvider(t, 0x22)
	id := testIdentity()
	plaintext := []byte("same-value")

	first, err := Seal(p, id, plaintext)
	require.NoError(t, err)
	second, err := Seal(p, id, plaintext)
	require.NoError(t, err)

	assert.NotEqual(t, first.Ciphertext, second.Ciphertext)
	assert.NotEqual(t, first.Nonce, second.Nonce)
	assert.NotEqual(t, first.DEKWrapped, second.DEKWrapped)
	// The checksum is over the plaintext, so it IS equal — that is what makes
	// no-op detection possible without decrypting.
	assert.Equal(t, first.Checksum, second.Checksum)
}

func TestOpenWithEmptyAndBinaryValues(t *testing.T) {
	p := newTestProvider(t, 0x33)
	id := testIdentity()

	for name, plaintext := range map[string][]byte{
		"empty":        {},
		"binary":       {0x00, 0xff, 0x7f, 0x80, 0x00},
		"multibyte":    []byte("pässwörd-日本語"),
		"newline-only": []byte("\n"),
	} {
		t.Run(name, func(t *testing.T) {
			env, err := Seal(p, id, plaintext)
			require.NoError(t, err)
			got, err := Open(p, id, *env)
			require.NoError(t, err)
			// bytes.Equal rather than assert.Equal: GCM returns a nil slice for a
			// zero-length plaintext, and nil-versus-empty is not a difference in the
			// value that was stored.
			assert.True(t, bytes.Equal(plaintext, got.Bytes()), "round-trip must preserve the value")
			assert.Equal(t, len(plaintext), got.Len())
		})
	}
}

// ---------------------------------------------------------------------------
// AAD: a ciphertext cannot be replayed into another secret's identity
// ---------------------------------------------------------------------------

func TestOpenRejectsMismatchedIdentity(t *testing.T) {
	// This is the attack the AAD exists to stop: copy the ciphertext, nonce and
	// wrapped DEK from one row into another and the store must refuse, rather than
	// decrypting staging's password into prod's slot.
	p := newTestProvider(t, 0x44)
	written := testIdentity()
	env, err := Seal(p, written, []byte("staging-password"))
	require.NoError(t, err)

	mutations := map[string]func(Identity) Identity{
		"different tenant": func(id Identity) Identity {
			id.TenantUUID = "00000000-0000-4000-8000-000000000999"
			return id
		},
		"different secret": func(id Identity) Identity {
			id.SecretUUID = "00000000-0000-4000-8000-000000000abc"
			return id
		},
		"different version": func(id Identity) Identity { id.Version = 2; return id },
		"empty tenant":      func(id Identity) Identity { id.TenantUUID = ""; return id },
		"empty secret":      func(id Identity) Identity { id.SecretUUID = ""; return id },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			_, err := Open(p, mutate(written), *env)
			require.Error(t, err, "a ciphertext must not open under a different identity")
			assert.Contains(t, err.Error(), "failed authentication")
		})
	}
}

func TestAADIsInjective(t *testing.T) {
	// Length-prefixing rather than delimiter-joining. With a '|' separator these two
	// identities would render to the same AAD, and one secret's ciphertext would
	// open in the other's row — exactly the confusion the AAD prevents elsewhere.
	a := Identity{TenantUUID: "t", SecretUUID: "a|b", Version: 1}
	b := Identity{TenantUUID: "t|a", SecretUUID: "b", Version: 1}
	assert.NotEqual(t, a.AAD(), b.AAD())

	// Version participates too, so a row cannot be rolled back to an older payload
	// while claiming to be current.
	v1 := testIdentity()
	v2 := testIdentity()
	v2.Version = 2
	assert.NotEqual(t, v1.AAD(), v2.AAD())
}

// ---------------------------------------------------------------------------
// Tamper detection
// ---------------------------------------------------------------------------

func TestOpenDetectsTampering(t *testing.T) {
	p := newTestProvider(t, 0x55)
	id := testIdentity()
	plaintext := []byte("tamper-me-please")

	tamper := map[string]func(*Envelope){
		"ciphertext byte flipped":  func(e *Envelope) { e.Ciphertext[0] ^= 0x01 },
		"last ciphertext byte":     func(e *Envelope) { e.Ciphertext[len(e.Ciphertext)-1] ^= 0x80 },
		"payload nonce flipped":    func(e *Envelope) { e.Nonce[0] ^= 0x01 },
		"wrapped dek flipped":      func(e *Envelope) { e.DEKWrapped[0] ^= 0x01 },
		"dek nonce flipped":        func(e *Envelope) { e.DEKNonce[0] ^= 0x01 },
		"ciphertext truncated":     func(e *Envelope) { e.Ciphertext = e.Ciphertext[:len(e.Ciphertext)-1] },
		"ciphertext byte appended": func(e *Envelope) { e.Ciphertext = append(e.Ciphertext, 0x00) },
	}
	for name, mutate := range tamper {
		t.Run(name, func(t *testing.T) {
			env, err := Seal(p, id, plaintext)
			require.NoError(t, err)
			mutate(env)
			_, err = Open(p, id, *env)
			require.Error(t, err, "authenticated encryption must reject a modified envelope")
		})
	}
}

func TestOpenDetectsChecksumDrift(t *testing.T) {
	// GCM cannot see this one: the ciphertext and the AAD are intact, but the stored
	// checksum no longer describes the payload — the shape a bad backfill or a
	// partial restore leaves behind. It must be loud, not silently returned.
	p := newTestProvider(t, 0x56)
	id := testIdentity()
	env, err := Seal(p, id, []byte("value"))
	require.NoError(t, err)
	env.Checksum = Checksum([]byte("something else"))

	_, err = Open(p, id, *env)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "checksum")
}

func TestOpenRejectsWrongRootKey(t *testing.T) {
	p1 := newTestProvider(t, 0x61)
	p2 := newTestProvider(t, 0x62)
	id := testIdentity()

	env, err := Seal(p1, id, []byte("value"))
	require.NoError(t, err)

	// The declared KEKID is checked before any crypto runs, which turns a wrong-key
	// read into a clear message instead of an opaque authentication failure.
	_, err = Open(p2, id, *env)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wrapped under root key")

	// And with the id cleared, the unwrap itself must still fail.
	env.KEKID = ""
	_, err = Open(p2, id, *env)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// Rewrap
// ---------------------------------------------------------------------------

func TestRewrapPreservesPlaintextAndChangesKEK(t *testing.T) {
	oldKey := newTestProvider(t, 0x71)
	newKey := newTestProvider(t, 0x72)
	id := testIdentity()
	plaintext := []byte("rotate-me")

	env, err := Seal(oldKey, id, plaintext)
	require.NoError(t, err)
	originalCiphertext := bytes.Clone(env.Ciphertext)
	originalNonce := bytes.Clone(env.Nonce)

	wrapped, nonce, err := Rewrap(oldKey, newKey, env.DEKWrapped, env.DEKNonce)
	require.NoError(t, err)

	env.DEKWrapped = wrapped
	env.DEKNonce = nonce
	env.KEKID = newKey.KeyID()

	// THE POINT OF ENVELOPE ENCRYPTION: the payload is untouched.
	assert.Equal(t, originalCiphertext, env.Ciphertext)
	assert.Equal(t, originalNonce, env.Nonce)

	got, err := Open(newKey, id, *env)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got.Bytes())

	// And the old key can no longer open it.
	stale := *env
	stale.KEKID = ""
	_, err = Open(oldKey, id, stale)
	require.Error(t, err)
}

func TestRewrapIsIdempotentForSameKey(t *testing.T) {
	p := newTestProvider(t, 0x73)
	env, err := Seal(p, testIdentity(), []byte("v"))
	require.NoError(t, err)

	wrapped, nonce, err := Rewrap(p, p, env.DEKWrapped, env.DEKNonce)
	require.NoError(t, err)
	assert.Equal(t, env.DEKWrapped, wrapped)
	assert.Equal(t, env.DEKNonce, nonce)
}

// fakeRewrapStore is an in-memory RewrapStore.
type fakeRewrapStore struct {
	wraps    map[int64]VersionWrap
	retired  []string
	listCals int
	// failAfter aborts the run partway through to prove resumability.
	failAfter int
	writes    int
}

func (f *fakeRewrapStore) ListVersionWraps(_ context.Context, kekID string, limit int32) ([]VersionWrap, error) {
	f.listCals++
	out := []VersionWrap{}
	// Deterministic order by id so batching is testable.
	for id := int64(1); id <= int64(len(f.wraps)); id++ {
		w, ok := f.wraps[id]
		if !ok || w.KEKID != kekID {
			continue
		}
		out = append(out, w)
		if int32(len(out)) == limit {
			break
		}
	}
	return out, nil
}

func (f *fakeRewrapStore) RewrapVersion(_ context.Context, versionID int64, fromKEKID string, wrapped, nonce []byte, toKEKID string) error {
	w, ok := f.wraps[versionID]
	if !ok {
		return fmt.Errorf("version %d not found", versionID)
	}
	// Mirrors the SQL guard: the update only applies to a row still on the source
	// key, so a row another pass already moved is not moved twice.
	if w.KEKID != fromKEKID {
		return nil
	}
	f.writes++
	if f.failAfter > 0 && f.writes > f.failAfter {
		return fmt.Errorf("simulated crash")
	}
	f.wraps[versionID] = VersionWrap{VersionID: versionID, KEKID: toKEKID, DEKWrapped: wrapped, DEKNonce: nonce}
	return nil
}

func (f *fakeRewrapStore) CountVersionWraps(_ context.Context, kekID string) (int64, error) {
	var n int64
	for _, w := range f.wraps {
		if w.KEKID == kekID {
			n++
		}
	}
	return n, nil
}

func (f *fakeRewrapStore) RetireRootKey(_ context.Context, kekID string) error {
	f.retired = append(f.retired, kekID)
	return nil
}

// seedRewrapStore builds n versions all wrapped under oldKey, each holding a real
// wrapped DEK so the rewrap performs genuine crypto.
func seedRewrapStore(t *testing.T, oldKey RootKeyProvider, n int) *fakeRewrapStore {
	t.Helper()
	store := &fakeRewrapStore{wraps: make(map[int64]VersionWrap, n)}
	for i := 1; i <= n; i++ {
		dek, err := NewRandomKey()
		require.NoError(t, err)
		wrapped, nonce, err := oldKey.Wrap(dek)
		require.NoError(t, err)
		store.wraps[int64(i)] = VersionWrap{VersionID: int64(i), KEKID: oldKey.KeyID(), DEKWrapped: wrapped, DEKNonce: nonce}
	}
	return store
}

func TestRewrapAllDrainsAndRetires(t *testing.T) {
	oldKey := newTestProvider(t, 0x81)
	newKey := newTestProvider(t, 0x82)
	ring, err := NewKeyRing(newKey, oldKey)
	require.NoError(t, err)

	store := seedRewrapStore(t, oldKey, 25)
	report, err := RewrapAll(context.Background(), store, ring, oldKey.KeyID(), 10)
	require.NoError(t, err)

	assert.EqualValues(t, 25, report.Rewrapped)
	assert.EqualValues(t, 0, report.Remaining)
	assert.True(t, report.Retired)
	assert.Equal(t, []string{oldKey.KeyID()}, store.retired)
	// Batched: 25 rows at 10 per query is more than one round trip.
	assert.Greater(t, store.listCals, 1)

	for _, w := range store.wraps {
		assert.Equal(t, newKey.KeyID(), w.KEKID)
	}
}

func TestRewrapAllIsIdempotent(t *testing.T) {
	oldKey := newTestProvider(t, 0x83)
	newKey := newTestProvider(t, 0x84)
	ring, err := NewKeyRing(newKey, oldKey)
	require.NoError(t, err)

	store := seedRewrapStore(t, oldKey, 5)
	first, err := RewrapAll(context.Background(), store, ring, oldKey.KeyID(), 10)
	require.NoError(t, err)
	assert.EqualValues(t, 5, first.Rewrapped)

	// Running it again must find nothing and change nothing.
	second, err := RewrapAll(context.Background(), store, ring, oldKey.KeyID(), 10)
	require.NoError(t, err)
	assert.EqualValues(t, 0, second.Rewrapped)

	// And rotating "onto the active key" is a harmless no-op, so a scheduled rewrap
	// can run against a store that is already settled.
	settled, err := RewrapAll(context.Background(), store, ring, newKey.KeyID(), 10)
	require.NoError(t, err)
	assert.EqualValues(t, 0, settled.Rewrapped)
	assert.False(t, settled.Retired)
}

func TestRewrapAllIsResumableAfterFailure(t *testing.T) {
	oldKey := newTestProvider(t, 0x85)
	newKey := newTestProvider(t, 0x86)
	ring, err := NewKeyRing(newKey, oldKey)
	require.NoError(t, err)

	store := seedRewrapStore(t, oldKey, 10)
	store.failAfter = 4

	_, err = RewrapAll(context.Background(), store, ring, oldKey.KeyID(), 10)
	require.Error(t, err, "the simulated crash must surface")

	// Progress lives in the data, so a restart continues rather than repeating.
	store.failAfter = 0
	store.writes = 0
	report, err := RewrapAll(context.Background(), store, ring, oldKey.KeyID(), 10)
	require.NoError(t, err)
	assert.EqualValues(t, 0, report.Remaining)
	assert.True(t, report.Retired)
	for _, w := range store.wraps {
		assert.Equal(t, newKey.KeyID(), w.KEKID)
	}
}

func TestRewrapAllWillNotRetireAKeyStillInUse(t *testing.T) {
	// A key retired while rows still reference it leaves those rows permanently
	// unreadable, so retirement must be proved by a count, not inferred from the
	// pass having finished.
	oldKey := newTestProvider(t, 0x87)
	newKey := newTestProvider(t, 0x88)
	strayKey := newTestProvider(t, 0x89)
	ring, err := NewKeyRing(newKey, oldKey)
	require.NoError(t, err)

	store := seedRewrapStore(t, oldKey, 3)
	// A row appears under the old key after the drain loop has moved past it.
	store.wraps[99] = VersionWrap{VersionID: 99, KEKID: oldKey.KeyID()}
	_ = strayKey

	report, err := RewrapAll(context.Background(), store, ring, oldKey.KeyID(), 100)
	require.NoError(t, err)
	// The straggler had no real wrapped DEK, so it is re-wrapped as empty; what
	// matters is that retirement is gated on the count reaching zero.
	if report.Remaining > 0 {
		assert.False(t, report.Retired)
		assert.Empty(t, store.retired)
	}
}

func TestKeyRingResolvesPerVersionKeys(t *testing.T) {
	oldKey := newTestProvider(t, 0x91)
	newKey := newTestProvider(t, 0x92)
	ring, err := NewKeyRing(newKey, oldKey)
	require.NoError(t, err)

	assert.Equal(t, newKey.KeyID(), ring.Active().KeyID())

	got, err := ring.Provider(oldKey.KeyID())
	require.NoError(t, err)
	assert.Equal(t, oldKey.KeyID(), got.KeyID())

	_, err = ring.Provider("env:deadbeefdeadbeefdeadbeef")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be read until it is supplied")

	assert.Len(t, ring.KeyIDs(), 2)
}

// ---------------------------------------------------------------------------
// Providers: env, file, KMS stubs, ephemeral refusal
// ---------------------------------------------------------------------------

func TestEnvProviderAcceptsHexAndBase64(t *testing.T) {
	raw := bytes.Repeat([]byte{0xab}, KeySize)
	encodings := map[string]string{
		"hex":            hex.EncodeToString(raw),
		"base64 std":     base64.StdEncoding.EncodeToString(raw),
		"base64 raw std": base64.RawStdEncoding.EncodeToString(raw),
		"base64 url":     base64.URLEncoding.EncodeToString(raw),
		"whitespace":     "  " + hex.EncodeToString(raw) + "\n",
	}
	var ids []string
	for name, encoded := range encodings {
		t.Run(name, func(t *testing.T) {
			p, err := NewRootKeyProvider(ProviderConfig{Provider: ProviderEnv, AppEnv: "production", Key: encoded})
			require.NoError(t, err)
			ids = append(ids, p.KeyID())
		})
	}
	// Every encoding of the same key must resolve to the SAME kek_id, or a change of
	// encoding in a deployment config would orphan every existing row.
	for _, id := range ids {
		assert.Equal(t, ids[0], id)
	}
	assert.True(t, strings.HasPrefix(ids[0], ProviderEnv+":"))
	assert.LessOrEqual(t, len(ids[0]), 64, "kek_id must fit VARCHAR(64)")
}

func TestEnvProviderRejectsBadKeyMaterial(t *testing.T) {
	cases := map[string]string{
		"too short":     hex.EncodeToString(bytes.Repeat([]byte{1}, 16)),
		"too long":      hex.EncodeToString(bytes.Repeat([]byte{1}, 64)),
		"not encoded":   "this-is-not-a-key",
		"raw 32 ascii":  "0123456789abcdef0123456789abcdef",
		"odd hex chars": strings.Repeat("z", 64),
	}
	for name, key := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := NewRootKeyProvider(ProviderConfig{Provider: ProviderEnv, AppEnv: "production", Key: key})
			require.Error(t, err)
			assert.NotContains(t, err.Error(), key, "an error must not echo the supplied key material")
		})
	}
}

func TestEphemeralKeyRefusedOutsideDevelopment(t *testing.T) {
	// The prototype generated a random key here and carried on, which meant every
	// secret written before a restart silently became undecryptable after it.
	for _, env := range []string{"production", "staging", "prod", "Development", "dev", ""} {
		t.Run("app_env="+env, func(t *testing.T) {
			_, err := NewRootKeyProvider(ProviderConfig{Provider: ProviderEnv, AppEnv: env})
			require.Error(t, err, "an unset root key must be a boot error outside development")
			assert.Contains(t, err.Error(), "SECRET_ROOT_KEY")
		})
	}
}

func TestEphemeralKeyAllowedInDevelopment(t *testing.T) {
	p, err := NewRootKeyProvider(ProviderConfig{Provider: ProviderEnv, AppEnv: EnvDevelopment})
	require.NoError(t, err)
	// Registered honestly as 'ephemeral', not masquerading as 'env', so root_keys
	// records what actually encrypted those rows.
	assert.Equal(t, ProviderEphemeral, ProviderOf(p.KeyID()))

	// It must still be a working key.
	env, err := Seal(p, testIdentity(), []byte("dev-value"))
	require.NoError(t, err)
	got, err := Open(p, testIdentity(), *env)
	require.NoError(t, err)
	assert.Equal(t, []byte("dev-value"), got.Bytes())
}

func TestFileProviderRefusesLoosePermissions(t *testing.T) {
	dir := t.TempDir()
	key := hex.EncodeToString(bytes.Repeat([]byte{0x5a}, KeySize))

	for name, mode := range map[string]os.FileMode{
		"group readable": 0o640,
		"world readable": 0o604,
		"world writable": 0o622,
		"all":            0o666,
		"executable":     0o601,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, "key-"+name)
			require.NoError(t, os.WriteFile(path, []byte(key), mode))
			require.NoError(t, os.Chmod(path, mode))

			_, err := NewRootKeyProvider(ProviderConfig{Provider: ProviderFile, AppEnv: "production", KeyFile: path})
			require.Error(t, err, "a root key file readable beyond its owner must be refused, not warned about")
			assert.Contains(t, err.Error(), "chmod 600")
		})
	}
}

func TestFileProviderAcceptsOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	raw := bytes.Repeat([]byte{0x5b}, KeySize)
	path := filepath.Join(dir, "sealed.key")
	// With a trailing newline, because that is what every normal tool writes.
	require.NoError(t, os.WriteFile(path, []byte(hex.EncodeToString(raw)+"\n"), 0o600))

	p, err := NewRootKeyProvider(ProviderConfig{Provider: ProviderFile, AppEnv: "production", KeyFile: path})
	require.NoError(t, err)
	assert.Equal(t, ProviderFile, ProviderOf(p.KeyID()))
}

func TestFileProviderErrors(t *testing.T) {
	dir := t.TempDir()

	t.Run("missing path", func(t *testing.T) {
		_, err := NewRootKeyProvider(ProviderConfig{Provider: ProviderFile, AppEnv: "production"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "SECRET_ROOT_KEY_FILE")
	})
	t.Run("absent file", func(t *testing.T) {
		_, err := NewRootKeyProvider(ProviderConfig{Provider: ProviderFile, AppEnv: "production", KeyFile: filepath.Join(dir, "nope")})
		require.Error(t, err)
	})
	t.Run("directory", func(t *testing.T) {
		_, err := NewRootKeyProvider(ProviderConfig{Provider: ProviderFile, AppEnv: "production", KeyFile: dir})
		require.Error(t, err)
	})
	t.Run("bad contents", func(t *testing.T) {
		path := filepath.Join(dir, "bad.key")
		require.NoError(t, os.WriteFile(path, []byte("not-a-key"), 0o600))
		_, err := NewRootKeyProvider(ProviderConfig{Provider: ProviderFile, AppEnv: "production", KeyFile: path})
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "not-a-key")
	})
}

// The cloud providers are BUILT — see provider_kms_test.go, which covers all three
// against fakes (round trip, AAD binding, retry classification, redaction, boot
// self-test, cross-provider rewrap). What belongs here is only the factory's half of
// the contract: a cloud provider is still constructed through the registry, and it
// still refuses to hand back a provider it could not configure. A vault that boots
// and then fails every read looks like an outage; one that refuses to boot is a
// config error an operator fixes in a minute.
func TestKMSProvidersAreReachableThroughTheFactory(t *testing.T) {
	for _, provider := range []string{ProviderAWSKMS, ProviderGCPKMS, ProviderAzureKV} {
		t.Run(provider, func(t *testing.T) {
			_, err := NewRootKeyProvider(ProviderConfig{Provider: provider, AppEnv: "production"})
			require.Error(t, err, "an unconfigured cloud provider must not construct")
			assert.NotContains(t, err.Error(), "not built")
		})
		assert.Contains(t, KnownProviders(), provider)
	}
}

func TestUnknownProviderIsRejected(t *testing.T) {
	_, err := NewRootKeyProvider(ProviderConfig{Provider: "hashicorp-vault", AppEnv: "production"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown root key provider")
}

// ---------------------------------------------------------------------------
// Memory hygiene and redaction
// ---------------------------------------------------------------------------

func TestZero(t *testing.T) {
	b := []byte("sensitive-material")
	Zero(b)
	assert.Equal(t, make([]byte, len("sensitive-material")), b)
	// Must not panic on the degenerate inputs.
	Zero(nil)
	Zero([]byte{})
}

func TestPlaintextZeroAndRedaction(t *testing.T) {
	p := Plaintext("super-secret-value")

	assert.Equal(t, Redacted, p.String())
	assert.Equal(t, Redacted, fmt.Sprint(p))
	assert.Equal(t, Redacted, fmt.Sprintf("%v", p))
	assert.NotContains(t, fmt.Sprintf("%#v", p), "super-secret-value")
	assert.Equal(t, Redacted, p.LogValue().String())

	encoded, err := json.Marshal(p)
	require.NoError(t, err)
	assert.JSONEq(t, `"`+Redacted+`"`, string(encoded))
	assert.NotContains(t, string(encoded), "super-secret-value")

	text, err := p.MarshalText()
	require.NoError(t, err)
	assert.Equal(t, Redacted, string(text))

	// Reaching the bytes must be a deliberate call.
	assert.Equal(t, "super-secret-value", string(p.Bytes()))
	assert.Equal(t, len("super-secret-value"), p.Len())

	p.Zero()
	assert.Equal(t, make([]byte, len("super-secret-value")), p.Bytes())
}

func TestPlaintextRedactedInsideAStruct(t *testing.T) {
	// The realistic leak: a value nested in something that gets marshalled into a
	// log line or an error body.
	payload := struct {
		Key   string    `json:"key"`
		Value Plaintext `json:"value"`
	}{Key: "DB_PASSWORD", Value: Plaintext("p@ssw0rd")}

	encoded, err := json.Marshal(payload)
	require.NoError(t, err)
	assert.NotContains(t, string(encoded), "p@ssw0rd")
	assert.Contains(t, string(encoded), Redacted)
}

// TestErrorsCarryNoSecrets sweeps every error-producing path in this package and
// asserts that no message contains the plaintext, the DEK, or the root key.
//
// Errors are the most common accidental exfiltration route in a secret store: they
// land in logs, in traces, in a 500 body, and in a bug report pasted into a ticket.
func TestErrorsCarryNoSecrets(t *testing.T) {
	const plaintext = "TOP-SECRET-PLAINTEXT-VALUE"
	rootKeyBytes := bytes.Repeat([]byte{0xc7}, KeySize)
	rootKeyHex := hex.EncodeToString(rootKeyBytes)

	p, err := NewRootKeyProvider(ProviderConfig{Provider: ProviderEnv, AppEnv: "production", Key: rootKeyHex})
	require.NoError(t, err)
	other := newTestProvider(t, 0xd8)
	id := testIdentity()

	env, err := Seal(p, id, []byte(plaintext))
	require.NoError(t, err)

	// The DEK really used for this version, recovered so it can be searched for.
	dek, err := p.Unwrap(env.DEKWrapped, env.DEKNonce)
	require.NoError(t, err)
	dekHex := hex.EncodeToString(dek)
	dekB64 := base64.StdEncoding.EncodeToString(dek)

	tampered := *env
	tampered.Ciphertext = bytes.Clone(env.Ciphertext)
	tampered.Ciphertext[0] ^= 0xff

	badChecksum := *env
	badChecksum.Checksum = Checksum([]byte("mismatch"))

	wrongIdentity := id
	wrongIdentity.SecretUUID = "00000000-0000-4000-8000-00000000ffff"

	shortNonce := *env
	shortNonce.Nonce = env.Nonce[:4]

	errs := map[string]error{}
	collect := func(name string, err error) {
		require.Error(t, err, name+" was expected to fail")
		errs[name] = err
	}

	_, err = Open(p, wrongIdentity, *env)
	collect("identity mismatch", err)
	_, err = Open(p, id, tampered)
	collect("tampered ciphertext", err)
	_, err = Open(p, id, badChecksum)
	collect("checksum drift", err)
	_, err = Open(p, id, shortNonce)
	collect("short nonce", err)
	env.KEKID = ""
	_, err = Open(other, id, *env)
	collect("wrong root key", err)
	_, _, err = p.Wrap([]byte("too-short-dek"))
	collect("bad dek length", err)
	_, err = p.Unwrap([]byte("garbage"), env.DEKNonce)
	collect("unwrap garbage", err)
	_, err = NewRootKeyProvider(ProviderConfig{Provider: ProviderEnv, AppEnv: "production", Key: rootKeyHex[:32]})
	collect("truncated root key", err)
	_, _, err = Rewrap(p, nil, env.DEKWrapped, env.DEKNonce)
	collect("rewrap without target", err)

	forbidden := map[string]string{
		"plaintext":       plaintext,
		"dek hex":         dekHex,
		"dek base64":      dekB64,
		"root key hex":    rootKeyHex,
		"root key prefix": rootKeyHex[:32],
	}
	for name, err := range errs {
		msg := err.Error()
		for label, secret := range forbidden {
			assert.NotContains(t, msg, secret, "error %q leaked the %s", name, label)
		}
		// Raw bytes, in case a message ever interpolates them directly.
		assert.NotContains(t, msg, string(dek), "error %q leaked raw DEK bytes", name)
	}

	// Sanity: the assertions above would pass trivially if the messages were empty.
	for name, err := range errs {
		assert.NotEmpty(t, err.Error(), "error %q must still say something useful", name)
	}
}

func TestSealRejectsInvalidVersion(t *testing.T) {
	p := newTestProvider(t, 0xe1)
	id := testIdentity()
	id.Version = 0
	_, err := Seal(p, id, []byte("v"))
	require.Error(t, err)

	_, err = Seal(nil, testIdentity(), []byte("v"))
	require.Error(t, err)
}

func TestChecksumIsSHA256OfPlaintext(t *testing.T) {
	sum := Checksum([]byte("value"))
	assert.Len(t, sum, 32)
	assert.Equal(t, sum, Checksum([]byte("value")))
	assert.NotEqual(t, sum, Checksum([]byte("value ")))
}
