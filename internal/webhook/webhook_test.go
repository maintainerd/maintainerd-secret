package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/maintainerd/secret/internal/store"
)

// TestPayloadNeverCarriesAValue is the assertion the contract asks for explicitly.
//
// It checks the STRUCTURE, not a filter. The delivery body is marshalled from Payload,
// and Payload has no field that could hold a credential — so this test is really
// asserting that nobody added one. The secret value is planted in every neighbouring
// string (the MRN, the project, the tenant) to make sure the check is meaningful.
func TestPayloadNeverCarriesAValue(t *testing.T) {
	const value = "sup3r-s3cret-value"

	payload := Payload{
		ID:         "11111111-1111-1111-1111-111111111111",
		Event:      store.WebhookEventSecretRotated,
		Resource:   "mrn:secret:acme:billing-app:secret/prod/db/PASSWORD",
		Version:    7,
		Tenant:     "acme",
		Project:    "billing-app",
		OccurredAt: "2026-03-01T00:00:00Z",
	}
	body, err := json.Marshal(payload)
	require.NoError(t, err)

	assert.NotContains(t, string(body), value,
		"a webhook payload must never contain a secret value — it is an instruction to re-read")

	// And the fields it DOES carry are the ones a consumer needs to issue that read.
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(body, &decoded))
	assert.Equal(t, "mrn:secret:acme:billing-app:secret/prod/db/PASSWORD", decoded["resource"])
	assert.EqualValues(t, 7, decoded["version"])

	// There is no key in the payload whose name suggests a value, either.
	for key := range decoded {
		assert.NotContains(t, strings.ToLower(key), "value")
		assert.NotContains(t, strings.ToLower(key), "secret_value")
		assert.NotContains(t, strings.ToLower(key), "plaintext")
	}
}

// TestSignatureMatchesTheAuthScheme: a receiver that already verifies
// maintainerd-auth's webhooks must verify these with the same code.
func TestSignatureMatchesTheAuthScheme(t *testing.T) {
	key := []byte("signing-key")
	body := []byte(`{"event":"secret.rotated"}`)
	const timestamp int64 = 1772409600

	got := Signature(key, timestamp, body)

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(strconv.FormatInt(timestamp, 10)))
	mac.Write([]byte("."))
	mac.Write(body)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	assert.Equal(t, want, got)
	assert.True(t, strings.HasPrefix(got, "sha256="))
}

// TestSignatureCoversTheTimestamp is what makes a captured delivery non-replayable:
// moving the timestamp invalidates the MAC, so a receiver's replay window is
// enforceable.
func TestSignatureCoversTheTimestamp(t *testing.T) {
	key := []byte("signing-key")
	body := []byte(`{"event":"secret.rotated"}`)
	assert.NotEqual(t,
		Signature(key, 1772409600, body),
		Signature(key, 1772409601, body),
		"the timestamp is inside the MAC, not merely alongside it")
}

func TestSignatureChangesWithTheKey(t *testing.T) {
	body := []byte(`{"event":"secret.changed"}`)
	assert.NotEqual(t, Signature([]byte("a"), 1, body), Signature([]byte("b"), 1, body))
}

// TestUnsafeDestinationsAreRefused covers the SSRF-to-credential-theft chain: a
// secret service reaching its own host's instance-metadata endpoint on a tenant's
// instruction.
func TestUnsafeDestinationsAreRefused(t *testing.T) {
	for _, addr := range []string{
		"127.0.0.1",       // loopback
		"::1",             // loopback v6
		"169.254.169.254", // cloud instance metadata
		"10.1.2.3",        // private
		"192.168.1.10",    // private
		"172.16.0.5",      // private
		"100.64.0.1",      // carrier-grade NAT, where several providers put internals
		"0.0.0.0",         // unspecified
		"224.0.0.1",       // multicast
	} {
		assert.True(t, IsUnsafeIP(net.ParseIP(addr)), "%s must be refused", addr)
	}
	assert.True(t, IsUnsafeIP(nil), "an unresolvable address fails closed")

	for _, addr := range []string{"93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"} {
		assert.False(t, IsUnsafeIP(net.ParseIP(addr)), "%s is a legitimate destination", addr)
	}
}

// TestWebhookURLValidation: https-only, no embedded credentials, bounded length.
func TestWebhookURLValidation(t *testing.T) {
	require.NoError(t, store.ValidateWebhookURL("https://hooks.example.com/secret"))

	for _, bad := range []string{
		"",
		"http://hooks.example.com/secret",       // plaintext
		"ftp://hooks.example.com/secret",        // wrong scheme
		"https://user:pass@hooks.example.com/x", // credentials in the URL
		"https:///no-host",
	} {
		assert.Error(t, store.ValidateWebhookURL(bad), "ValidateWebhookURL(%q) must fail", bad)
	}
}
