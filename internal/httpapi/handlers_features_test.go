package httpapi_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sdkauthz "github.com/maintainerd/sdk/authz"
	"github.com/maintainerd/secret/internal/api"
	"github.com/maintainerd/secret/internal/audit"
	"github.com/maintainerd/secret/internal/crypto"
	"github.com/maintainerd/secret/internal/httpapi"
	"github.com/maintainerd/secret/internal/platform/permissions"
	"github.com/maintainerd/secret/internal/storage"
	"github.com/maintainerd/secret/internal/store"
	"github.com/maintainerd/secret/internal/transit"
)

// TRANSPORT-LEVEL TESTS FOR THE NEW SURFACES.
//
// The api layer's own tests (internal/api) own the permission split, the audit
// guarantee and the no-leak rules. What can only be checked HERE is what the handler
// does with the result — and one of those checks catches a bug that no api-level test
// can see:
//
//	A RECOVERED PLAINTEXT MUST NOT BE PASSED TO A GENERIC MARSHALLER. crypto.Plaintext
//	deliberately marshals as "[REDACTED]", so a decrypt handler written with
//	response.OK would compile, return 200, and hand every caller the literal string
//	"[REDACTED]" instead of their data. The handler base64s the bytes by hand for
//	exactly that reason, and the test below is what proves the hand-encoding is wired
//	up rather than merely present.

// ---------------------------------------------------------------------------
// A transit-only in-memory repository
// ---------------------------------------------------------------------------

// transitRepo answers the queries a transit encrypt/decrypt round trip makes and
// nothing else.
//
// It embeds store.TxRepository as a nil interface, the same technique the parity
// harness uses: any query these paths reach that is not modelled here panics with a
// nil dereference NAMING THE METHOD, so a new data dependency shows up as a loud
// failure rather than a zero value that quietly changes behaviour.
type transitRepo struct {
	store.TxRepository

	tenantUUID uuid.UUID
	keyUUID    uuid.UUID
	nextID     int64
	versions   map[int32]*storage.TransitKeyVersion
	key        *storage.TransitKey
	audited    int
}

func newTransitRepo() *transitRepo {
	return &transitRepo{
		tenantUUID: uuid.MustParse("22222222-2222-2222-2222-222222222222"),
		keyUUID:    uuid.MustParse("33333333-3333-3333-3333-333333333333"),
		versions:   map[int32]*storage.TransitKeyVersion{},
	}
}

func (r *transitRepo) InTx(ctx context.Context, fn func(store.Repository) error) error {
	return fn(r)
}

func (r *transitRepo) tenantRow() storage.Tenant {
	return storage.Tenant{
		TenantID: 1, TenantUuid: r.tenantUUID, Name: featureTenant,
		DisplayName: "Acme", Status: store.StatusActive,
	}
}

func (r *transitRepo) GetTenantByName(_ context.Context, _ string) (storage.Tenant, error) {
	return r.tenantRow(), nil
}

func (r *transitRepo) GetTenantByUUID(_ context.Context, _ uuid.UUID) (storage.Tenant, error) {
	return r.tenantRow(), nil
}

func (r *transitRepo) GetProjectBySlug(_ context.Context, arg storage.GetProjectBySlugParams) (storage.Project, error) {
	return storage.Project{
		ProjectID: 1, ProjectUuid: uuid.New(), TenantID: arg.TenantID,
		Slug: arg.Slug, Name: arg.Slug, Status: store.StatusActive,
	}, nil
}

func (r *transitRepo) CreateTransitKey(_ context.Context, arg storage.CreateTransitKeyParams) (storage.TransitKey, error) {
	row := storage.TransitKey{
		KeyID: 1, KeyUuid: r.keyUUID, TenantID: arg.TenantID, ProjectID: arg.ProjectID,
		Name: arg.Name, Description: arg.Description, Status: arg.Status,
		MinDecryptVersion: arg.MinDecryptVersion, Metadata: arg.Metadata,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	r.key = &row
	return row, nil
}

func (r *transitRepo) CreateTransitKeyVersion(_ context.Context, arg storage.CreateTransitKeyVersionParams) (storage.TransitKeyVersion, error) {
	r.nextID++
	row := storage.TransitKeyVersion{
		VersionID: r.nextID, KeyID: arg.KeyID, Version: arg.Version,
		MaterialCiphertext: arg.MaterialCiphertext, MaterialNonce: arg.MaterialNonce,
		MaterialDekWrapped: arg.MaterialDekWrapped, MaterialDekNonce: arg.MaterialDekNonce,
		KekID: arg.KekID, CreatedAt: time.Now(),
	}
	r.versions[arg.Version] = &row
	return row, nil
}

func (r *transitRepo) SetTransitKeyCurrentVersion(_ context.Context, arg storage.SetTransitKeyCurrentVersionParams) (storage.TransitKey, error) {
	if r.key == nil {
		return storage.TransitKey{}, pgx.ErrNoRows
	}
	r.key.CurrentVersion = arg.CurrentVersion
	return *r.key, nil
}

func (r *transitRepo) GetTransitKeyByName(_ context.Context, _ storage.GetTransitKeyByNameParams) (storage.TransitKey, error) {
	if r.key == nil {
		return storage.TransitKey{}, pgx.ErrNoRows
	}
	return *r.key, nil
}

func (r *transitRepo) GetTransitKeyVersion(_ context.Context, arg storage.GetTransitKeyVersionParams) (storage.TransitKeyVersion, error) {
	v, ok := r.versions[arg.Version]
	if !ok {
		return storage.TransitKeyVersion{}, pgx.ErrNoRows
	}
	return *v, nil
}

func (r *transitRepo) AppendAuditEvent(_ context.Context, arg storage.AppendAuditEventParams) (storage.AuditLog, error) {
	r.audited++
	return storage.AuditLog{
		EventID: int64(r.audited), EventUuid: uuid.New(),
		Action: arg.Action, ResourceMrn: arg.ResourceMrn, Outcome: arg.Outcome,
		CreatedAt: time.Now(),
	}, nil
}

const featureTenant = "acme"

// featureHarness is the real chi router over a real api.Service over transitRepo.
type featureHarness struct {
	router http.Handler
	repo   *transitRepo
}

// newFeatureHarness builds the router with an ENFORCING guard that verifies one token
// into the supplied principal, so the route table and the actor model are the real ones.
func newFeatureHarness(t *testing.T, principal *sdkauthz.Claims) featureHarness {
	t.Helper()
	repo := newTransitRepo()
	st, err := store.NewService(repo, parityKeyRing(t), store.Policy{
		KeepVersions:       10,
		DefaultTenant:      featureTenant,
		DefaultProject:     "billing-app",
		DefaultEnvironment: "prod",
	})
	require.NoError(t, err)
	auditor, err := audit.New(st)
	require.NoError(t, err)
	svc, err := api.New(st, auditor, nil, api.Options{DefaultTenant: featureTenant})
	require.NoError(t, err)

	guard := sdkauthz.Guard{
		Mode: sdkauthz.ModeEnforced,
		Verify: func(_ context.Context, token string) (*sdkauthz.Claims, error) {
			if token != "good" {
				return nil, errors.New("bad token")
			}
			return principal, nil
		},
	}
	return featureHarness{
		router: httpapi.NewServer(svc, nil, guard, httpapi.Options{}).Router(),
		repo:   repo,
	}
}

func (h featureHarness) call(t *testing.T, method, target string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader([]byte("{}"))
	}
	req := httptest.NewRequest(method, target, reader)
	req.Header.Set("Authorization", "Bearer good")
	w := httptest.NewRecorder()
	h.router.ServeHTTP(w, req)
	return w
}

// featurePrincipal builds a USER principal holding the given actions. A user, because
// the key-lifecycle routes are user-only and a service principal would be refused a step
// earlier by the actor check — which has its own tests.
func featurePrincipal(actions ...string) *sdkauthz.Claims {
	grants := make([]sdkauthz.Grant, 0, len(actions))
	for _, a := range actions {
		grants = append(grants, sdkauthz.Grant{Action: a})
	}
	return &sdkauthz.Claims{
		Subject:        "operator-1",
		Kind:           sdkauthz.ActorKindUser,
		Tenant:         featureTenant,
		Grants:         grants,
		BlanketActions: permissions.BlanketActions(),
	}
}

// ---------------------------------------------------------------------------
// The decrypt response
// ---------------------------------------------------------------------------

// TestTheDecryptResponseCarriesTheRealPlaintextAndIsNotCacheable.
//
// The property is the hand-encoding: a decrypt handler that passed its result to a
// generic marshaller would return 200 with "[REDACTED]" and no test that only checked
// the status would notice. So this asserts the base64 decodes back to the exact bytes
// that went in — and, on the way, that no-store is set, because a recovered credential
// must not land in a shared cache, a disk cache or a proxy.
func TestTheDecryptResponseCarriesTheRealPlaintextAndIsNotCacheable(t *testing.T) {
	h := newFeatureHarness(t, featurePrincipal(permissions.PermAdmin))
	const plaintext = "4111-1111-1111-1111"

	created := h.call(t, http.MethodPost, "/api/v1/transit", map[string]any{
		"project": "billing-app", "name": "pii",
	})
	require.Equal(t, http.StatusCreated, created.Code, created.Body.String())

	sealed := h.call(t, http.MethodPost, "/api/v1/transit/encrypt", map[string]any{
		"project":   "billing-app",
		"name":      "pii",
		"plaintext": base64.StdEncoding.EncodeToString([]byte(plaintext)),
	})
	require.Equal(t, http.StatusOK, sealed.Code, sealed.Body.String())
	assert.Equal(t, "no-store", sealed.Header().Get("Cache-Control"),
		"a token is derived from a caller's own data and has no business in a shared cache")

	var envelope struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
			KeyVersion int32  `json:"key_version"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(sealed.Body.Bytes(), &envelope))
	require.NotEmpty(t, envelope.Data.Ciphertext)
	assert.EqualValues(t, 1, envelope.Data.KeyVersion)
	assert.NotContains(t, sealed.Body.String(), plaintext,
		"the encrypt response must not echo the plaintext back")

	opened := h.call(t, http.MethodPost, "/api/v1/transit/decrypt", map[string]any{
		"project": "billing-app", "ciphertext": envelope.Data.Ciphertext,
	})
	require.Equal(t, http.StatusOK, opened.Code, opened.Body.String())
	assert.Equal(t, "no-store", opened.Header().Get("Cache-Control"))

	var body struct {
		Success   bool   `json:"success"`
		KeyName   string `json:"key_name"`
		Version   int32  `json:"key_version"`
		Plaintext string `json:"plaintext"`
	}
	require.NoError(t, json.Unmarshal(opened.Body.Bytes(), &body))
	assert.True(t, body.Success)
	assert.Equal(t, "pii", body.KeyName)
	assert.EqualValues(t, 1, body.Version)

	assert.NotContains(t, opened.Body.String(), crypto.Redacted,
		"the plaintext is base64ed by hand precisely so it does NOT go through "+
			"crypto.Plaintext's redacting marshaller")
	decoded, err := base64.StdEncoding.DecodeString(body.Plaintext)
	require.NoError(t, err, "the field must be base64 of the raw bytes")
	assert.Equal(t, plaintext, string(decoded))
}

// TestAFailedDecryptSaysNothingAboutTheValue. A token that does not authenticate is the
// caller's input being wrong, and the message must say no more than that — no plaintext,
// no key material, no driver detail.
func TestAFailedDecryptSaysNothingAboutTheValue(t *testing.T) {
	h := newFeatureHarness(t, featurePrincipal(permissions.PermAdmin))

	created := h.call(t, http.MethodPost, "/api/v1/transit", map[string]any{
		"project": "billing-app", "name": "pii",
	})
	require.Equal(t, http.StatusCreated, created.Code)

	sealed := h.call(t, http.MethodPost, "/api/v1/transit/encrypt", map[string]any{
		"project": "billing-app", "name": "pii",
		"plaintext": base64.StdEncoding.EncodeToString([]byte("the-card-number")),
	})
	require.Equal(t, http.StatusOK, sealed.Code)
	var envelope struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(sealed.Body.Bytes(), &envelope))

	// Tamper with a CIPHERTEXT BYTE, not with the encoded text.
	//
	// This test used to flip the last character of the base64url payload, which is
	// flaky by construction: the final character of a base64 string may carry fewer
	// than six significant bits, so substituting it can decode to the SAME bytes. When
	// that happened the token authenticated, decrypt returned 200, and the assertion
	// below failed — dependent on the random nonce and the payload length, so it passed
	// locally and failed on CI at random.
	//
	// Decoding the payload, flipping one bit inside the ciphertext region (past the
	// 12-byte nonce) and re-encoding is deterministic: the AEAD tag cannot validate a
	// payload whose bytes actually differ, so this exercises authentication failure
	// rather than the encoder's padding rules.
	parts := strings.Split(envelope.Data.Ciphertext, ":")
	require.Len(t, parts, 5, "token shape is m9dt:v1:<key>:<version>:<payload>")
	payload, err := base64.RawURLEncoding.DecodeString(parts[4])
	require.NoError(t, err)
	require.Greater(t, len(payload), transit.NonceSize,
		"the payload must carry ciphertext past the nonce for this to tamper with anything")
	payload[transit.NonceSize] ^= 0x01
	parts[4] = base64.RawURLEncoding.EncodeToString(payload)
	tampered := strings.Join(parts, ":")
	require.NotEqual(t, envelope.Data.Ciphertext, tampered)

	refused := h.call(t, http.MethodPost, "/api/v1/transit/decrypt", map[string]any{
		"project": "billing-app", "ciphertext": tampered,
	})
	assert.Equal(t, http.StatusBadRequest, refused.Code,
		"a token that does not authenticate is the caller's input being wrong, not this "+
			"service being broken")
	assert.NotContains(t, refused.Body.String(), "the-card-number")
	assert.NotContains(t, strings.ToLower(refused.Body.String()), "dek")
	assert.NotContains(t, strings.ToLower(refused.Body.String()), "material")
}

// ---------------------------------------------------------------------------
// The guard, over the real route table
// ---------------------------------------------------------------------------

// TestTheDataPlaneRoutesDemandTheirOwnPermission is the per-route half of the
// three-way split, driven through the actual router.
//
// A token holding Encrypt reaches /transit/encrypt and is refused at
// /transit/decrypt — by the SURFACE guard, before any handler runs. That is the
// property a segment pair could not express, and the reason /transit is declared route
// by route.
func TestTheDataPlaneRoutesDemandTheirOwnPermission(t *testing.T) {
	encryptOnly := newFeatureHarness(t, featurePrincipal(permissions.PermEncrypt))

	refused := encryptOnly.call(t, http.MethodPost, "/api/v1/transit/decrypt", map[string]any{
		"project": "billing-app", "ciphertext": "m9dt:v1:pii:1:AAAA",
	})
	require.Equal(t, http.StatusForbidden, refused.Code)
	var denial struct {
		Code  string `json:"code"`
		Error string `json:"error"`
	}
	require.NoError(t, json.Unmarshal(refused.Body.Bytes(), &denial))
	assert.Equal(t, "insufficient_permission", denial.Code)
	assert.Contains(t, denial.Error, permissions.PermDecrypt,
		"the refusal names the grant the operator needs")
	assert.Equal(t, 0, encryptOnly.repo.audited,
		"the surface guard refused before the api layer ran, so no operation was attempted")

	// And the mirror: a Decrypt-only token is refused on encrypt.
	decryptOnly := newFeatureHarness(t, featurePrincipal(permissions.PermDecrypt))
	refused = decryptOnly.call(t, http.MethodPost, "/api/v1/transit/encrypt", map[string]any{
		"project": "billing-app", "name": "pii",
		"plaintext": base64.StdEncoding.EncodeToString([]byte("x")),
	})
	require.Equal(t, http.StatusForbidden, refused.Code)
	require.NoError(t, json.Unmarshal(refused.Body.Bytes(), &denial))
	assert.Contains(t, denial.Error, permissions.PermEncrypt)

	// And neither of them may touch the key lifecycle.
	for _, target := range []string{"/api/v1/transit", "/api/v1/transit/rotate"} {
		w := decryptOnly.call(t, http.MethodPost, target, map[string]any{
			"project": "billing-app", "name": "pii",
		})
		assert.Equal(t, http.StatusForbidden, w.Code, "%s must demand ManageTransitKey", target)
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &denial))
		assert.Contains(t, denial.Error, permissions.PermManageTransitKey)
	}
}

// TestTheNewRoutesDemandTheirOwnPermissionAtTheDoor sweeps every new surface with a
// token that holds every OTHER permission in the vocabulary.
//
// It is the per-route version of the gap audit, driven end to end: a route that had been
// folded into a segment pair, or mapped to a neighbour's permission, would be reachable
// here and is not. The 403 body names the missing grant, which is also what an operator
// debugging one sees.
func TestTheNewRoutesDemandTheirOwnPermissionAtTheDoor(t *testing.T) {
	cases := []struct {
		method string
		target string
		want   string
	}{
		{http.MethodPost, "/api/v1/transit", permissions.PermManageTransitKey},
		{http.MethodPatch, "/api/v1/transit", permissions.PermManageTransitKey},
		{http.MethodDelete, "/api/v1/transit?project=billing-app&name=pii", permissions.PermManageTransitKey},
		{http.MethodPost, "/api/v1/transit/rotate", permissions.PermManageTransitKey},
		{http.MethodPost, "/api/v1/transit/encrypt", permissions.PermEncrypt},
		{http.MethodPost, "/api/v1/transit/decrypt", permissions.PermDecrypt},
		{http.MethodPost, "/api/v1/dynamic", permissions.PermManageDynamicRole},
		{http.MethodPatch, "/api/v1/dynamic", permissions.PermManageDynamicRole},
		{http.MethodDelete, "/api/v1/dynamic?project=billing-app&name=reporting", permissions.PermManageDynamicRole},
		{http.MethodPost, "/api/v1/dynamic/credentials", permissions.PermIssueDynamicCredential},
		{http.MethodPost, "/api/v1/dynamic/credentials/revoke", permissions.PermIssueDynamicCredential},
		{http.MethodPost, "/api/v1/secrets/lease-policy", permissions.PermManageLease},
		{http.MethodPost, "/api/v1/secrets/leases/revoke", permissions.PermManageLease},
		{http.MethodGet, "/api/v1/transit?project=billing-app", permissions.PermReadMetadata},
		{http.MethodGet, "/api/v1/transit/describe?project=billing-app&name=pii", permissions.PermReadMetadata},
		{http.MethodGet, "/api/v1/transit/versions?project=billing-app&name=pii", permissions.PermReadMetadata},
		{http.MethodGet, "/api/v1/dynamic?project=billing-app", permissions.PermReadMetadata},
		{http.MethodGet, "/api/v1/dynamic/describe?project=billing-app&name=reporting", permissions.PermReadMetadata},
		{http.MethodGet, "/api/v1/dynamic/leases?project=billing-app&name=reporting", permissions.PermReadMetadata},
		{http.MethodGet, "/api/v1/secrets/lease-policy?project=billing-app&environment=prod&key=K", permissions.PermReadMetadata},
		{http.MethodGet, "/api/v1/secrets/leases?project=billing-app&environment=prod&key=K", permissions.PermReadMetadata},
	}

	for _, tc := range cases {
		t.Run(tc.method+" "+tc.target, func(t *testing.T) {
			// Every permission this service has EXCEPT the one the route needs — so the
			// refusal can only be about that one. secret:Admin is excluded because it is
			// a blanket over every action.
			var held []string
			for _, p := range permissions.All() {
				if p == tc.want || p == permissions.PermAdmin {
					continue
				}
				held = append(held, p)
			}
			h := newFeatureHarness(t, featurePrincipal(held...))

			w := h.call(t, tc.method, tc.target, map[string]any{})
			require.Equal(t, http.StatusForbidden, w.Code,
				"%s %s must demand %s and nothing weaker", tc.method, tc.target, tc.want)
			var denial struct {
				Code  string `json:"code"`
				Error string `json:"error"`
			}
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &denial))
			assert.Equal(t, "insufficient_permission", denial.Code)
			assert.Contains(t, denial.Error, tc.want)
			assert.Equal(t, 0, h.repo.audited,
				"the guard refused at the door, so nothing reached the api layer")
		})
	}
}
