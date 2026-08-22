package httpapi_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	secretv1 "github.com/maintainerd/secret/gen/maintainerd/secret/v1"
	"github.com/maintainerd/secret/internal/api"
	"github.com/maintainerd/secret/internal/audit"
	"github.com/maintainerd/secret/internal/crypto"
	"github.com/maintainerd/secret/internal/grpcserver"
	"github.com/maintainerd/secret/internal/httpapi"
	"github.com/maintainerd/secret/internal/platform/authz"
	"github.com/maintainerd/secret/internal/storage"
	"github.com/maintainerd/secret/internal/store"
)

// TRANSPORT PARITY.
//
// This file exists to hold ONE property, which is the whole reason validation lives in
// internal/api rather than in the handlers: a payload the REST surface refuses is a
// payload the gRPC surface refuses, for the same reason, with the same message.
//
// It is a property that decays silently. Nothing about a handler stops someone adding
// a check to one transport and not the other; the drift shows up as a client that
// "works over gRPC" writing a secret with a key the REST API would never have accepted.
// So the test drives BOTH REAL SURFACES — the actual chi router and the actual
// SecretService implementation — over one api.Service, and asserts both reject.
//
// The store beneath them is a stub that answers only the tenant lookup. That is
// sufficient BY CONSTRUCTION: every case below is rejected by the DTO's Validate()
// before the api method touches the store, and a case that somehow reached the store
// would panic on the embedded nil interface rather than pass quietly. The panic IS the
// assertion that validation ran first.

// ---------------------------------------------------------------------------
// The stub store
// ---------------------------------------------------------------------------

const parityTenant = "acme"

// tenantOnlyRepo answers the one query a request makes before validation
// (ResolveCaller's tenant lookup) and nothing else.
//
// storage.Querier has dozens of methods; embedding the interface gives them all with a
// nil implementation, so any method this test's paths reach beyond the tenant lookup
// panics with a nil-pointer dereference. That is deliberate: it turns "validation was
// skipped and the request hit the database" from a silent pass into a test failure.
type tenantOnlyRepo struct {
	store.TxRepository
}

func (tenantOnlyRepo) GetTenantByName(_ context.Context, name string) (storage.Tenant, error) {
	return storage.Tenant{
		TenantID:    1,
		TenantUuid:  uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		Name:        name,
		DisplayName: "Acme",
		Status:      store.StatusActive,
	}, nil
}

func parityKeyRing(t *testing.T) *crypto.KeyRing {
	t.Helper()
	raw := make([]byte, crypto.KeySize)
	for i := range raw {
		raw[i] = 0x2a
	}
	provider, err := crypto.NewRootKeyProvider(crypto.ProviderConfig{
		Provider: crypto.ProviderEnv,
		AppEnv:   "production",
		Key:      hex.EncodeToString(raw),
	})
	require.NoError(t, err)
	ring, err := crypto.NewKeyRing(provider)
	require.NoError(t, err)
	return ring
}

// parityHarness builds one api.Service and both transports over it.
type parityHarness struct {
	rest http.Handler
	grpc *grpcserver.Service
}

func newParityHarness(t *testing.T) parityHarness {
	t.Helper()
	st, err := store.NewService(tenantOnlyRepo{}, parityKeyRing(t), store.Policy{
		KeepVersions:       10,
		DefaultTenant:      parityTenant,
		DefaultProject:     "default",
		DefaultEnvironment: "default",
	})
	require.NoError(t, err)

	auditor, err := audit.New(st)
	require.NoError(t, err)

	svc, err := api.New(st, auditor, nil, api.Options{DefaultTenant: parityTenant})
	require.NoError(t, err)

	// ModeDevOpen attaches DevClaims (a blanket grant) so the surface guard lets the
	// request through to the handler. That is exactly what this test wants: an
	// authorization refusal would mask the validation refusal it is asserting.
	guard := authz.Guard{Mode: authz.ModeDevOpen, Reason: "parity test"}

	return parityHarness{
		rest: httpapi.NewServer(svc, nil, guard, httpapi.Options{}).Router(),
		grpc: grpcserver.New(svc, nil, "", true, parityTenant),
	}
}

// callREST posts a JSON body and returns the status and body.
func (h parityHarness) callREST(t *testing.T, method, target string, body any) (int, string) {
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
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.rest.ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

// grpcCtx carries the claims the interceptor would have attached in dev-open mode. The
// service methods are called directly rather than over a socket, because the property
// under test is the handler's, not the wire's.
func grpcCtx() context.Context {
	return authz.NewContext(context.Background(), authz.DevClaims())
}

// ---------------------------------------------------------------------------
// The parity table
// ---------------------------------------------------------------------------

// TestAPayloadRejectedOnRESTIsRejectedOnGRPC drives one bad payload through both
// surfaces per case and requires both to refuse it.
func TestAPayloadRejectedOnRESTIsRejectedOnGRPC(t *testing.T) {
	h := newParityHarness(t)

	cases := []struct {
		name string
		// rest performs the REST call and returns its status code.
		rest func(t *testing.T) (int, string)
		// grpc performs the equivalent RPC and returns its error.
		grpc func(t *testing.T) error
	}{
		{
			name: "put secret with a key containing a slash",
			rest: func(t *testing.T) (int, string) {
				return h.callREST(t, http.MethodPost, "/api/v1/secrets", map[string]any{
					"project":     "billing",
					"environment": "prod",
					"key":         "db/PASSWORD",
					"value":       base64.StdEncoding.EncodeToString([]byte("hunter2")),
				})
			},
			grpc: func(t *testing.T) error {
				_, err := h.grpc.PutSecret(grpcCtx(), &secretv1.PutSecretRequest{
					Address: &secretv1.SecretAddress{
						Project: "billing", Environment: "prod", Key: "db/PASSWORD",
					},
					Value: []byte("hunter2"),
				})
				return err
			},
		},
		{
			name: "put secret with an uppercase project slug",
			rest: func(t *testing.T) (int, string) {
				return h.callREST(t, http.MethodPost, "/api/v1/secrets", map[string]any{
					"project":     "Billing",
					"environment": "prod",
					"key":         "PASSWORD",
					"value":       base64.StdEncoding.EncodeToString([]byte("hunter2")),
				})
			},
			grpc: func(t *testing.T) error {
				_, err := h.grpc.PutSecret(grpcCtx(), &secretv1.PutSecretRequest{
					Address: &secretv1.SecretAddress{
						Project: "Billing", Environment: "prod", Key: "PASSWORD",
					},
					Value: []byte("hunter2"),
				})
				return err
			},
		},
		{
			name: "put secret with an unknown value type",
			rest: func(t *testing.T) (int, string) {
				return h.callREST(t, http.MethodPost, "/api/v1/secrets", map[string]any{
					"project":     "billing",
					"environment": "prod",
					"key":         "PASSWORD",
					"value":       base64.StdEncoding.EncodeToString([]byte("hunter2")),
					"value_type":  "opaqe",
				})
			},
			grpc: func(t *testing.T) error {
				_, err := h.grpc.PutSecret(grpcCtx(), &secretv1.PutSecretRequest{
					Address: &secretv1.SecretAddress{
						Project: "billing", Environment: "prod", Key: "PASSWORD",
					},
					Value:     []byte("hunter2"),
					ValueType: "opaqe",
				})
				return err
			},
		},
		{
			name: "put a reference value with a malformed placeholder",
			rest: func(t *testing.T) (int, string) {
				return h.callREST(t, http.MethodPost, "/api/v1/secrets", map[string]any{
					"project":     "billing",
					"environment": "prod",
					"key":         "DSN",
					"value":       base64.StdEncoding.EncodeToString([]byte("${PASSWORD}")),
					"value_type":  store.ValueTypeReference,
				})
			},
			grpc: func(t *testing.T) error {
				_, err := h.grpc.PutSecret(grpcCtx(), &secretv1.PutSecretRequest{
					Address: &secretv1.SecretAddress{
						Project: "billing", Environment: "prod", Key: "DSN",
					},
					Value:     []byte("${PASSWORD}"),
					ValueType: store.ValueTypeReference,
				})
				return err
			},
		},
		{
			name: "put secret with a value over the size limit",
			rest: func(t *testing.T) (int, string) {
				oversized := bytes.Repeat([]byte("a"), api.CurrentLimits().MaxSecretValueBytes+1)
				return h.callREST(t, http.MethodPost, "/api/v1/secrets", map[string]any{
					"project":     "billing",
					"environment": "prod",
					"key":         "PASSWORD",
					"value":       base64.StdEncoding.EncodeToString(oversized),
				})
			},
			grpc: func(t *testing.T) error {
				oversized := bytes.Repeat([]byte("a"), api.CurrentLimits().MaxSecretValueBytes+1)
				_, err := h.grpc.PutSecret(grpcCtx(), &secretv1.PutSecretRequest{
					Address: &secretv1.SecretAddress{
						Project: "billing", Environment: "prod", Key: "PASSWORD",
					},
					Value: oversized,
				})
				return err
			},
		},
		{
			name: "reveal with a negative version",
			rest: func(t *testing.T) (int, string) {
				return h.callREST(t, http.MethodPost, "/api/v1/secrets/reveal", map[string]any{
					"project":     "billing",
					"environment": "prod",
					"key":         "PASSWORD",
					"version":     -1,
				})
			},
			grpc: func(t *testing.T) error {
				_, err := h.grpc.GetSecret(grpcCtx(), &secretv1.GetSecretRequest{
					Address: &secretv1.SecretAddress{
						Project: "billing", Environment: "prod", Key: "PASSWORD",
					},
					Version: -1,
				})
				return err
			},
		},
		{
			name: "reveal with a traversal in the folder path",
			rest: func(t *testing.T) (int, string) {
				return h.callREST(t, http.MethodPost, "/api/v1/secrets/reveal", map[string]any{
					"project":     "billing",
					"environment": "prod",
					"folder_path": "/db/../../etc",
					"key":         "PASSWORD",
				})
			},
			grpc: func(t *testing.T) error {
				_, err := h.grpc.GetSecret(grpcCtx(), &secretv1.GetSecretRequest{
					Address: &secretv1.SecretAddress{
						Project: "billing", Environment: "prod",
						FolderPath: "/db/../../etc", Key: "PASSWORD",
					},
				})
				return err
			},
		},
		{
			name: "restore with a malformed secret uuid",
			rest: func(t *testing.T) (int, string) {
				return h.callREST(t, http.MethodPost, "/api/v1/secrets/restore", map[string]any{
					"secret_uuid": "not-a-uuid",
				})
			},
			grpc: func(t *testing.T) error {
				_, err := h.grpc.RestoreSecret(grpcCtx(), &secretv1.RestoreSecretRequest{
					SecretUuid: "not-a-uuid",
				})
				return err
			},
		},
		{
			name: "rollback to version zero",
			rest: func(t *testing.T) (int, string) {
				return h.callREST(t, http.MethodPost, "/api/v1/secrets/rollback", map[string]any{
					"project":     "billing",
					"environment": "prod",
					"key":         "PASSWORD",
					"version":     0,
				})
			},
			grpc: func(t *testing.T) error {
				_, err := h.grpc.RollbackSecret(grpcCtx(), &secretv1.RollbackSecretRequest{
					Address: &secretv1.SecretAddress{
						Project: "billing", Environment: "prod", Key: "PASSWORD",
					},
					Version: 0,
				})
				return err
			},
		},
		{
			name: "rotation policy carrying a generator value",
			rest: func(t *testing.T) (int, string) {
				return h.callREST(t, http.MethodPost, "/api/v1/secrets/rotation-policy", map[string]any{
					"project":     "billing",
					"environment": "prod",
					"key":         "PASSWORD",
					"enabled":     true,
					"interval":    "720h",
					"generator": map[string]any{
						"type":  "supplied",
						"value": base64.StdEncoding.EncodeToString([]byte("hunter2")),
					},
				})
			},
			grpc: func(t *testing.T) error {
				_, err := h.grpc.SetRotationPolicy(grpcCtx(), &secretv1.SetRotationPolicyRequest{
					Address: &secretv1.SecretAddress{
						Project: "billing", Environment: "prod", Key: "PASSWORD",
					},
					Enabled:  true,
					Interval: "720h",
					Generator: &secretv1.GeneratorSpec{
						Type:  "supplied",
						Value: []byte("hunter2"),
					},
				})
				return err
			},
		},
		{
			name: "rotate with a generated length below the entropy floor",
			rest: func(t *testing.T) (int, string) {
				return h.callREST(t, http.MethodPost, "/api/v1/secrets/rotate", map[string]any{
					"project":     "billing",
					"environment": "prod",
					"key":         "PASSWORD",
					"generator":   map[string]any{"type": "random", "length": 4},
				})
			},
			grpc: func(t *testing.T) error {
				_, err := h.grpc.RotateSecret(grpcCtx(), &secretv1.RotateSecretRequest{
					Address: &secretv1.SecretAddress{
						Project: "billing", Environment: "prod", Key: "PASSWORD",
					},
					Generator: &secretv1.GeneratorSpec{Type: "random", Length: 4},
				})
				return err
			},
		},
		{
			name: "create a project with an invalid slug",
			rest: func(t *testing.T) (int, string) {
				return h.callREST(t, http.MethodPost, "/api/v1/projects", map[string]any{
					"slug": "Not A Slug",
				})
			},
			grpc: func(t *testing.T) error {
				_, err := h.grpc.CreateProject(grpcCtx(), &secretv1.CreateProjectRequest{
					Slug: "Not A Slug",
				})
				return err
			},
		},
		{
			name: "move a folder onto itself",
			rest: func(t *testing.T) (int, string) {
				return h.callREST(t, http.MethodPost, "/api/v1/folders/move", map[string]any{
					"project":     "billing",
					"environment": "prod",
					"from":        "/db",
					"to":          "/db",
				})
			},
			grpc: func(t *testing.T) error {
				_, err := h.grpc.MoveFolder(grpcCtx(), &secretv1.MoveFolderRequest{
					Project: "billing", Environment: "prod", From: "/db", To: "/db",
				})
				return err
			},
		},
		{
			name: "move a folder into its own subtree",
			rest: func(t *testing.T) (int, string) {
				return h.callREST(t, http.MethodPost, "/api/v1/folders/move", map[string]any{
					"project":     "billing",
					"environment": "prod",
					"from":        "/db",
					"to":          "/db/primary",
				})
			},
			grpc: func(t *testing.T) error {
				_, err := h.grpc.MoveFolder(grpcCtx(), &secretv1.MoveFolderRequest{
					Project: "billing", Environment: "prod", From: "/db", To: "/db/primary",
				})
				return err
			},
		},
		{
			name: "create an import of a scope into itself",
			rest: func(t *testing.T) (int, string) {
				return h.callREST(t, http.MethodPost, "/api/v1/imports", map[string]any{
					"project":            "billing",
					"environment":        "prod",
					"folder_path":        "/db",
					"source_project":     "billing",
					"source_environment": "prod",
					"source_folder_path": "/db",
				})
			},
			grpc: func(t *testing.T) error {
				_, err := h.grpc.CreateImport(grpcCtx(), &secretv1.CreateImportRequest{
					Project: "billing", Environment: "prod", FolderPath: "/db",
					SourceProject: "billing", SourceEnvironment: "prod", SourceFolderPath: "/db",
				})
				return err
			},
		},
		{
			name: "register a webhook over plaintext http",
			rest: func(t *testing.T) (int, string) {
				return h.callREST(t, http.MethodPost, "/api/v1/webhooks", map[string]any{
					"project": "billing",
					"url":     "http://hooks.example.com/secret",
				})
			},
			grpc: func(t *testing.T) error {
				_, err := h.grpc.CreateWebhookEndpoint(grpcCtx(), &secretv1.CreateWebhookEndpointRequest{
					Project: "billing",
					Url:     "http://hooks.example.com/secret",
				})
				return err
			},
		},
		{
			name: "register a webhook subscribing to an unknown event",
			rest: func(t *testing.T) (int, string) {
				return h.callREST(t, http.MethodPost, "/api/v1/webhooks", map[string]any{
					"project": "billing",
					"url":     "https://hooks.example.com/secret",
					"events":  []string{"secret.exfiltrated"},
				})
			},
			grpc: func(t *testing.T) error {
				_, err := h.grpc.CreateWebhookEndpoint(grpcCtx(), &secretv1.CreateWebhookEndpointRequest{
					Project: "billing",
					Url:     "https://hooks.example.com/secret",
					Events:  []string{"secret.exfiltrated"},
				})
				return err
			},
		},
		{
			name: "list secrets with a page limit above the cap",
			rest: func(t *testing.T) (int, string) {
				return h.callREST(t, http.MethodGet,
					"/api/v1/secrets?project=billing&environment=prod&limit=100000", nil)
			},
			grpc: func(t *testing.T) error {
				_, err := h.grpc.ListSecrets(grpcCtx(), &secretv1.ListSecretsRequest{
					Project: "billing", Environment: "prod",
					Page: &secretv1.Page{Page: 1, Limit: 100000},
				})
				return err
			},
		},
		{
			name: "batch get over the item bound",
			rest: func(t *testing.T) (int, string) {
				items := make([]map[string]any, 0, api.MaxBatchSize+1)
				for i := 0; i <= api.MaxBatchSize; i++ {
					items = append(items, map[string]any{
						"project": "billing", "environment": "prod", "key": "K",
					})
				}
				return h.callREST(t, http.MethodPost, "/api/v1/bulk/get", map[string]any{"items": items})
			},
			grpc: func(t *testing.T) error {
				items := make([]*secretv1.BatchGetSecretsItem, 0, api.MaxBatchSize+1)
				for i := 0; i <= api.MaxBatchSize; i++ {
					items = append(items, &secretv1.BatchGetSecretsItem{
						Address: &secretv1.SecretAddress{
							Project: "billing", Environment: "prod", Key: "K",
						},
					})
				}
				_, err := h.grpc.BatchGetSecrets(grpcCtx(), &secretv1.BatchGetSecretsRequest{Items: items})
				return err
			},
		},
		{
			name: "batch get with an empty item list",
			rest: func(t *testing.T) (int, string) {
				return h.callREST(t, http.MethodPost, "/api/v1/bulk/get", map[string]any{
					"items": []map[string]any{},
				})
			},
			grpc: func(t *testing.T) error {
				_, err := h.grpc.BatchGetSecrets(grpcCtx(), &secretv1.BatchGetSecretsRequest{})
				return err
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, body := tc.rest(t)
			require.Equal(t, http.StatusBadRequest, code,
				"REST should refuse this payload; body was %s", body)

			err := tc.grpc(t)
			require.Error(t, err, "gRPC accepted a payload REST refused")
			require.Equal(t, codes.InvalidArgument, status.Code(err),
				"gRPC refused for the wrong reason: %v", err)
		})
	}
}

// TestBothTransportsAcceptAWellFormedAddress is the other half of parity, and it is
// worth asserting separately: a validator that refused everything would pass the table
// above while breaking the service.
//
// A well-formed request gets past validation and reaches the stub store, which has no
// implementation and panics. REACHING THE STORE IS THE ASSERTION — it is the proof that
// validation let a good payload through. The two transports report it differently and
// that difference is itself correct:
//
//	gRPC  the panic escapes to the caller here, because the recovery INTERCEPTOR is
//	      installed on the grpc.Server and this test calls the service method directly.
//	REST  the panic is caught by middleware.Recovery and rendered as a 500, which is
//	      exactly the behaviour that middleware exists to provide. A 500 here therefore
//	      means "validation passed and the (absent) store blew up", and specifically NOT
//	      400, which would mean validation refused a good payload.
func TestBothTransportsAcceptAWellFormedAddress(t *testing.T) {
	h := newParityHarness(t)

	panicked := func(fn func()) (reached bool) {
		defer func() {
			if recover() != nil {
				reached = true
			}
		}()
		fn()
		return false
	}

	require.True(t, panicked(func() {
		_, _ = h.grpc.PutSecret(grpcCtx(), &secretv1.PutSecretRequest{
			Address: &secretv1.SecretAddress{
				Project: "billing", Environment: "prod", FolderPath: "/db", Key: "PASSWORD",
			},
			Value: []byte("hunter2"),
		})
	}), "gRPC rejected a well-formed put before reaching the store")

	code, body := h.callREST(t, http.MethodPost, "/api/v1/secrets", map[string]any{
		"project":     "billing",
		"environment": "prod",
		"folder_path": "/db",
		"key":         "PASSWORD",
		"value":       base64.StdEncoding.EncodeToString([]byte("hunter2")),
	})
	require.NotEqual(t, http.StatusBadRequest, code,
		"REST rejected a well-formed put at validation: %s", body)
	require.Equal(t, http.StatusInternalServerError, code,
		"the request should have reached the stub store and been recovered as a 500; body was %s", body)
	require.NotContains(t, body, "panic", "a recovered panic must not leak internals to the client")
	require.NotContains(t, body, "hunter2", "a recovered panic must not echo the request's value")
}

// TestPanicResponseCarriesNoInternals pins the recovery middleware's contract from the
// client's side: a 500 produced by a panic says "internal error" and nothing about the
// stack, the store, or the request that provoked it.
func TestPanicResponseCarriesNoInternals(t *testing.T) {
	h := newParityHarness(t)

	code, body := h.callREST(t, http.MethodGet,
		"/api/v1/secrets?project=billing&environment=prod", nil)
	require.Equal(t, http.StatusInternalServerError, code)
	require.Contains(t, body, "internal error")
	require.NotContains(t, body, "goroutine")
	require.NotContains(t, body, "internal/store")
}
