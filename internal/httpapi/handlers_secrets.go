package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/maintainerd/secret/internal/api"
	"github.com/maintainerd/secret/internal/crypto"
	"github.com/maintainerd/secret/internal/platform/response"
	"github.com/maintainerd/secret/internal/rotation"
	"github.com/maintainerd/secret/internal/store"
)

// Secret handlers.
//
// VALUES ON THE WIRE ARE BASE64. A secret value is arbitrary bytes — a binary key, a
// certificate, a password with a newline in it — and JSON strings cannot carry
// arbitrary bytes. Base64 makes the encoding lossless and explicit rather than
// silently mangling anything that is not valid UTF-8.
//
// THE REVEAL RESPONSE IS ENCODED BY HAND, not through the shared response helpers.
// That is deliberate: the helpers take `any` and marshal it, and a decrypted value
// must never be handed to a generic marshaller — one refactor away from a value in a
// log line or an error body. Encoding it here means "which responses can contain a
// value" is answerable by grep, and it is one function.

// addressQuery reads a secret address from the query string.
func addressQuery(w http.ResponseWriter, r *http.Request) (api.SecretAddress, bool) {
	project, ok := requireQuery(w, r, "project")
	if !ok {
		return api.SecretAddress{}, false
	}
	environment, ok := requireQuery(w, r, "environment")
	if !ok {
		return api.SecretAddress{}, false
	}
	key, ok := requireQuery(w, r, "key")
	if !ok {
		return api.SecretAddress{}, false
	}
	return api.SecretAddress{
		Project:     project,
		Environment: environment,
		FolderPath:  r.URL.Query().Get("folder_path"),
		Key:         key,
	}, true
}

// ---------------------------------------------------------------------------
// List / describe / versions
// ---------------------------------------------------------------------------

func (s *Server) listSecrets(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	project, ok := requireQuery(w, r, "project")
	if !ok {
		return
	}
	environment, ok := requireQuery(w, r, "environment")
	if !ok {
		return
	}
	page, limit := response.PageParams(r)
	metas, total, err := s.api.ListSecrets(r.Context(), c, api.ListSecretsInput{
		Project:     project,
		Environment: environment,
		PathPrefix:  r.URL.Query().Get("prefix"),
		Page:        page,
		Limit:       limit,
	})
	if err != nil {
		response.ServiceError(w, r, "could not list secrets", err)
		return
	}
	// metas is []store.SecretMeta — a type with no value field — so this response
	// cannot carry a value even if a future edit wanted it to.
	response.List(w, metas, page, limit, total)
}

func (s *Server) describeSecret(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	addr, ok := addressQuery(w, r)
	if !ok {
		return
	}
	meta, err := s.api.DescribeSecret(r.Context(), c, addr)
	if err != nil {
		response.ServiceError(w, r, "could not describe the secret", err)
		return
	}
	response.OK(w, meta, "")
}

func (s *Server) listVersions(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	addr, ok := addressQuery(w, r)
	if !ok {
		return
	}
	page, limit := response.PageParams(r)
	versions, total, err := s.api.ListVersions(r.Context(), c, addr, page, limit)
	if err != nil {
		response.ServiceError(w, r, "could not list versions", err)
		return
	}
	response.List(w, versions, page, limit, total)
}

func (s *Server) listDeletedSecrets(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	project, ok := requireQuery(w, r, "project")
	if !ok {
		return
	}
	environment, ok := requireQuery(w, r, "environment")
	if !ok {
		return
	}
	page, limit := response.PageParams(r)
	deleted, err := s.api.ListDeletedSecrets(r.Context(), c, project, environment, page, limit)
	if err != nil {
		response.ServiceError(w, r, "could not list deleted secrets", err)
		return
	}
	response.OK(w, deleted, "")
}

// ---------------------------------------------------------------------------
// Reveal
// ---------------------------------------------------------------------------

type revealRequest struct {
	api.SecretAddress
	Version int32 `json:"version,omitempty"`
}

// revealResponse is the ONE response shape in this service that carries a value.
type revealResponse struct {
	Success bool   `json:"success"`
	Key     string `json:"key"`
	Version int32  `json:"version"`
	Type    string `json:"value_type"`
	// Value is base64 of the raw plaintext bytes.
	Value string `json:"value"`
	MRN   string `json:"mrn"`
	// ReferenceHops names the secrets a reference chain traversed, so a caller can
	// see where the value actually came from.
	ReferenceHops []string `json:"reference_hops,omitempty"`
}

func (s *Server) revealSecret(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	var req revealRequest
	if !decode(w, r, &req) {
		return
	}
	revealed, err := s.api.Reveal(r.Context(), c, req.SecretAddress, req.Version)
	if err != nil {
		response.ServiceError(w, r, "could not reveal the secret", err)
		return
	}
	// The plaintext is copied into the response and the store's buffer is zeroized
	// immediately; from there the value's lifetime is the response's.
	defer revealed.Secret.Zero()

	body := revealResponse{
		Success:       true,
		Key:           revealed.Secret.Meta.Key,
		Version:       revealed.Secret.Version,
		Type:          revealed.Secret.ValueType,
		Value:         base64.StdEncoding.EncodeToString(revealed.Secret.Value.Bytes()),
		MRN:           revealed.Secret.Meta.MRN,
		ReferenceHops: revealed.ReferenceHops,
	}
	// No-store, not merely no-cache: a revealed credential must not land in a shared
	// cache, a disk cache, or a proxy.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(body)
}

// ---------------------------------------------------------------------------
// Write
// ---------------------------------------------------------------------------

type putSecretRequest struct {
	api.SecretAddress
	// Value is base64 of the raw plaintext bytes.
	Value          string         `json:"value"`
	ValueType      string         `json:"value_type,omitempty"`
	Description    string         `json:"description,omitempty"`
	Tags           []string       `json:"tags,omitempty"`
	KeepVersions   *int32         `json:"keep_versions,omitempty"`
	RotationPolicy map[string]any `json:"rotation_policy,omitempty"`
	ExpiresAt      *time.Time     `json:"expires_at,omitempty"`
	CreateFolders  bool           `json:"create_folders,omitempty"`
}

func (s *Server) putSecret(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	var req putSecretRequest
	if !decode(w, r, &req) {
		return
	}
	value, err := base64.StdEncoding.DecodeString(req.Value)
	if err != nil {
		response.Error(w, http.StatusBadRequest, "value must be base64-encoded")
		return
	}
	// The decoded plaintext is zeroized as soon as the write returns; it exists in
	// this handler's memory for exactly as long as the store needs it.
	defer crypto.Zero(value)

	result, err := s.api.PutSecret(r.Context(), c, api.PutSecretInput{
		Address:        req.SecretAddress,
		Value:          value,
		ValueType:      req.ValueType,
		Description:    req.Description,
		Tags:           req.Tags,
		KeepVersions:   req.KeepVersions,
		RotationPolicy: req.RotationPolicy,
		ExpiresAt:      req.ExpiresAt,
		CreateFolders:  req.CreateFolders,
	})
	if err != nil {
		response.ServiceError(w, r, "could not write the secret", err)
		return
	}
	if result.Created {
		response.Created(w, result, "secret created")
		return
	}
	response.OK(w, result, "secret written")
}

type updateSecretMetaRequest struct {
	api.SecretAddress
	Description    string         `json:"description,omitempty"`
	Tags           []string       `json:"tags,omitempty"`
	KeepVersions   *int32         `json:"keep_versions,omitempty"`
	RotationPolicy map[string]any `json:"rotation_policy,omitempty"`
	ExpiresAt      *time.Time     `json:"expires_at,omitempty"`
}

func (s *Server) updateSecretMeta(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	var req updateSecretMetaRequest
	if !decode(w, r, &req) {
		return
	}
	meta, err := s.api.UpdateSecretMeta(r.Context(), c, api.UpdateSecretMetaInput{
		Address:        req.SecretAddress,
		Description:    req.Description,
		Tags:           req.Tags,
		KeepVersions:   req.KeepVersions,
		RotationPolicy: req.RotationPolicy,
		ExpiresAt:      req.ExpiresAt,
	})
	if err != nil {
		response.ServiceError(w, r, "could not update the secret metadata", err)
		return
	}
	response.OK(w, meta, "secret metadata updated")
}

type rollbackRequest struct {
	api.SecretAddress
	Version int32 `json:"version"`
}

func (s *Server) rollbackSecret(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	var req rollbackRequest
	if !decode(w, r, &req) {
		return
	}
	result, err := s.api.Rollback(r.Context(), c, req.SecretAddress, req.Version)
	if err != nil {
		response.ServiceError(w, r, "could not roll the secret back", err)
		return
	}
	response.OK(w, result, "secret rolled back")
}

// ---------------------------------------------------------------------------
// Rotation
// ---------------------------------------------------------------------------

type rotateRequest struct {
	api.SecretAddress
	Generator rotationSpecRequest `json:"generator,omitempty"`
}

// rotationSpecRequest mirrors rotation.Spec. It is restated here rather than embedded
// so the wire shape is a decision of this package: a value the caller supplies arrives
// base64-encoded like every other value on this API.
type rotationSpecRequest struct {
	Type    string `json:"type,omitempty"`
	Length  int    `json:"length,omitempty"`
	Charset string `json:"charset,omitempty"`
	// Value is base64 of a caller-supplied plaintext, for the `supplied` generator.
	Value string `json:"value,omitempty"`
}

func (s *Server) rotateSecret(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	var req rotateRequest
	if !decode(w, r, &req) {
		return
	}
	spec := rotation.Spec{
		Type:    req.Generator.Type,
		Length:  req.Generator.Length,
		Charset: req.Generator.Charset,
	}
	if req.Generator.Value != "" {
		decoded, err := base64.StdEncoding.DecodeString(req.Generator.Value)
		if err != nil {
			response.Error(w, http.StatusBadRequest, "generator value must be base64-encoded")
			return
		}
		spec.Value = string(decoded)
	}
	result, err := s.api.RotateSecret(r.Context(), c, api.RotateSecretInput{
		Address:   req.SecretAddress,
		Generator: spec,
	})
	if err != nil {
		response.ServiceError(w, r, "could not rotate the secret", err)
		return
	}
	// The rotated value is NOT in this response. Reading it is a reveal, with its own
	// grant and its own audit row.
	response.OK(w, result, "secret rotated")
}

type rotationPolicyRequest struct {
	api.SecretAddress
	Enabled   bool                `json:"enabled"`
	Interval  string              `json:"interval,omitempty"`
	Generator rotationSpecRequest `json:"generator,omitempty"`
}

func (s *Server) setRotationPolicy(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	var req rotationPolicyRequest
	if !decode(w, r, &req) {
		return
	}
	if req.Generator.Value != "" {
		// A stored policy must never carry a value — it lives in readable metadata.
		// Refused here with a message that says why, rather than silently dropped.
		response.Error(w, http.StatusBadRequest,
			"a rotation policy must not carry a generator value: the policy is stored as readable metadata")
		return
	}
	policy := rotation.Policy{
		Enabled:  req.Enabled,
		Interval: req.Interval,
		Generator: rotation.Spec{
			Type:    req.Generator.Type,
			Length:  req.Generator.Length,
			Charset: req.Generator.Charset,
		},
	}
	meta, err := s.api.SetRotationPolicy(r.Context(), c, req.SecretAddress, policy)
	if err != nil {
		response.ServiceError(w, r, "could not set the rotation policy", err)
		return
	}
	response.OK(w, meta, "rotation policy set")
}

// ---------------------------------------------------------------------------
// Delete / restore / destroy
// ---------------------------------------------------------------------------

type deleteSecretRequest struct {
	api.SecretAddress
	// RecoveryWindow overrides the service default, as a duration string.
	RecoveryWindow string `json:"recovery_window,omitempty"`
}

func (s *Server) deleteSecret(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	var req deleteSecretRequest
	if !decode(w, r, &req) {
		return
	}
	var window *time.Duration
	if req.RecoveryWindow != "" {
		d, err := time.ParseDuration(req.RecoveryWindow)
		if err != nil {
			response.Error(w, http.StatusBadRequest, "recovery_window must be a duration such as \"168h\"")
			return
		}
		window = &d
	}
	deleted, err := s.api.DeleteSecret(r.Context(), c, req.SecretAddress, window)
	if err != nil {
		response.ServiceError(w, r, "could not delete the secret", err)
		return
	}
	response.OK(w, deleted, "secret deleted; it can be restored until destroy_after")
}

type secretUUIDRequest struct {
	SecretUUID string `json:"secret_uuid"`
}

func (s *Server) restoreSecret(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	var req secretUUIDRequest
	if !decode(w, r, &req) {
		return
	}
	id, err := uuid.Parse(req.SecretUUID)
	if err != nil {
		response.Error(w, http.StatusBadRequest, "secret_uuid must be a UUID")
		return
	}
	meta, err := s.api.RestoreSecret(r.Context(), c, id)
	if err != nil {
		response.ServiceError(w, r, "could not restore the secret", err)
		return
	}
	response.OK(w, meta, "secret restored")
}

func (s *Server) destroySecret(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	var req secretUUIDRequest
	if !decode(w, r, &req) {
		return
	}
	id, err := uuid.Parse(req.SecretUUID)
	if err != nil {
		response.Error(w, http.StatusBadRequest, "secret_uuid must be a UUID")
		return
	}
	if err := s.api.DestroySecret(r.Context(), c, id); err != nil {
		response.ServiceError(w, r, "could not destroy the secret", err)
		return
	}
	response.OK(w, map[string]any{"destroyed": true}, "secret destroyed permanently")
}

// ---------------------------------------------------------------------------
// Bulk
// ---------------------------------------------------------------------------

type batchGetRequest struct {
	Items []struct {
		api.SecretAddress
		Version int32 `json:"version,omitempty"`
	} `json:"items"`
}

// batchGetResponseItem is a per-item outcome. Error is a string rather than an object
// because the useful thing about a partial failure is the message.
type batchGetResponseItem struct {
	Address       api.SecretAddress `json:"address"`
	Version       int32             `json:"version,omitempty"`
	Type          string            `json:"value_type,omitempty"`
	Value         string            `json:"value,omitempty"`
	MRN           string            `json:"mrn,omitempty"`
	ReferenceHops []string          `json:"reference_hops,omitempty"`
	Error         string            `json:"error,omitempty"`
}

func (s *Server) batchGet(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	var req batchGetRequest
	if !decode(w, r, &req) {
		return
	}
	items := make([]api.BatchGetItem, 0, len(req.Items))
	for _, item := range req.Items {
		items = append(items, api.BatchGetItem{Address: item.SecretAddress, Version: item.Version})
	}
	results, err := s.api.BatchGet(r.Context(), c, items)
	if err != nil {
		response.ServiceError(w, r, "could not perform the batch get", err)
		return
	}
	defer func() {
		for i := range results {
			results[i].Zero()
		}
	}()

	out := make([]batchGetResponseItem, 0, len(results))
	for i := range results {
		res := &results[i]
		item := batchGetResponseItem{Address: res.Address}
		if res.Error != nil {
			item.Error = res.Error.Error()
			out = append(out, item)
			continue
		}
		item.Version = res.Secret.Version
		item.Type = res.Secret.ValueType
		item.Value = base64.StdEncoding.EncodeToString(res.Secret.Value.Bytes())
		item.MRN = res.Secret.Meta.MRN
		item.ReferenceHops = res.ReferenceHops
		out = append(out, item)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "data": out})
}

type batchPutRequest struct {
	Items []struct {
		api.SecretAddress
		Value         string   `json:"value"`
		ValueType     string   `json:"value_type,omitempty"`
		Description   string   `json:"description,omitempty"`
		Tags          []string `json:"tags,omitempty"`
		CreateFolders bool     `json:"create_folders,omitempty"`
	} `json:"items"`
}

type batchPutResponseItem struct {
	Address api.SecretAddress `json:"address"`
	Result  *store.PutResult  `json:"result,omitempty"`
	Error   string            `json:"error,omitempty"`
}

func (s *Server) batchPut(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	var req batchPutRequest
	if !decode(w, r, &req) {
		return
	}
	items := make([]api.BatchPutItem, 0, len(req.Items))
	for _, item := range req.Items {
		value, err := base64.StdEncoding.DecodeString(item.Value)
		if err != nil {
			response.Error(w, http.StatusBadRequest,
				"item "+strconv.Itoa(len(items))+": value must be base64-encoded")
			return
		}
		items = append(items, api.BatchPutItem{
			Address:       item.SecretAddress,
			Value:         value,
			ValueType:     item.ValueType,
			Description:   item.Description,
			Tags:          item.Tags,
			CreateFolders: item.CreateFolders,
		})
	}
	defer func() {
		for i := range items {
			crypto.Zero(items[i].Value)
		}
	}()

	results, err := s.api.BatchPut(r.Context(), c, items)
	if err != nil {
		response.ServiceError(w, r, "could not perform the batch put", err)
		return
	}
	out := make([]batchPutResponseItem, 0, len(results))
	for _, res := range results {
		item := batchPutResponseItem{Address: res.Address, Result: res.Result}
		if res.Error != nil {
			item.Error = res.Error.Error()
		}
		out = append(out, item)
	}
	response.OK(w, out, "batch put complete")
}
