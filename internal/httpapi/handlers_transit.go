package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/maintainerd/secret/internal/api"
	"github.com/maintainerd/secret/internal/crypto"
	"github.com/maintainerd/secret/internal/platform/response"
)

// Transit handlers: transit-key lifecycle, and the two data-plane operations.
//
// THE KEY IS ADDRESSED BY FIELDS, NOT BY A PATH PARAMETER, and that is a routing
// decision with a security consequence rather than a style preference. The surface
// guard's Exact table is keyed by METHOD + PATH and matches the REQUEST path, so a
// parameterized route (/transit/{name}) cannot carry an exact entry — it would fall
// through to a segment pair, and a segment pair is only ever as strong as the weakest
// route on the segment. That is the exact weakening /secrets was fixed to remove: one
// pair cannot say that encrypt needs secret:Encrypt, decrypt needs secret:Decrypt and a
// rotate needs secret:ManageTransitKey. So every route here is a STATIC path with its
// own entry, and the key name travels in the query string on a read and in the body on a
// write — the same shape /secrets uses for a secret address.
//
// PLAINTEXTS ON THE WIRE ARE BASE64, for the reason a secret value is: a transit
// payload is arbitrary bytes and JSON strings cannot carry arbitrary bytes.
//
// THE DECRYPT RESPONSE IS ENCODED BY HAND, not through the shared response helpers.
// Two reasons, and the second one is a bug rather than a principle: the helpers take
// `any` and marshal it, and a recovered plaintext must never be handed to a generic
// marshaller; and crypto.Plaintext deliberately marshals as "[REDACTED]", so a caller
// that passed one to response.OK would silently return no value at all.

// transitKeyQuery reads a transit key reference from the query string.
func transitKeyQuery(w http.ResponseWriter, r *http.Request) (api.TransitKeyRef, bool) {
	project, ok := requireQuery(w, r, "project")
	if !ok {
		return api.TransitKeyRef{}, false
	}
	name, ok := requireQuery(w, r, "name")
	if !ok {
		return api.TransitKeyRef{}, false
	}
	return api.TransitKeyRef{Project: project, Name: name}, true
}

// ---------------------------------------------------------------------------
// Key lifecycle
// ---------------------------------------------------------------------------

func (s *Server) createTransitKey(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	var req api.CreateTransitKeyInput
	if !decode(w, r, &req) {
		return
	}
	key, err := s.api.CreateTransitKey(r.Context(), c, req)
	if err != nil {
		response.ServiceError(w, r, "could not create the transit key", err)
		return
	}
	response.Created(w, key, "transit key created")
}

func (s *Server) listTransitKeys(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	project, ok := requireQuery(w, r, "project")
	if !ok {
		return
	}
	page, limit := response.PageParams(r)
	keys, total, err := s.api.ListTransitKeys(r.Context(), c, api.ListTransitKeysInput{
		Project:    project,
		Pagination: api.Pagination{Page: page, Limit: limit},
	})
	if err != nil {
		response.ServiceError(w, r, "could not list transit keys", err)
		return
	}
	// keys is []store.TransitKey — a type with no material field — so this response
	// cannot carry key bytes even if a future edit wanted it to.
	response.List(w, keys, page, limit, total)
}

func (s *Server) describeTransitKey(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	ref, ok := transitKeyQuery(w, r)
	if !ok {
		return
	}
	key, err := s.api.GetTransitKey(r.Context(), c, ref)
	if err != nil {
		response.ServiceError(w, r, "could not read the transit key", err)
		return
	}
	response.OK(w, key, "")
}

func (s *Server) listTransitKeyVersions(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	ref, ok := transitKeyQuery(w, r)
	if !ok {
		return
	}
	page, limit := response.PageParams(r)
	versions, total, err := s.api.ListTransitKeyVersions(r.Context(), c, api.ListTransitKeyVersionsInput{
		Project:    ref.Project,
		Name:       ref.Name,
		Pagination: api.Pagination{Page: page, Limit: limit},
	})
	if err != nil {
		response.ServiceError(w, r, "could not list transit key versions", err)
		return
	}
	response.List(w, versions, page, limit, total)
}

func (s *Server) updateTransitKey(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	var req api.UpdateTransitKeyInput
	if !decode(w, r, &req) {
		return
	}
	key, err := s.api.UpdateTransitKey(r.Context(), c, req)
	if err != nil {
		response.ServiceError(w, r, "could not update the transit key", err)
		return
	}
	response.OK(w, key, "transit key updated")
}

func (s *Server) rotateTransitKey(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	var req api.TransitKeyRef
	if !decode(w, r, &req) {
		return
	}
	key, err := s.api.RotateTransitKey(r.Context(), c, req)
	if err != nil {
		response.ServiceError(w, r, "could not rotate the transit key", err)
		return
	}
	// The new key material is NOT in this response, and there is no operation that
	// would return it: a transit key's whole value proposition is that the material
	// never leaves the service.
	response.OK(w, key, "transit key rotated; tokens issued under earlier versions still decrypt")
}

func (s *Server) deleteTransitKey(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	ref, ok := transitKeyQuery(w, r)
	if !ok {
		return
	}
	if err := s.api.DeleteTransitKey(r.Context(), c, ref); err != nil {
		response.ServiceError(w, r, "could not delete the transit key", err)
		return
	}
	response.NoContent(w)
}

// ---------------------------------------------------------------------------
// The data plane
// ---------------------------------------------------------------------------

type transitEncryptRequest struct {
	Project string `json:"project"`
	Name    string `json:"name"`
	// Plaintext is base64 of the raw bytes to seal.
	Plaintext string `json:"plaintext"`
}

// transitEncrypt seals a plaintext and returns the wire token.
//
// A POST carrying what is conceptually a pure function of its input, because the input
// is a plaintext: a value in a URL ends up in access logs, proxy logs, browser history
// and referer headers, and a body does not.
func (s *Server) transitEncrypt(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	var req transitEncryptRequest
	if !decode(w, r, &req) {
		return
	}
	plaintext, err := base64.StdEncoding.DecodeString(req.Plaintext)
	if err != nil {
		response.Error(w, http.StatusBadRequest, "plaintext must be base64-encoded")
		return
	}
	// The decoded plaintext is zeroized as soon as the seal returns; it exists in this
	// handler's memory for exactly as long as the store needs it.
	defer crypto.Zero(plaintext)

	sealed, err := s.api.TransitEncrypt(r.Context(), c, api.TransitEncryptInput{
		Project:   req.Project,
		Name:      req.Name,
		Plaintext: plaintext,
	})
	if err != nil {
		response.ServiceError(w, r, "could not encrypt", err)
		return
	}
	// The response carries a CIPHERTEXT, not a value — but no-store anyway: a token is
	// derived from a caller's own data and has no business in a shared or disk cache.
	w.Header().Set("Cache-Control", "no-store")
	response.OK(w, sealed, "")
}

type transitDecryptRequest struct {
	Project string `json:"project"`
	// Ciphertext is the wire token. The key name is inside it, deliberately: the caller
	// stores one opaque string and never tracks a key version.
	Ciphertext string `json:"ciphertext"`
}

// transitDecryptResponse is one of the two response shapes in this service that carry a
// recovered plaintext (the other is revealResponse). Encoded by hand for the reason
// stated in the file comment.
type transitDecryptResponse struct {
	Success bool   `json:"success"`
	KeyName string `json:"key_name"`
	Version int32  `json:"key_version"`
	// Plaintext is base64 of the raw recovered bytes.
	Plaintext string `json:"plaintext"`
}

func (s *Server) transitDecrypt(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	var req transitDecryptRequest
	if !decode(w, r, &req) {
		return
	}
	opened, err := s.api.TransitDecrypt(r.Context(), c, api.TransitDecryptInput{
		Project:    req.Project,
		Ciphertext: req.Ciphertext,
	})
	if err != nil {
		// The api layer's errors describe the caller's own token or name a missing
		// grant; none of them carries a plaintext, and the store's decrypt failure is
		// reported as a validation error whose message says no more than "this token
		// does not authenticate".
		response.ServiceError(w, r, "could not decrypt", err)
		return
	}
	// The plaintext is copied into the response and the store's buffer is zeroized
	// immediately; from there its lifetime is the response's.
	defer opened.Zero()

	body := transitDecryptResponse{
		Success:   true,
		KeyName:   opened.KeyName,
		Version:   opened.KeyVersion,
		Plaintext: base64.StdEncoding.EncodeToString(opened.Plaintext.Bytes()),
	}
	// No-store, not merely no-cache: a recovered plaintext must not land in a shared
	// cache, a disk cache, or a proxy.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(body)
}
