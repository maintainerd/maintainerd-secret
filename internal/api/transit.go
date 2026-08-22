package api

import (
	"context"

	"github.com/maintainerd/secret/internal/audit"
	"github.com/maintainerd/secret/internal/crypto"
	"github.com/maintainerd/secret/internal/platform/apperror"
	"github.com/maintainerd/secret/internal/platform/permissions"
	"github.com/maintainerd/secret/internal/store"
	"github.com/maintainerd/secret/internal/transit"
)

// Transit: encryption as a service. Key LIFECYCLE, and the two data-plane operations.
//
// THREE PERMISSIONS RATHER THAN ONE, split by blast radius rather than by verb, and
// the split is only worth anything if each surface demands the right one. Encrypt
// produces ciphertext and on its own recovers nothing, so an ingest path that stores
// encrypted columns and never reads them back holds secret:Encrypt alone. Decrypt is
// the grant that recovers plaintext. Managing keys decides what both of the others
// operate on. Collapsing Encrypt and Decrypt would mean every service that WRITES an
// encrypted column could also READ every encrypted column — the same mistake as
// collapsing ReadMetadata into GetSecret.
//
// KEY MANAGEMENT IS USER-ONLY AT THE ROUTE (see internal/platform/permissions); the
// data plane is open to both classes of caller, because a workload encrypting its own
// columns IS the feature and an operator does the same thing from the console.
//
// AUTHORIZATION IS PER KEY, never per project. A create and a listing are authorized
// against the project's transit COLLECTION (store.ResourceTransit) because no key name
// exists yet or the request spans all of them; everything else names one key
// (store.TransitResourcePath), so a grant written for `transit/pii` reaches that key and
// no other.
//
// NOTHING HERE RETURNS KEY MATERIAL, and no audit row carries a plaintext or a
// ciphertext. The rows carry a byte count and a key version — enough to answer "who
// decrypted, and how much", which is the same question a reveal row answers.

// ---------------------------------------------------------------------------
// Key lifecycle
// ---------------------------------------------------------------------------

// CreateTransitKey registers a key and generates its first version.
//
// Authorized against the project's transit COLLECTION rather than the key's own MRN:
// the key does not exist yet, so there is nothing narrower to name. That is the same
// reasoning CreateWebhookEndpoint makes, and it has the same consequence — a grant
// scoped to one key name does not carry the ability to create another.
func (s *Service) CreateTransitKey(ctx context.Context, c Caller, in CreateTransitKeyInput) (*store.TransitKey, error) {
	if err := validate(in); err != nil {
		return nil, err
	}
	resourceMRN := c.mrn(in.Project, store.ResourceTransit)
	if err := s.guard(ctx, c, permissions.PermManageTransitKey, store.ActionTransitKeyCreate, resourceMRN); err != nil {
		return nil, err
	}
	key, err := s.store.CreateTransitKey(ctx, store.CreateTransitKeyInput{
		TenantUUID:  c.TenantUUID,
		Project:     in.Project,
		Name:        in.Name,
		Description: in.Description,
	})
	if err != nil {
		s.recordFailure(ctx, c, store.ActionTransitKeyCreate, resourceMRN, err)
		return nil, err
	}
	// Recorded against the CREATED key's own MRN rather than the collection's, so a
	// reviewer filtering the trail by `transit/pii` sees the row that brought it into
	// existence. Same shape as CreateWebhookEndpoint.
	if err := s.recordSuccess(ctx, c, audit.Event{
		Action:      store.ActionTransitKeyCreate,
		ResourceMRN: c.mrn(in.Project, store.TransitResourcePath(key.Name)),
		Metadata:    map[string]any{"key_uuid": key.UUID.String(), "version": key.CurrentVersion},
	}); err != nil {
		return nil, err
	}
	return key, nil
}

// RotateTransitKey creates a new key version and makes it current.
//
// OLD VERSIONS KEEP DECRYPTING — see store.RotateTransitKey. That is why a rotation is
// safe to hand to whoever manages the key rather than being an irreversible act: it
// changes what the NEXT Encrypt seals under and nothing about what is already stored.
func (s *Service) RotateTransitKey(ctx context.Context, c Caller, in TransitKeyRef) (*store.TransitKey, error) {
	if err := validate(in); err != nil {
		return nil, err
	}
	resourceMRN := c.mrn(in.Project, store.TransitResourcePath(in.Name))
	if err := s.guard(ctx, c, permissions.PermManageTransitKey, store.ActionTransitKeyRotate, resourceMRN); err != nil {
		return nil, err
	}
	key, err := s.store.RotateTransitKey(ctx, c.TenantUUID, in.Project, in.Name)
	if err != nil {
		s.recordFailure(ctx, c, store.ActionTransitKeyRotate, resourceMRN, err)
		return nil, err
	}
	if err := s.recordSuccess(ctx, c, audit.Event{
		Action:      store.ActionTransitKeyRotate,
		ResourceMRN: resourceMRN,
		Version:     int32Ptr(key.CurrentVersion),
		Metadata:    map[string]any{"version": key.CurrentVersion},
	}); err != nil {
		return nil, err
	}
	return key, nil
}

// GetTransitKey reads one key's metadata.
//
// Requires secret:ReadMetadata, not secret:ManageTransitKey: the fields it returns are
// a name, a status, a current version and a decrypt floor. A consumer that can see
// "this key is disabled and its floor is version 3" can explain its own refusals
// instead of discovering them as unattributable errors. store.TransitKey has no
// material field, so this cannot leak key bytes structurally rather than by filtering.
func (s *Service) GetTransitKey(ctx context.Context, c Caller, in TransitKeyRef) (*store.TransitKey, error) {
	if err := validate(in); err != nil {
		return nil, err
	}
	resourceMRN := c.mrn(in.Project, store.TransitResourcePath(in.Name))
	if err := s.guard(ctx, c, permissions.PermReadMetadata, store.ActionRead, resourceMRN); err != nil {
		return nil, err
	}
	key, err := s.store.GetTransitKey(ctx, c.TenantUUID, in.Project, in.Name)
	if err != nil {
		s.recordFailure(ctx, c, store.ActionRead, resourceMRN, err)
		return nil, err
	}
	if err := s.recordSuccess(ctx, c, audit.Event{
		Action:      store.ActionRead,
		ResourceMRN: resourceMRN,
		Metadata:    map[string]any{"read": "transit_key", "status": key.Status},
	}); err != nil {
		return nil, err
	}
	return key, nil
}

// ListTransitKeys pages a project's keys. Metadata only — the query it uses does not
// select a material column at all.
func (s *Service) ListTransitKeys(ctx context.Context, c Caller, in ListTransitKeysInput) ([]store.TransitKey, int64, error) {
	if err := validate(in); err != nil {
		return nil, 0, err
	}
	page, limit := in.Pagination.resolved()
	resourceMRN := c.mrn(in.Project, store.ResourceTransit)
	if err := s.guard(ctx, c, permissions.PermReadMetadata, store.ActionRead, resourceMRN); err != nil {
		return nil, 0, err
	}
	keys, total, err := s.store.ListTransitKeys(ctx, c.TenantUUID, in.Project, page, limit)
	if err != nil {
		s.recordFailure(ctx, c, store.ActionRead, resourceMRN, err)
		return nil, 0, err
	}
	if err := s.recordSuccess(ctx, c, audit.Event{
		Action:      store.ActionRead,
		ResourceMRN: resourceMRN,
		Metadata:    map[string]any{"read": "transit_keys", "returned": len(keys), "total": total},
	}); err != nil {
		return nil, 0, err
	}
	return keys, total, nil
}

// ListTransitKeyVersions returns a key's version history as metadata: version numbers
// and which root key wraps each. No material, for the reason ListVersions returns no
// payloads — browsing history must never be a way to enumerate key material.
func (s *Service) ListTransitKeyVersions(ctx context.Context, c Caller, in ListTransitKeyVersionsInput) ([]store.TransitKeyVersionMeta, int64, error) {
	if err := validate(in); err != nil {
		return nil, 0, err
	}
	page, limit := in.Pagination.resolved()
	resourceMRN := c.mrn(in.Project, store.TransitResourcePath(in.Name))
	if err := s.guard(ctx, c, permissions.PermReadMetadata, store.ActionRead, resourceMRN); err != nil {
		return nil, 0, err
	}
	versions, total, err := s.store.ListTransitKeyVersions(ctx, c.TenantUUID, in.Project, in.Name, page, limit)
	if err != nil {
		s.recordFailure(ctx, c, store.ActionRead, resourceMRN, err)
		return nil, 0, err
	}
	if err := s.recordSuccess(ctx, c, audit.Event{
		Action:      store.ActionRead,
		ResourceMRN: resourceMRN,
		Metadata:    map[string]any{"read": "transit_key_versions", "returned": len(versions), "total": total},
	}); err != nil {
		return nil, 0, err
	}
	return versions, total, nil
}

// UpdateTransitKey rewrites a key's mutable fields: description, status, and the
// decrypt floor.
//
// THE DECRYPT FLOOR IS WHY THIS IS A MANAGEMENT PERMISSION AND NOT A METADATA ONE.
// Raising min_decrypt_version retires material without deleting it, which makes every
// token sealed under a retired version unreadable — a deliberate, recoverable act when
// somebody decides material is compromised, and a service-wide outage when it is done
// by mistake. The store refuses a floor above the current version for exactly that
// reason; the grant is what decides who may move it at all.
func (s *Service) UpdateTransitKey(ctx context.Context, c Caller, in UpdateTransitKeyInput) (*store.TransitKey, error) {
	if err := validate(in); err != nil {
		return nil, err
	}
	resourceMRN := c.mrn(in.Project, store.TransitResourcePath(in.Name))
	if err := s.guard(ctx, c, permissions.PermManageTransitKey, store.ActionTransitKeyUpdate, resourceMRN); err != nil {
		return nil, err
	}
	key, err := s.store.UpdateTransitKey(ctx, store.UpdateTransitKeyInput{
		TenantUUID:        c.TenantUUID,
		Project:           in.Project,
		Name:              in.Name,
		Description:       in.Description,
		Status:            in.Status,
		MinDecryptVersion: in.MinDecryptVersion,
	})
	if err != nil {
		s.recordFailure(ctx, c, store.ActionTransitKeyUpdate, resourceMRN, err)
		return nil, err
	}
	// status and min_decrypt_version are on the row because they are the two fields
	// that change which tokens still open. "The floor was raised to 4 at 03:12" is the
	// fact an incident review needs when a service starts failing to decrypt, and it is
	// unreconstructable from anything else.
	if err := s.recordSuccess(ctx, c, audit.Event{
		Action:      store.ActionTransitKeyUpdate,
		ResourceMRN: resourceMRN,
		Metadata: map[string]any{
			"status":              key.Status,
			"min_decrypt_version": key.MinDecryptVersion,
		},
	}); err != nil {
		return nil, err
	}
	return key, nil
}

// DeleteTransitKey soft-deletes a key. Its versions are untouched, so a delete is
// recoverable and no stored ciphertext is destroyed — see store.DeleteTransitKey for
// why hard-deleting material as a side-effect of removing a row from a listing would be
// the one mistake in that file that cannot be undone.
func (s *Service) DeleteTransitKey(ctx context.Context, c Caller, in TransitKeyRef) error {
	if err := validate(in); err != nil {
		return err
	}
	resourceMRN := c.mrn(in.Project, store.TransitResourcePath(in.Name))
	if err := s.guard(ctx, c, permissions.PermManageTransitKey, store.ActionTransitKeyDelete, resourceMRN); err != nil {
		return err
	}
	if err := s.store.DeleteTransitKey(ctx, c.TenantUUID, in.Project, in.Name); err != nil {
		s.recordFailure(ctx, c, store.ActionTransitKeyDelete, resourceMRN, err)
		return err
	}
	return s.recordSuccess(ctx, c, audit.Event{
		Action:      store.ActionTransitKeyDelete,
		ResourceMRN: resourceMRN,
	})
}

// ---------------------------------------------------------------------------
// The data plane
// ---------------------------------------------------------------------------

// TransitEncrypted is a sealed payload leaving the service. There is no plaintext
// field: the caller supplied it and owns zeroizing it.
type TransitEncrypted struct {
	// Ciphertext is the wire token: m9dt:v1:<key>:<version>:<payload>.
	Ciphertext string `json:"ciphertext"`
	// KeyVersion is the version that sealed it, returned so a caller can see that a
	// rotation has taken effect. It is also inside the token.
	KeyVersion int32 `json:"key_version"`
}

// TransitEncrypt seals a plaintext under a named key's current version.
//
// It requires secret:Encrypt — deliberately NOT secret:ManageTransitKey and
// deliberately NOT secret:Decrypt. An ingest path that stores encrypted columns needs
// exactly this and nothing else, and giving it either of the others would hand it the
// ability to read every column it has ever written, or to retire the key.
//
// The caller owns zeroizing the plaintext it passed in; this function does not, because
// the buffer belongs to whoever decoded it (see the REST handler, which defers a Zero
// on the decoded bytes).
func (s *Service) TransitEncrypt(ctx context.Context, c Caller, in TransitEncryptInput) (*TransitEncrypted, error) {
	if err := validate(in); err != nil {
		return nil, err
	}
	resourceMRN := c.mrn(in.Project, store.TransitResourcePath(in.Name))
	if err := s.guard(ctx, c, permissions.PermEncrypt, store.ActionTransitEncrypt, resourceMRN); err != nil {
		return nil, err
	}
	token, version, err := s.store.TransitEncrypt(ctx, c.TenantUUID, in.Project, in.Name, in.Plaintext)
	if err != nil {
		s.recordFailure(ctx, c, store.ActionTransitEncrypt, resourceMRN, err)
		return nil, err
	}
	// A LENGTH AND A VERSION, never the payload and never the token. The length is safe
	// — it is not a value — and it is what makes "this caller encrypted 40 bytes a
	// second for an hour" visible. Recording the token would put a ciphertext an
	// attacker could later present into a table with a broader read audience than the
	// data it protects.
	if err := s.recordSuccess(ctx, c, audit.Event{
		Action:      store.ActionTransitEncrypt,
		ResourceMRN: resourceMRN,
		Version:     int32Ptr(version),
		Metadata:    map[string]any{"plaintext_bytes": len(in.Plaintext), "key_version": version},
	}); err != nil {
		return nil, err
	}
	return &TransitEncrypted{Ciphertext: token, KeyVersion: version}, nil
}

// TransitDecrypted is a recovered plaintext leaving the service.
//
// Plaintext is a crypto.Plaintext, which renders as "[REDACTED]" through String, %v,
// %#v, slog and json — so this struct cannot leak its own contents into a log line or a
// generic marshaller. THE CALLER MUST Zero IT.
type TransitDecrypted struct {
	Plaintext crypto.Plaintext
	// KeyName and KeyVersion are what the token resolved to, returned so a caller can
	// see which key and which version actually opened it.
	KeyName    string
	KeyVersion int32
}

// Zero overwrites the recovered plaintext in place.
func (d *TransitDecrypted) Zero() {
	if d != nil {
		d.Plaintext.Zero()
	}
}

// TransitDecrypt opens a wire token and returns its plaintext.
//
// THIS IS A REVEAL BY ANOTHER NAME, and it carries the reveal path's contract:
//
//   - It requires secret:Decrypt, a DISTINCT grant from secret:Encrypt.
//   - It refuses to run without an auditor. Not "skips the audit" — refuses.
//   - It refuses to SUCCEED without an audit row: if the audit write fails, the
//     recovered plaintext is zeroized and an error is returned. A caller that receives
//     a plaintext has, by construction, produced a row in audit_log.
//
// THE MRN IS DERIVED FROM THE TOKEN'S KEY NAME, and that is correct rather than
// caller-controlled authorization. The token names a key; the store resolves that same
// name inside the CALLER'S OWN tenant and project and rebuilds the AAD from the row it
// found, so the key this check names is the key that will be opened. A token naming a
// key the caller holds no grant on is an audited denial, and a token naming a key that
// does not exist in this scope is a not-found — never another tenant's key.
//
// Authorizing against the project's transit collection instead would be the bug this
// paragraph exists to prevent: it would let a grant on one key open every ciphertext in
// the project.
func (s *Service) TransitDecrypt(ctx context.Context, c Caller, in TransitDecryptInput) (*TransitDecrypted, error) {
	// Checked FIRST, before the token is parsed: an unauditable service must not
	// perform a decrypt, and must not do the work leading up to one either.
	if s.auditor == nil {
		return nil, audit.ErrNoAuditor
	}
	if err := validate(in); err != nil {
		return nil, err
	}
	// Parsed for its KEY NAME only, so the grant check can name the key the token will
	// resolve to. The DTO's transitTokenRule already proved the token parses, so this
	// error is unreachable; it is handled rather than ignored because a silent
	// zero-value key name would authorize against `transit/` and match a wildcard.
	token, err := transit.ParseToken(in.Ciphertext)
	if err != nil {
		return nil, apperror.NewValidation(err.Error())
	}
	resourceMRN := c.mrn(in.Project, store.TransitResourcePath(token.KeyName))
	if err := s.guard(ctx, c, permissions.PermDecrypt, store.ActionTransitDecrypt, resourceMRN); err != nil {
		return nil, err
	}

	plaintext, keyName, version, err := s.store.TransitDecrypt(ctx, c.TenantUUID, in.Project, in.Ciphertext)
	if err != nil {
		s.recordFailure(ctx, c, store.ActionTransitDecrypt, resourceMRN, err)
		return nil, err
	}
	if err := s.recordSuccess(ctx, c, audit.Event{
		Action:      store.ActionTransitDecrypt,
		ResourceMRN: resourceMRN,
		Version:     int32Ptr(version),
		Metadata:    map[string]any{"plaintext_bytes": plaintext.Len(), "key_version": version},
	}); err != nil {
		// The audit write failed. The plaintext is destroyed rather than returned: a
		// decrypt nobody can prove happened is the one outcome this surface must not
		// produce. Same rule as Reveal.
		plaintext.Zero()
		return nil, err
	}
	return &TransitDecrypted{Plaintext: plaintext, KeyName: keyName, KeyVersion: version}, nil
}
