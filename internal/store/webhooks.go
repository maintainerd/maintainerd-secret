package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/maintainerd/secret/internal/crypto"
	"github.com/maintainerd/secret/internal/platform/apperror"
	"github.com/maintainerd/secret/internal/storage"
)

// Webhook endpoints: per-project HTTP destinations notified when a secret changes or
// rotates, so a consumer can re-read.
//
// THE SIGNING KEY IS A SECRET AND IS TREATED AS ONE. It is generated here, sealed
// with the same envelope primitives a secret value uses (AAD bound to the endpoint's
// UUID), and returned to the caller EXACTLY ONCE — at creation, in the create
// response, so the receiver can be configured. There is no read-it-back endpoint. An
// HMAC key that can be fetched is a forgery primitive: whoever reads it can sign a
// delivery the receiver will trust, which is worse than a leaked value because it
// lets an attacker tell a consumer to re-read at a moment of their choosing (or,
// with a compromised receiver, to accept a forged event).

// Webhook event names. They are the vocabulary a subscriber filters on, so they are
// constants rather than free strings a caller invents.
const (
	// WebhookEventSecretChanged fires on any new version written by a caller.
	WebhookEventSecretChanged = "secret.changed"
	// WebhookEventSecretRotated fires on a rotation — manual or scheduled. It is
	// separate from `changed` because a consumer that only needs to reload on
	// rotation should not be woken by every ordinary edit.
	WebhookEventSecretRotated = "secret.rotated"
)

// knownWebhookEvents is the closed set an endpoint may subscribe to. A typo in a
// subscription is silent otherwise: the endpoint simply never fires, and the
// operator discovers it during the incident the webhook existed to prevent.
var knownWebhookEvents = map[string]bool{
	WebhookEventSecretChanged: true,
	WebhookEventSecretRotated: true,
}

// WebhookEvents returns the closed event set, in a stable order. It exists so the API
// layer's validation lists exactly what this package accepts rather than a second copy
// that can drift.
func WebhookEvents() []string {
	return []string{WebhookEventSecretChanged, WebhookEventSecretRotated}
}

// IsKnownWebhookEvent reports whether an event name is one an endpoint may subscribe
// to.
func IsKnownWebhookEvent(event string) bool {
	return knownWebhookEvents[strings.TrimSpace(event)]
}

// Endpoint statuses. Exported for the same reason ResourceStatuses is.
const (
	WebhookStatusActive   = "active"
	WebhookStatusDisabled = "disabled"
)

// WebhookStatuses is the closed set.
var WebhookStatuses = []string{WebhookStatusActive, WebhookStatusDisabled}

// WebhookEndpoint is an endpoint as it leaves this package. NOTE THE ABSENCE of any
// signing-key field — this type cannot carry one.
type WebhookEndpoint struct {
	UUID            uuid.UUID  `json:"endpoint_uuid"`
	URL             string     `json:"url"`
	Description     string     `json:"description"`
	Events          []string   `json:"events"`
	Status          string     `json:"status"`
	TimeoutSeconds  int32      `json:"timeout_seconds"`
	MaxAttempts     int32      `json:"max_attempts"`
	LastTriggeredAt *time.Time `json:"last_triggered_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// CreatedWebhookEndpoint is the create response: the endpoint plus the signing key,
// the one and only time it is disclosed.
type CreatedWebhookEndpoint struct {
	WebhookEndpoint
	// SigningKey is base64 (standard, padded). It is a crypto.Plaintext-free string
	// because it has to be JSON-encoded into the create response — the one place a
	// generated secret legitimately leaves this service — and the caller is
	// responsible for not logging the response body.
	SigningKey string `json:"signing_key"`
}

// SignedWebhookEndpoint is an endpoint together with its DECRYPTED signing key, for
// the delivery path only. The key is a crypto.Plaintext so it cannot be logged or
// marshalled by accident; the caller must Zero it.
type SignedWebhookEndpoint struct {
	ID             int64
	UUID           uuid.UUID
	URL            string
	Events         []string
	TimeoutSeconds int32
	MaxAttempts    int32
	SigningKey     crypto.Plaintext
}

// Zero overwrites the decrypted signing key.
func (e *SignedWebhookEndpoint) Zero() {
	if e != nil {
		e.SigningKey.Zero()
	}
}

// Subscribes reports whether this endpoint wants the given event. An empty
// subscription list means every event.
func (e SignedWebhookEndpoint) Subscribes(event string) bool {
	if len(e.Events) == 0 {
		return true
	}
	for _, want := range e.Events {
		if want == event {
			return true
		}
	}
	return false
}

// CreateWebhookEndpointInput describes a new endpoint.
type CreateWebhookEndpointInput struct {
	TenantUUID  uuid.UUID
	Project     string
	URL         string
	Description string
	// Events is the subscription filter; empty means every event.
	Events         []string
	TimeoutSeconds int32
	MaxAttempts    int32
}

// CreateWebhookEndpoint registers an endpoint and generates its signing key.
func (s *Service) CreateWebhookEndpoint(ctx context.Context, in CreateWebhookEndpointInput) (*CreatedWebhookEndpoint, error) {
	if err := ValidateWebhookURL(in.URL); err != nil {
		return nil, apperror.NewValidation(err.Error())
	}
	events, err := normalizeWebhookEvents(in.Events)
	if err != nil {
		return nil, err
	}
	eventsJSON, err := json.Marshal(events)
	if err != nil {
		return nil, apperror.NewInternal("encode webhook events", err)
	}
	meta, err := encodeObject(nil)
	if err != nil {
		return nil, apperror.NewInternal("encode webhook metadata", err)
	}
	timeout := in.TimeoutSeconds
	if timeout <= 0 {
		timeout = 10
	}
	attempts := in.MaxAttempts
	if attempts <= 0 {
		attempts = 3
	}

	tenant, err := s.repo.GetTenantByUUID(ctx, in.TenantUUID)
	if err != nil {
		return nil, mapReadError(err, "tenant")
	}
	project, err := s.repo.GetProjectBySlug(ctx, storage.GetProjectBySlugParams{
		TenantID: tenant.TenantID,
		Slug:     in.Project,
	})
	if err != nil {
		return nil, mapReadError(err, "project")
	}

	// crypto.NewRandomKey produces 32 bytes — HMAC-SHA256's block-relevant size, so a
	// shorter key buys nothing and a longer one is hashed down to it anyway.
	key, err := crypto.NewRandomKey()
	if err != nil {
		return nil, apperror.NewInternal("generate webhook signing key", err)
	}
	defer crypto.Zero(key)

	endpointUUID := uuid.New()
	envelope, err := crypto.Seal(s.ring.Active(), webhookIdentity(tenant.TenantUuid, endpointUUID), key)
	if err != nil {
		return nil, apperror.NewInternal("seal webhook signing key", err)
	}

	row, err := s.repo.CreateWebhookEndpoint(ctx, storage.CreateWebhookEndpointParams{
		EndpointUuid:     endpointUUID,
		TenantID:         tenant.TenantID,
		ProjectID:        project.ProjectID,
		Url:              in.URL,
		Description:      in.Description,
		SecretCiphertext: envelope.Ciphertext,
		SecretNonce:      envelope.Nonce,
		SecretDekWrapped: envelope.DEKWrapped,
		SecretDekNonce:   envelope.DEKNonce,
		KekID:            envelope.KEKID,
		Events:           eventsJSON,
		Status:           "active",
		TimeoutSeconds:   timeout,
		MaxAttempts:      attempts,
		Metadata:         meta,
	})
	if err != nil {
		return nil, mapWriteError(err, "webhook endpoint", fmt.Sprintf("an endpoint for %s already exists in this project", in.URL))
	}

	return &CreatedWebhookEndpoint{
		WebhookEndpoint: toWebhookEndpoint(row),
		SigningKey:      base64.StdEncoding.EncodeToString(key),
	}, nil
}

// ListWebhookEndpoints pages a project's endpoints. Metadata only — the query it
// uses does not select the signing-key columns at all.
func (s *Service) ListWebhookEndpoints(ctx context.Context, tenantUUID uuid.UUID, project string, page, limit int) ([]WebhookEndpoint, int64, error) {
	tenant, err := s.repo.GetTenantByUUID(ctx, tenantUUID)
	if err != nil {
		return nil, 0, mapReadError(err, "tenant")
	}
	proj, err := s.repo.GetProjectBySlug(ctx, storage.GetProjectBySlugParams{
		TenantID: tenant.TenantID,
		Slug:     project,
	})
	if err != nil {
		return nil, 0, mapReadError(err, "project")
	}
	page, limit = normalizePage(page, limit)
	rows, err := s.repo.ListWebhookEndpointMetaByProject(ctx, storage.ListWebhookEndpointMetaByProjectParams{
		TenantID:  tenant.TenantID,
		ProjectID: proj.ProjectID,
		RowLimit:  int32(limit),
		RowOffset: int32((page - 1) * limit),
	})
	if err != nil {
		return nil, 0, apperror.NewInternal("list webhook endpoints", err)
	}
	total, err := s.repo.CountWebhookEndpointsByProject(ctx, storage.CountWebhookEndpointsByProjectParams{
		TenantID:  tenant.TenantID,
		ProjectID: proj.ProjectID,
	})
	if err != nil {
		return nil, 0, apperror.NewInternal("count webhook endpoints", err)
	}
	out := make([]WebhookEndpoint, 0, len(rows))
	for _, r := range rows {
		out = append(out, WebhookEndpoint{
			UUID:            r.EndpointUuid,
			URL:             r.Url,
			Description:     r.Description,
			Events:          decodeStringList(r.Events),
			Status:          r.Status,
			TimeoutSeconds:  r.TimeoutSeconds,
			MaxAttempts:     r.MaxAttempts,
			LastTriggeredAt: timePtr(r.LastTriggeredAt),
			CreatedAt:       r.CreatedAt,
			UpdatedAt:       r.UpdatedAt,
		})
	}
	return out, total, nil
}

// UpdateWebhookEndpointInput changes an endpoint. The signing key is absent: it is
// not editable, and rotating it means creating a new endpoint (which is honest —
// the receiver has to be reconfigured either way, and a silent key change would
// break deliveries with a signature mismatch nobody could diagnose).
type UpdateWebhookEndpointInput struct {
	TenantUUID     uuid.UUID
	EndpointUUID   uuid.UUID
	URL            string
	Description    string
	Events         []string
	Status         string
	TimeoutSeconds int32
	MaxAttempts    int32
}

// UpdateWebhookEndpoint rewrites an endpoint's configuration.
func (s *Service) UpdateWebhookEndpoint(ctx context.Context, in UpdateWebhookEndpointInput) (*WebhookEndpoint, error) {
	if err := ValidateWebhookURL(in.URL); err != nil {
		return nil, apperror.NewValidation(err.Error())
	}
	switch in.Status {
	case WebhookStatusActive, WebhookStatusDisabled:
	case "":
		in.Status = WebhookStatusActive
	default:
		return nil, apperror.NewValidation(fmt.Sprintf("status %q must be %s or %s",
			in.Status, WebhookStatusActive, WebhookStatusDisabled))
	}
	events, err := normalizeWebhookEvents(in.Events)
	if err != nil {
		return nil, err
	}
	eventsJSON, err := json.Marshal(events)
	if err != nil {
		return nil, apperror.NewInternal("encode webhook events", err)
	}
	tenant, err := s.repo.GetTenantByUUID(ctx, in.TenantUUID)
	if err != nil {
		return nil, mapReadError(err, "tenant")
	}
	timeout := in.TimeoutSeconds
	if timeout <= 0 {
		timeout = 10
	}
	attempts := in.MaxAttempts
	if attempts <= 0 {
		attempts = 3
	}
	row, err := s.repo.UpdateWebhookEndpoint(ctx, storage.UpdateWebhookEndpointParams{
		Url:            in.URL,
		Description:    in.Description,
		Events:         eventsJSON,
		Status:         in.Status,
		TimeoutSeconds: timeout,
		MaxAttempts:    attempts,
		TenantID:       tenant.TenantID,
		EndpointUuid:   in.EndpointUUID,
	})
	if err != nil {
		return nil, mapWriteError(err, "webhook endpoint", "an endpoint for that URL already exists in this project")
	}
	out := toWebhookEndpoint(row)
	return &out, nil
}

// DeleteWebhookEndpoint soft-deletes an endpoint.
func (s *Service) DeleteWebhookEndpoint(ctx context.Context, tenantUUID, endpointUUID uuid.UUID) error {
	tenant, err := s.repo.GetTenantByUUID(ctx, tenantUUID)
	if err != nil {
		return mapReadError(err, "tenant")
	}
	n, err := s.repo.SoftDeleteWebhookEndpoint(ctx, storage.SoftDeleteWebhookEndpointParams{
		TenantID:     tenant.TenantID,
		EndpointUuid: endpointUUID,
	})
	if err != nil {
		return apperror.NewInternal("delete webhook endpoint", err)
	}
	if n == 0 {
		return apperror.NewNotFound("webhook endpoint")
	}
	return nil
}

// SignedEndpointsForProject returns a project's active endpoints with their signing
// keys decrypted, for delivery. The caller MUST Zero every returned endpoint.
func (s *Service) SignedEndpointsForProject(ctx context.Context, tenantUUID uuid.UUID, project string) ([]SignedWebhookEndpoint, error) {
	tenant, err := s.repo.GetTenantByUUID(ctx, tenantUUID)
	if err != nil {
		return nil, mapReadError(err, "tenant")
	}
	proj, err := s.repo.GetProjectBySlug(ctx, storage.GetProjectBySlugParams{
		TenantID: tenant.TenantID,
		Slug:     project,
	})
	if err != nil {
		return nil, mapReadError(err, "project")
	}
	rows, err := s.repo.ListActiveWebhookEndpointsByProject(ctx, storage.ListActiveWebhookEndpointsByProjectParams{
		TenantID:  tenant.TenantID,
		ProjectID: proj.ProjectID,
	})
	if err != nil {
		return nil, apperror.NewInternal("list active webhook endpoints", err)
	}

	out := make([]SignedWebhookEndpoint, 0, len(rows))
	for _, r := range rows {
		provider, err := s.ring.Provider(r.KekID)
		if err != nil {
			// One endpoint whose key was wrapped under a root key this process was
			// not given must not silence the others: notification is best-effort by
			// nature, and dropping every delivery because one endpoint is unreadable
			// would turn a configuration gap into an outage.
			continue
		}
		key, err := crypto.Open(provider, webhookIdentity(tenant.TenantUuid, r.EndpointUuid), crypto.Envelope{
			Ciphertext: r.SecretCiphertext,
			Nonce:      r.SecretNonce,
			DEKWrapped: r.SecretDekWrapped,
			DEKNonce:   r.SecretDekNonce,
			KEKID:      r.KekID,
		})
		if err != nil {
			continue
		}
		out = append(out, SignedWebhookEndpoint{
			ID:             r.EndpointID,
			UUID:           r.EndpointUuid,
			URL:            r.Url,
			Events:         decodeStringList(r.Events),
			TimeoutSeconds: r.TimeoutSeconds,
			MaxAttempts:    r.MaxAttempts,
			SigningKey:     key,
		})
	}
	return out, nil
}

// WebhookDelivery is one delivery record as it leaves this package.
type WebhookDelivery struct {
	UUID           uuid.UUID      `json:"delivery_uuid"`
	EventType      string         `json:"event_type"`
	ResourceMRN    string         `json:"resource_mrn"`
	Version        *int32         `json:"version,omitempty"`
	AttemptCount   int32          `json:"attempt_count"`
	Status         string         `json:"status"`
	ResponseStatus *int32         `json:"response_status,omitempty"`
	Error          string         `json:"error,omitempty"`
	Payload        map[string]any `json:"payload"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
}

// OpenWebhookDelivery records a pending delivery and returns its internal id.
//
// The row is written BEFORE the HTTP attempt, deliberately. A record created only on
// completion loses exactly the deliveries that matter — the ones where the process
// died mid-attempt — and "we never told the consumer its credential changed" is the
// fact an incident review needs.
func (s *Service) OpenWebhookDelivery(ctx context.Context, tenantUUID uuid.UUID, endpointID int64, eventType, resourceMRN string, version *int32, payload []byte) (int64, uuid.UUID, error) {
	tenant, err := s.repo.GetTenantByUUID(ctx, tenantUUID)
	if err != nil {
		return 0, uuid.Nil, mapReadError(err, "tenant")
	}
	params := storage.CreateWebhookDeliveryParams{
		EndpointID:  endpointID,
		TenantID:    tenant.TenantID,
		EventType:   eventType,
		ResourceMrn: resourceMRN,
		Payload:     payload,
	}
	if version != nil {
		params.Version = pgInt4(*version)
	}
	row, err := s.repo.CreateWebhookDelivery(ctx, params)
	if err != nil {
		return 0, uuid.Nil, apperror.NewInternal("record webhook delivery", err)
	}
	return row.DeliveryID, row.DeliveryUuid, nil
}

// FinishWebhookDelivery records the outcome of a delivery attempt sequence.
func (s *Service) FinishWebhookDelivery(ctx context.Context, deliveryID int64, attempts int32, status string, responseStatus *int32, failure string) error {
	params := storage.FinishWebhookDeliveryParams{
		AttemptCount: attempts,
		Status:       status,
		Error:        failure,
		DeliveryID:   deliveryID,
	}
	if responseStatus != nil {
		params.ResponseStatus = pgInt4(*responseStatus)
	}
	if _, err := s.repo.FinishWebhookDelivery(ctx, params); err != nil {
		return apperror.NewInternal("finish webhook delivery", err)
	}
	return nil
}

// TouchWebhookEndpoint records that an endpoint was just notified.
func (s *Service) TouchWebhookEndpoint(ctx context.Context, endpointID int64) error {
	if _, err := s.repo.TouchWebhookEndpoint(ctx, endpointID); err != nil {
		return apperror.NewInternal("touch webhook endpoint", err)
	}
	return nil
}

// ListWebhookDeliveries pages one endpoint's delivery history, newest first.
func (s *Service) ListWebhookDeliveries(ctx context.Context, tenantUUID, endpointUUID uuid.UUID, page, limit int) ([]WebhookDelivery, int64, error) {
	tenant, err := s.repo.GetTenantByUUID(ctx, tenantUUID)
	if err != nil {
		return nil, 0, mapReadError(err, "tenant")
	}
	endpoint, err := s.repo.GetWebhookEndpointByUUID(ctx, storage.GetWebhookEndpointByUUIDParams{
		TenantID:     tenant.TenantID,
		EndpointUuid: endpointUUID,
	})
	if err != nil {
		return nil, 0, mapReadError(err, "webhook endpoint")
	}
	page, limit = normalizePage(page, limit)
	rows, err := s.repo.ListWebhookDeliveriesByEndpoint(ctx, storage.ListWebhookDeliveriesByEndpointParams{
		TenantID:   tenant.TenantID,
		EndpointID: endpoint.EndpointID,
		RowLimit:   int32(limit),
		RowOffset:  int32((page - 1) * limit),
	})
	if err != nil {
		return nil, 0, apperror.NewInternal("list webhook deliveries", err)
	}
	total, err := s.repo.CountWebhookDeliveriesByEndpoint(ctx, storage.CountWebhookDeliveriesByEndpointParams{
		TenantID:   tenant.TenantID,
		EndpointID: endpoint.EndpointID,
	})
	if err != nil {
		return nil, 0, apperror.NewInternal("count webhook deliveries", err)
	}
	out := make([]WebhookDelivery, 0, len(rows))
	for _, r := range rows {
		d := WebhookDelivery{
			UUID:         r.DeliveryUuid,
			EventType:    r.EventType,
			ResourceMRN:  r.ResourceMrn,
			AttemptCount: r.AttemptCount,
			Status:       r.Status,
			Error:        r.Error,
			Payload:      decodeObject(r.Payload),
			CreatedAt:    r.CreatedAt,
			UpdatedAt:    r.UpdatedAt,
		}
		if r.Version.Valid {
			v := r.Version.Int32
			d.Version = &v
		}
		if r.ResponseStatus.Valid {
			v := r.ResponseStatus.Int32
			d.ResponseStatus = &v
		}
		out = append(out, d)
	}
	return out, total, nil
}

// ValidateWebhookURL enforces the shape a delivery target must have.
//
// https-only, and that is not negotiable even though the payload carries no value: a
// signed http delivery is still a credential-change announcement an on-path observer
// can read (telling them exactly when to look) and, with a stripped signature
// header, one a naive receiver may accept. The SSRF question — does this host
// resolve somewhere it should not — is answered at DIAL time by the delivery client,
// because a check here would be a TOCTOU window a DNS rebind walks straight through.
func ValidateWebhookURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("webhook url is required")
	}
	if len(raw) > 2048 {
		return fmt.Errorf("webhook url must be at most 2048 characters")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("webhook url is not a valid URL")
	}
	if u.Scheme != "https" {
		return fmt.Errorf("webhook url must use https")
	}
	if u.Host == "" {
		return fmt.Errorf("webhook url must include a host")
	}
	if u.User != nil {
		// Credentials in a URL end up in logs, in the delivery record, and in the
		// console. There is a header for that.
		return fmt.Errorf("webhook url must not embed credentials")
	}
	return nil
}

// normalizeWebhookEvents validates and de-duplicates a subscription list.
func normalizeWebhookEvents(events []string) ([]string, error) {
	out := make([]string, 0, len(events))
	seen := map[string]bool{}
	for _, e := range events {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if !knownWebhookEvents[e] {
			return nil, apperror.NewValidation(fmt.Sprintf(
				"webhook event %q is not one of %s, %s", e, WebhookEventSecretChanged, WebhookEventSecretRotated))
		}
		if seen[e] {
			continue
		}
		seen[e] = true
		out = append(out, e)
	}
	return out, nil
}

// webhookIdentity is the AAD identity a signing key is sealed under. The endpoint
// UUID stands where a secret's UUID stands, so a ciphertext copied between endpoint
// rows fails authentication for exactly the same reason it would between secret
// rows. Version is 1 because an endpoint's key is not versioned — rotating it means
// a new endpoint.
func webhookIdentity(tenantUUID, endpointUUID uuid.UUID) crypto.Identity {
	return crypto.Identity{
		TenantUUID: tenantUUID.String(),
		SecretUUID: endpointUUID.String(),
		Version:    1,
	}
}

func toWebhookEndpoint(r storage.WebhookEndpoint) WebhookEndpoint {
	return WebhookEndpoint{
		UUID:            r.EndpointUuid,
		URL:             r.Url,
		Description:     r.Description,
		Events:          decodeStringList(r.Events),
		Status:          r.Status,
		TimeoutSeconds:  r.TimeoutSeconds,
		MaxAttempts:     r.MaxAttempts,
		LastTriggeredAt: timePtr(r.LastTriggeredAt),
		CreatedAt:       r.CreatedAt,
		UpdatedAt:       r.UpdatedAt,
	}
}

func decodeStringList(raw []byte) []string {
	out := []string{}
	if len(raw) == 0 {
		return out
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return []string{}
	}
	return out
}
