package api

import (
	"context"

	"github.com/google/uuid"

	"github.com/maintainerd/secret/internal/audit"
	"github.com/maintainerd/secret/internal/platform/authz"
	"github.com/maintainerd/secret/internal/store"
)

// Webhook endpoint management, and the audit read.
//
// Endpoints require secret:ManageRotation. Grouping them with rotation rather than
// giving them a permission of their own is deliberate: an endpoint's whole purpose is
// to announce a change so consumers re-read, so whoever decides how a credential
// rotates is exactly who decides who gets told. Splitting them would create a grant
// that can schedule rotations nobody is notified about.

// CreateWebhookEndpoint registers an endpoint and returns its signing key ONCE.
//
// The audit row records the endpoint's URL host and its UUID — never the signing key,
// which appears in exactly one place in this service's lifetime: the create response.
func (s *Service) CreateWebhookEndpoint(ctx context.Context, c Caller, in store.CreateWebhookEndpointInput) (*store.CreatedWebhookEndpoint, error) {
	in.TenantUUID = c.TenantUUID
	resourceMRN := c.mrn(in.Project, "webhook")
	if err := s.guard(ctx, c, authz.PermManageRotation, store.ActionWebhookCreate, resourceMRN); err != nil {
		return nil, err
	}
	endpoint, err := s.store.CreateWebhookEndpoint(ctx, in)
	if err != nil {
		s.recordFailure(ctx, c, store.ActionWebhookCreate, resourceMRN, err)
		return nil, err
	}
	if err := s.recordSuccess(ctx, c, audit.Event{
		Action:      store.ActionWebhookCreate,
		ResourceMRN: c.mrn(in.Project, store.WebhookResourcePath(endpoint.UUID)),
		Metadata:    map[string]any{"url": endpoint.URL, "events": endpoint.Events},
	}); err != nil {
		return nil, err
	}
	return endpoint, nil
}

// ListWebhookEndpoints pages a project's endpoints. Metadata only — the query used
// does not select the signing-key columns at all.
func (s *Service) ListWebhookEndpoints(ctx context.Context, c Caller, project string, page, limit int) ([]store.WebhookEndpoint, int64, error) {
	resourceMRN := c.mrn(project, "webhook")
	if err := s.guard(ctx, c, authz.PermReadMetadata, store.ActionRead, resourceMRN); err != nil {
		return nil, 0, err
	}
	endpoints, total, err := s.store.ListWebhookEndpoints(ctx, c.TenantUUID, project, page, limit)
	if err != nil {
		s.recordFailure(ctx, c, store.ActionRead, resourceMRN, err)
		return nil, 0, err
	}
	if err := s.recordSuccess(ctx, c, audit.Event{
		Action:      store.ActionRead,
		ResourceMRN: resourceMRN,
		Metadata:    map[string]any{"endpoints": len(endpoints), "total": total},
	}); err != nil {
		return nil, 0, err
	}
	return endpoints, total, nil
}

// UpdateWebhookEndpoint rewrites an endpoint's configuration. The signing key is not
// editable — rotating it means creating a new endpoint, which is honest, because the
// receiver has to be reconfigured either way and a silent key change would break
// deliveries with a signature mismatch nobody could diagnose.
func (s *Service) UpdateWebhookEndpoint(ctx context.Context, c Caller, project string, in store.UpdateWebhookEndpointInput) (*store.WebhookEndpoint, error) {
	in.TenantUUID = c.TenantUUID
	resourceMRN := c.mrn(project, store.WebhookResourcePath(in.EndpointUUID))
	if err := s.guard(ctx, c, authz.PermManageRotation, store.ActionWebhookUpdate, resourceMRN); err != nil {
		return nil, err
	}
	endpoint, err := s.store.UpdateWebhookEndpoint(ctx, in)
	if err != nil {
		s.recordFailure(ctx, c, store.ActionWebhookUpdate, resourceMRN, err)
		return nil, err
	}
	if err := s.recordSuccess(ctx, c, audit.Event{
		Action:      store.ActionWebhookUpdate,
		ResourceMRN: resourceMRN,
		Metadata:    map[string]any{"url": endpoint.URL, "status": endpoint.Status},
	}); err != nil {
		return nil, err
	}
	return endpoint, nil
}

// DeleteWebhookEndpoint removes an endpoint.
func (s *Service) DeleteWebhookEndpoint(ctx context.Context, c Caller, project string, endpointUUID uuid.UUID) error {
	resourceMRN := c.mrn(project, store.WebhookResourcePath(endpointUUID))
	if err := s.guard(ctx, c, authz.PermManageRotation, store.ActionWebhookDelete, resourceMRN); err != nil {
		return err
	}
	if err := s.store.DeleteWebhookEndpoint(ctx, c.TenantUUID, endpointUUID); err != nil {
		s.recordFailure(ctx, c, store.ActionWebhookDelete, resourceMRN, err)
		return err
	}
	return s.recordSuccess(ctx, c, audit.Event{Action: store.ActionWebhookDelete, ResourceMRN: resourceMRN})
}

// ListWebhookDeliveries pages one endpoint's delivery history.
func (s *Service) ListWebhookDeliveries(ctx context.Context, c Caller, project string, endpointUUID uuid.UUID, page, limit int) ([]store.WebhookDelivery, int64, error) {
	resourceMRN := c.mrn(project, store.WebhookResourcePath(endpointUUID))
	if err := s.guard(ctx, c, authz.PermReadMetadata, store.ActionRead, resourceMRN); err != nil {
		return nil, 0, err
	}
	deliveries, total, err := s.store.ListWebhookDeliveries(ctx, c.TenantUUID, endpointUUID, page, limit)
	if err != nil {
		s.recordFailure(ctx, c, store.ActionRead, resourceMRN, err)
		return nil, 0, err
	}
	if err := s.recordSuccess(ctx, c, audit.Event{
		Action:      store.ActionRead,
		ResourceMRN: resourceMRN,
		Metadata:    map[string]any{"deliveries": len(deliveries), "total": total},
	}); err != nil {
		return nil, 0, err
	}
	return deliveries, total, nil
}

// ListAuditEvents pages the tenant's access trail, newest first.
//
// READING THE TRAIL IS ITSELF AUDITED. That is not recursion for its own sake: the
// first move of an attacker who has read a credential is to find out what the trail
// says about it, so "who read the audit log" is a first-class signal. The row this
// call writes is the one that catches that.
func (s *Service) ListAuditEvents(ctx context.Context, c Caller, page, limit int) ([]store.AuditEntry, int64, error) {
	resourceMRN := c.mrn("", store.ResourceAudit)
	if err := s.guard(ctx, c, authz.PermReadAudit, store.ActionAuditRead, resourceMRN); err != nil {
		return nil, 0, err
	}
	entries, total, err := s.store.ListAuditEvents(ctx, c.TenantUUID, page, limit)
	if err != nil {
		s.recordFailure(ctx, c, store.ActionAuditRead, resourceMRN, err)
		return nil, 0, err
	}
	if err := s.recordSuccess(ctx, c, audit.Event{
		Action:      store.ActionAuditRead,
		ResourceMRN: resourceMRN,
		Metadata:    map[string]any{"returned": len(entries), "total": total},
	}); err != nil {
		return nil, 0, err
	}
	return entries, total, nil
}
