package api

import (
	"context"

	"github.com/google/uuid"

	"github.com/maintainerd/secret/internal/audit"
	"github.com/maintainerd/secret/internal/platform/apperror"
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
func (s *Service) CreateWebhookEndpoint(ctx context.Context, c Caller, in CreateWebhookEndpointInput) (*store.CreatedWebhookEndpoint, error) {
	if err := validate(in); err != nil {
		return nil, err
	}
	resourceMRN := c.mrn(in.Project, store.ResourceWebhook)
	if err := s.guard(ctx, c, authz.PermManageRotation, store.ActionWebhookCreate, resourceMRN); err != nil {
		return nil, err
	}
	endpoint, err := s.store.CreateWebhookEndpoint(ctx, store.CreateWebhookEndpointInput{
		TenantUUID:     c.TenantUUID,
		Project:        in.Project,
		URL:            in.URL,
		Description:    in.Description,
		Events:         in.Events,
		TimeoutSeconds: in.TimeoutSeconds,
		MaxAttempts:    in.MaxAttempts,
	})
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
func (s *Service) ListWebhookEndpoints(ctx context.Context, c Caller, in ListWebhookEndpointsInput) ([]store.WebhookEndpoint, int64, error) {
	if err := validate(in); err != nil {
		return nil, 0, err
	}
	page, limit := in.Pagination.resolved()
	resourceMRN := c.mrn(in.Project, store.ResourceWebhook)
	if err := s.guard(ctx, c, authz.PermReadMetadata, store.ActionRead, resourceMRN); err != nil {
		return nil, 0, err
	}
	endpoints, total, err := s.store.ListWebhookEndpoints(ctx, c.TenantUUID, in.Project, page, limit)
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
func (s *Service) UpdateWebhookEndpoint(ctx context.Context, c Caller, in UpdateWebhookEndpointInput) (*store.WebhookEndpoint, error) {
	if err := validate(in); err != nil {
		return nil, err
	}
	endpointUUID, err := uuid.Parse(in.EndpointUUID)
	if err != nil {
		return nil, apperror.NewValidation("endpoint_uuid must be a valid UUID")
	}
	resourceMRN := c.mrn(in.Project, store.WebhookResourcePath(endpointUUID))
	if err := s.guard(ctx, c, authz.PermManageRotation, store.ActionWebhookUpdate, resourceMRN); err != nil {
		return nil, err
	}
	endpoint, err := s.store.UpdateWebhookEndpoint(ctx, store.UpdateWebhookEndpointInput{
		TenantUUID:     c.TenantUUID,
		EndpointUUID:   endpointUUID,
		URL:            in.URL,
		Description:    in.Description,
		Events:         in.Events,
		Status:         in.Status,
		TimeoutSeconds: in.TimeoutSeconds,
		MaxAttempts:    in.MaxAttempts,
	})
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
func (s *Service) DeleteWebhookEndpoint(ctx context.Context, c Caller, in WebhookEndpointRef) error {
	if err := validate(in); err != nil {
		return err
	}
	endpointUUID, err := uuid.Parse(in.EndpointUUID)
	if err != nil {
		return apperror.NewValidation("endpoint_uuid must be a valid UUID")
	}
	resourceMRN := c.mrn(in.Project, store.WebhookResourcePath(endpointUUID))
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
func (s *Service) ListWebhookDeliveries(ctx context.Context, c Caller, in ListWebhookDeliveriesInput) ([]store.WebhookDelivery, int64, error) {
	if err := validate(in); err != nil {
		return nil, 0, err
	}
	endpointUUID, err := uuid.Parse(in.EndpointUUID)
	if err != nil {
		return nil, 0, apperror.NewValidation("endpoint_uuid must be a valid UUID")
	}
	page, limit := in.Pagination.resolved()
	resourceMRN := c.mrn(in.Project, store.WebhookResourcePath(endpointUUID))
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
func (s *Service) ListAuditEvents(ctx context.Context, c Caller, in ListAuditEventsInput) ([]store.AuditEntry, int64, error) {
	if err := validate(in); err != nil {
		return nil, 0, err
	}
	page, limit := in.Pagination.resolved()
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
