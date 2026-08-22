package httpapi

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/maintainerd/secret/internal/api"
	"github.com/maintainerd/secret/internal/platform/response"
)

// Webhook endpoint handlers and the audit read.
//
// The handlers construct the api-layer DTOs (api.CreateWebhookEndpointInput and
// friends) and hand them straight over; the URL policy, the event-name set, the status
// set and the timeout/retry caps all live on those DTOs, so the gRPC surface enforces
// exactly the same rules.

type createWebhookRequest struct {
	Project        string   `json:"project"`
	URL            string   `json:"url"`
	Description    string   `json:"description,omitempty"`
	Events         []string `json:"events,omitempty"`
	TimeoutSeconds int32    `json:"timeout_seconds,omitempty"`
	MaxAttempts    int32    `json:"max_attempts,omitempty"`
}

// createWebhook registers an endpoint.
//
// THE RESPONSE CONTAINS THE SIGNING KEY, once and only once. There is no read-it-back
// endpoint: an HMAC key that can be fetched is a forgery primitive. The response is
// marked no-store for the same reason a reveal is.
func (s *Server) createWebhook(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	var req createWebhookRequest
	if !decode(w, r, &req) {
		return
	}
	endpoint, err := s.api.CreateWebhookEndpoint(r.Context(), c, api.CreateWebhookEndpointInput{
		Project:        req.Project,
		URL:            req.URL,
		Description:    req.Description,
		Events:         req.Events,
		TimeoutSeconds: req.TimeoutSeconds,
		MaxAttempts:    req.MaxAttempts,
	})
	if err != nil {
		response.ServiceError(w, r, "could not create the webhook endpoint", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	response.Created(w, endpoint, "webhook endpoint created; the signing key is shown once and cannot be retrieved again")
}

func (s *Server) listWebhooks(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	page, limit := response.PageParams(r)
	endpoints, total, err := s.api.ListWebhookEndpoints(r.Context(), c, api.ListWebhookEndpointsInput{
		Project:    r.URL.Query().Get("project"),
		Pagination: api.Pagination{Page: page, Limit: limit},
	})
	if err != nil {
		response.ServiceError(w, r, "could not list webhook endpoints", err)
		return
	}
	response.List(w, endpoints, page, limit, total)
}

type updateWebhookRequest struct {
	Project        string   `json:"project"`
	URL            string   `json:"url"`
	Description    string   `json:"description,omitempty"`
	Events         []string `json:"events,omitempty"`
	Status         string   `json:"status,omitempty"`
	TimeoutSeconds int32    `json:"timeout_seconds,omitempty"`
	MaxAttempts    int32    `json:"max_attempts,omitempty"`
}

func (s *Server) updateWebhook(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	var req updateWebhookRequest
	if !decode(w, r, &req) {
		return
	}
	endpoint, err := s.api.UpdateWebhookEndpoint(r.Context(), c, api.UpdateWebhookEndpointInput{
		Project:        req.Project,
		EndpointUUID:   chi.URLParam(r, "endpointUUID"),
		URL:            req.URL,
		Description:    req.Description,
		Events:         req.Events,
		Status:         req.Status,
		TimeoutSeconds: req.TimeoutSeconds,
		MaxAttempts:    req.MaxAttempts,
	})
	if err != nil {
		response.ServiceError(w, r, "could not update the webhook endpoint", err)
		return
	}
	response.OK(w, endpoint, "webhook endpoint updated")
}

func (s *Server) deleteWebhook(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	if err := s.api.DeleteWebhookEndpoint(r.Context(), c, api.WebhookEndpointRef{
		Project:      r.URL.Query().Get("project"),
		EndpointUUID: chi.URLParam(r, "endpointUUID"),
	}); err != nil {
		response.ServiceError(w, r, "could not delete the webhook endpoint", err)
		return
	}
	response.NoContent(w)
}

func (s *Server) listWebhookDeliveries(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	page, limit := response.PageParams(r)
	deliveries, total, err := s.api.ListWebhookDeliveries(r.Context(), c, api.ListWebhookDeliveriesInput{
		Project:      r.URL.Query().Get("project"),
		EndpointUUID: chi.URLParam(r, "endpointUUID"),
		Pagination:   api.Pagination{Page: page, Limit: limit},
	})
	if err != nil {
		response.ServiceError(w, r, "could not list webhook deliveries", err)
		return
	}
	response.List(w, deliveries, page, limit, total)
}

// listAudit pages the tenant's access trail. Reading it is itself audited.
func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	page, limit := response.PageParams(r)
	entries, total, err := s.api.ListAuditEvents(r.Context(), c, api.ListAuditEventsInput{
		Pagination: api.Pagination{Page: page, Limit: limit},
	})
	if err != nil {
		response.ServiceError(w, r, "could not read the audit trail", err)
		return
	}
	response.List(w, entries, page, limit, total)
}
