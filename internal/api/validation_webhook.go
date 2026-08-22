package api

import (
	"fmt"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"

	"github.com/maintainerd/secret/internal/store"
)

// Webhook endpoint request DTOs.
//
// THE URL RULE IS A SECURITY RULE, not a formatting one. store.ValidateWebhookURL
// refuses anything but https, refuses embedded credentials (they end up in logs, in
// the delivery record and in the console), and bounds the length. The delivery-time
// pinned dial in internal/webhook is the authoritative SSRF guard — it re-resolves and
// refuses private/link-local addresses at connect time, so a DNS answer that changes
// between registration and delivery cannot smuggle a metadata endpoint through. This
// rule is the early, legible rejection; that dial is the one that cannot be evaded.

// CreateWebhookEndpointInput registers an endpoint on a project.
type CreateWebhookEndpointInput struct {
	Project     string `json:"project"`
	URL         string `json:"url"`
	Description string `json:"description,omitempty"`
	// Events is the subscription filter; empty means every event.
	Events         []string `json:"events,omitempty"`
	TimeoutSeconds int32    `json:"timeout_seconds,omitempty"`
	MaxAttempts    int32    `json:"max_attempts,omitempty"`
}

// Validate checks an endpoint create.
func (in CreateWebhookEndpointInput) Validate() error {
	return validation.ValidateStruct(&in,
		validation.Field(&in.Project,
			validation.Required.Error("project is required"),
			slugRule("project"),
		),
		validation.Field(&in.URL,
			validation.Required.Error("webhook url is required"),
			is.URL.Error("webhook url must be a valid URL"),
			webhookURLRule,
		),
		validation.Field(&in.Description, descriptionRule()),
		validation.Field(&in.Events, webhookEventsRule),
		validation.Field(&in.TimeoutSeconds, webhookTimeoutRule),
		validation.Field(&in.MaxAttempts, webhookAttemptsRule),
	)
}

// UpdateWebhookEndpointInput rewrites an endpoint's configuration. The signing key is
// absent because it is not editable — rotating it means creating a new endpoint, which
// is honest, because the receiver has to be reconfigured either way.
type UpdateWebhookEndpointInput struct {
	Project        string   `json:"project"`
	EndpointUUID   string   `json:"endpoint_uuid"`
	URL            string   `json:"url"`
	Description    string   `json:"description,omitempty"`
	Events         []string `json:"events,omitempty"`
	Status         string   `json:"status,omitempty"`
	TimeoutSeconds int32    `json:"timeout_seconds,omitempty"`
	MaxAttempts    int32    `json:"max_attempts,omitempty"`
}

// Validate checks an endpoint update.
func (in UpdateWebhookEndpointInput) Validate() error {
	return validation.ValidateStruct(&in,
		validation.Field(&in.Project,
			validation.Required.Error("project is required"),
			slugRule("project"),
		),
		validation.Field(&in.EndpointUUID,
			validation.Required.Error("endpoint_uuid is required"),
			is.UUID.Error("endpoint_uuid must be a valid UUID"),
		),
		validation.Field(&in.URL,
			validation.Required.Error("webhook url is required"),
			is.URL.Error("webhook url must be a valid URL"),
			webhookURLRule,
		),
		validation.Field(&in.Description, descriptionRule()),
		validation.Field(&in.Events, webhookEventsRule),
		validation.Field(&in.Status, webhookStatusRule),
		validation.Field(&in.TimeoutSeconds, webhookTimeoutRule),
		validation.Field(&in.MaxAttempts, webhookAttemptsRule),
	)
}

// WebhookEndpointRef addresses one endpoint on a project — the delete path.
type WebhookEndpointRef struct {
	Project      string `json:"project"`
	EndpointUUID string `json:"endpoint_uuid"`
}

// Validate checks an endpoint reference.
func (in WebhookEndpointRef) Validate() error {
	return validation.ValidateStruct(&in,
		validation.Field(&in.Project,
			validation.Required.Error("project is required"),
			slugRule("project"),
		),
		validation.Field(&in.EndpointUUID,
			validation.Required.Error("endpoint_uuid is required"),
			is.UUID.Error("endpoint_uuid must be a valid UUID"),
		),
	)
}

// ListWebhookEndpointsInput pages a project's endpoints.
type ListWebhookEndpointsInput struct {
	Project    string `json:"project"`
	Pagination `json:"page"`
}

// Validate checks an endpoint listing request.
func (in ListWebhookEndpointsInput) Validate() error {
	return validation.ValidateStruct(&in,
		validation.Field(&in.Project,
			validation.Required.Error("project is required"),
			slugRule("project"),
		),
		validation.Field(&in.Pagination),
	)
}

// ListWebhookDeliveriesInput pages one endpoint's delivery history.
type ListWebhookDeliveriesInput struct {
	Project      string `json:"project"`
	EndpointUUID string `json:"endpoint_uuid"`
	Pagination   `json:"page"`
}

// Validate checks a delivery listing request.
func (in ListWebhookDeliveriesInput) Validate() error {
	return validation.ValidateStruct(&in,
		validation.Field(&in.Project,
			validation.Required.Error("project is required"),
			slugRule("project"),
		),
		validation.Field(&in.EndpointUUID,
			validation.Required.Error("endpoint_uuid is required"),
			is.UUID.Error("endpoint_uuid must be a valid UUID"),
		),
		validation.Field(&in.Pagination),
	)
}

// ---------------------------------------------------------------------------
// Shared webhook field rules
// ---------------------------------------------------------------------------

// webhookURLRule runs the store's URL policy: https only, no embedded credentials,
// bounded length.
var webhookURLRule = validation.By(func(value any) error {
	raw, _ := value.(string)
	if raw == "" {
		return nil
	}
	if err := store.ValidateWebhookURL(raw); err != nil {
		return validation.NewError("validation_webhook_url", err.Error())
	}
	return nil
})

// webhookEventsRule restricts a subscription to the closed set of event names. A typo
// is otherwise silent: the endpoint simply never fires, and the operator discovers it
// during the incident the webhook existed to prevent.
var webhookEventsRule = validation.By(func(value any) error {
	events, ok := value.([]string)
	if !ok || len(events) == 0 {
		return nil // empty means "every event".
	}
	if len(events) > len(store.WebhookEvents()) {
		return validation.NewError("validation_webhook_events",
			"the subscription list contains more entries than there are event types")
	}
	for _, e := range events {
		if !store.IsKnownWebhookEvent(e) {
			return validation.NewError("validation_webhook_events", fmt.Sprintf(
				"webhook event %q is not one of %s", e, joinQuoted(store.WebhookEvents())))
		}
	}
	return nil
})

// webhookStatusRule restricts an endpoint status to the closed set the store accepts.
var webhookStatusRule = validation.By(func(value any) error {
	raw, _ := value.(string)
	if raw == "" {
		return nil // empty means "active"; the store resolves it.
	}
	for _, s := range store.WebhookStatuses {
		if raw == s {
			return nil
		}
	}
	return validation.NewError("validation_webhook_status",
		"status must be one of "+joinQuoted(store.WebhookStatuses))
})

// webhookTimeoutRule caps a per-endpoint delivery timeout. Deliveries run inline on a
// write path (see internal/webhook), so an endpoint configured with a several-minute
// timeout would hold a secret write open for several minutes.
var webhookTimeoutRule = validation.By(func(value any) error {
	seconds, ok := value.(int32)
	if !ok || seconds == 0 {
		return nil // zero means "use the default".
	}
	max := int32(CurrentLimits().MaxWebhookTimeoutSeconds)
	if seconds < 1 {
		return validation.NewError("validation_webhook_timeout", "timeout_seconds must be at least 1")
	}
	if seconds > max {
		return validation.NewError("validation_webhook_timeout",
			fmt.Sprintf("timeout_seconds must be at most %d", max))
	}
	return nil
})

// webhookAttemptsRule caps per-endpoint retries, for the same reason as the timeout:
// the whole retry budget is spent inline on a write.
var webhookAttemptsRule = validation.By(func(value any) error {
	attempts, ok := value.(int32)
	if !ok || attempts == 0 {
		return nil // zero means "use the default".
	}
	max := int32(CurrentLimits().MaxWebhookAttempts)
	if attempts < 1 {
		return validation.NewError("validation_webhook_attempts", "max_attempts must be at least 1")
	}
	if attempts > max {
		return validation.NewError("validation_webhook_attempts",
			fmt.Sprintf("max_attempts must be at most %d", max))
	}
	return nil
})
