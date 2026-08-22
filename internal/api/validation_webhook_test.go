package api

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/maintainerd/secret/internal/store"
)

func validWebhookCreate() CreateWebhookEndpointInput {
	return CreateWebhookEndpointInput{
		Project:        "billing-app",
		URL:            "https://hooks.example.com/maintainerd",
		Description:    "reload on rotation",
		Events:         []string{store.WebhookEventSecretRotated},
		TimeoutSeconds: 5,
		MaxAttempts:    3,
	}
}

func TestCreateWebhookEndpointInput_Validate(t *testing.T) {
	assert.NoError(t, validWebhookCreate().Validate())

	t.Run("an empty event list means every event", func(t *testing.T) {
		in := validWebhookCreate()
		in.Events = nil
		assert.NoError(t, in.Validate())
	})
	t.Run("zero timeout and attempts mean the defaults", func(t *testing.T) {
		in := validWebhookCreate()
		in.TimeoutSeconds = 0
		in.MaxAttempts = 0
		assert.NoError(t, in.Validate())
	})

	cases := []struct {
		name    string
		mutate  func(*CreateWebhookEndpointInput)
		wantSub string
	}{
		{"missing url", func(in *CreateWebhookEndpointInput) { in.URL = "" }, "url is required"},
		{"plaintext http", func(in *CreateWebhookEndpointInput) {
			in.URL = "http://hooks.example.com/x"
		}, "must use https"},
		{"credentials in the url", func(in *CreateWebhookEndpointInput) {
			in.URL = "https://user:pass@hooks.example.com/x"
		}, "must not embed credentials"},
		// These two are caught by the is.URL rule before the store's policy runs, so
		// the message is the generic one. What matters is that they are refused; the
		// store's checks (host present, length bound) are the backstop for anything
		// is.URL considers well-formed.
		{"url with no host", func(in *CreateWebhookEndpointInput) {
			in.URL = "https:///path"
		}, "valid URL"},
		{"url far too long", func(in *CreateWebhookEndpointInput) {
			in.URL = "https://hooks.example.com/" + strings.Repeat("p", 2100)
		}, "valid URL"},
		{"unknown event", func(in *CreateWebhookEndpointInput) {
			in.Events = []string{"secret.exfiltrated"}
		}, "is not one of"},
		{"missing project", func(in *CreateWebhookEndpointInput) { in.Project = "" }, "project is required"},
		{"timeout above the cap", func(in *CreateWebhookEndpointInput) {
			in.TimeoutSeconds = int32(CurrentLimits().MaxWebhookTimeoutSeconds) + 1
		}, "timeout_seconds must be at most"},
		{"negative timeout", func(in *CreateWebhookEndpointInput) {
			in.TimeoutSeconds = -1
		}, "timeout_seconds must be at least 1"},
		{"attempts above the cap", func(in *CreateWebhookEndpointInput) {
			in.MaxAttempts = int32(CurrentLimits().MaxWebhookAttempts) + 1
		}, "max_attempts must be at most"},
		{"description too long", func(in *CreateWebhookEndpointInput) {
			in.Description = strings.Repeat("d", CurrentLimits().MaxDescriptionLength+1)
		}, "description must be at most"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := validWebhookCreate()
			tc.mutate(&in)
			err := in.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantSub)
		})
	}

	t.Run("every sanctioned event is accepted", func(t *testing.T) {
		in := validWebhookCreate()
		in.Events = store.WebhookEvents()
		assert.NoError(t, in.Validate())
	})
}

func TestUpdateWebhookEndpointInput_Validate(t *testing.T) {
	valid := UpdateWebhookEndpointInput{
		Project:      "billing-app",
		EndpointUUID: uuid.NewString(),
		URL:          "https://hooks.example.com/maintainerd",
		Status:       store.WebhookStatusActive,
	}
	assert.NoError(t, valid.Validate())

	t.Run("every sanctioned status", func(t *testing.T) {
		for _, status := range store.WebhookStatuses {
			in := valid
			in.Status = status
			assert.NoError(t, in.Validate(), status)
		}
	})
	t.Run("a project status is not a webhook status", func(t *testing.T) {
		in := valid
		in.Status = store.StatusArchived
		err := in.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "status must be one of")
	})
	t.Run("a malformed endpoint uuid", func(t *testing.T) {
		in := valid
		in.EndpointUUID = "endpoint-1"
		err := in.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "valid UUID")
	})
	t.Run("the url policy still applies on update", func(t *testing.T) {
		in := valid
		in.URL = "http://hooks.example.com/x"
		require.Error(t, in.Validate())
	})
}

func TestWebhookRefAndListInputs_Validate(t *testing.T) {
	id := uuid.NewString()

	assert.NoError(t, WebhookEndpointRef{Project: "billing-app", EndpointUUID: id}.Validate())
	require.Error(t, WebhookEndpointRef{EndpointUUID: id}.Validate())
	require.Error(t, WebhookEndpointRef{Project: "billing-app", EndpointUUID: "x"}.Validate())

	assert.NoError(t, ListWebhookEndpointsInput{Project: "billing-app"}.Validate())
	require.Error(t, ListWebhookEndpointsInput{}.Validate())

	deliveries := ListWebhookDeliveriesInput{Project: "billing-app", EndpointUUID: id}
	assert.NoError(t, deliveries.Validate())
	deliveries.Limit = CurrentLimits().MaxPageLimit + 1
	require.Error(t, deliveries.Validate())
}
