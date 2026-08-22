package grpcserver

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	secretv1 "github.com/maintainerd/secret/gen/maintainerd/secret/v1"
	"github.com/maintainerd/secret/internal/api"
	"github.com/maintainerd/secret/internal/crypto"
	"github.com/maintainerd/secret/internal/rotation"
	"github.com/maintainerd/secret/internal/store"
)

// Secret RPCs. As on the REST side, the only response shapes that carry a value are
// GetSecretResponse and BatchGetSecretsResult; everything else returns metadata
// types that have no value field at all.

func addressOf(a *secretv1.SecretAddress) api.SecretAddress {
	if a == nil {
		return api.SecretAddress{}
	}
	return api.SecretAddress{
		Project:     a.GetProject(),
		Environment: a.GetEnvironment(),
		FolderPath:  a.GetFolderPath(),
		Key:         a.GetKey(),
	}
}

func toProtoAddress(a api.SecretAddress) *secretv1.SecretAddress {
	return &secretv1.SecretAddress{
		Project:     a.Project,
		Environment: a.Environment,
		FolderPath:  a.FolderPath,
		Key:         a.Key,
	}
}

// GetSecret is the reveal.
func (s *Service) GetSecret(ctx context.Context, req *secretv1.GetSecretRequest) (*secretv1.GetSecretResponse, error) {
	c, err := s.caller(ctx)
	if err != nil {
		return nil, err
	}
	revealed, err := s.api.Reveal(ctx, c, addressOf(req.GetAddress()), req.GetVersion())
	if err != nil {
		return nil, toStatus(err, "reveal secret")
	}
	defer revealed.Secret.Zero()
	return &secretv1.GetSecretResponse{
		Value:         copyBytes(revealed.Secret.Value.Bytes()),
		Version:       revealed.Secret.Version,
		ValueType:     revealed.Secret.ValueType,
		Mrn:           revealed.Secret.Meta.MRN,
		ReferenceHops: revealed.ReferenceHops,
	}, nil
}

func (s *Service) DescribeSecret(ctx context.Context, req *secretv1.DescribeSecretRequest) (*secretv1.DescribeSecretResponse, error) {
	c, err := s.caller(ctx)
	if err != nil {
		return nil, err
	}
	meta, err := s.api.DescribeSecret(ctx, c, addressOf(req.GetAddress()))
	if err != nil {
		return nil, toStatus(err, "describe secret")
	}
	return &secretv1.DescribeSecretResponse{Secret: toProtoSecretMeta(meta)}, nil
}

func (s *Service) ListSecrets(ctx context.Context, req *secretv1.ListSecretsRequest) (*secretv1.ListSecretsResponse, error) {
	c, err := s.caller(ctx)
	if err != nil {
		return nil, err
	}
	page, limit := pageOf(req.GetPage())
	metas, total, err := s.api.ListSecrets(ctx, c, api.ListSecretsInput{
		Project:     req.GetProject(),
		Environment: req.GetEnvironment(),
		PathPrefix:  req.GetPathPrefix(),
		Page:        page,
		Limit:       limit,
	})
	if err != nil {
		return nil, toStatus(err, "list secrets")
	}
	out := make([]*secretv1.SecretMetadata, 0, len(metas))
	for i := range metas {
		out = append(out, toProtoSecretMeta(&metas[i]))
	}
	return &secretv1.ListSecretsResponse{Secrets: out, PageInfo: pageInfo(page, limit, total)}, nil
}

func (s *Service) PutSecret(ctx context.Context, req *secretv1.PutSecretRequest) (*secretv1.PutSecretResponse, error) {
	c, err := s.caller(ctx)
	if err != nil {
		return nil, err
	}
	policy, err := decodeRotationPolicyJSON(req.GetRotationPolicyJson())
	if err != nil {
		return nil, err
	}
	expires, err := optionalTime(req.GetExpiresAt())
	if err != nil {
		return nil, err
	}
	in := api.PutSecretInput{
		Address:        addressOf(req.GetAddress()),
		Value:          req.GetValue(),
		ValueType:      req.GetValueType(),
		Description:    req.GetDescription(),
		Tags:           req.GetTags(),
		RotationPolicy: policy,
		ExpiresAt:      expires,
		CreateFolders:  req.GetCreateFolders(),
	}
	if req.GetKeepVersions() > 0 {
		keep := req.GetKeepVersions()
		in.KeepVersions = &keep
	}
	result, err := s.api.PutSecret(ctx, c, in)
	if err != nil {
		return nil, toStatus(err, "put secret")
	}
	return &secretv1.PutSecretResponse{Result: toProtoPutResult(result)}, nil
}

func (s *Service) UpdateSecretMetadata(ctx context.Context, req *secretv1.UpdateSecretMetadataRequest) (*secretv1.UpdateSecretMetadataResponse, error) {
	c, err := s.caller(ctx)
	if err != nil {
		return nil, err
	}
	policy, err := decodeRotationPolicyJSON(req.GetRotationPolicyJson())
	if err != nil {
		return nil, err
	}
	expires, err := optionalTime(req.GetExpiresAt())
	if err != nil {
		return nil, err
	}
	in := api.UpdateSecretMetaInput{
		Address:        addressOf(req.GetAddress()),
		Description:    req.GetDescription(),
		Tags:           req.GetTags(),
		RotationPolicy: policy,
		ExpiresAt:      expires,
	}
	if req.GetKeepVersions() > 0 {
		keep := req.GetKeepVersions()
		in.KeepVersions = &keep
	}
	meta, err := s.api.UpdateSecretMeta(ctx, c, in)
	if err != nil {
		return nil, toStatus(err, "update secret metadata")
	}
	return &secretv1.UpdateSecretMetadataResponse{Secret: toProtoSecretMeta(meta)}, nil
}

func (s *Service) ListSecretVersions(ctx context.Context, req *secretv1.ListSecretVersionsRequest) (*secretv1.ListSecretVersionsResponse, error) {
	c, err := s.caller(ctx)
	if err != nil {
		return nil, err
	}
	page, limit := pageOf(req.GetPage())
	versions, total, err := s.api.ListVersions(ctx, c, addressOf(req.GetAddress()), page, limit)
	if err != nil {
		return nil, toStatus(err, "list secret versions")
	}
	out := make([]*secretv1.VersionMetadata, 0, len(versions))
	for _, v := range versions {
		out = append(out, &secretv1.VersionMetadata{
			Version:   v.Version,
			KekId:     v.KEKID,
			ValueType: v.ValueType,
			Checksum:  hex.EncodeToString(v.Checksum),
			CreatedAt: v.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
	return &secretv1.ListSecretVersionsResponse{Versions: out, PageInfo: pageInfo(page, limit, total)}, nil
}

func (s *Service) RollbackSecret(ctx context.Context, req *secretv1.RollbackSecretRequest) (*secretv1.RollbackSecretResponse, error) {
	c, err := s.caller(ctx)
	if err != nil {
		return nil, err
	}
	result, err := s.api.Rollback(ctx, c, addressOf(req.GetAddress()), req.GetVersion())
	if err != nil {
		return nil, toStatus(err, "roll secret back")
	}
	return &secretv1.RollbackSecretResponse{Result: toProtoPutResult(result)}, nil
}

func (s *Service) RotateSecret(ctx context.Context, req *secretv1.RotateSecretRequest) (*secretv1.RotateSecretResponse, error) {
	c, err := s.caller(ctx)
	if err != nil {
		return nil, err
	}
	spec := specOf(req.GetGenerator())
	// The caller-supplied bytes are zeroized once the rotation returns; they exist in
	// this handler for exactly as long as the write needs them.
	defer func() { spec.Value = "" }()
	result, err := s.api.RotateSecret(ctx, c, api.RotateSecretInput{
		Address:   addressOf(req.GetAddress()),
		Generator: spec,
	})
	if err != nil {
		return nil, toStatus(err, "rotate secret")
	}
	return &secretv1.RotateSecretResponse{Result: toProtoPutResult(result)}, nil
}

func (s *Service) SetRotationPolicy(ctx context.Context, req *secretv1.SetRotationPolicyRequest) (*secretv1.SetRotationPolicyResponse, error) {
	c, err := s.caller(ctx)
	if err != nil {
		return nil, err
	}
	if len(req.GetGenerator().GetValue()) > 0 {
		// A stored policy must never carry a value — it lives in readable metadata.
		return nil, status.Error(codes.InvalidArgument,
			"a rotation policy must not carry a generator value: the policy is stored as readable metadata")
	}
	policy := rotation.Policy{
		Enabled:  req.GetEnabled(),
		Interval: req.GetInterval(),
		Generator: rotation.Spec{
			Type:    req.GetGenerator().GetType(),
			Length:  int(req.GetGenerator().GetLength()),
			Charset: req.GetGenerator().GetCharset(),
		},
	}
	meta, err := s.api.SetRotationPolicy(ctx, c, addressOf(req.GetAddress()), policy)
	if err != nil {
		return nil, toStatus(err, "set rotation policy")
	}
	return &secretv1.SetRotationPolicyResponse{Secret: toProtoSecretMeta(meta)}, nil
}

func (s *Service) DeleteSecret(ctx context.Context, req *secretv1.DeleteSecretRequest) (*secretv1.DeleteSecretResponse, error) {
	c, err := s.caller(ctx)
	if err != nil {
		return nil, err
	}
	window, err := optionalDuration(req.GetRecoveryWindow())
	if err != nil {
		return nil, err
	}
	deleted, err := s.api.DeleteSecret(ctx, c, addressOf(req.GetAddress()), window)
	if err != nil {
		return nil, toStatus(err, "delete secret")
	}
	return &secretv1.DeleteSecretResponse{Deleted: toProtoDeleted(deleted)}, nil
}

func (s *Service) ListDeletedSecrets(ctx context.Context, req *secretv1.ListDeletedSecretsRequest) (*secretv1.ListDeletedSecretsResponse, error) {
	c, err := s.caller(ctx)
	if err != nil {
		return nil, err
	}
	page, limit := pageOf(req.GetPage())
	deleted, err := s.api.ListDeletedSecrets(ctx, c, req.GetProject(), req.GetEnvironment(), page, limit)
	if err != nil {
		return nil, toStatus(err, "list deleted secrets")
	}
	out := make([]*secretv1.DeletedSecret, 0, len(deleted))
	for i := range deleted {
		out = append(out, toProtoDeleted(&deleted[i]))
	}
	return &secretv1.ListDeletedSecretsResponse{Deleted: out}, nil
}

func (s *Service) RestoreSecret(ctx context.Context, req *secretv1.RestoreSecretRequest) (*secretv1.RestoreSecretResponse, error) {
	c, err := s.caller(ctx)
	if err != nil {
		return nil, err
	}
	id, err := uuid.Parse(req.GetSecretUuid())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "secret_uuid must be a UUID")
	}
	meta, err := s.api.RestoreSecret(ctx, c, id)
	if err != nil {
		return nil, toStatus(err, "restore secret")
	}
	return &secretv1.RestoreSecretResponse{Secret: toProtoSecretMeta(meta)}, nil
}

func (s *Service) DestroySecret(ctx context.Context, req *secretv1.DestroySecretRequest) (*secretv1.DestroySecretResponse, error) {
	c, err := s.caller(ctx)
	if err != nil {
		return nil, err
	}
	id, err := uuid.Parse(req.GetSecretUuid())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "secret_uuid must be a UUID")
	}
	if err := s.api.DestroySecret(ctx, c, id); err != nil {
		return nil, toStatus(err, "destroy secret")
	}
	return &secretv1.DestroySecretResponse{Destroyed: true}, nil
}

// ---------------------------------------------------------------------------
// Bulk
// ---------------------------------------------------------------------------

func (s *Service) BatchGetSecrets(ctx context.Context, req *secretv1.BatchGetSecretsRequest) (*secretv1.BatchGetSecretsResponse, error) {
	c, err := s.caller(ctx)
	if err != nil {
		return nil, err
	}
	items := make([]api.BatchGetItem, 0, len(req.GetItems()))
	for _, item := range req.GetItems() {
		items = append(items, api.BatchGetItem{Address: addressOf(item.GetAddress()), Version: item.GetVersion()})
	}
	results, err := s.api.BatchGet(ctx, c, items)
	if err != nil {
		return nil, toStatus(err, "batch get")
	}
	defer func() {
		for i := range results {
			results[i].Zero()
		}
	}()

	out := make([]*secretv1.BatchGetSecretsResult, 0, len(results))
	for i := range results {
		res := &results[i]
		item := &secretv1.BatchGetSecretsResult{Address: toProtoAddress(res.Address)}
		if res.Error != nil {
			item.Error = res.Error.Error()
			out = append(out, item)
			continue
		}
		item.Value = copyBytes(res.Secret.Value.Bytes())
		item.Version = res.Secret.Version
		item.ValueType = res.Secret.ValueType
		item.Mrn = res.Secret.Meta.MRN
		item.ReferenceHops = res.ReferenceHops
		out = append(out, item)
	}
	return &secretv1.BatchGetSecretsResponse{Results: out}, nil
}

func (s *Service) BatchPutSecrets(ctx context.Context, req *secretv1.BatchPutSecretsRequest) (*secretv1.BatchPutSecretsResponse, error) {
	c, err := s.caller(ctx)
	if err != nil {
		return nil, err
	}
	items := make([]api.BatchPutItem, 0, len(req.GetItems()))
	for _, item := range req.GetItems() {
		items = append(items, api.BatchPutItem{
			Address:       addressOf(item.GetAddress()),
			Value:         item.GetValue(),
			ValueType:     item.GetValueType(),
			Description:   item.GetDescription(),
			Tags:          item.GetTags(),
			CreateFolders: item.GetCreateFolders(),
		})
	}
	results, err := s.api.BatchPut(ctx, c, items)
	if err != nil {
		return nil, toStatus(err, "batch put")
	}
	out := make([]*secretv1.BatchPutSecretsResult, 0, len(results))
	for _, res := range results {
		item := &secretv1.BatchPutSecretsResult{Address: toProtoAddress(res.Address)}
		if res.Error != nil {
			item.Error = res.Error.Error()
		} else {
			item.Result = toProtoPutResult(res.Result)
		}
		out = append(out, item)
	}
	return &secretv1.BatchPutSecretsResponse{Results: out}, nil
}

// ---------------------------------------------------------------------------
// Webhooks + audit
// ---------------------------------------------------------------------------

func (s *Service) CreateWebhookEndpoint(ctx context.Context, req *secretv1.CreateWebhookEndpointRequest) (*secretv1.CreateWebhookEndpointResponse, error) {
	c, err := s.caller(ctx)
	if err != nil {
		return nil, err
	}
	endpoint, err := s.api.CreateWebhookEndpoint(ctx, c, store.CreateWebhookEndpointInput{
		Project:        req.GetProject(),
		URL:            req.GetUrl(),
		Description:    req.GetDescription(),
		Events:         req.GetEvents(),
		TimeoutSeconds: req.GetTimeoutSeconds(),
		MaxAttempts:    req.GetMaxAttempts(),
	})
	if err != nil {
		return nil, toStatus(err, "create webhook endpoint")
	}
	return &secretv1.CreateWebhookEndpointResponse{
		Endpoint:   toProtoEndpoint(&endpoint.WebhookEndpoint),
		SigningKey: endpoint.SigningKey,
	}, nil
}

func (s *Service) ListWebhookEndpoints(ctx context.Context, req *secretv1.ListWebhookEndpointsRequest) (*secretv1.ListWebhookEndpointsResponse, error) {
	c, err := s.caller(ctx)
	if err != nil {
		return nil, err
	}
	page, limit := pageOf(req.GetPage())
	endpoints, total, err := s.api.ListWebhookEndpoints(ctx, c, req.GetProject(), page, limit)
	if err != nil {
		return nil, toStatus(err, "list webhook endpoints")
	}
	out := make([]*secretv1.WebhookEndpoint, 0, len(endpoints))
	for i := range endpoints {
		out = append(out, toProtoEndpoint(&endpoints[i]))
	}
	return &secretv1.ListWebhookEndpointsResponse{Endpoints: out, PageInfo: pageInfo(page, limit, total)}, nil
}

func (s *Service) UpdateWebhookEndpoint(ctx context.Context, req *secretv1.UpdateWebhookEndpointRequest) (*secretv1.UpdateWebhookEndpointResponse, error) {
	c, err := s.caller(ctx)
	if err != nil {
		return nil, err
	}
	id, err := uuid.Parse(req.GetEndpointUuid())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "endpoint_uuid must be a UUID")
	}
	endpoint, err := s.api.UpdateWebhookEndpoint(ctx, c, req.GetProject(), store.UpdateWebhookEndpointInput{
		EndpointUUID:   id,
		URL:            req.GetUrl(),
		Description:    req.GetDescription(),
		Events:         req.GetEvents(),
		Status:         req.GetStatus(),
		TimeoutSeconds: req.GetTimeoutSeconds(),
		MaxAttempts:    req.GetMaxAttempts(),
	})
	if err != nil {
		return nil, toStatus(err, "update webhook endpoint")
	}
	return &secretv1.UpdateWebhookEndpointResponse{Endpoint: toProtoEndpoint(endpoint)}, nil
}

func (s *Service) DeleteWebhookEndpoint(ctx context.Context, req *secretv1.DeleteWebhookEndpointRequest) (*secretv1.DeleteWebhookEndpointResponse, error) {
	c, err := s.caller(ctx)
	if err != nil {
		return nil, err
	}
	id, err := uuid.Parse(req.GetEndpointUuid())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "endpoint_uuid must be a UUID")
	}
	if err := s.api.DeleteWebhookEndpoint(ctx, c, req.GetProject(), id); err != nil {
		return nil, toStatus(err, "delete webhook endpoint")
	}
	return &secretv1.DeleteWebhookEndpointResponse{Deleted: true}, nil
}

func (s *Service) ListWebhookDeliveries(ctx context.Context, req *secretv1.ListWebhookDeliveriesRequest) (*secretv1.ListWebhookDeliveriesResponse, error) {
	c, err := s.caller(ctx)
	if err != nil {
		return nil, err
	}
	id, err := uuid.Parse(req.GetEndpointUuid())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "endpoint_uuid must be a UUID")
	}
	page, limit := pageOf(req.GetPage())
	deliveries, total, err := s.api.ListWebhookDeliveries(ctx, c, req.GetProject(), id, page, limit)
	if err != nil {
		return nil, toStatus(err, "list webhook deliveries")
	}
	out := make([]*secretv1.WebhookDelivery, 0, len(deliveries))
	for _, d := range deliveries {
		item := &secretv1.WebhookDelivery{
			DeliveryUuid: d.UUID.String(),
			EventType:    d.EventType,
			ResourceMrn:  d.ResourceMRN,
			AttemptCount: d.AttemptCount,
			Status:       d.Status,
			Error:        d.Error,
			CreatedAt:    d.CreatedAt.UTC().Format(time.RFC3339),
		}
		if d.Version != nil {
			item.Version = *d.Version
		}
		if d.ResponseStatus != nil {
			item.ResponseStatus = *d.ResponseStatus
		}
		out = append(out, item)
	}
	return &secretv1.ListWebhookDeliveriesResponse{Deliveries: out, PageInfo: pageInfo(page, limit, total)}, nil
}

func (s *Service) ListAuditEvents(ctx context.Context, req *secretv1.ListAuditEventsRequest) (*secretv1.ListAuditEventsResponse, error) {
	c, err := s.caller(ctx)
	if err != nil {
		return nil, err
	}
	page, limit := pageOf(req.GetPage())
	entries, total, err := s.api.ListAuditEvents(ctx, c, page, limit)
	if err != nil {
		return nil, toStatus(err, "list audit events")
	}
	out := make([]*secretv1.AuditEvent, 0, len(entries))
	for _, e := range entries {
		item := &secretv1.AuditEvent{
			EventUuid:    e.UUID.String(),
			ActorSubject: e.ActorSubject,
			ActorKind:    e.ActorKind,
			Action:       e.Action,
			ResourceMrn:  e.ResourceMRN,
			Outcome:      e.Outcome,
			Reason:       e.Reason,
			IpAddress:    e.IPAddress,
			UserAgent:    e.UserAgent,
			RequestId:    e.RequestID,
			CreatedAt:    e.CreatedAt.UTC().Format(time.RFC3339),
		}
		if e.Version != nil {
			item.Version = *e.Version
		}
		out = append(out, item)
	}
	return &secretv1.ListAuditEventsResponse{Events: out, PageInfo: pageInfo(page, limit, total)}, nil
}

// ---------------------------------------------------------------------------
// Conversions
// ---------------------------------------------------------------------------

func toProtoSecretMeta(m *store.SecretMeta) *secretv1.SecretMetadata {
	if m == nil {
		return nil
	}
	policyJSON := ""
	if len(m.RotationPolicy) > 0 {
		if raw, err := json.Marshal(m.RotationPolicy); err == nil {
			policyJSON = string(raw)
		}
	}
	return &secretv1.SecretMetadata{
		SecretUuid:         m.UUID.String(),
		FolderPath:         m.FolderPath,
		Key:                m.Key,
		Description:        m.Description,
		Tags:               m.Tags,
		CurrentVersion:     m.CurrentVersion,
		KeepVersions:       m.KeepVersions,
		Mrn:                m.MRN,
		RotatedAt:          formatTime(m.RotatedAt),
		ExpiresAt:          formatTime(m.ExpiresAt),
		CreatedAt:          m.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:          m.UpdatedAt.UTC().Format(time.RFC3339),
		RotationPolicyJson: policyJSON,
	}
}

func toProtoPutResult(r *store.PutResult) *secretv1.PutResult {
	if r == nil {
		return nil
	}
	return &secretv1.PutResult{
		SecretUuid: r.SecretUUID.String(),
		Version:    r.Version,
		Created:    r.Created,
		Unchanged:  r.Unchanged,
		Pruned:     int32(r.Pruned),
	}
}

func toProtoDeleted(d *store.DeletedSecret) *secretv1.DeletedSecret {
	if d == nil {
		return nil
	}
	return &secretv1.DeletedSecret{
		SecretUuid:     d.UUID.String(),
		FolderPath:     d.FolderPath,
		Key:            d.Key,
		CurrentVersion: d.CurrentVersion,
		DeletedAt:      d.DeletedAt.UTC().Format(time.RFC3339),
		DestroyAfter:   formatTime(d.DestroyAfter),
	}
}

func toProtoEndpoint(e *store.WebhookEndpoint) *secretv1.WebhookEndpoint {
	if e == nil {
		return nil
	}
	return &secretv1.WebhookEndpoint{
		EndpointUuid:    e.UUID.String(),
		Url:             e.URL,
		Description:     e.Description,
		Events:          e.Events,
		Status:          e.Status,
		TimeoutSeconds:  e.TimeoutSeconds,
		MaxAttempts:     e.MaxAttempts,
		LastTriggeredAt: formatTime(e.LastTriggeredAt),
	}
}

// specOf converts a wire generator spec. The supplied value arrives as raw bytes on
// gRPC (no base64 hop, unlike JSON) and is carried as a string only because that is
// what rotation.Spec holds.
func specOf(g *secretv1.GeneratorSpec) rotation.Spec {
	if g == nil {
		return rotation.Spec{}
	}
	spec := rotation.Spec{
		Type:    g.GetType(),
		Length:  int(g.GetLength()),
		Charset: g.GetCharset(),
	}
	if v := g.GetValue(); len(v) > 0 {
		spec.Value = string(v)
		crypto.Zero(v)
	}
	return spec
}

// decodeRotationPolicyJSON parses the JSON-encoded policy field.
//
// It is JSON-in-a-string rather than a proto message so the wire format does not have
// to track every future policy field — a policy is configuration, and configuration
// that needs a proto change to gain a knob is configuration that stops gaining knobs.
func decodeRotationPolicyJSON(raw string) (map[string]any, error) {
	if raw == "" {
		return nil, nil
	}
	out := map[string]any{}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, status.Error(codes.InvalidArgument, "rotation_policy_json must be a JSON object")
	}
	return out, nil
}
