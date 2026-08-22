package store

import (
	"context"
	"net/netip"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/maintainerd/secret/internal/platform/apperror"
	"github.com/maintainerd/secret/internal/storage"
)

// Audited actions. READS ARE IN THIS LIST, and that is the point: for a secret
// store the read is the sensitive event, so there is no unaudited get path.
//
// ActionRead and ActionReveal are deliberately separate. Reading metadata and
// revealing a value are different grants, and an incident review needs to
// distinguish "who listed the secrets" from "who saw the production database
// password".
const (
	ActionRead    = "secret.read"
	ActionReveal  = "secret.reveal"
	ActionWrite   = "secret.write"
	ActionRotate  = "secret.rotate"
	ActionDelete  = "secret.delete"
	ActionRestore = "secret.restore"
	ActionDestroy = "secret.destroy"
	ActionList    = "secret.list"

	ActionProjectCreate     = "project.create"
	ActionEnvironmentCreate = "environment.create"
	ActionFolderCreate      = "folder.create"
	ActionFolderMove        = "folder.move"
	ActionRootKeyRotate     = "rootkey.rotate"
	ActionSetupComplete     = "setup.complete"
)

// Actor kinds.
const (
	ActorKindUser    = "user"
	ActorKindService = "service"
	ActorKindSetup   = "setup"
)

// Outcomes. Denied is recorded, not swallowed: a refused access attempt is the most
// interesting row in the table.
const (
	OutcomeSuccess = "success"
	OutcomeDenied  = "denied"
	OutcomeError   = "error"
)

// AuditEvent is one row of the trail.
//
// It carries no value and no checksum. There is no field on this struct that could
// hold a secret, which is a stronger guarantee than remembering not to fill one in.
type AuditEvent struct {
	// TenantUUID is nil for platform-scoped events — notably the setup call that
	// creates the first tenant, which cannot reference one yet.
	TenantUUID *uuid.UUID
	// ActorSubject is the principal as authenticated: an Auth subject, a service
	// identity, or the setup controller. Stored as text because this service does
	// not own the identity table and an audit row must outlive the principal it
	// names.
	ActorSubject string
	ActorKind    string
	Action       string
	// ResourceMRN is the full MRN as evaluated, denormalized so the trail still
	// reads correctly after the folder moves or the secret is destroyed.
	ResourceMRN string
	// SecretUUID is a best-effort link to a live secret; ResourceMRN is the durable
	// identifier.
	SecretUUID *uuid.UUID
	Version    *int32
	Outcome    string
	Reason     string
	IPAddress  string
	UserAgent  string
	RequestID  string
	Metadata   map[string]any
}

// RecordAudit appends an event. Append-only at the database level: the trigger on
// audit_log rejects any UPDATE, and permits DELETE only for retention or tenant
// erasure.
func (s *Service) RecordAudit(ctx context.Context, ev AuditEvent) error {
	if ev.Action == "" {
		return apperror.NewValidation("audit action is required")
	}
	if ev.ActorKind == "" {
		ev.ActorKind = ActorKindService
	}
	if ev.Outcome == "" {
		ev.Outcome = OutcomeSuccess
	}
	meta, err := encodeObject(ev.Metadata)
	if err != nil {
		return apperror.NewInternal("encode audit metadata", err)
	}

	params := storage.AppendAuditEventParams{
		ActorSubject: ev.ActorSubject,
		ActorKind:    ev.ActorKind,
		Action:       ev.Action,
		ResourceMrn:  ev.ResourceMRN,
		Outcome:      ev.Outcome,
		Reason:       ev.Reason,
		UserAgent:    ev.UserAgent,
		RequestID:    ev.RequestID,
		Metadata:     meta,
		IpAddress:    parseIP(ev.IPAddress),
	}
	if ev.Version != nil {
		params.Version = pgtype.Int4{Int32: *ev.Version, Valid: true}
	}
	if ev.TenantUUID != nil {
		tenant, err := s.repo.GetTenantByUUID(ctx, *ev.TenantUUID)
		if err != nil {
			return mapReadError(err, "tenant")
		}
		params.TenantID = pgtype.Int8{Int64: tenant.TenantID, Valid: true}
		if ev.SecretUUID != nil {
			// Best-effort: a destroyed secret has no row to link, and that must not
			// prevent the event from being recorded. Losing the audit row would be
			// the worse outcome by far.
			if row, err := s.repo.GetSecretByUUID(ctx, storage.GetSecretByUUIDParams{
				TenantID:   tenant.TenantID,
				SecretUuid: *ev.SecretUUID,
			}); err == nil {
				params.SecretID = pgtype.Int8{Int64: row.SecretID, Valid: true}
			}
		}
	}

	if _, err := s.repo.AppendAuditEvent(ctx, params); err != nil {
		return apperror.NewInternal("append audit event", err)
	}
	return nil
}

// parseIP converts a textual address to the pgx inet representation, tolerating an
// empty or unparseable value rather than failing the event.
func parseIP(s string) *netip.Addr {
	if s == "" {
		return nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return nil
	}
	return &addr
}
