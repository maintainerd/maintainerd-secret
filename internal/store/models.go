package store

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/maintainerd/secret/internal/crypto"
	"github.com/maintainerd/secret/internal/storage"
)

// The domain types below are what leaves this package. They are deliberately not
// the sqlc row structs: a row carries internal ids (tenant_id, secret_id,
// folder_id) that no caller should hold, because an integer id is a handle that
// bypasses the tenant-scoped lookup that produced it. Callers address things by
// UUID and by slug/path.
//
// NONE OF THESE TYPES HAS A VALUE FIELD except RevealedSecret, and that one holds a
// crypto.Plaintext so it cannot be logged or marshalled by accident.

// Tenant is the local mirror of an Auth tenant.
type Tenant struct {
	UUID           uuid.UUID  `json:"tenant_uuid"`
	AuthTenantUUID *uuid.UUID `json:"auth_tenant_uuid,omitempty"`
	Name           string     `json:"name"`
	DisplayName    string     `json:"display_name"`
	Status         string     `json:"status"`
	IsSystem       bool       `json:"is_system"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// Project groups a tenant's secrets.
type Project struct {
	UUID        uuid.UUID `json:"project_uuid"`
	Name        string    `json:"name"`
	Slug        string    `json:"slug"`
	Description string    `json:"description"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Environment is a project's deployment stage.
type Environment struct {
	UUID        uuid.UUID `json:"environment_uuid"`
	Name        string    `json:"name"`
	Slug        string    `json:"slug"`
	Description string    `json:"description"`
	Position    int32     `json:"position"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Folder is a node in an environment's hierarchy.
type Folder struct {
	UUID uuid.UUID `json:"folder_uuid"`
	Name string    `json:"name"`
	// Path is the materialized absolute path: '/' or '/db/primary'.
	Path      string    `json:"path"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// SecretRef is a secret's address. It is the primary way to name a secret in this
// API, in preference to a UUID, because it is the form a caller actually has: a
// consumer knows which project, environment, folder and key it wants, not a UUID it
// has never seen.
type SecretRef struct {
	// TenantUUID scopes everything else. Required on every operation — it is the
	// value the query layer's tenant boundary is built from.
	TenantUUID uuid.UUID
	// Project is the project slug.
	Project string
	// Environment is the environment slug.
	Environment string
	// FolderPath is the folder's absolute path; empty means the root.
	FolderPath string
	// Key is the secret's name within that folder.
	Key string
}

// SecretMeta is everything about a secret except its value. This is what listing
// returns, and what a console renders.
type SecretMeta struct {
	UUID           uuid.UUID      `json:"secret_uuid"`
	FolderPath     string         `json:"folder_path"`
	Key            string         `json:"key"`
	Description    string         `json:"description"`
	Tags           []string       `json:"tags"`
	CurrentVersion int32          `json:"current_version"`
	KeepVersions   int32          `json:"keep_versions"`
	RotationPolicy map[string]any `json:"rotation_policy"`
	// MRNResourcePath is the parsed resource segment policy evaluation compares.
	MRNResourcePath string `json:"mrn_resource_path"`
	// MRN is the full presentation identifier. Audit rows and the console want the
	// whole string; policy compares the parsed columns instead.
	MRN       string     `json:"mrn"`
	RotatedAt *time.Time `json:"rotated_at,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// VersionMeta describes one version without its payload. checksum is included
// because it is how a caller detects change without a reveal.
type VersionMeta struct {
	Version   int32     `json:"version"`
	KEKID     string    `json:"kek_id"`
	ValueType string    `json:"value_type"`
	Checksum  []byte    `json:"checksum"`
	CreatedAt time.Time `json:"created_at"`
}

// DeletedSecret is an entry in the recovery window.
type DeletedSecret struct {
	UUID           uuid.UUID  `json:"secret_uuid"`
	FolderPath     string     `json:"folder_path"`
	Key            string     `json:"key"`
	CurrentVersion int32      `json:"current_version"`
	DeletedAt      time.Time  `json:"deleted_at"`
	DestroyAfter   *time.Time `json:"destroy_after,omitempty"`
}

// RevealedSecret is a decrypted secret. The value is a crypto.Plaintext, which
// renders as "[REDACTED]" through every stringly and marshalling path — reaching
// the bytes requires calling Value.Bytes().
//
// The caller owns zeroizing it: call Zero when done.
type RevealedSecret struct {
	Meta      SecretMeta
	Version   int32
	ValueType string
	Value     crypto.Plaintext
}

// Zero overwrites the decrypted value.
func (r *RevealedSecret) Zero() {
	if r != nil {
		r.Value.Zero()
	}
}

// PutResult reports what a write did.
type PutResult struct {
	SecretUUID uuid.UUID `json:"secret_uuid"`
	Version    int32     `json:"version"`
	// Created is true when this write created the secret (version 1).
	Created bool `json:"created"`
	// Unchanged is true when the submitted value matched the current version's
	// checksum, so no new version was written and Version is the existing one.
	Unchanged bool `json:"unchanged"`
	// Pruned counts versions retention removed as part of this write.
	Pruned int `json:"pruned"`
}

// SetupState is the durable one-shot setup lock.
type SetupState struct {
	Complete       bool       `json:"complete"`
	CompletedAt    *time.Time `json:"completed_at,omitempty"`
	Controller     string     `json:"controller,omitempty"`
	ControllerKind string     `json:"controller_kind,omitempty"`
}

// ---------------------------------------------------------------------------
// Row -> domain conversion
// ---------------------------------------------------------------------------

func toTenant(r storage.Tenant) Tenant {
	t := Tenant{
		UUID:        r.TenantUuid,
		Name:        r.Name,
		DisplayName: r.DisplayName,
		Status:      r.Status,
		IsSystem:    r.IsSystem,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}
	if r.AuthTenantUuid.Valid {
		id := uuid.UUID(r.AuthTenantUuid.Bytes)
		t.AuthTenantUUID = &id
	}
	return t
}

func toProject(r storage.Project) Project {
	return Project{
		UUID:        r.ProjectUuid,
		Name:        r.Name,
		Slug:        r.Slug,
		Description: r.Description,
		Status:      r.Status,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}
}

func toEnvironment(r storage.Environment) Environment {
	return Environment{
		UUID:        r.EnvironmentUuid,
		Name:        r.Name,
		Slug:        r.Slug,
		Description: r.Description,
		Position:    r.Position,
		Status:      r.Status,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}
}

func toFolder(r storage.Folder) Folder {
	return Folder{
		UUID:      r.FolderUuid,
		Name:      r.Name,
		Path:      r.Path,
		CreatedAt: r.CreatedAt,
		UpdatedAt: r.UpdatedAt,
	}
}

// toSecretMeta converts the listing row. defaultKeep supplies the service-wide
// retention default for secrets that do not override it, so a caller never sees a
// bare NULL it would have to interpret.
func toSecretMeta(r storage.ListSecretMetaBySubtreeRow, defaultKeep int32) SecretMeta {
	m := SecretMeta{
		UUID:            r.SecretUuid,
		FolderPath:      r.FolderPath,
		Key:             r.Key,
		Description:     r.Description,
		Tags:            decodeTags(r.Tags),
		CurrentVersion:  r.CurrentVersion,
		KeepVersions:    defaultKeep,
		RotationPolicy:  decodeObject(r.RotationPolicy),
		MRNResourcePath: r.MrnResourcePath,
		MRN:             mrn(r.MrnTenant, r.MrnProject, r.MrnResourcePath),
		CreatedAt:       r.CreatedAt,
		UpdatedAt:       r.UpdatedAt,
	}
	if r.KeepVersions.Valid {
		m.KeepVersions = r.KeepVersions.Int32
	}
	m.RotatedAt = timePtr(r.RotatedAt)
	m.ExpiresAt = timePtr(r.ExpiresAt)
	return m
}

// secretRowToMeta converts a full secrets row. folderPath is passed in because the
// row carries only folder_id, and the caller resolved the path to get there.
func secretRowToMeta(r storage.Secret, folderPath string, defaultKeep int32) SecretMeta {
	m := SecretMeta{
		UUID:            r.SecretUuid,
		FolderPath:      folderPath,
		Key:             r.Key,
		Description:     r.Description,
		Tags:            decodeTags(r.Tags),
		CurrentVersion:  r.CurrentVersion,
		KeepVersions:    defaultKeep,
		RotationPolicy:  decodeObject(r.RotationPolicy),
		MRNResourcePath: r.MrnResourcePath,
		MRN:             mrn(r.MrnTenant, r.MrnProject, r.MrnResourcePath),
		CreatedAt:       r.CreatedAt,
		UpdatedAt:       r.UpdatedAt,
	}
	if r.KeepVersions.Valid {
		m.KeepVersions = r.KeepVersions.Int32
	}
	m.RotatedAt = timePtr(r.RotatedAt)
	m.ExpiresAt = timePtr(r.ExpiresAt)
	return m
}

func toVersionMeta(r storage.ListSecretVersionMetaRow) VersionMeta {
	return VersionMeta{
		Version:   r.Version,
		KEKID:     r.KekID,
		ValueType: r.ValueType,
		Checksum:  r.Checksum,
		CreatedAt: r.CreatedAt,
	}
}

func toDeletedSecret(r storage.ListDeletedSecretMetaRow) DeletedSecret {
	d := DeletedSecret{
		UUID:           r.SecretUuid,
		FolderPath:     r.FolderPath,
		Key:            r.Key,
		CurrentVersion: r.CurrentVersion,
		DestroyAfter:   timePtr(r.DestroyAfter),
	}
	if r.DeletedAt.Valid {
		d.DeletedAt = r.DeletedAt.Time
	}
	return d
}

func toSetupState(r storage.SetupState) SetupState {
	s := SetupState{
		Complete:       r.CompletedAt.Valid,
		Controller:     r.Controller,
		ControllerKind: r.ControllerKind,
	}
	s.CompletedAt = timePtr(r.CompletedAt)
	return s
}

// ---------------------------------------------------------------------------
// Small pgtype / JSONB helpers
// ---------------------------------------------------------------------------

func toAuditEntry(r storage.AuditLog) AuditEntry {
	e := AuditEntry{
		UUID:         r.EventUuid,
		ActorSubject: r.ActorSubject,
		ActorKind:    r.ActorKind,
		Action:       r.Action,
		ResourceMRN:  r.ResourceMrn,
		Outcome:      r.Outcome,
		Reason:       r.Reason,
		UserAgent:    r.UserAgent,
		RequestID:    r.RequestID,
		Metadata:     decodeObject(r.Metadata),
		CreatedAt:    r.CreatedAt,
	}
	if r.Version.Valid {
		v := r.Version.Int32
		e.Version = &v
	}
	if r.IpAddress != nil {
		e.IPAddress = r.IpAddress.String()
	}
	return e
}

func pgInt8(v int64) pgtype.Int8 { return pgtype.Int8{Int64: v, Valid: true} }

func pgInt4(v int32) pgtype.Int4 { return pgtype.Int4{Int32: v, Valid: true} }

func timePtr(ts pgtype.Timestamptz) *time.Time {
	if !ts.Valid {
		return nil
	}
	t := ts.Time
	return &t
}

func timestamptz(t *time.Time) pgtype.Timestamptz {
	if t == nil {
		return pgtype.Timestamptz{}
	}
	return pgtype.Timestamptz{Time: *t, Valid: true}
}

func int4(v *int32) pgtype.Int4 {
	if v == nil {
		return pgtype.Int4{}
	}
	return pgtype.Int4{Int32: *v, Valid: true}
}

func uuidPtr(v *uuid.UUID) pgtype.UUID {
	if v == nil {
		return pgtype.UUID{}
	}
	return pgtype.UUID{Bytes: *v, Valid: true}
}

// encodeTags marshals a tag list, normalizing nil to an empty array so the column
// never holds JSON null where the schema promises '[]'.
func encodeTags(tags []string) ([]byte, error) {
	if tags == nil {
		tags = []string{}
	}
	return json.Marshal(tags)
}

func decodeTags(raw []byte) []string {
	out := []string{}
	if len(raw) == 0 {
		return out
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		// A malformed tag list is metadata noise, not a reason to fail a read of a
		// credential. Report it as empty rather than propagating an error up a path
		// whose caller wanted a secret.
		return []string{}
	}
	return out
}

func encodeObject(m map[string]any) ([]byte, error) {
	if m == nil {
		m = map[string]any{}
	}
	return json.Marshal(m)
}

func decodeObject(raw []byte) map[string]any {
	out := map[string]any{}
	if len(raw) == 0 {
		return out
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return map[string]any{}
	}
	return out
}
