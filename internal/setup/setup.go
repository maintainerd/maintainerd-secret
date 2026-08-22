// Package setup is the first-run surface, in BOTH modes an instance can be
// bootstrapped in — and it guarantees an instance has exactly ONE of them.
//
//	STANDALONE   an operator drives a REST wizard (POST /api/v1/setup), gated by
//	             SETUP_BOOTSTRAP_TOKEN. This is the "adoptable alone" path: run
//	             maintainerd-secret as your vault with none of the rest of the
//	             platform.
//	CONTROLLED   a controller (Core) drives the gRPC SetupService, gated by an
//	             x-setup-token metadata header. This is the ecosystem path, where
//	             Core provisions the service and records itself as controller.
//
// WHY ONE INSTANCE MUST HAVE EXACTLY ONE PATH. Both paths create the first tenant.
// Two open paths is a race whose winner owns the vault, and the REST one is reachable
// by anything on the network. So once an ORCHESTRATOR has provisioned this instance
// (controller_kind = service in the durable setup_state row), the REST wizard refuses
// — the same refuseWhenOrchestrated rule maintainerd-auth applies, for the same
// reason. Note the condition is "an orchestrator owns this instance", not merely
// "setup is complete": a completed standalone setup also closes the wizard, but it is
// the ORCHESTRATED case that would otherwise leave a second, weaker door into a
// service Core believes it alone controls.
//
// THE LOCK IS DURABLE, NOT IN MEMORY. It is the setup_state row (migration 00009),
// which is what fixes the prototype's bug: a process-memory lock reopened the setup
// window on every restart, so a crash loop was an unbounded series of chances to
// register as controller of the vault.
//
// SINGLE-FLIGHT. Provisioning is serialized by a mutex here AND by the database's
// one-shot upsert. The mutex is not the correctness mechanism (it is per-process, and
// there can be several processes); it exists so that a caller retrying a slow
// provision does not run a second one concurrently in the SAME process, where both
// would race to create the default project and one would get a confusing conflict.
package setup

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/google/uuid"

	"github.com/maintainerd/secret/internal/audit"
	"github.com/maintainerd/secret/internal/platform/apperror"
	"github.com/maintainerd/secret/internal/store"
)

// Mode names how an instance was (or will be) provisioned.
const (
	// ModeStandalone is the REST wizard path; the controller is an operator.
	ModeStandalone = "standalone"
	// ModeControlled is the gRPC SetupService path; the controller is a service.
	ModeControlled = "controlled"
)

// Status is what a status query returns.
//
// AnonymousStatus is the reduced form: an unauthenticated caller learns only whether
// setup is complete. That single bit is unavoidable — a client has to know whether to
// show a wizard — but everything else (who the controller is, which tenant and
// project exist, which auth tenant this maps to) is reconnaissance and requires the
// setup token or secret:Admin.
type Status struct {
	Completed bool `json:"completed"`

	Controller     string `json:"controller,omitempty"`
	ControllerKind string `json:"controller_kind,omitempty"`
	Mode           string `json:"mode,omitempty"`
	CompletedAt    string `json:"completed_at,omitempty"`
	Tenant         string `json:"tenant,omitempty"`
	AuthTenantUUID string `json:"auth_tenant_uuid,omitempty"`
	Project        string `json:"project,omitempty"`
	Environment    string `json:"environment,omitempty"`
	// Permissions is the list this service enforces, so a controller can register
	// exactly what is enforced instead of a hand-maintained copy.
	Permissions []string `json:"permissions,omitempty"`
	// RESTWizardOpen reports whether the standalone wizard will still accept a
	// provision. It is false once an orchestrator owns the instance.
	RESTWizardOpen bool `json:"rest_wizard_open"`
}

// AnonymousStatus reduces a Status to the one bit an unauthenticated caller may see.
func AnonymousStatus(full Status) Status {
	return Status{Completed: full.Completed}
}

// ProvisionInput is the first-run request.
type ProvisionInput struct {
	// Tenant is the tenant slug to create. Defaults to the configured default.
	Tenant string
	// TenantDisplayName is cosmetic.
	TenantDisplayName string
	// AuthTenantUUID links this mirror to Auth's authoritative tenant. Present in
	// controlled mode, absent in standalone: a standalone install owns its own tenant
	// names because there is no Auth to mirror.
	AuthTenantUUID *uuid.UUID
	// Project and Environment are the defaults created alongside the tenant, so the
	// instance is immediately usable rather than merely provisioned.
	Project     string
	Environment string
	// Controller identifies who is provisioning. Recorded on the durable lock.
	Controller string
	// Mode is ModeStandalone or ModeControlled.
	Mode string
}

// ProvisionResult reports what provisioning created.
type ProvisionResult struct {
	TenantUUID  uuid.UUID `json:"tenant_uuid"`
	Tenant      string    `json:"tenant"`
	Project     string    `json:"project"`
	Environment string    `json:"environment"`
	// AlreadyExisted is true when provisioning found the scope already in place.
	// Provisioning is idempotent on purpose: a controller whose response was lost
	// must be able to retry, and answering a retry with a conflict reads to Core as
	// "somebody else claimed this instance" when the truth is "your own first call
	// landed".
	AlreadyExisted bool `json:"already_existed"`
	// Permissions is what a controller should register in Auth.
	Permissions []string `json:"permissions"`
}

// Options configures the service.
type Options struct {
	// BootstrapToken gates both surfaces. An EMPTY token means setup is DISABLED
	// outside development — config refuses to boot without one, so an empty value
	// here only ever occurs in development.
	BootstrapToken string
	// Development permits an empty bootstrap token.
	Development bool
	// DefaultTenant/Project/Environment are the fallbacks when a request names none.
	DefaultTenant      string
	DefaultProject     string
	DefaultEnvironment string
	// DeclaredPermissions is what this service enforces, reported so a controller
	// registers exactly that.
	DeclaredPermissions []string
	// CoreAttached is MAINTAINERD_MODE=core: the operator has DECLARED that a
	// controller provisions this instance.
	//
	// It closes the REST wizard from the first boot rather than from the moment
	// the controller wins the race. Without it there is a window — every second
	// between "the instance is up" and "core has provisioned it" — in which the
	// unauthenticated-by-Auth REST wizard is reachable by anything on the network
	// and would hand the vault to whoever posts first. The bootstrap token still
	// gates that window, but a declared mode is a second, free gate, and the
	// operator has already told us which path they intend to use.
	//
	// FALSE (standalone) IS THE DEFAULT and leaves today's behaviour exactly as it
	// was: the wizard is open until an orchestrator actually owns the instance.
	// Nothing about the gRPC SetupService changes in either mode — an operator who
	// runs standalone and later adopts core must still be able to be provisioned.
	CoreAttached bool
}

// Service provisions the instance.
type Service struct {
	store   *store.Service
	auditor *audit.Auditor
	opts    Options

	// mu single-flights provisioning within this process. See the package comment
	// for why it is not the correctness mechanism.
	mu sync.Mutex
}

// New builds the setup service.
func New(st *store.Service, auditor *audit.Auditor, opts Options) (*Service, error) {
	if st == nil {
		return nil, errors.New("setup: store is required")
	}
	if auditor == nil {
		// Setup writes the first rows in the trail — who provisioned this vault and
		// when. Running it unauditably would leave the single most important event in
		// the instance's life unrecorded.
		return nil, audit.ErrNoAuditor
	}
	return &Service{store: st, auditor: auditor, opts: opts}, nil
}

// ErrSetupDisabled is returned when no bootstrap token is configured outside
// development, so neither surface may provision.
var ErrSetupDisabled = errors.New("setup is not available: no bootstrap token is configured")

// CheckToken validates a presented bootstrap token in constant time.
//
// An empty CONFIGURED token is refused outside development. The prototype treated
// empty as "setup is open", which combined with its in-memory lock meant every
// restart reopened unauthenticated controller registration.
//
// The comparison is constant-time because a token check that leaks its progress
// through timing is a token check an attacker completes one byte at a time.
func (s *Service) CheckToken(presented string) error {
	if s.opts.BootstrapToken == "" {
		if !s.opts.Development {
			slog.Error("setup: refusing — SETUP_BOOTSTRAP_TOKEN is not configured")
			return ErrSetupDisabled
		}
		// Development with no token configured: open, and the boot banner has already
		// said so.
		return nil
	}
	if subtle.ConstantTimeCompare([]byte(presented), []byte(s.opts.BootstrapToken)) != 1 {
		return apperror.NewForbidden("invalid bootstrap token")
	}
	return nil
}

// Status reports the instance's setup state, in full. Callers decide whether the
// requester may see all of it (see AnonymousStatus).
func (s *Service) Status(ctx context.Context) (Status, error) {
	state, err := s.store.SetupState(ctx)
	if err != nil {
		return Status{}, err
	}
	out := Status{
		Completed:      state.Complete,
		Controller:     state.Controller,
		ControllerKind: state.ControllerKind,
		Permissions:    s.opts.DeclaredPermissions,
		RESTWizardOpen: !s.orchestrated(state),
	}
	switch state.ControllerKind {
	case store.ControllerKindService:
		out.Mode = ModeControlled
	case store.ControllerKindOperator:
		out.Mode = ModeStandalone
	}
	if state.CompletedAt != nil {
		out.CompletedAt = state.CompletedAt.UTC().Format("2006-01-02T15:04:05Z07:00")
	}
	// The default scope is reported when it exists, so a controller can confirm what
	// it is attaching to rather than assuming.
	if tenant, terr := s.store.GetTenantByName(ctx, s.opts.DefaultTenant); terr == nil {
		out.Tenant = tenant.Name
		if tenant.AuthTenantUUID != nil {
			out.AuthTenantUUID = tenant.AuthTenantUUID.String()
		}
		out.Project = s.opts.DefaultProject
		out.Environment = s.opts.DefaultEnvironment
	}
	return out, nil
}

// RefuseWhenOrchestrated reports whether the REST wizard must refuse this request.
//
// TWO WAYS TO BE ORCHESTRATED, and either one closes the wizard:
//
//	DECLARED   MAINTAINERD_MODE=core (Options.CoreAttached). The operator has said
//	           a controller owns first-run, so the wizard is shut from the first
//	           boot rather than from the moment the controller wins the race.
//	OBSERVED   an orchestrator actually provisioned this instance —
//	           controller_kind = service in the durable setup_state row. This is
//	           the original rule and it still applies in standalone mode, so an
//	           instance that started standalone and was later adopted by core
//	           closes its wizard the moment that happens.
//
// The condition is orchestration, NOT merely "setup is complete". With the
// control path unused there is no gRPC controller to bootstrap through, so
// closing REST on completion alone would leave an instance with no way to be
// provisioned at all — which is exactly the asymmetry maintainerd-auth's version
// documents.
func (s *Service) RefuseWhenOrchestrated(ctx context.Context) (bool, error) {
	if s.opts.CoreAttached {
		return true, nil
	}
	state, err := s.store.SetupState(ctx)
	if err != nil {
		return false, err
	}
	return s.orchestrated(state), nil
}

func (s *Service) orchestrated(state *store.SetupState) bool {
	if s.opts.CoreAttached {
		return true
	}
	return state != nil && state.Complete && state.ControllerKind == store.ControllerKindService
}

// Provision creates the first tenant mirror plus the default project and environment.
//
// Idempotent (see ProvisionResult.AlreadyExisted) and single-flighted. It does NOT
// close the setup window — Complete does, as a separate call — because a controller
// provisions several things across several RPCs and must be able to finish before the
// door shuts. In standalone mode the REST wizard calls both in one request.
func (s *Service) Provision(ctx context.Context, in ProvisionInput, actor audit.Actor) (*ProvisionResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tenantName := firstNonEmpty(in.Tenant, s.opts.DefaultTenant)
	project := firstNonEmpty(in.Project, s.opts.DefaultProject)
	environment := firstNonEmpty(in.Environment, s.opts.DefaultEnvironment)
	if tenantName == "" || project == "" || environment == "" {
		return nil, apperror.NewValidation("tenant, project and environment names are all required")
	}
	if in.Controller == "" {
		return nil, apperror.NewValidation("controller is required")
	}

	result := &ProvisionResult{
		Tenant:      tenantName,
		Project:     project,
		Environment: environment,
		Permissions: s.opts.DeclaredPermissions,
	}

	tenant, err := s.store.GetTenantByName(ctx, tenantName)
	switch {
	case err == nil:
		result.AlreadyExisted = true
	case apperror.IsNotFound(err):
		tenant, err = s.store.CreateTenant(ctx, store.CreateTenantInput{
			AuthTenantUUID: in.AuthTenantUUID,
			Name:           tenantName,
			DisplayName:    firstNonEmpty(in.TenantDisplayName, tenantName),
			// The first tenant of an install is the system tenant: the schema keeps at
			// most one, and marking it is what makes "the bootstrap root" identifiable
			// later without guessing from names.
			IsSystem: true,
		})
		if err != nil {
			if !apperror.IsConflict(err) {
				return nil, err
			}
			// Another replica won the race, which is a success for our purposes.
			tenant, err = s.store.GetTenantByName(ctx, tenantName)
			if err != nil {
				return nil, err
			}
			result.AlreadyExisted = true
		}
	default:
		return nil, err
	}
	result.TenantUUID = tenant.UUID

	if _, err := s.store.GetProject(ctx, tenant.UUID, project); err != nil {
		if !apperror.IsNotFound(err) {
			return nil, err
		}
		if _, cerr := s.store.CreateProject(ctx, store.CreateProjectInput{
			TenantUUID: tenant.UUID,
			Slug:       project,
			Name:       project,
		}); cerr != nil && !apperror.IsConflict(cerr) {
			return nil, cerr
		}
	}

	if _, err := s.store.GetEnvironment(ctx, tenant.UUID, project, environment); err != nil {
		if !apperror.IsNotFound(err) {
			return nil, err
		}
		if _, cerr := s.store.CreateEnvironment(ctx, store.CreateEnvironmentInput{
			TenantUUID: tenant.UUID,
			Project:    project,
			Slug:       environment,
			Name:       environment,
		}); cerr != nil && !apperror.IsConflict(cerr) {
			return nil, cerr
		}
	}

	// Audited under the setup actor kind, with a nil tenant on the event when the
	// tenant did not exist a moment ago — the same reason audit_log.tenant_id is
	// nullable.
	if actor.Kind == "" {
		actor.Kind = store.ActorKindSetup
	}
	if actor.Subject == "" {
		actor.Subject = in.Controller
	}
	tenantUUID := tenant.UUID
	if err := s.auditor.Record(ctx, actor, audit.Event{
		TenantUUID:  &tenantUUID,
		Action:      store.ActionSetupProvision,
		ResourceMRN: store.MRN(tenantName, "", store.ResourceSetup),
		Metadata: map[string]any{
			"mode":             in.Mode,
			"controller":       in.Controller,
			"project":          project,
			"environment":      environment,
			"already_existed":  result.AlreadyExisted,
			"auth_tenant_uuid": uuidString(in.AuthTenantUUID),
		},
	}); err != nil {
		return nil, err
	}
	return result, nil
}

// Complete closes the setup window permanently, recording who closed it.
//
// Single-use is enforced by the DATABASE (the upsert's DO UPDATE branch is guarded on
// completed_at IS NULL), not by a check-then-act here: two concurrent callers are
// serialized by the row lock ON CONFLICT takes, and the loser sees the winner's
// completed_at. A read-then-write in Go would have a race exactly wide enough to
// matter.
func (s *Service) Complete(ctx context.Context, controller, mode string, actor audit.Actor) (Status, error) {
	kind := store.ControllerKindService
	if mode == ModeStandalone {
		kind = store.ControllerKindOperator
	}
	state, err := s.store.CompleteSetup(ctx, controller, kind)
	if err != nil {
		return Status{}, err
	}
	if actor.Kind == "" {
		actor.Kind = store.ActorKindSetup
	}
	if actor.Subject == "" {
		actor.Subject = controller
	}
	if aerr := s.auditor.Record(ctx, actor, audit.Event{
		Action:      store.ActionSetupComplete,
		ResourceMRN: store.MRN(s.opts.DefaultTenant, "", store.ResourceSetup),
		Metadata:    map[string]any{"controller": controller, "mode": mode, "controller_kind": kind},
	}); aerr != nil {
		// The window is already closed and that is irreversible; reporting a failure
		// would invite a retry that can only fail. Logged loudly instead.
		slog.Error("setup: completed the setup window but could not record the audit row",
			"controller", controller, "error", aerr)
	}
	out, err := s.Status(ctx)
	if err != nil {
		// Fall back to what CompleteSetup already told us rather than failing a
		// completed setup on a follow-up read.
		return Status{
			Completed:      state.Complete,
			Controller:     state.Controller,
			ControllerKind: state.ControllerKind,
			Mode:           mode,
		}, nil
	}
	return out, nil
}

// ProvisionAndComplete is the standalone wizard's single call: provision the scope
// and close the window, in that order.
//
// The order matters and the failure mode is asymmetric. Provisioning first means a
// failure leaves the window OPEN and the operator can retry; completing first would
// leave an instance whose setup is locked and whose scope does not exist — a state
// with no recovery short of a database edit.
func (s *Service) ProvisionAndComplete(ctx context.Context, in ProvisionInput, actor audit.Actor) (*ProvisionResult, Status, error) {
	in.Mode = ModeStandalone
	result, err := s.Provision(ctx, in, actor)
	if err != nil {
		return nil, Status{}, err
	}
	status, err := s.Complete(ctx, in.Controller, ModeStandalone, actor)
	if err != nil {
		return nil, Status{}, err
	}
	return result, status, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func uuidString(id *uuid.UUID) string {
	if id == nil {
		return ""
	}
	return id.String()
}

// DescribeMode renders the mode for a log line.
func DescribeMode(mode string) string {
	switch mode {
	case ModeControlled:
		return fmt.Sprintf("%s (a controller drives the gRPC SetupService)", mode)
	case ModeStandalone:
		return fmt.Sprintf("%s (an operator drives the REST wizard)", mode)
	default:
		return "not provisioned"
	}
}
