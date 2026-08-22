package store

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/maintainerd/secret/internal/platform/apperror"
	"github.com/maintainerd/secret/internal/storage"
)

// Controller kinds recorded on the setup lock.
const (
	// ControllerKindService is Core (or another service) attaching to this
	// instance.
	ControllerKindService = "service"
	// ControllerKindOperator is a human bootstrapping a standalone install.
	ControllerKindOperator = "operator"
)

// SetupState reports whether the one-time setup window is still open.
//
// The answer comes from the database, not from process memory, and that is the
// entire reason this method exists. The prototype held the lock in a struct field
// (kit setup.Mode), so every restart reopened the setup window — and with an empty
// SETUP_BOOTSTRAP_TOKEN it reopened it unauthenticated. A crash loop was an
// unbounded series of chances to register as controller of the vault. A one-shot
// lock has to derive from a stored fact.
func (s *Service) SetupState(ctx context.Context) (*SetupState, error) {
	row, err := s.repo.GetSetupState(ctx)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// No row yet: setup has never been attempted, so the window is open.
			return &SetupState{Complete: false}, nil
		}
		return nil, apperror.NewInternal("read setup state", err)
	}
	st := toSetupState(row)
	return &st, nil
}

// CompleteSetup closes the setup window permanently, recording who closed it.
//
// Single-use is enforced by the database rather than by a check-then-act here: the
// upsert's DO UPDATE branch is guarded on completed_at IS NULL, so a second caller
// updates no row and receives none. Two concurrent callers cannot both win, because
// the row lock ON CONFLICT takes serializes them and the loser then sees the
// winner's completed_at. A read-then-write in Go would have a race exactly wide
// enough to matter.
func (s *Service) CompleteSetup(ctx context.Context, controller, controllerKind string) (*SetupState, error) {
	controller = strings.TrimSpace(controller)
	if controller == "" {
		return nil, apperror.NewValidation("controller is required")
	}
	if len(controller) > 255 {
		return nil, apperror.NewValidation("controller must be at most 255 characters")
	}
	switch controllerKind {
	case ControllerKindService, ControllerKindOperator:
	case "":
		controllerKind = ControllerKindService
	default:
		return nil, apperror.NewValidation(fmt.Sprintf("controller kind %q must be service or operator", controllerKind))
	}

	var out SetupState
	err := s.repo.InTx(ctx, func(tx Repository) error {
		if err := tx.EnsureSetupState(ctx); err != nil {
			return apperror.NewInternal("initialize setup state", err)
		}
		row, err := tx.CompleteSetup(ctx, storage.CompleteSetupParams{
			Controller:     controller,
			ControllerKind: controllerKind,
		})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return apperror.NewConflict("setup is already complete")
			}
			return apperror.NewInternal("complete setup", err)
		}
		out = toSetupState(row)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}
