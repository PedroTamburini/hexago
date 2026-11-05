package usecase

import (
	"context"

	domainerr "github.com/PedroTamburini/hexago/internal/core/domain/error"
	"github.com/PedroTamburini/hexago/internal/core/dto"
)

// SetStatus activates or deactivates an account. The administrator guards only
// apply to admin targets: nobody may deactivate their own admin account, and
// the last active admin cannot be deactivated because that would leave the
// application without a privileged account. Tokens are revoked only on an
// active -> inactive transition, so reactivating an account does not disturb
// sessions that are still valid.
func (uc *userUseCase) SetStatus(ctx context.Context, input dto.SetUserStatusInput) (*dto.SetUserStatusOutput, error) {
	target, err := uc.users.FindByID(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	isAdmin, err := uc.roles.IsAdmin(ctx, input.ID)
	if err != nil {
		return nil, err
	}
	if isAdmin {
		if input.ID == input.ActorID && !input.IsActive {
			return nil, domainerr.ErrAdminSelfDeactivate
		}

		if !input.IsActive && target.IsActive {
			activeAdmins, err := uc.roles.CountActiveAdmins(ctx)
			if err != nil {
				return nil, err
			}

			if activeAdmins <= 1 {
				return nil, domainerr.ErrCannotDeactivateLastAdmin
			}
		}
	}

	if err := uc.users.SetStatus(ctx, input.ID, input.IsActive); err != nil {
		return nil, err
	}

	if !input.IsActive && target.IsActive {
		if err := revokeAllUserTokens(ctx, uc.tokenVersions, uc.sessions, input.ID); err != nil {
			return nil, err
		}
	}

	return &dto.SetUserStatusOutput{
		ID:       input.ID,
		IsActive: input.IsActive,
	}, nil
}
