package usecase

import (
	"context"

	domainerr "github.com/PedroTamburini/hexago/internal/core/domain/error"
	"github.com/PedroTamburini/hexago/internal/core/dto"
)

// AssignRole attaches a role to a user. The target is resolved before the role
// so a missing user takes precedence over a missing role in the error returned
// to the caller. HasRole keeps a repeated assignment from becoming a silent
// success, which lets the HTTP layer answer 409.
func (uc *userUseCase) AssignRole(ctx context.Context, input dto.AssignRoleInput) error {
	if _, err := uc.users.FindByID(ctx, input.TargetID); err != nil {
		return err
	}

	role, err := uc.roles.FindRoleByID(ctx, input.RoleID)
	if err != nil {
		return err
	}

	has, err := uc.roles.HasRole(ctx, input.TargetID, role.ID)
	if err != nil {
		return err
	}

	if has {
		return domainerr.ErrRoleAlreadyAssigned
	}

	return uc.roles.AssignRole(ctx, input.TargetID, role.ID)
}

// RemoveRole detaches a role from a user. Removing admin is guarded only for an
// active admin: an inactive admin cannot exercise permissions, so stripping the
// role from it cannot lock the application out.
func (uc *userUseCase) RemoveRole(ctx context.Context, input dto.RemoveRoleInput) error {
	target, err := uc.users.FindByID(ctx, input.TargetID)
	if err != nil {
		return err
	}

	role, err := uc.roles.FindRoleByID(ctx, input.RoleID)
	if err != nil {
		return err
	}

	if role.Name == "admin" {
		isAdmin, err := uc.roles.IsAdmin(ctx, input.TargetID)
		if err != nil {
			return err
		}

		if isAdmin && target.IsActive {
			activeAdmins, err := uc.roles.CountActiveAdmins(ctx)
			if err != nil {
				return err
			}

			if activeAdmins <= 1 {
				return domainerr.ErrCannotRemoveLastAdmin
			}
		}
	}

	return uc.roles.RemoveRole(ctx, input.TargetID, role.ID)
}
