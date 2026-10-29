package primary

import (
	"context"

	"github.com/PedroTamburini/hexago/internal/core/dto"
)

// UserUseCase is the capability exposed to the HTTP layer to manage users.
type UserUseCase interface {
	Create(ctx context.Context, input dto.CreateUserInput) (*dto.CreateUserOutput, error)
	FindByID(ctx context.Context, input dto.FindUserByIDInput) (*dto.FindUserByIDOutput, error)
	FindAll(ctx context.Context, input dto.FindAllUsersInput) (*dto.FindAllUsersOutput, error)
	Update(ctx context.Context, input dto.UpdateUserInput) (*dto.UpdateUserOutput, error)
	Delete(ctx context.Context, input dto.DeleteUserInput) error
	SetStatus(ctx context.Context, input dto.SetUserStatusInput) (*dto.SetUserStatusOutput, error)
	ResetPassword(ctx context.Context, input dto.ResetPasswordInput) (*dto.ResetPasswordOutput, error)
	AssignRole(ctx context.Context, input dto.AssignRoleInput) error
	RemoveRole(ctx context.Context, input dto.RemoveRoleInput) error
}
