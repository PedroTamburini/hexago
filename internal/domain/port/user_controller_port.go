package port

import (
	"context"

	"github.com/PedroTamburini/hexago/internal/domain/dto"
)

type UserController interface {
	Create(ctx context.Context, input dto.CreateUserInput) (*dto.CreateUserOutput, error)
	FindByID(ctx context.Context, input dto.FindUserByIDInput) (*dto.FindUserByIDOutput, error)
	FindAll(ctx context.Context, input dto.FindAllUsersInput) (*dto.FindAllUsersOutput, error)
	Update(ctx context.Context, input dto.UpdateUserInput) (*dto.UpdateUserOutput, error)
	Delete(ctx context.Context, input dto.DeleteUserInput) error
}
