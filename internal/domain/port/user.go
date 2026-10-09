package port

import (
	"context"

	"github.com/PedroTamburini/hexago/internal/domain/dto"
	"github.com/PedroTamburini/hexago/internal/domain/entity"
)

// UserUseCase is the capability exposed to the HTTP layer to manage users.
type UserUseCase interface {
	Create(ctx context.Context, input dto.CreateUserInput) (*dto.CreateUserOutput, error)
	FindByID(ctx context.Context, input dto.FindUserByIDInput) (*dto.FindUserByIDOutput, error)
	FindAll(ctx context.Context, input dto.FindAllUsersInput) (*dto.FindAllUsersOutput, error)
	Update(ctx context.Context, input dto.UpdateUserInput) (*dto.UpdateUserOutput, error)
	Delete(ctx context.Context, input dto.DeleteUserInput) error
}

// UserRepository is the persistence capability required to manage users.
type UserRepository interface {
	Create(ctx context.Context, user *entity.User) error
	FindByID(ctx context.Context, id uint64) (*entity.User, error)
	FindAll(ctx context.Context, limit, offset int) ([]*entity.User, error)
	Update(ctx context.Context, user *entity.User) error
	Delete(ctx context.Context, id uint64) error
}
