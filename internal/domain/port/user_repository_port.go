package port

import (
	"context"

	"github.com/PedroTamburini/hexago/internal/domain/entity"
)

type UserRepository interface {
	UserCredentialsFinder

	Create(ctx context.Context, user *entity.User) error
	FindByID(ctx context.Context, id uint64) (*entity.User, error)
	FindAll(ctx context.Context, limit, offset int) ([]*entity.User, error)
	Update(ctx context.Context, user *entity.User) error
	Delete(ctx context.Context, id uint64) error
}
