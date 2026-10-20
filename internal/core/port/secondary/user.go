package secondary

import (
	"context"

	"github.com/PedroTamburini/hexago/internal/core/domain/entity"
)

// UserRepository is the persistence capability required to manage users.
type UserRepository interface {
	Create(ctx context.Context, user *entity.User) error
	FindByID(ctx context.Context, id uint64) (*entity.User, error)
	FindAll(ctx context.Context, limit, offset int) ([]*entity.User, error)
	Update(ctx context.Context, user *entity.User) error
	Delete(ctx context.Context, id uint64) error
	IsAdmin(ctx context.Context, userID uint64) (bool, error)
	CountActiveAdmins(ctx context.Context) (int64, error)
}
