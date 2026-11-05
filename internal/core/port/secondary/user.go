package secondary

import (
	"context"

	"github.com/PedroTamburini/hexago/internal/core/domain/entity"
)

// UserRepository is the persistence capability required to manage the user
// aggregate: its profile, lifecycle and active flag. Credentials and roles live
// in their own ports so this interface stays focused.
type UserRepository interface {
	Create(ctx context.Context, user *entity.User) error
	FindByID(ctx context.Context, id uint64) (*entity.User, error)
	FindAll(ctx context.Context, limit, offset int) ([]*entity.User, error)
	Update(ctx context.Context, user *entity.User) error
	Delete(ctx context.Context, id uint64) error
	SetStatus(ctx context.Context, id uint64, isActive bool) error
}
