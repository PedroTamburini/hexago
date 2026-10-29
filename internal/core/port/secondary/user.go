package secondary

import (
	"context"
	"time"

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
	SetStatus(ctx context.Context, id uint64, isActive bool) error
	FindCredentialsByID(ctx context.Context, id uint64) (*Credentials, error)
	UpdatePasswordAndClearTemp(ctx context.Context, id uint64, passwordHash string) error
	SetTempPassword(ctx context.Context, id uint64, passwordHash string, expiresAt time.Time) error
	FindRoleByID(ctx context.Context, roleID uint64) (*entity.Role, error)
	HasRole(ctx context.Context, userID uint64, roleID uint64) (bool, error)
	AssignRole(ctx context.Context, userID uint64, roleID uint64) error
	RemoveRole(ctx context.Context, userID uint64, roleID uint64) error
}
