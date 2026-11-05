package secondary

import (
	"context"

	"github.com/PedroTamburini/hexago/internal/core/domain/entity"
)

// RoleRepository is the persistence capability required to manage role
// assignments and to answer the role-based questions the business rules depend
// on (whether a user is an administrator and how many active administrators
// exist).
type RoleRepository interface {
	FindRoleByID(ctx context.Context, roleID uint64) (*entity.Role, error)
	HasRole(ctx context.Context, userID uint64, roleID uint64) (bool, error)
	AssignRole(ctx context.Context, userID uint64, roleID uint64) error
	RemoveRole(ctx context.Context, userID uint64, roleID uint64) error
	IsAdmin(ctx context.Context, userID uint64) (bool, error)
	CountActiveAdmins(ctx context.Context) (int64, error)
}
