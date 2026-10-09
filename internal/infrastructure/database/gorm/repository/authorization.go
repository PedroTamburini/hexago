package repository

import (
	"context"
	"errors"

	"github.com/PedroTamburini/hexago/internal/infrastructure/database/gorm/model"
	"gorm.io/gorm"
)

type AuthorizationRepository struct {
	db *gorm.DB
}

func NewAuthorizationRepository(db *gorm.DB) *AuthorizationRepository {
	return &AuthorizationRepository{db: db}
}

// HasPermission reports whether the user is allowed to perform permission.
// Administrators (users.is_admin = true) are granted every permission, which
// makes the flag meaningful instead of being silently ignored.
func (r *AuthorizationRepository) HasPermission(ctx context.Context, userID uint64, permission string) (bool, error) {
	var user model.UserModel

	err := r.db.WithContext(ctx).
		Select("is_admin").
		Where("id = ?", userID).
		First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, err
	}

	if user.IsAdmin {
		return true, nil
	}

	var count int64

	err = r.db.WithContext(ctx).
		Table("user_roles AS ur").
		Joins("JOIN role_permissions AS rp ON rp.role_id = ur.role_id").
		Joins("JOIN permissions AS p ON p.id = rp.permission_id").
		Where("ur.user_id = ?", userID).
		Where("p.name = ?", permission).
		Count(&count).Error
	if err != nil {
		return false, err
	}

	return count > 0, nil
}
