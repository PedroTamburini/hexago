package repository

import (
	"context"
	"errors"

	"github.com/PedroTamburini/hexago/internal/adapter/secondary/database/gorm/model"
	"github.com/PedroTamburini/hexago/internal/core/domain/entity"
	domainerr "github.com/PedroTamburini/hexago/internal/core/domain/error"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// RoleRepository owns role assignments and the role-based queries the business
// rules depend on.
type RoleRepository struct {
	db *gorm.DB
}

func NewRoleRepository(db *gorm.DB) *RoleRepository {
	return &RoleRepository{db: db}
}

// FindRoleByID resolves a role for the role assignment flows. A missing role is
// translated to ErrRoleNotFound so both assign and remove answer 404.
func (r *RoleRepository) FindRoleByID(ctx context.Context, roleID uint64) (*entity.Role, error) {
	var roleModel model.RoleModel

	err := r.db.WithContext(ctx).First(&roleModel, roleID).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domainerr.ErrRoleNotFound
		}

		return nil, err
	}

	return &entity.Role{ID: roleModel.ID, Name: roleModel.Name}, nil
}

func (r *RoleRepository) HasRole(ctx context.Context, userID uint64, roleID uint64) (bool, error) {
	var count int64

	err := r.db.WithContext(ctx).
		Model(&model.UserRoleModel{}).
		Where("user_id = ? AND role_id = ?", userID, roleID).
		Count(&count).Error
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

// AssignRole inserts the user-role link and ignores an existing one. The use
// case checks HasRole first, so the conflict handling here is a safety net for
// concurrent requests rather than the primary duplicate check.
func (r *RoleRepository) AssignRole(ctx context.Context, userID uint64, roleID uint64) error {
	ur := model.UserRoleModel{UserID: userID, RoleID: roleID}

	err := r.db.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&ur).Error
	if err != nil {
		return err
	}

	return nil
}

// RemoveRole deletes the user-role link. Removing a role that is not assigned is
// a no-op, which makes a repeated request succeed instead of returning 404.
func (r *RoleRepository) RemoveRole(ctx context.Context, userID uint64, roleID uint64) error {
	result := r.db.WithContext(ctx).
		Where("user_id = ? AND role_id = ?", userID, roleID).
		Delete(&model.UserRoleModel{})
	if result.Error != nil {
		return result.Error
	}

	return nil
}

// IsAdmin reports whether the user holds the admin role. Administrator status
// is derived from the RBAC tables only: the legacy users.is_admin column is
// never read, so there is a single source of truth for authorization and for
// the business rules that depend on being an admin. Soft deleted users are
// excluded so a deleted account can never still be reported as an admin.
func (r *RoleRepository) IsAdmin(ctx context.Context, userID uint64) (bool, error) {
	var count int64

	err := r.db.WithContext(ctx).
		Table("user_roles AS ur").
		Joins("JOIN roles AS rl ON rl.id = ur.role_id").
		Joins(`JOIN "user" AS u ON u.id = ur.user_id`).
		Where("ur.user_id = ?", userID).
		Where("rl.name = ?", model.AdminRoleName).
		Where("u.deleted_at IS NULL").
		Count(&count).Error
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

// CountActiveAdmins returns how many users are active administrators. The
// delete use case relies on it to refuse removing the last one, which would
// leave the application with no privileged account until the database is fixed
// by hand. Deactivated or soft deleted users do not count, because they cannot
// exercise any permission.
func (r *RoleRepository) CountActiveAdmins(ctx context.Context) (int64, error) {
	var count int64

	err := r.db.WithContext(ctx).
		Table(`"user" AS u`).
		Joins("JOIN user_roles AS ur ON ur.user_id = u.id").
		Joins("JOIN roles AS rl ON rl.id = ur.role_id").
		Where("u.deleted_at IS NULL").
		Where("u.is_active = ?", true).
		Where("rl.name = ?", model.AdminRoleName).
		Count(&count).Error
	if err != nil {
		return 0, err
	}

	return count, nil
}
