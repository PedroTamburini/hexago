package repository

import (
	"context"
	"errors"
	"time"

	"github.com/PedroTamburini/hexago/internal/adapter/secondary/database/gorm/model"
	"github.com/PedroTamburini/hexago/internal/core/domain/entity"
	domainerr "github.com/PedroTamburini/hexago/internal/core/domain/error"
	portout "github.com/PedroTamburini/hexago/internal/core/port/secondary"
	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type UserRepository struct {
	db *gorm.DB
}

// userReadColumns lists the columns loaded by read paths. password_hash is
// deliberately excluded so credentials only flow through the authentication
// repository.
var userReadColumns = []string{
	"id",
	"name",
	"username",
	"email",
	"is_active",
	"created_at",
	"updated_at",
}

func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(ctx context.Context, user *entity.User) error {
	userModel := model.FromDomain(user)

	if err := r.db.WithContext(ctx).Create(userModel).Error; err != nil {
		return mapUserRepositoryError(err)
	}

	user.ID = userModel.ID

	return nil
}

// SetStatus updates the active flag of a user that was not removed. A missing
// row is reported as ErrUserNotFound so the HTTP layer can answer 404 instead
// of silently accepting a status change for a nonexistent account.
func (r *UserRepository) SetStatus(ctx context.Context, id uint64, isActive bool) error {
	result := r.db.WithContext(ctx).
		Model(&model.UserModel{}).
		Where("id = ? AND deleted_at IS NULL", id).
		Update("is_active", isActive)
	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return domainerr.ErrUserNotFound
	}

	return nil
}

// FindCredentialsByID loads only the columns needed by the change-password
// flow. Keeping this read separate from FindByID prevents the password hash
// from entering the regular user read model.
func (r *UserRepository) FindCredentialsByID(ctx context.Context, id uint64) (*portout.Credentials, error) {
	var userModel model.UserModel

	err := r.db.WithContext(ctx).
		Select("id", "password_hash", "temp_password_expires_at").
		First(&userModel, id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domainerr.ErrUserNotFound
		}

		return nil, err
	}

	return &portout.Credentials{
		ID:                    userModel.ID,
		PasswordHash:          userModel.PasswordHash,
		TempPasswordExpiresAt: userModel.TempPasswordExpiresAt,
	}, nil
}

// UpdatePasswordAndClearTemp writes the new hash and clears the temporary
// password marker in the same statement, so a password change cannot leave an
// expiration behind that would keep the account in the temporary-password flow.
func (r *UserRepository) UpdatePasswordAndClearTemp(ctx context.Context, id uint64, passwordHash string) error {
	result := r.db.WithContext(ctx).
		Model(&model.UserModel{}).
		Where("id = ?", id).
		Updates(map[string]any{
			"password_hash":            passwordHash,
			"temp_password_expires_at": nil,
		})
	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return domainerr.ErrUserNotFound
	}

	return nil
}

// SetTempPassword stores the hash of the temporary password together with its
// expiration. The plaintext is never persisted; only the value returned to the
// administrator can be used to log in.
func (r *UserRepository) SetTempPassword(ctx context.Context, id uint64, passwordHash string, expiresAt time.Time) error {
	result := r.db.WithContext(ctx).
		Model(&model.UserModel{}).
		Where("id = ?", id).
		Updates(map[string]any{
			"password_hash":            passwordHash,
			"temp_password_expires_at": expiresAt,
		})
	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return domainerr.ErrUserNotFound
	}

	return nil
}

// FindRoleByID resolves a role for the role assignment flows. A missing role is
// translated to ErrRoleNotFound so both assign and remove answer 404.
func (r *UserRepository) FindRoleByID(ctx context.Context, roleID uint64) (*entity.Role, error) {
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

func (r *UserRepository) HasRole(ctx context.Context, userID uint64, roleID uint64) (bool, error) {
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
func (r *UserRepository) AssignRole(ctx context.Context, userID uint64, roleID uint64) error {
	ur := model.UserRoleModel{UserID: userID, RoleID: roleID}

	err := r.db.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&ur).Error
	if err != nil {
		return err
	}

	return nil
}

// RemoveRole deletes the user-role link. Removing a role that is not assigned is
// a no-op, which makes a repeated request succeed instead of returning 404.
func (r *UserRepository) RemoveRole(ctx context.Context, userID uint64, roleID uint64) error {
	result := r.db.WithContext(ctx).
		Where("user_id = ? AND role_id = ?", userID, roleID).
		Delete(&model.UserRoleModel{})
	if result.Error != nil {
		return result.Error
	}

	return nil
}

func (r *UserRepository) FindByID(ctx context.Context, id uint64) (*entity.User, error) {
	var userModel model.UserModel

	err := r.db.WithContext(ctx).Select(userReadColumns).First(&userModel, id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domainerr.ErrUserNotFound
		}
		return nil, err
	}

	return userModel.ToDomain(), nil
}

func (r *UserRepository) FindAll(ctx context.Context, limit, offset int) ([]*entity.User, error) {
	var usersModel []model.UserModel

	err := r.db.WithContext(ctx).
		Select(userReadColumns).
		Order("id ASC").
		Limit(limit).
		Offset(offset).
		Find(&usersModel).Error
	if err != nil {
		return nil, err
	}

	users := make([]*entity.User, len(usersModel))
	for i := range usersModel {
		users[i] = usersModel[i].ToDomain()
	}

	return users, nil
}

// Delete removes a user. The removal is a soft delete: the row stays in the
// table but leaves the unique indexes, so the identity it held can be
// registered again. The account is deactivated in the same statement, so a
// removed user never keeps the active flag that says the account is still
// usable.
//
// Both columns are written by a single statement to avoid a window in which
// the account is removed but still reported as active. The soft delete scope
// of GORM keeps the statement restricted to the rows that were not removed
// yet, so deleting an already deleted user affects no row and is reported as
// not found.
func (r *UserRepository) Delete(ctx context.Context, id uint64) error {
	result := r.db.WithContext(ctx).
		Model(&model.UserModel{}).
		Where("id = ?", id).
		Updates(map[string]any{
			"is_active":  false,
			"deleted_at": r.db.NowFunc(),
		})

	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return domainerr.ErrUserNotFound
	}

	return nil
}

// IsAdmin reports whether the user holds the admin role. Administrator status
// is derived from the RBAC tables only: the legacy users.is_admin column is
// never read, so there is a single source of truth for authorization and for
// the business rules that depend on being an admin. Soft deleted users are
// excluded so a deleted account can never still be reported as an admin.
func (r *UserRepository) IsAdmin(ctx context.Context, userID uint64) (bool, error) {
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
func (r *UserRepository) CountActiveAdmins(ctx context.Context) (int64, error) {
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

func (r *UserRepository) Update(ctx context.Context, user *entity.User) error {
	userModel := model.FromDomain(user)

	result := r.db.WithContext(ctx).Model(userModel).
		Where("id = ?", userModel.ID).
		Select("name", "username", "email").
		Clauses(clause.Returning{
			Columns: []clause.Column{
				{Name: "updated_at"},
			},
		}).
		Updates(userModel)

	if result.Error != nil {
		return mapUserRepositoryError(result.Error)
	}

	if result.RowsAffected == 0 {
		return domainerr.ErrUserNotFound
	}

	user.UpdatedAt = userModel.UpdatedAt

	return nil
}

func mapUserRepositoryError(err error) error {
	var pgErr *pgconn.PgError

	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return domainerr.ErrUserAlreadyExists
	}

	return err
}
