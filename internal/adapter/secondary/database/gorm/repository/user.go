package repository

import (
	"context"
	"errors"

	"github.com/PedroTamburini/hexago/internal/adapter/secondary/database/gorm/model"
	"github.com/PedroTamburini/hexago/internal/core/domain/entity"
	domainerr "github.com/PedroTamburini/hexago/internal/core/domain/error"
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
