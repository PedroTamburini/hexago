package repository

import (
	"context"
	"errors"

	"github.com/PedroTamburini/hexago/internal/domain/entity"
	domainerr "github.com/PedroTamburini/hexago/internal/domain/error"
	"github.com/PedroTamburini/hexago/internal/infrastructure/database/gorm/model"
	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type UserRepository struct {
	db *gorm.DB
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

	err := r.db.WithContext(ctx).First(&userModel, id).Error
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
		Select(
			"id",
			"name",
			"username",
			"email",
			"is_admin",
			"is_active",
			"created_at",
			"updated_at",
		).
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

func (r *UserRepository) Delete(ctx context.Context, id uint64) error {
	result := r.db.WithContext(ctx).Delete(&model.UserModel{}, id)
	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return domainerr.ErrUserNotFound
	}

	return nil
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
