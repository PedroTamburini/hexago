package repository

import (
	"context"
	"errors"

	"github.com/PedroTamburini/hexago/internal/adapter/secondary/database/gorm/model"
	domainerr "github.com/PedroTamburini/hexago/internal/core/domain/error"
	portout "github.com/PedroTamburini/hexago/internal/core/port/secondary"
	"gorm.io/gorm"
)

type AuthenticationRepository struct {
	db *gorm.DB
}

func NewAuthenticationRepository(db *gorm.DB) *AuthenticationRepository {
	return &AuthenticationRepository{db: db}
}

func (r *AuthenticationRepository) FindCredentialsByUsername(ctx context.Context, username string) (*portout.Credentials, error) {
	var userModel model.UserModel

	err := r.db.WithContext(ctx).
		Select("id", "password_hash").
		Where("username = ? AND is_active = ?", username, true).
		First(&userModel).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domainerr.ErrUserNotFound
		}
		return nil, err
	}

	return &portout.Credentials{
		ID:           userModel.ID,
		PasswordHash: userModel.PasswordHash,
	}, nil
}
