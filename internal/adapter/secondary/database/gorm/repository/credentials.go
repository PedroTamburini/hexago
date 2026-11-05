package repository

import (
	"context"
	"errors"
	"time"

	"github.com/PedroTamburini/hexago/internal/adapter/secondary/database/gorm/model"
	domainerr "github.com/PedroTamburini/hexago/internal/core/domain/error"
	portout "github.com/PedroTamburini/hexago/internal/core/port/secondary"
	"gorm.io/gorm"
)

// CredentialsRepository owns every read and write of password credentials. The
// password hash is deliberately kept out of the regular user repository so it
// can never leak through a read model that is serialized or logged.
type CredentialsRepository struct {
	db *gorm.DB
}

func NewCredentialsRepository(db *gorm.DB) *CredentialsRepository {
	return &CredentialsRepository{db: db}
}

// FindCredentialsByUsername loads the credentials of an active account so the
// login flow can verify the password and decide whether the account is using a
// temporary password.
func (r *CredentialsRepository) FindCredentialsByUsername(ctx context.Context, username string) (*portout.Credentials, error) {
	var userModel model.UserModel

	err := r.db.WithContext(ctx).
		Select("id", "password_hash", "temp_password_expires_at").
		Where("username = ? AND is_active = ?", username, true).
		First(&userModel).Error
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

// FindCredentialsByID loads only the columns needed by the password flows.
// Keeping this read separate from FindByID prevents the password hash from
// entering the regular user read model.
func (r *CredentialsRepository) FindCredentialsByID(ctx context.Context, id uint64) (*portout.Credentials, error) {
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
func (r *CredentialsRepository) UpdatePasswordAndClearTemp(ctx context.Context, id uint64, passwordHash string) error {
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
func (r *CredentialsRepository) SetTempPassword(ctx context.Context, id uint64, passwordHash string, expiresAt time.Time) error {
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
