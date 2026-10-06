package seed

import (
	"errors"
	"fmt"

	"github.com/PedroTamburini/hexago/internal/adapter/secondary/security"
	"github.com/PedroTamburini/hexago/internal/infrastructure/config"
	"github.com/PedroTamburini/hexago/internal/infrastructure/database/gorm"
	"github.com/PedroTamburini/hexago/internal/infrastructure/database/gorm/model"
	"gorm.io/gorm/clause"
)

// RunSeed creates the initial admin user when the users table has no records.
// It is idempotent: unique index conflicts (concurrent instances, soft-deleted
// records) are ignored instead of failing the boot.
func RunSeed(db *gorm.Database, cfg *config.Config) error {
	var count int64

	if err := db.Model(&model.UserModel{}).Count(&count).Error; err != nil {
		return fmt.Errorf("failed to count users: %w", err)
	}

	if count > 0 {
		return nil
	}

	if cfg.AdminPassword == "" {
		return errors.New("ADMIN_PASSWORD environment variable is required for seeding")
	}

	hasherService := security.NewPasswordHasher(cfg.HasherCost)

	passwordHash, err := hasherService.Hash(cfg.AdminPassword)
	if err != nil {
		return fmt.Errorf("failed to encrypt admin password: %w", err)
	}

	user := &model.UserModel{
		Name:         "Admin",
		Username:     cfg.AdminUsername,
		Email:        cfg.AdminEmail,
		PasswordHash: passwordHash,
		IsAdmin:      true,
		IsActive:     true,
	}

	if err := db.Clauses(clause.OnConflict{DoNothing: true}).Create(user).Error; err != nil {
		return fmt.Errorf("failed to create admin user: %w", err)
	}

	return nil
}
