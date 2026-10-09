package seed

import (
	"errors"
	"fmt"

	"github.com/PedroTamburini/hexago/internal/adapter/secondary/security"
	"github.com/PedroTamburini/hexago/internal/domain/permission"
	"github.com/PedroTamburini/hexago/internal/infrastructure/config"
	"github.com/PedroTamburini/hexago/internal/infrastructure/database/gorm"
	"github.com/PedroTamburini/hexago/internal/infrastructure/database/gorm/model"
	gormio "gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// RunSeed ensures the admin user exists and that the admin role is linked to
// every permission. It is idempotent and, unlike a user-count guard, it also
// repairs an existing database whose users were created before RBAC existed:
// permissions and role links are always reconciled, not only on an empty DB.
func RunSeed(db *gorm.Database, cfg *config.Config) error {
	admin, err := ensureAdminUser(db, cfg)
	if err != nil {
		return err
	}

	role, err := ensureAdminRole(db)
	if err != nil {
		return err
	}

	if err := ensurePermissions(db, role); err != nil {
		return err
	}

	// Relate the admin user to the admin role.
	if err := db.Clauses(clause.OnConflict{DoNothing: true}).Create(&model.UserRoleModel{
		UserID: admin.ID,
		RoleID: role.ID,
	}).Error; err != nil {
		return fmt.Errorf("failed to relate admin user to admin role: %w", err)
	}

	return nil
}

func ensureAdminUser(db *gorm.Database, cfg *config.Config) (*model.UserModel, error) {
	var admin model.UserModel

	err := db.Where("username = ?", cfg.AdminUsername).First(&admin).Error
	if err != nil && !errors.Is(err, gormio.ErrRecordNotFound) {
		return nil, fmt.Errorf("failed to look up admin user: %w", err)
	}

	if errors.Is(err, gormio.ErrRecordNotFound) {
		if cfg.AdminPassword == "" {
			return nil, errors.New("ADMIN_PASSWORD environment variable is required for seeding")
		}

		hasherService := security.NewPasswordHasher(cfg.HasherCost)

		passwordHash, hashErr := hasherService.Hash(cfg.AdminPassword)
		if hashErr != nil {
			return nil, fmt.Errorf("failed to encrypt admin password: %w", hashErr)
		}

		admin = model.UserModel{
			Name:         "ADMIN",
			Username:     cfg.AdminUsername,
			Email:        cfg.AdminEmail,
			PasswordHash: passwordHash,
			IsAdmin:      true,
			IsActive:     true,
		}

		if createErr := db.Clauses(clause.OnConflict{DoNothing: true}).Create(&admin).Error; createErr != nil {
			return nil, fmt.Errorf("failed to create admin user: %w", createErr)
		}
	}

	// OnConflict(DoNothing) leaves ID zero when the row already existed (or a
	// concurrent process won the race), so reload to get the real primary key.
	if admin.ID == 0 {
		if err := db.Where("username = ?", cfg.AdminUsername).First(&admin).Error; err != nil {
			return nil, fmt.Errorf("failed to retrieve admin user: %w", err)
		}
	}

	return &admin, nil
}

func ensureAdminRole(db *gorm.Database) (*model.RoleModel, error) {
	role := &model.RoleModel{Name: "admin"}

	if err := db.Clauses(clause.OnConflict{DoNothing: true}).Create(role).Error; err != nil {
		return nil, fmt.Errorf("failed to create admin role: %w", err)
	}

	// Retrieve the role ID in case it already existed.
	if err := db.Where("name = ?", "admin").First(role).Error; err != nil {
		return nil, fmt.Errorf("failed to retrieve admin role: %w", err)
	}

	return role, nil
}

func ensurePermissions(db *gorm.Database, role *model.RoleModel) error {
	for _, name := range permission.All() {
		perm := model.PermissionModel{Name: name}

		if err := db.Clauses(clause.OnConflict{DoNothing: true}).Create(&perm).Error; err != nil {
			return fmt.Errorf("failed to create permission %q: %w", name, err)
		}

		// DoNothing leaves ID zero when the permission already existed, so
		// reload before using it as a foreign key.
		if err := db.Where("name = ?", name).First(&perm).Error; err != nil {
			return fmt.Errorf("failed to retrieve permission %q: %w", name, err)
		}

		if err := db.Clauses(clause.OnConflict{DoNothing: true}).Create(&model.RolePermissionModel{
			RoleID:       role.ID,
			PermissionID: perm.ID,
		}).Error; err != nil {
			return fmt.Errorf("failed to relate permission %q to admin role: %w", name, err)
		}
	}

	return nil
}
