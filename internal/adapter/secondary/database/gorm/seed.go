package gorm

import (
	"errors"
	"fmt"

	"github.com/PedroTamburini/hexago/internal/adapter/secondary/database/gorm/model"
	"github.com/PedroTamburini/hexago/internal/core/domain/entity"
	"github.com/PedroTamburini/hexago/internal/core/permission"
	portout "github.com/PedroTamburini/hexago/internal/core/port/secondary"
	gormio "gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// SeedOptions carries the bootstrap admin details. Plain values are used
// instead of the application config so this adapter stays independent from the
// infrastructure config package.
type SeedOptions struct {
	AdminUsername string
	AdminEmail    string
	AdminPassword string
}

// RunSeed ensures the admin user exists and that the admin role is linked to
// every permission. It is idempotent and, unlike a user-count guard, it also
// repairs an existing database whose users were created before RBAC existed:
// permissions and role links are always reconciled, not only on an empty DB.
//
// The password hasher is injected so seeding does not reach into a concrete
// adapter and so the admin password goes through the same hashing path as any
// other user.
func RunSeed(db *gormio.DB, opts SeedOptions, hasher portout.PasswordHasher) error {
	admin, err := ensureAdminUser(db, opts, hasher)
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

func ensureAdminUser(db *gormio.DB, opts SeedOptions, hasher portout.PasswordHasher) (*model.UserModel, error) {
	var admin model.UserModel

	err := db.Where("username = ?", opts.AdminUsername).First(&admin).Error
	if err != nil && !errors.Is(err, gormio.ErrRecordNotFound) {
		return nil, fmt.Errorf("failed to look up admin user: %w", err)
	}

	if errors.Is(err, gormio.ErrRecordNotFound) {
		if opts.AdminPassword == "" {
			return nil, errors.New("ADMIN_PASSWORD environment variable is required for seeding")
		}

		user, buildErr := entity.NewUser("ADMIN", opts.AdminUsername, opts.AdminEmail)
		if buildErr != nil {
			return nil, fmt.Errorf("invalid admin user configuration: %w", buildErr)
		}

		passwordHash, hashErr := hasher.Hash(opts.AdminPassword)
		if hashErr != nil {
			return nil, fmt.Errorf("failed to encrypt admin password: %w", hashErr)
		}

		user.SetPasswordHash(passwordHash)

		admin = *model.FromDomain(user)

		if createErr := db.Clauses(clause.OnConflict{DoNothing: true}).Create(&admin).Error; createErr != nil {
			return nil, fmt.Errorf("failed to create admin user: %w", createErr)
		}
	}

	// OnConflict(DoNothing) leaves ID zero when the row already existed (or a
	// concurrent process won the race), so reload to get the real primary key.
	if admin.ID == 0 {
		if err := db.Where("username = ?", opts.AdminUsername).First(&admin).Error; err != nil {
			return nil, fmt.Errorf("failed to retrieve admin user: %w", err)
		}
	}

	return &admin, nil
}

func ensureAdminRole(db *gormio.DB) (*model.RoleModel, error) {
	role := &model.RoleModel{Name: model.AdminRoleName}

	if err := db.Clauses(clause.OnConflict{DoNothing: true}).Create(role).Error; err != nil {
		return nil, fmt.Errorf("failed to create admin role: %w", err)
	}

	// Retrieve the role ID in case it already existed.
	if err := db.Where("name = ?", model.AdminRoleName).First(role).Error; err != nil {
		return nil, fmt.Errorf("failed to retrieve admin role: %w", err)
	}

	return role, nil
}

func ensurePermissions(db *gormio.DB, role *model.RoleModel) error {
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
