package repository

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/PedroTamburini/hexago/internal/adapter/secondary/database/gorm/model"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// newTestDB opens a real SQLite database in a temporary file. A file (instead of
// ":memory:") is used because every pooled connection would otherwise get its
// own isolated in-memory database.
func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	path := filepath.Join(t.TempDir(), "test.db")

	db, err := gorm.Open(sqlite.Open(path), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}

	if err := db.AutoMigrate(
		&model.UserModel{},
		&model.RoleModel{},
		&model.UserRoleModel{},
		&model.PermissionModel{},
		&model.RolePermissionModel{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql db: %v", err)
	}
	t.Cleanup(func() {
		_ = sqlDB.Close()
	})

	return db
}

type userSeed struct {
	name     string
	username string
	email    string
	hash     string
	active   bool
	temp     *time.Time
}

func createUser(t *testing.T, db *gorm.DB, seed userSeed) *model.UserModel {
	t.Helper()

	if seed.hash == "" {
		seed.hash = "hash"
	}

	user := &model.UserModel{
		Name:                  seed.name,
		Username:              seed.username,
		Email:                 seed.email,
		PasswordHash:          seed.hash,
		IsActive:              true,
		TempPasswordExpiresAt: seed.temp,
	}

	if err := db.Create(user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	if !seed.active {
		if err := db.Model(&model.UserModel{}).Where("id = ?", user.ID).Update("is_active", false).Error; err != nil {
			t.Fatalf("deactivate user: %v", err)
		}
		user.IsActive = false
	}

	return user
}

func createRole(t *testing.T, db *gorm.DB, name string) *model.RoleModel {
	t.Helper()

	role := &model.RoleModel{Name: name}
	if err := db.Create(role).Error; err != nil {
		t.Fatalf("create role: %v", err)
	}

	return role
}

func createPermission(t *testing.T, db *gorm.DB, name string) *model.PermissionModel {
	t.Helper()

	permission := &model.PermissionModel{Name: name}
	if err := db.Create(permission).Error; err != nil {
		t.Fatalf("create permission: %v", err)
	}

	return permission
}

func assignRole(t *testing.T, db *gorm.DB, userID, roleID uint64) {
	t.Helper()

	if err := db.Create(&model.UserRoleModel{UserID: userID, RoleID: roleID}).Error; err != nil {
		t.Fatalf("assign role: %v", err)
	}
}

func grantPermission(t *testing.T, db *gorm.DB, roleID, permissionID uint64) {
	t.Helper()

	if err := db.Create(&model.RolePermissionModel{RoleID: roleID, PermissionID: permissionID}).Error; err != nil {
		t.Fatalf("grant permission: %v", err)
	}
}
