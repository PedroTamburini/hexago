package gorm

import (
	"github.com/PedroTamburini/hexago/internal/adapter/secondary/database/gorm/model"
	"gorm.io/gorm"
)

// RunAutoMigrations creates or updates the tables backing the GORM models. It
// is intended for development and fresh databases; production should use
// versioned migrations.
//
// For larger projects with more robust infrastructure, prefer migrations
// created/tested locally with golang-migrate:
//
//	migrate create \
//	  -ext sql \
//	  -dir internal/infrastructure/database/migrations \
//	  add_..._to_users
//
//	migrate ... up
//	migrate ... down 1
//	migrate ... up
//
// And apply them in production via the CLI in the deployment pipeline.
func RunAutoMigrations(db *gorm.DB) error {
	return db.AutoMigrate(
		&model.UserModel{},
		&model.RoleModel{},
		&model.UserRoleModel{},
		&model.PermissionModel{},
		&model.RolePermissionModel{},
	)
}
