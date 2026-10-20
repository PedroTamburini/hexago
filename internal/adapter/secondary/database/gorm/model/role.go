package model

// AdminRoleName is the role seeded with every permission.
const AdminRoleName = "admin"

type RoleModel struct {
	ID   uint64 `gorm:"primaryKey"`
	Name string `gorm:"uniqueIndex;not null"`
}

func (RoleModel) TableName() string {
	return "roles"
}
