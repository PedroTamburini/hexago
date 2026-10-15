package model

type RolePermissionModel struct {
	RoleID       uint64 `gorm:"primaryKey"`
	PermissionID uint64 `gorm:"primaryKey"`
}

func (RolePermissionModel) TableName() string {
	return "role_permissions"
}
