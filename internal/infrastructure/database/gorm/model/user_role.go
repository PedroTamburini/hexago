package model

type UserRoleModel struct {
	UserID uint64 `gorm:"primaryKey"`
	RoleID uint64 `gorm:"primaryKey"`
}

func (UserRoleModel) TableName() string {
	return "user_roles"
}
