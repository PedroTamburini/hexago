package model

type PermissionModel struct {
	ID   uint64 `gorm:"primaryKey"`
	Name string `gorm:"uniqueIndex;not null"`
}

func (PermissionModel) TableName() string {
	return "permissions"
}
