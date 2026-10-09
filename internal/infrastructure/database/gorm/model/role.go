package model

type RoleModel struct {
	ID   uint64 `gorm:"primaryKey"`
	Name string `gorm:"uniqueIndex;not null"`
}

func (RoleModel) TableName() string {
	return "roles"
}
