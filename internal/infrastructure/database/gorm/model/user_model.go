package model

import (
	"time"

	"gorm.io/gorm"
)

type UserModel struct {
	ID           uint64 `gorm:"primaryKey"`
	Name         string `gorm:"not null;size:100"`
	Username     string `gorm:"uniqueIndex;not null;size:60"`
	Email        string `gorm:"uniqueIndex;not null;size:254"`
	PasswordHash string `gorm:"not null;"`
	IsAdmin      bool   `gorm:"default:false"`
	IsActive     bool   `gorm:"default:true"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DeletedAt    gorm.DeletedAt `gorm:"index"`
}

func (UserModel) TableName() string {
	return "user"
}
