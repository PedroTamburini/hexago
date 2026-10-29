package model

import (
	"time"

	"gorm.io/gorm"
)

// UserModel is the persistence representation of a user.
//
// The uniqueness of the username and the email is enforced by partial unique
// indexes that only cover the rows that were not removed. Removing a user is a
// soft delete, so the row stays in the table but leaves the index: the
// identity it held becomes available again and can be registered by another
// account. A full unique index would block that reuse forever.
//
// The predicate is declared with the "where" option of the index tag and is
// materialized by GORM as:
//
//	CREATE UNIQUE INDEX uniq_user_username ON "user" (username) WHERE deleted_at IS NULL
//	CREATE UNIQUE INDEX uniq_user_email    ON "user" (email)    WHERE deleted_at IS NULL
//
// The is_active flag is deliberately not part of the predicate: a deactivated
// account still holds its identity, only a removed one frees it.
type UserModel struct {
	ID                    uint64     `gorm:"primaryKey"`
	Name                  string     `gorm:"not null;size:100"`
	Username              string     `gorm:"uniqueIndex:uniq_user_username,where:deleted_at IS NULL;not null;size:60"`
	Email                 string     `gorm:"uniqueIndex:uniq_user_email,where:deleted_at IS NULL;not null;size:254"`
	PasswordHash          string     `gorm:"not null;"`
	TempPasswordExpiresAt *time.Time `gorm:"column:temp_password_expires_at"`
	IsActive              bool       `gorm:"default:true"`
	CreatedAt             time.Time
	UpdatedAt             time.Time
	DeletedAt             gorm.DeletedAt `gorm:"index"`
}

func (UserModel) TableName() string {
	return "user"
}
