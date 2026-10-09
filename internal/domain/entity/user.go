package entity

import (
	"strings"
	"time"

	domainerr "github.com/PedroTamburini/hexago/internal/domain/error"
	"github.com/PedroTamburini/hexago/internal/domain/validator"
)

type User struct {
	ID           uint64
	Name         string
	Username     string
	Email        string
	PasswordHash string
	IsAdmin      bool
	IsActive     bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

func prepareUserData(name, username, email string) (string, string, string, error) {
	name = strings.ToUpper(strings.TrimSpace(name))
	username = strings.ToLower(strings.TrimSpace(username))
	email = strings.ToLower(strings.TrimSpace(email))

	if !validator.IsValidName(name) {
		return "", "", "", domainerr.ErrInvalidName
	}

	if !validator.IsValidUsername(username) {
		return "", "", "", domainerr.ErrInvalidUsername
	}

	if !validator.IsValidEmail(email) {
		return "", "", "", domainerr.ErrInvalidEmail
	}

	return name, username, email, nil
}

func NewUser(name, username, email string) (*User, error) {
	name, username, email, err := prepareUserData(name, username, email)
	if err != nil {
		return nil, err
	}

	return &User{
		Name:     name,
		Username: username,
		Email:    email,
		IsActive: true,
	}, nil
}

func (u *User) SetPasswordHash(hash string) {
	u.PasswordHash = hash
}

func (u *User) Update(name, username, email string) error {
	name, username, email, err := prepareUserData(name, username, email)
	if err != nil {
		return err
	}

	u.Name = name
	u.Username = username
	u.Email = email

	return nil
}
