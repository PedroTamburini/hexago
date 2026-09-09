package model

import "github.com/PedroTamburini/hexago/internal/domain/entity"

func (u *UserModel) ToDomain() *entity.User {
	if u == nil {
		return nil
	}
	return &entity.User{
		ID:           u.ID,
		Name:         u.Name,
		Username:     u.Username,
		Email:        u.Email,
		PasswordHash: u.PasswordHash,
		IsAdmin:      u.IsAdmin,
		IsActive:     u.IsActive,
		CreatedAt:    u.CreatedAt,
		UpdatedAt:    u.UpdatedAt,
	}
}

func FromDomain(u *entity.User) *UserModel {
	if u == nil {
		return nil
	}
	return &UserModel{
		ID:           u.ID,
		Name:         u.Name,
		Username:     u.Username,
		Email:        u.Email,
		PasswordHash: u.PasswordHash,
		IsAdmin:      u.IsAdmin,
		IsActive:     u.IsActive,
		CreatedAt:    u.CreatedAt,
		UpdatedAt:    u.UpdatedAt,
	}
}
