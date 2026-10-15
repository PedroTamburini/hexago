package model

import "github.com/PedroTamburini/hexago/internal/core/domain/entity"

func (u *UserModel) ToDomain() *entity.User {
	if u == nil {
		return nil
	}
	// PasswordHash is deliberately not mapped: read paths never select it, so
	// the hash can never leak through an entity that is about to be serialized
	// or logged.
	return &entity.User{
		ID:        u.ID,
		Name:      u.Name,
		Username:  u.Username,
		Email:     u.Email,
		IsAdmin:   u.IsAdmin,
		IsActive:  u.IsActive,
		CreatedAt: u.CreatedAt,
		UpdatedAt: u.UpdatedAt,
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
