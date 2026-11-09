package model

import (
	"testing"
	"time"

	"github.com/PedroTamburini/hexago/internal/core/domain/entity"
	"gorm.io/gorm"
)

func TestUserModelToDomainMapsFieldsAndHidesPasswordHash(t *testing.T) {
	now := time.Now().Truncate(time.Second)

	stored := &UserModel{
		ID:           7,
		Name:         "JOHN DOE",
		Username:     "john.doe",
		Email:        "john@example.com",
		PasswordHash: "secret-hash",
		IsActive:     true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	user := stored.ToDomain()
	if user == nil {
		t.Fatal("ToDomain returned nil for a non-nil model")
	}

	if user.ID != 7 || user.Name != "JOHN DOE" || user.Username != "john.doe" || user.Email != "john@example.com" {
		t.Fatalf("unexpected mapping: %+v", user)
	}

	if !user.IsActive {
		t.Fatal("IsActive was not mapped")
	}

	if !user.CreatedAt.Equal(now) || !user.UpdatedAt.Equal(now) {
		t.Fatalf("timestamps were not mapped: %+v", user)
	}

	if user.PasswordHash != "" {
		t.Fatalf("PasswordHash leaked through ToDomain: %q", user.PasswordHash)
	}
}

func TestUserModelToDomainHandlesNil(t *testing.T) {
	var stored *UserModel

	if user := stored.ToDomain(); user != nil {
		t.Fatalf("ToDomain(nil) = %+v, want nil", user)
	}
}

func TestFromDomainMapsFields(t *testing.T) {
	now := time.Now().Truncate(time.Second)

	user := &entity.User{
		ID:           7,
		Name:         "JOHN DOE",
		Username:     "john.doe",
		Email:        "john@example.com",
		PasswordHash: "secret-hash",
		IsActive:     true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	stored := FromDomain(user)
	if stored == nil {
		t.Fatal("FromDomain returned nil for a non-nil entity")
	}

	if stored.ID != 7 || stored.Name != "JOHN DOE" || stored.Username != "john.doe" || stored.Email != "john@example.com" {
		t.Fatalf("unexpected mapping: %+v", stored)
	}

	if stored.PasswordHash != "secret-hash" {
		t.Fatalf("PasswordHash = %q, want secret-hash", stored.PasswordHash)
	}

	if !stored.IsActive {
		t.Fatal("IsActive was not mapped")
	}

	if !stored.CreatedAt.Equal(now) || !stored.UpdatedAt.Equal(now) {
		t.Fatalf("timestamps were not mapped: %+v", stored)
	}

	if stored.DeletedAt != (gorm.DeletedAt{}) {
		t.Fatalf("expected no deleted marker, got %+v", stored.DeletedAt)
	}
}

func TestFromDomainHandlesNil(t *testing.T) {
	if stored := FromDomain(nil); stored != nil {
		t.Fatalf("FromDomain(nil) = %+v, want nil", stored)
	}
}
